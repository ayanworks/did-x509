// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Certificate + key material handling for the playground.
 *
 * Two ways an identity enters the playground:
 *
 *   1. **Generated** — a throwaway CA + leaf chain built in memory.
 *   2. **Uploaded** — a real PEM chain plus the leaf's private key.
 *
 * Both produce the same `DidX509Identity` shape, so every later step (DID
 * derivation, database detail view, VC signing) is agnostic to the origin.
 *
 * ## Why the private key is required for signing
 *
 * A `did:x509` DID is derived from certificates alone, so a chain by itself is
 * enough to *resolve*. Signing is different: the credential is signed with the
 * key the certificate vouches for, so the signing flows need the matching
 * private key. Uploads without a key can still be inspected and resolved; the
 * signing actions are disabled for them rather than failing at signing time.
 *
 * ## Nothing is persisted
 *
 * Parsing happens per request. No uploaded material is written to disk, and
 * nothing is retained between requests — matching the playground's existing
 * "nothing is stored" guarantee. Callers pass the PEM material back in with
 * each signing request instead of the server holding session state.
 */

import 'reflect-metadata';

import {
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509Certificate,
} from '@peculiar/x509';

// ---------------------------------------------------------------------------
// PEM parsing
// ---------------------------------------------------------------------------

/**
 * Split a PEM bundle into labelled blocks: `{ label, bytes }`.
 *
 * The label is kept because the private-key format matters downstream
 * (`PRIVATE KEY` is PKCS#8, `RSA PRIVATE KEY` is PKCS#1).
 */
export interface PemBlock {
  label: string;
  bytes: Uint8Array;
}

export function parsePemBlocks(pem: string): PemBlock[] {
  const blocks: PemBlock[] = [];
  const re = /-----BEGIN ([^-]+)-----([\s\S]*?)-----END \1-----/g;
  for (const match of pem.matchAll(re)) {
    const body = match[2]!.replace(/\s+/g, '');
    if (!body) continue;
    blocks.push({
      label: match[1]!.trim(),
      bytes: Uint8Array.from(atob(body), c => c.charCodeAt(0)),
    });
  }
  return blocks;
}

/** True when the string looks like a PEM certificate. */
export function looksLikePem(value: string): boolean {
  return /-----BEGIN (CERTIFICATE|TRUSTED CERTIFICATE)-----/.test(value);
}

/** True when the string looks like a PEM private key of any common form. */
export function looksLikePrivateKey(value: string): boolean {
  return /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value);
}

// ---------------------------------------------------------------------------
// Certificate details
// ---------------------------------------------------------------------------

/** A single subject/issuer attribute, in display order. */
export interface AttributeView {
  label: string;
  value: string;
}

/** A parsed SAN entry, normalised for display. */
export interface SanView {
  type: string;
  value: string;
}

/**
 * Everything the UI shows about one certificate.
 *
 * Deliberately flat and JSON-safe: it crosses the HTTP boundary as-is, so the
 * browser needs no certificate parsing library of its own.
 */
export interface CertificateView {
  /** Position in the chain: 0 is the leaf (end-entity) certificate. */
  index: number;
  role: 'leaf' | 'intermediate' | 'root';
  subject: string;
  issuer: string;
  subjectAttributes: AttributeView[];
  issuerAttributes: AttributeView[];
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  expired: boolean;
  notYetValid: boolean;
  validityDays: number;
  /** True for self-signed certificates. */
  selfSigned: boolean;
  signatureAlgorithm: string;
  /** Key algorithm as reported by the platform, e.g. "EC P-256". */
  keyType: string;
  keyCurve?: string;
  keySizeBits?: number;
  /** Public JWK of this certificate's key. */
  publicKeyJwk: JsonWebKey;
  /** Lowercase hex SHA-256 fingerprint; the value a DID can anchor to. */
  sha256: string;
  fingerprint: { sha256: string; sha384: string; sha512: string };
  extensions: {
    basicConstraints?: string;
    keyUsage?: string[];
    extendedKeyUsage?: string[];
    subjectAltName?: SanView[];
    isCa: boolean;
    /** Whether the leaf may sign (digitalSignature / nonRepudiation). */
    canSign: boolean;
  };
  /** PEM of this certificate, for display and re-download. */
  pem: string;
  /** DER byte length. */
  sizeBytes: number;
}

/** Lowercase hex SHA-256 of a certificate's DER, the did:x509 anchor form. */
export async function sha256Hex(certificate: X509Certificate): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new Uint8Array(certificate.rawData)
  );
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Lowercase hex of a certificate's DER under the named digest. */
async function hexDigest(
  certificate: X509Certificate,
  algorithm: 'SHA-256' | 'SHA-384' | 'SHA-512'
): Promise<string> {
  const digest = await crypto.subtle.digest(
    algorithm,
    new Uint8Array(certificate.rawData)
  );
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Extended key usage OIDs → friendly names.
 *
 * `@peculiar/x509` returns raw dotted OIDs for EKU, which is accurate but
 * unreadable; these are the ones that actually appear on CA and TLS certs.
 */
const EKU_NAMES: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
  '1.3.6.1.5.5.7.3.5': 'ipsecEndSystem',
  '1.3.6.1.5.5.7.3.6': 'ipsecTunnel',
  '1.3.6.1.5.5.7.3.7': 'ipsecUser',
  '1.3.6.1.5.5.7.3.8': 'timeStamping',
  '1.3.6.1.5.5.7.3.9': 'ocspSigning',
  '2.5.29.37.0': 'anyExtendedKeyUsage',
};

const KEY_USAGE_NAMES: Array<[number, string]> = [
  [1, 'digitalSignature'],
  [2, 'nonRepudiation'],
  [4, 'keyEncipherment'],
  [8, 'dataEncipherment'],
  [16, 'keyAgreement'],
  [32, 'keyCertSign'],
  [64, 'cRLSign'],
  [128, 'encipherOnly'],
  [256, 'decipherOnly'],
];

function keyUsageNames(bits: number): string[] {
  return KEY_USAGE_NAMES.filter(([flag]) => (bits & flag) !== 0).map(
    ([, name]) => name
  );
}

/** Parse an RFC 4514 name string into ordered label/value pairs. */
function splitName(name: string): AttributeView[] {
  const out: AttributeView[] = [];
  // Names may contain escaped commas; the certificates here do not, and a
  // naive split is what `@peculiar/x509`'s own formatting assumes.
  for (const part of name.split(/,\s*(?=[^=]+=)/)) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const label = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (label && value) out.push({ label, value });
  }
  return out;
}

/** Describe the key algorithm of a certificate in one line. */
function describeKey(certificate: X509Certificate): {
  keyType: string;
  keyCurve?: string;
  keySizeBits?: number;
} {
  const alg = certificate.publicKey.algorithm as {
    name: string;
    namedCurve?: string;
    modulusLength?: number;
  };

  switch (alg.name) {
    case 'ECDSA':
      return {
        keyType: `EC ${alg.namedCurve ?? ''}`.trim(),
        keyCurve: alg.namedCurve,
        keySizeBits:
          alg.namedCurve === 'P-256'
            ? 256
            : alg.namedCurve === 'P-384'
              ? 384
              : alg.namedCurve === 'P-521'
                ? 521
                : undefined,
      };
    case 'Ed25519':
    case 'Ed448':
      return { keyType: alg.name, keyCurve: alg.name, keySizeBits: undefined };
    case 'RSASSA-PKCS1-v1_5':
    case 'RSA-PSS':
      return { keyType: 'RSA', keySizeBits: alg.modulusLength };
    default:
      return { keyType: alg.name };
  }
}

/** Human-readable description of a certificate's signature algorithm. */
function describeSignature(certificate: X509Certificate): string {
  const alg = certificate.signatureAlgorithm as {
    name?: string;
    hash?: { name?: string };
  };
  const name = alg?.name ?? 'unknown';
  const hash = alg?.hash?.name;
  if (!hash) return name;
  const family =
    name === 'ECDSA'
      ? 'ECDSA'
      : name === 'RSA-PSS'
        ? 'RSA-PSS'
        : name === 'RSASSA-PKCS1-v1_5'
          ? 'RSA'
          : name;
  return `${family} with ${hash}`;
}

/**
 * Build the display model for one certificate in a chain.
 *
 * @param index position in the chain, leaf first (0 = leaf)
 * @param chainLength used only to label the last certificate as the root
 */
export async function buildCertificateView(
  certificate: X509Certificate,
  index: number,
  chainLength: number
): Promise<CertificateView> {
  // `isSelfSigned` is async in @peculiar/x509, despite reading like a property.
  const selfSigned = await certificate.isSelfSigned();

  const isLast = index === chainLength - 1;
  const role: CertificateView['role'] =
    index === 0 ? 'leaf' : isLast && selfSigned ? 'root' : 'intermediate';

  const now = Date.now();
  const notBefore = certificate.notBefore;
  const notAfter = certificate.notAfter;

  let isCa = false;
  const keyUsageStrings: string[] = [];
  const eku: string[] = [];
  const san: SanView[] = [];
  let basicConstraints: string | undefined;

  for (const extension of certificate.extensions) {
    if (extension instanceof BasicConstraintsExtension) {
      isCa = extension.ca ?? false;
      basicConstraints = isCa
        ? `CA:TRUE${extension.pathLength !== undefined ? `, pathlen:${extension.pathLength}` : ''}`
        : 'CA:FALSE';
    } else if (extension instanceof KeyUsagesExtension) {
      keyUsageStrings.push(...keyUsageNames(extension.usages));
    } else if (extension instanceof ExtendedKeyUsageExtension) {
      eku.push(
        ...(extension.usages as Array<string | { toString(): string }>).map(
          usage => {
            const key = typeof usage === 'string' ? usage : String(usage);
            return EKU_NAMES[key] ?? key;
          }
        )
      );
    } else if (extension instanceof SubjectAlternativeNameExtension) {
      for (const entry of extension.names.toJSON() as Array<{
        type: string;
        value: unknown;
      }>) {
        san.push({
          type: entry.type === 'url' ? 'uri' : entry.type,
          value:
            typeof entry.value === 'string'
              ? entry.value
              : JSON.stringify(entry.value),
        });
      }
    }
  }

  const publicKeyJwk = await publicJwkOf(certificate);

  const sizeBytes = new Uint8Array(certificate.rawData).byteLength;

  return {
    index,
    role,
    subject: certificate.subject,
    issuer: certificate.issuer,
    subjectAttributes: splitName(certificate.subject),
    issuerAttributes: splitName(certificate.issuer),
    serialNumber: certificate.serialNumber,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    expired: notAfter.getTime() < now,
    notYetValid: notBefore.getTime() > now,
    validityDays: Math.round(
      (notAfter.getTime() - notBefore.getTime()) / 86_400_000
    ),
    selfSigned,
    signatureAlgorithm: describeSignature(certificate),
    ...describeKey(certificate),
    publicKeyJwk,
    sha256: await sha256Hex(certificate),
    fingerprint: {
      sha256: await hexDigest(certificate, 'SHA-256'),
      sha384: await hexDigest(certificate, 'SHA-384'),
      sha512: await hexDigest(certificate, 'SHA-512'),
    },
    extensions: {
      basicConstraints,
      keyUsage: keyUsageStrings,
      extendedKeyUsage: eku.length > 0 ? eku : undefined,
      subjectAltName: san.length > 0 ? san : undefined,
      isCa,
      // Signing a credential needs digitalSignature or nonRepudiation; a CA-only
      // leaf (keyCertSign) cannot sign a VC, so the UI warns rather than failing.
      canSign:
        keyUsageStrings.includes('digitalSignature') ||
        keyUsageStrings.includes('nonRepudiation'),
    },
    pem: certificate.toString('pem'),
    sizeBytes,
  };
}

/**
 * Import a certificate's public key and export it as a JWK.
 *
 * `certificate.publicKey` is a parsed wrapper, not a Web Crypto `CryptoKey`,
 * so the SPKI bytes are imported first. The algorithm descriptor still has to
 * be supplied (Web Crypto will not infer it from SPKI alone), and the curve is
 * taken from the certificate rather than assumed.
 */
async function publicJwkOf(certificate: X509Certificate): Promise<JsonWebKey> {
  const alg = certificate.publicKey.algorithm as {
    name: string;
    namedCurve?: string;
  };
  const spki = certificate.publicKey.rawData;

  const algorithm:
    | AlgorithmIdentifier
    | RsaHashedImportParams
    | EcKeyImportParams =
    alg.name === 'ECDSA'
      ? { name: 'ECDSA', namedCurve: alg.namedCurve as NamedCurve }
      : alg.name === 'RSA-PSS'
        ? { name: 'RSA-PSS', hash: 'SHA-256' }
        : alg.name === 'RSASSA-PKCS1-v1_5'
          ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
          : alg.name;

  const key = await crypto.subtle.importKey('spki', spki, algorithm, true, [
    'verify',
  ]);
  return (await crypto.subtle.exportKey('jwk', key)) as JsonWebKey;
}

/**
 * Parse a PEM certificate bundle into views, leaf first.
 *
 * Certificate order is preserved as given: did:x509 expects the leaf first
 * followed by its issuers, and reordering would silently change the DID.
 */
export async function buildChainViews(
  pems: string[]
): Promise<CertificateView[]> {
  const certificates = pems.map(pem => new X509Certificate(pem));
  return Promise.all(
    certificates.map((certificate, index) =>
      buildCertificateView(certificate, index, certificates.length)
    )
  );
}

