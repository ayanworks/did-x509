// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Recovering an issuer from a credential — the verifier's half of did:x509.
 *
 * A did:x509 credential is self-describing: the signing certificate chain is
 * carried inside the credential itself (JSON-LD and SD-JWT use `x5c`, mDoc
 * uses the COSE `x5chain`). That is what lets a verifier answer "who issued
 * this, and are they who they claim?" without being handed the chain out of
 * band.
 *
 * The chain is what makes the DID derivable: `did:x509:0:sha256:<CA
 * fingerprint>::subject:CN:<leaf CN>` names the CA, not the leaf, so the
 * verifier recomputes the fingerprint of the root it received and checks it
 * matches the DID the credential asserts. A chain swapped for another would
 * produce a different fingerprint and fail.
 */

import 'reflect-metadata';

import { computeFingerprintAsync, pctEncode } from '@didx509/core';
import { X509Certificate } from '@peculiar/x509';

import { buildCertificateView, type CertificateView } from './cert-parse.ts';
import { subjectAttributeOf, type SubjectAttribute } from './upload.ts';

/** Where the chain was found in the credential. */
export type ChainSource = 'x5c (JSON-LD proof)' | 'x5c (JWT header)' | 'x5chain (COSE)';

/** What a verifier can learn about an issuer from a credential alone. */
export interface IssuerDetails {
  /** Where in the credential the chain came from. */
  source: ChainSource;
  /** The DID the credential claims as issuer. */
  claimedDid: string;
  /** The DID recomputed from the embedded chain. */
  derivedDid: string;
  /**
   * Whether the two agree — the actual trust check. A credential whose
   * embedded chain does not reproduce its own issuer DID is rejected.
   */
  didMatchesChain: boolean;
  /** The subject attribute the DID pins, as parsed from the DID. */
  subjectAttribute?: SubjectAttribute;
  subjectValue?: string;
  /** Certificate details for every certificate in the embedded chain. */
  certificates: CertificateView[];
  warnings: string[];
}

/** Extract base64url `x5c` entries from a JSON-LD Data Integrity proof. */
export function x5cFromProof(credential: unknown): string[] {
  const proof = (credential as { proof?: unknown })?.proof;
  const proofs = Array.isArray(proof) ? proof : proof ? [proof] : [];
  for (const entry of proofs) {
    const x5c = (entry as { x5c?: unknown }).x5c;
    if (Array.isArray(x5c) && x5c.every(item => typeof item === 'string')) {
      return x5c as string[];
    }
  }
  return [];
}

/** Extract base64url `x5c` entries from a JOSE header (compact or object). */
export function x5cFromJoseHeader(
  header: Record<string, unknown> | undefined
): string[] {
  const x5c = header?.x5c;
  if (Array.isArray(x5c) && x5c.every(item => typeof item === 'string')) {
    return x5c as string[];
  }
  return [];
}

/**
 * Reconstruct a signing identity from a chain embedded in a credential.
 *
 * This is the verifier's equivalent of the issuer's in-memory identity: no
 * private key (the verifier never has one), just the certificates and the DID
 * they imply. It is what lets a verifier build a DID document loader without
 * being handed the chain out of band.
 *
 * The DID is *derived*, not taken on trust: the caller's `claimedDid` only
 * decides which subject attribute to pin, and a mismatch between the two is
 * reported by `extractIssuerDetails`.
 */
export async function identityFromX5c(
  x5c: string[],
  claimedDid: string
): Promise<{
  did: string;
  x509chain: string;
  pemChain: string;
  leafPublicJwk: JsonWebKey;
  verificationMethodId: string;
  leafCertificate: X509Certificate;
  caCertificate: X509Certificate;
}> {
  const certificates = x5c.map(entry => parseCertificate(b64urlDecode(entry)));
  const leafCertificate = certificates[0]!;
  const caCertificate = certificates[certificates.length - 1]!;

  const { attribute } = parseDidSubject(claimedDid);
  const did = attribute
    ? await deriveDidFromChain(certificates, attribute)
    : claimedDid;

  const leafPublicJwk = (await crypto.subtle.exportKey(
    'jwk',
    await crypto.subtle.importKey(
      'spki',
      leafCertificate.publicKey.rawData,
      spkiAlgorithm(leafCertificate),
      true,
      ['verify']
    )
  )) as JsonWebKey;

  return {
    did,
    x509chain: x5c.join(','),
    pemChain: certificates.map(c => c.toString('pem')).join('\n'),
    leafPublicJwk,
    verificationMethodId: `${did}#0`,
    leafCertificate,
    caCertificate,
  };
}

/** Web Crypto algorithm descriptor for a certificate's public key. */
function spkiAlgorithm(
  certificate: X509Certificate
): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams {
  const alg = certificate.publicKey.algorithm as {
    name: string;
    namedCurve?: string;
  };
  if (alg.name === 'ECDSA') {
    return { name: 'ECDSA', namedCurve: alg.namedCurve as NamedCurve };
  }
  if (alg.name === 'RSASSA-PKCS1-v1_5' || alg.name === 'RSA-PSS') {
    return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  }
  return alg.name;
}

/** Split a compact SD-JWT into its issuer JWT and its disclosures. */
function splitCompact(compact: string): { jwt: string; disclosures: string[] } {
  const parts = compact.split('~');
  return { jwt: parts[0] ?? '', disclosures: parts.slice(1).filter(Boolean) };
}

/** Decode a base64url string to UTF-8 text. */
function b64urlUtf8(value: string): string {
  const binary = b64urlDecode(value);
  return new TextDecoder().decode(binary);
}

/** Read the JOSE header of a compact SD-JWT's issuer JWT. */
export function compactHeader(
  compact: string
): Record<string, unknown> {
  const { jwt } = splitCompact(compact);
  const headerPart = jwt.split('.')[0];
  if (!headerPart) return {};
  try {
    return JSON.parse(b64urlUtf8(headerPart)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/** Read the payload of a compact SD-JWT's issuer JWT. */
export function parseCompactPayload(
  compact: string
): Record<string, unknown> {
  const { jwt } = splitCompact(compact);
  const payloadPart = jwt.split('.')[1];
  if (!payloadPart) return {};
  try {
    return JSON.parse(b64urlUtf8(payloadPart)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/** Read `x5c` out of the JWT header of a compact SD-JWT. */
export function x5cFromCompactSdJwt(compact: string): string[] {
  return x5cFromJoseHeader(compactHeader(compact));
}

/** Decode base64url to bytes. */
function b64urlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

/**
 * Parse DER into a certificate.
 *
 * `@peculiar/x509` wants `AsnEncodedType`, but bytes decoded from base64 are
 * typed as `Uint8Array<ArrayBufferLike>`. Copying into a fresh array satisfies
 * the type and gives the parser an allocation it owns — which also matters for
 * bytes that are views over a larger buffer.
 */
function parseCertificate(der: Uint8Array): X509Certificate {
  return new X509Certificate(new Uint8Array(der) as unknown as BufferSource);
}

/** Parse a did:x509 DID back into its subject attribute and value. */
export function parseDidSubject(
  did: string
): { attribute?: SubjectAttribute; value?: string } {
  // did:x509:0:sha256:<fp>::subject:CN:Acme%20Engineering
  const match = did.match(/::subject:([A-Z]+):(.+)$/);
  if (!match) return {};
  const attribute = match[1] as SubjectAttribute;
  let value = match[2]!;
  try {
    value = decodeURIComponent(value);
  } catch {
    // Leave the raw value if it is not valid percent-encoding.
  }
  return { attribute, value };
}

/**
 * Derive the did:x509 DID that a chain implies.
 *
 * The DID is anchored on the CA (the last certificate), and the subject value
 * comes from the leaf — the same rule the issuer used when the DID was built.
 */
async function deriveDidFromChain(
  chain: X509Certificate[],
  attribute: SubjectAttribute
): Promise<string> {
  const leaf = chain[0]!;
  const ca = chain[chain.length - 1]!;
  const value = subjectAttributeOf(leaf, attribute);
  if (!value) {
    throw new Error(
      `The credential's leaf certificate has no ${attribute} in its subject, ` +
        `so its did:x509 DID cannot be reproduced.`
    );
  }
  const fingerprint = await computeFingerprintAsync(ca, 'sha256');
  return `did:x509:0:sha256:${fingerprint}::subject:${attribute}:${pctEncode(value)}`;
}

/**
 * Derive a DID from an embedded chain, given only its base64url `x5c`.
 *
 * Used where a credential carries no issuer identifier of its own — mDoc has
 * no `iss` field — so the DID has to come from the chain rather than be
 * checked against it.
 */
export async function deriveDidForAttribute(
  x5c: string[],
  attribute: SubjectAttribute
): Promise<string> {
  const certificates = x5c.map(entry => parseCertificate(b64urlDecode(entry)));
  return deriveDidFromChain(certificates, attribute);
}

/**
 * Build the issuer view from an embedded chain.
 *
 * @param x5c        base64url DER certificates, leaf first
 * @param claimedDid the `issuer`/`iss` value the credential asserts
 * @param source     where the chain was found, for display
 */
export async function extractIssuerDetails(
  x5c: string[],
  claimedDid: string,
  source: ChainSource
): Promise<IssuerDetails> {
  const warnings: string[] = [];

  if (x5c.length === 0) {
    throw new Error(
      'The credential does not carry an x5c chain, so the issuer cannot be ' +
        'recovered from it alone.'
    );
  }

  const certificates = x5c.map(entry => parseCertificate(b64urlDecode(entry)));
  const chain = await Promise.all(
    certificates.map((certificate, index) =>
      buildCertificateView(certificate, index, certificates.length)
    )
  );

  const { attribute } = parseDidSubject(claimedDid);

  let derivedDid = '';
  let didMatchesChain = false;
  if (attribute) {
    derivedDid = await deriveDidFromChain(certificates, attribute);
    didMatchesChain = derivedDid === claimedDid;
    if (!didMatchesChain) {
      warnings.push(
        'The DID asserted by the credential does not match the one derived ' +
          'from its embedded certificate chain.'
      );
    }
  } else {
    warnings.push(
      'The issuer is not a did:x509 DID, so the chain could not be checked ' +
        'against it.'
    );
  }

  if (chain.length === 1) {
    warnings.push(
      'The credential carries only one certificate. A chain is needed to ' +
        'anchor trust at a CA.'
    );
  }

  const { value } = parseDidSubject(claimedDid);

  return {
    source,
    claimedDid,
    derivedDid,
    didMatchesChain,
    subjectAttribute: attribute,
    subjectValue: value,
    certificates: chain,
    warnings,
  };
}
