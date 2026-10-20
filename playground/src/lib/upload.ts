// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Uploaded identities: a real PEM chain, optionally with its private key.
 *
 * The chain alone is enough to derive a DID and resolve a DID document, so an
 * upload without a key is still useful for inspection. Signing needs the key,
 * and the `keyPresent` flag lets the UI disable the signing actions up front
 * rather than failing after the user has filled in a form.
 *
 * The DID is built from the *provided* chain rather than by regenerating
 * anything: the CA fingerprint comes from whichever certificate in the chain
 * is a CA, and the subject attribute comes from the leaf. Nothing about the
 * caller's certificates is modified.
 */

import 'reflect-metadata';

import { b64url, computeFingerprintAsync, pctEncode } from '@didx509/core';
import { X509Certificate } from '@peculiar/x509';

import { buildCertificateView, type CertificateView } from './cert-parse.ts';
import { importPrivateKey, type ImportedPrivateKey } from './key-import.ts';

/** A subject attribute a DID can be pinned to. */
export type SubjectAttribute = 'CN' | 'O' | 'OU' | 'C' | 'ST' | 'L';

/** Everything the playground needs to work with an uploaded identity. */
export interface UploadedIdentity {
  /** Certificate detail views, leaf first. */
  certificates: CertificateView[];
  /** The leaf certificate. */
  leafCertificate: X509Certificate;
  /** The issuing certificate (the CA whose fingerprint anchors the DID). */
  caCertificate: X509Certificate;
  /** PEM, leaf first. */
  pemChain: string;
  /** base64url DER, leaf first. */
  x509chain: string;
  /** Derived `did:x509`. */
  did: string;
  /** The subject attribute the DID references. */
  didSubjectAttribute: SubjectAttribute;
  verificationMethodId: string;
  /** Public JWK of the leaf's key. */
  leafPublicJwk: JsonWebKey;
  /** Present only when a private key was supplied. */
  leafPrivateJwk?: JsonWebKey;
  keyPresent: boolean;
  keyFormat?: string;
  /** The key algorithm as imported, when a key was supplied. */
  keyType?: string;
  /** Thrown-away parse diagnostics worth surfacing, e.g. key/cert mismatch. */
  warnings: string[];
}

/** Split a PEM bundle into individual certificate PEM strings, in order. */
export function splitCertificates(pem: string): string[] {
  return (
    pem.match(
      /-----BEGIN (?:TRUSTED )?CERTIFICATE-----[\s\S]*?-----END (?:TRUSTED )?CERTIFICATE-----/g
    ) ?? []
  );
}

/**
 * Choose the certificate whose fingerprint anchors the DID.
 *
 * did:x509 anchors on the CA, not the leaf. The conventional layout is
 * leaf-first, so the last certificate is normally the root. When the chain has
 * more than two entries the *last* one is used, because a self-signed root is
 * what an `x5c` list ends with.
 */
function pickCa(certificates: X509Certificate[]): X509Certificate {
  if (certificates.length === 0) {
    throw new Error('No certificates found in the uploaded PEM.');
  }
  return certificates[certificates.length - 1]!;
}

/** Read one subject attribute from a certificate. */
export function subjectAttributeOf(
  certificate: X509Certificate,
  attribute: SubjectAttribute
): string | undefined {
  // Subject strings are RFC 4514, e.g. "C=IN, O=Acme, CN=Acme Engineering".
  const pattern = new RegExp(`(?:^|,\\s*)${attribute}=([^,]+)`);
  const match = certificate.subject.match(pattern);
  return match?.[1]?.trim();
}

/**
 * Build the DID for a chain.
 *
 * `did:x509:0:sha256:<CA fingerprint>::subject:<ATTR>:<percent-encoded value>`
 *
 * @throws when the requested subject attribute is absent from the leaf, which
 *   would otherwise produce a DID that cannot resolve.
 */
export async function deriveDid(
  chain: X509Certificate[],
  attribute: SubjectAttribute
): Promise<string> {
  const leaf = chain[0]!;
  const ca = pickCa(chain);

  const value = subjectAttributeOf(leaf, attribute);
  if (!value) {
    throw new Error(
      `The leaf certificate has no ${attribute} in its subject, so a ` +
        `subject:${attribute} DID cannot be derived from it.`
    );
  }

  const fingerprint = await computeFingerprintAsync(ca, 'sha256');
  return `did:x509:0:sha256:${fingerprint}::subject:${attribute}:${pctEncode(value)}`;
}

/**
 * Parse an uploaded chain (and optional key) into a working identity.
 *
 * @param chainPem one or more PEM certificates, leaf first
 * @param keyPem   the leaf's private key, or empty for inspect-only
 * @param attribute which subject attribute the DID should reference
 */
export async function parseUploadedIdentity(
  chainPem: string,
  keyPem: string,
  attribute: SubjectAttribute
): Promise<UploadedIdentity> {
  const pems = splitCertificates(chainPem);
  if (pems.length === 0) {
    throw new Error(
      'No PEM certificates found. Paste or upload one or more ' +
        '-----BEGIN CERTIFICATE----- blocks, leaf first.'
    );
  }

  const certificates = pems.map(pem => new X509Certificate(pem));
  const leafCertificate = certificates[0]!;
  const caCertificate = pickCa(certificates);

  const views = await Promise.all(
    certificates.map((certificate, index) =>
      buildCertificateView(certificate, index, certificates.length)
    )
  );

  const did = await deriveDid(certificates, attribute);

  const warnings: string[] = [];
  let imported: ImportedPrivateKey | undefined;

  if (keyPem.trim()) {
    imported = await importPrivateKey(keyPem);

    // Compare the supplied key against the leaf certificate's public key. A
    // mismatch is the single most common upload mistake, and without this
    // check it surfaces much later as an opaque signing failure.
    const leafJwk = views[0]!.publicKeyJwk;
    if (!publicKeysMatch(leafJwk, imported.publicJwk)) {
      throw new Error(
        'The supplied private key does not match the leaf certificate: ' +
          `certificate key is ${describeJwk(leafJwk)}, ` +
          `private key is ${describeJwk(imported.publicJwk)}. ` +
          'Check that you uploaded the key for the leaf (first) certificate.'
      );
    }
  } else {
    warnings.push(
      'No private key supplied, so credentials cannot be signed. ' +
        'Resolving, certificate details, and DID derivation still work.'
    );
  }

  const pemChain = certificates.map(c => c.toString('pem')).join('\n');
  const x509chain = certificates
    .map(c => b64url(new Uint8Array(c.rawData)))
    .join(',');

  return {
    certificates: views,
    leafCertificate,
    caCertificate,
    pemChain,
    x509chain,
    did,
    didSubjectAttribute: attribute,
    verificationMethodId: `${did}#0`,
    leafPublicJwk: views[0]!.publicKeyJwk,
    leafPrivateJwk: imported?.privateJwk,
    keyPresent: Boolean(imported),
    keyFormat: imported?.format,
    keyType: imported
      ? `${imported.keyType}${imported.keyCurve ? ` ${imported.keyCurve}` : ''}`
      : undefined,
    warnings,
  };
}

/** Compare two public JWKs on the members that identify the key. */
function publicKeysMatch(a: JsonWebKey, b: JsonWebKey): boolean {
  if (a.kty !== b.kty) return false;
  if (a.kty === 'EC' || a.kty === 'OKP') {
    return a.crv === b.crv && a.x === b.x;
  }
  if (a.kty === 'RSA') {
    return a.n === b.n && a.e === b.e;
  }
  return false;
}

/** Short human description of a JWK, for error messages. */
function describeJwk(jwk: JsonWebKey): string {
  return `${jwk.kty}${jwk.crv ? ` ${jwk.crv}` : ''}`;
}
