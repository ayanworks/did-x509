// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Test-CA generation with caller-supplied subjects and key algorithms.
 *
 * The playground previously always produced one fixed P-256 "Acme Engineering"
 * chain. That is fine for a smoke test but useless for exploring what actually
 * changes a `did:x509` DID, which is the CA fingerprint and the subject
 * attribute named in the DID. This lets the caller vary:
 *
 *   - the key algorithm for the CA and the leaf (independently)
 *   - every subject attribute, including the ones a DID can be built from
 *   - validity period and serial numbers
 *
 * The generated chain is a *test* CA: self-signed, in memory, and never
 * persisted. It exists to be thrown away.
 */

import 'reflect-metadata';

import { b64url, computeFingerprintAsync, pctEncode } from '@didx509/core';
import {
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
  type X509Certificate,
} from '@peculiar/x509';

/** Key algorithms the generator can produce, and Web Crypto needs to name. */
export type GenAlgorithm =
  | 'P-256'
  | 'P-384'
  | 'P-521'
  | 'Ed25519'
  | 'RSA-2048'
  | 'RSA-4096';

/** Subject fields accepted by the generator, in display order. */
export interface SubjectInput {
  /** Country (C) — required by the mDoc profile, so it defaults to US. */
  C?: string;
  O?: string;
  OU?: string;
  /** Common name. This is the value a `subject:CN` DID pins. */
  CN: string;
  ST?: string;
  L?: string;
}

export interface GenerateOptions {
  caSubject: SubjectInput;
  leafSubject: SubjectInput;
  caAlgorithm: GenAlgorithm;
  leafAlgorithm: GenAlgorithm;
  validityDays?: number;
  /** Which subject attribute the derived DID references. */
  didSubjectAttribute?: 'CN' | 'O' | 'OU' | 'C' | 'ST' | 'L';
}

/** Web Crypto parameters for a generator algorithm. */
export function webCryptoAlgorithm(
  algorithm: GenAlgorithm
): AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams {
  switch (algorithm) {
    case 'Ed25519':
      return 'Ed25519';
    case 'RSA-2048':
    case 'RSA-4096':
      return {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
        modulusLength: algorithm === 'RSA-4096' ? 4096 : 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
      };
    default:
      return { name: 'ECDSA', namedCurve: algorithm };
  }
}

/** Render a subject input as an RFC 4514 name string. */
export function subjectToString(subject: SubjectInput): string {
  const order: Array<keyof SubjectInput> = ['C', 'ST', 'L', 'O', 'OU', 'CN'];
  return order
    .filter(key => subject[key])
    .map(key => `${key}=${subject[key]}`)
    .join(',');
}

/** A generated chain, plus everything derived from it. */
export interface GeneratedIdentity {
  did: string;
  /** base64url DER, leaf first. */
  x509chain: string;
  /** PEM, leaf first. */
  pemChain: string;
  /** PEM of the leaf private key, so the caller can re-send it when signing. */
  leafPrivatePem: string;
  leafPublicJwk: JsonWebKey;
  leafPrivateJwk: JsonWebKey;
  verificationMethodId: string;
  leafCertificate: X509Certificate;
  caCertificate: X509Certificate;
}

/** Generate a throwaway CA and a leaf signed by it. */
export async function generateIdentity(
  options: GenerateOptions
): Promise<GeneratedIdentity> {
  const {
    caSubject,
    leafSubject,
    caAlgorithm,
    leafAlgorithm,
    validityDays = 24,
    didSubjectAttribute = 'CN',
  } = options;

  const now = new Date();
  const notBefore = new Date(now.getTime() - 60_000);
  const notAfter = new Date(now.getTime() + validityDays * 24 * 60 * 60 * 1000);

  const caKeys = (await crypto.subtle.generateKey(
    webCryptoAlgorithm(caAlgorithm) as RsaHashedKeyGenParams,
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair;
  const leafKeys = (await crypto.subtle.generateKey(
    webCryptoAlgorithm(leafAlgorithm) as RsaHashedKeyGenParams,
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair;

  const caName = subjectToString(caSubject);
  const leafName = subjectToString(leafSubject);

  const caCertificate = await X509CertificateGenerator.create({
    serialNumber: '01',
    subject: caName,
    issuer: caName,
    notBefore,
    notAfter,
    publicKey: caKeys.publicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm: webCryptoAlgorithm(caAlgorithm) as Algorithm,
    extensions: [
      new BasicConstraintsExtension(true, 1, true),
      new KeyUsagesExtension(
        KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign,
        true
      ),
    ],
  });

  const leafCertificate = await X509CertificateGenerator.create({
    serialNumber: '02',
    subject: leafName,
    issuer: caName,
    notBefore,
    notAfter,
    publicKey: leafKeys.publicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm: webCryptoAlgorithm(caAlgorithm) as Algorithm,
    extensions: [
      new KeyUsagesExtension(
        KeyUsageFlags.digitalSignature | KeyUsageFlags.nonRepudiation,
        true
      ),
      new ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']),
      // A SAN is included because real leaf certificates carry one; it also
      // gives the details view something non-trivial to render.
      new SubjectAlternativeNameExtension([
        { type: 'dns', value: `cn-${leafSubject.CN.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.example.com` },
      ]),
    ],
  });

  // did:x509:<version>:<algorithm>:<CA fingerprint>::<subject attribute>:<value>
  const caFingerprint = await computeFingerprintAsync(caCertificate, 'sha256');
  const attributeValue = leafSubject[didSubjectAttribute] ?? leafSubject.CN;
  const did =
    `did:x509:0:sha256:${caFingerprint}` +
    `::subject:${didSubjectAttribute}:${pctEncode(attributeValue)}`;

  const der = (certificate: X509Certificate) =>
    b64url(new Uint8Array(certificate.rawData));

  // Export the leaf key as PKCS#8 PEM so it can travel to the browser and be
  // sent back with a signing request — the server keeps nothing between calls.
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', leafKeys.privateKey);
  const leafPrivatePem = pemOf('PRIVATE KEY', new Uint8Array(pkcs8));

  return {
    did,
    x509chain: `${der(leafCertificate)},${der(caCertificate)}`,
    pemChain: `${leafCertificate.toString('pem')}\n${caCertificate.toString('pem')}`,
    leafPrivatePem,
    leafPublicJwk: await crypto.subtle.exportKey('jwk', leafKeys.publicKey),
    leafPrivateJwk: await crypto.subtle.exportKey('jwk', leafKeys.privateKey),
    verificationMethodId: `${did}#0`,
    leafCertificate,
    caCertificate,
  };
}

/** Wrap DER bytes in a PEM block with the given label. */
function pemOf(label: string, der: Uint8Array): string {
  let binary = '';
  for (const byte of der) binary += String.fromCharCode(byte);
  const base64 = btoa(binary);
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}
