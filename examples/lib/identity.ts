// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Shared demo identity: a throwaway CA + leaf certificate chain and the
 * did:x509 DID derived from it.
 *
 * This mirrors the real-world flow: you already hold a CA-issued
 * certificate, and the DID falls out of it — no blockchain, no registration.
 * Every signing example uses the same identity: the leaf certificate's
 * public key signs, and the DID names the issuer.
 */

// @peculiar/x509's CJS build needs the reflect-metadata polyfill.
import 'reflect-metadata';

import { b64url, computeFingerprintAsync, pctEncode } from '@didx509/core';
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509CertificateGenerator,
  type X509Certificate,
} from '@peculiar/x509';

export interface DidX509Identity {
  /** The did:x509 DID, anchored in the CA cert + the leaf's CN. */
  did: string;
  /** base64url DER certificates, leaf first — the `x509chain` resolution option. */
  x509chain: string;
  /** PEM certificates, leaf first. */
  pemChain: string;
  /** Public JWK of the leaf key — appears as `publicKeyJwk` in the DID document. */
  leafPublicJwk: JsonWebKey;
  /** Private JWK of the leaf key — signs credentials in the examples. */
  leafPrivateJwk: JsonWebKey;
  /** Verification method id in the DID document (`${did}#0`). */
  verificationMethodId: string;
  leafCertificate: X509Certificate;
  caCertificate: X509Certificate;
}

export type DemoCurve = 'P-256' | 'Ed25519';

export async function createIdentity(
  options: { commonName?: string; curve?: DemoCurve } = {}
): Promise<DidX509Identity> {
  const { commonName = 'Acme Engineering', curve = 'P-256' } = options;

  const now = new Date();
  const notBefore = new Date(now.getTime() - 60_000);
  const notAfter = new Date(now.getTime() + 24 * 60 * 60 * 1000);

  const algorithm =
    curve === 'Ed25519'
      ? ('Ed25519' as const)
      : ({ name: 'ECDSA', namedCurve: 'P-256' } as const);

  const caKeys = (await crypto.subtle.generateKey(algorithm, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const leafKeys = (await crypto.subtle.generateKey(algorithm, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;

  // `C` is present because ISO 18013-5 issuer-auth validation requires the
  // document signer's subject to carry a country name.
  const caName = 'C=US,CN=did:x509 Demo Root CA';
  const leafName = `C=US,CN=${commonName}`;

  // Self-signed root CA.
  const caCertificate = await X509CertificateGenerator.create({
    serialNumber: '01',
    subject: caName,
    issuer: caName,
    notBefore,
    notAfter,
    publicKey: caKeys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [new BasicConstraintsExtension(true, 2, true)],
  });

  // Leaf certificate signed by the CA, with the CN the DID will pin.
  const leafCertificate = await X509CertificateGenerator.create({
    serialNumber: '02',
    subject: leafName,
    issuer: caName,
    notBefore,
    notAfter,
    publicKey: leafKeys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature),
    ],
  });

  // did:x509:0:sha256:<CA fingerprint>::subject:CN:<percent-encoded CN>
  const caFingerprint = await computeFingerprintAsync(caCertificate, 'sha256');
  const did = `did:x509:0:sha256:${caFingerprint}::subject:CN:${pctEncode(commonName)}`;

  const der = (certificate: X509Certificate) =>
    b64url(new Uint8Array(certificate.rawData));

  return {
    did,
    x509chain: `${der(leafCertificate)},${der(caCertificate)}`,
    pemChain: `${leafCertificate.toString()}\n${caCertificate.toString()}`,
    leafPublicJwk: await crypto.subtle.exportKey('jwk', leafKeys.publicKey),
    leafPrivateJwk: await crypto.subtle.exportKey('jwk', leafKeys.privateKey),
    verificationMethodId: `${did}#0`,
    leafCertificate,
    caCertificate,
  };
}
