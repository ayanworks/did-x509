// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * 04 — Issue and verify an mDoc (ISO/IEC 18013-5) credential signed by a
 * did:x509 issuer certificate (ES256, the mDL profile's mandatory algorithm).
 *
 * Run: npm run sign:mdoc
 *
 * mDoc is certificate-based by design: the issuer signs the MSO with the
 * private key of a certificate and ships the x5chain inside IssuerAuth. The
 * verifier validates that chain against trusted roots. did:x509 makes the
 * same certificate addressable as a DID, so the mDoc issuer and the DID are
 * one identity — resolve the DID to check who the document signer is.
 */

// @peculiar/x509's CJS build needs the reflect-metadata polyfill.
import 'reflect-metadata';

import { resolveDidFromPem } from '@didx509/core';
import { X509Certificate } from '@peculiar/x509';
import {
  CoseKey,
  DeviceKey,
  Issuer,
  SignatureAlgorithm,
  type MdocContext,
} from '@owf/mdoc';
import { createIdentity } from './lib/identity.ts';

// --- Issuer side -----------------------------------------------------------

const identity = await createIdentity(); // P-256 leaf key
console.log('Issuer DID:  ', identity.did);

// The mDoc security context: pluggable crypto. Everything runs on Web Crypto,
// which is available in Node, Deno, browsers and React Native.
const mdocContext: MdocContext = {
  fetch,
  crypto: {
    random: length => crypto.getRandomValues(new Uint8Array(length)),
    digest: async ({ digestAlgorithm, bytes }) => {
      const hash = digestAlgorithm === 'SHA-384' ? 'SHA-384' : 'SHA-256';
      return new Uint8Array(
        await crypto.subtle.digest(hash, bytes as BufferSource)
      );
    },
    // HKDF is only reached by ISO 18013-7 Annex C (DC API) flows, which this
    // issuance/verification example does not exercise.
    hdkf: () => {
      throw new Error('HKDF is only needed for ISO 18013-7 DC API flows');
    },
  },
  cose: {
    sign1: {
      sign: async ({ toBeSigned, key }) => {
        // The signing key arrives as a COSE_Key; its `.jwk` view is what Web
        // Crypto imports. ES256 signatures from Web Crypto are already raw
        // r‖s, which is what COSE Sign1 expects (no DER wrapping).
        const privateKey = await crypto.subtle.importKey(
          'jwk',
          key.jwk as JsonWebKey,
          { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['sign']
        );
        return new Uint8Array(
          await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            privateKey,
            toBeSigned as BufferSource
          )
        );
      },
      verify: async ({ toBeVerified, signature, key }) => {
        const publicKey = await crypto.subtle.importKey(
          'jwk',
          key.jwk as JsonWebKey,
          { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['verify']
        );
        return crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          publicKey,
          signature as BufferSource,
          toBeVerified as BufferSource
        );
      },
    },
    // MAC authentication is only used when a holder answers a device request.
    mac0: {
      authenticate: () => {
        throw new Error('MAC authentication is only used by device responses');
      },
      verify: () => {
        throw new Error('MAC authentication is only used by device responses');
      },
    },
  },
  x509: {
    getSubjectNameField: ({ certificate, field }) => {
      const name = new X509Certificate(certificate).subjectName;
      return name.getField(field);
    },
    getPublicKey: async ({ certificate }) => {
      const publicKey = await new X509Certificate(certificate).publicKey.export(
        crypto
      );
      return CoseKey.fromJwk(await crypto.subtle.exportKey('jwk', publicKey));
    },
    /**
     * Validate the chain the issuer shipped and return it with the trusted
     * root last, leaf first. did:x509 verifiers do the same thing, so the
     * chain check is shared logic rather than a demo stub.
     */
    verifyCertificateChain: ({ trustedCertificates, x5chain, now }) =>
      verifyChain(trustedCertificates, x5chain, now),
    getCertificateData: ({ certificate }) => {
      const parsed = new X509Certificate(certificate);
      return {
        issuerName: parsed.issuerName.toString(),
        subjectName: parsed.subjectName.toString(),
        serialNumber: parsed.serialNumber,
        thumbprint: parsed.thumbprint,
        notBefore: parsed.notBefore,
        notAfter: parsed.notAfter,
        pem: parsed.toString('pem'),
      };
    },
  },
};

const issuer = new Issuer('org.iso.18013.5.1', mdocContext);
issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
  family_name: 'Doe',
  given_name: 'Alice',
  issue_date: new Date().toISOString().slice(0, 10),
  expiry_date: new Date(Date.now() + 365 * 24 * 3600 * 1000)
    .toISOString()
    .slice(0, 10),
  issuing_authority: 'did:x509 Demo Authority',
});

const deviceKey = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,
  ['sign', 'verify']
);

const issuerSigned = await issuer.sign({
  signingKey: CoseKey.fromJwk(identity.leafPrivateJwk as JsonWebKey),
  algorithm: SignatureAlgorithm.ES256,
  digestAlgorithm: 'SHA-256',
  // x5chain: the leaf (the did:x509 issuer) first, then the CA.
  certificates: [
    new Uint8Array(identity.leafCertificate.rawData),
    new Uint8Array(identity.caCertificate.rawData),
  ],
  deviceKeyInfo: {
    deviceKey: DeviceKey.fromJwk(
      (await crypto.subtle.exportKey('jwk', deviceKey.publicKey)) as JsonWebKey
    ),
  },
  validityInfo: {
    signed: new Date(),
    validFrom: new Date(),
    validUntil: new Date(Date.now() + 365 * 24 * 3600 * 1000),
  },
});

const encoded = issuerSigned.encode();
console.log(
  `\nIssued mDoc: ${encoded.length} bytes, ` +
    `${issuerSigned.issuerAuth?.certificateChain.length ?? 0} certificates in x5chain`
);

// --- Verifier side ---------------------------------------------------------

// The verifier trusts the CA root, reads the x5chain from IssuerAuth, checks
// the MSO signature and the chain — then asks the same certificate who it is
// as a DID.
const pems = identity.pemChain.trim().split(/(?=-----BEGIN CERTIFICATE-----)/);
const trustedRoot = new Uint8Array(
  new X509Certificate(pems[pems.length - 1]!).rawData
);

const verification = await issuerSigned.issuerAuth?.verify(
  { trustedCertificates: [{ issuance: [trustedRoot] }] },
  mdocContext
);
console.log(
  'IssuerAuth verified against the CA root:',
  verification?.trustedIssuanceChain !== undefined
);
if (!verification?.trustedIssuanceChain) process.exit(1);

const didDocument = await resolveDidFromPem(identity.did, identity.pemChain);
const methodKey = didDocument.verificationMethod![0].publicKeyJwk!;
console.log('Same certificate as a did:x509 DID:', didDocument.id);
console.log(
  'DID document key (kty/crv):',
  methodKey.kty,
  methodKey.crv
);

// --- Helpers ---------------------------------------------------------------

/** Minimal chain validator: link signatures, then anchor at a trusted root. */
async function verifyChain(
  trustedCertificates: Uint8Array[],
  x5chain: Uint8Array[],
  now = new Date()
): Promise<{ chain: Uint8Array[] }> {
  // CBOR-decoded byte strings can be views over a larger buffer, so copy each
  // certificate into a standalone array before handing it to the X.509 parser.
  const chainDer = x5chain.map(der => new Uint8Array(der));
  const parsed = chainDer.map(der => new X509Certificate(der));
  const trusted = trustedCertificates.map(
    der => new X509Certificate(new Uint8Array(der))
  );

  const certificate = parsed[0];
  if (!certificate) throw new Error('x5chain is empty');

  // Walk up the chain: each certificate must be signed by the next one.
  // `verify` needs an X509Certificate (raw DER bytes silently fail).
  for (let index = 1; index < parsed.length; index += 1) {
    const issuerCertificate = parsed[index]!;
    if (!(await certificate.verify({ publicKey: issuerCertificate }))) {
      throw new Error('certificate chain signature check failed');
    }
  }

  // The top of the chain must be one of the trusted roots.
  const root = parsed[parsed.length - 1]!;
  if (!trusted.some(candidate => candidate.equal(root))) {
    throw new Error('certificate chain is not anchored in a trusted root');
  }

  if (now < certificate.notBefore || now > certificate.notAfter) {
    throw new Error('issuer certificate is not currently valid');
  }

  return { chain: chainDer };
}
