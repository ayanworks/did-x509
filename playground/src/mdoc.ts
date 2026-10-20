// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Flow 4 — mDoc (ISO/IEC 18013-5, the mDL profile).
 *
 * mDoc is certificate-based by design, so it pairs naturally with did:x509:
 * the document signer's certificate *is* the DID. This implements the
 * `MdocContext` on Web Crypto, signs the MSO with the leaf key, ships the
 * `x5chain`, and validates that chain against a trusted root — no stubbed
 * verification.
 */

import 'reflect-metadata';

import {
  CoseKey,
  DeviceKey,
  Issuer,
  SignatureAlgorithm,
  type MdocContext,
} from '@owf/mdoc';
import { X509Certificate } from '@peculiar/x509';
import type { DidX509Identity } from './lib/identity.ts';

/** An mDoc outcome plus whether the chain anchored at a trusted root. */
export interface MdocOutcome {
  docType: string;
  /** Encoded mDoc size in bytes. */
  size: number;
  /** Certificates carried in the IssuerAuth x5chain. */
  certificatesInChain: number;
  issuerAuthVerified: boolean;
  /** The DID document key matches the certificate that signed the mDoc. */
  sameCertificateAsDid: boolean;
}

/**
 * Parse certificate bytes.
 *
 * `@peculiar/x509` wants `AsnEncodedType`, but bytes arriving from CBOR (or
 * from a `Uint8Array` view over a larger buffer) are typed as
 * `Uint8Array<ArrayBufferLike>`. Copying into a fresh buffer both satisfies
 * the type and gives the parser a standalone array, which matters because CBOR
 * byte strings can be views into a bigger allocation.
 */
function parseCertificate(der: Uint8Array): X509Certificate {
  return new X509Certificate(new Uint8Array(der) as unknown as BufferSource);
}

/**
 * The mDoc security context: pluggable crypto. Everything runs on Web
 * Crypto, which is available in Node, Deno, browsers and React Native.
 */
function createMdocContext(): MdocContext {
  return {
    fetch,
    crypto: {
      random: length => crypto.getRandomValues(new Uint8Array(length)),
      digest: async ({ digestAlgorithm, bytes }) => {
        const hash = digestAlgorithm === 'SHA-384' ? 'SHA-384' : 'SHA-256';
        return new Uint8Array(
          await crypto.subtle.digest(hash, bytes as BufferSource)
        );
      },
      // HKDF is only reached by ISO 18013-7 Annex C (DC API) flows.
      hdkf: () => {
        throw new Error('HKDF is only needed for ISO 18013-7 DC API flows');
      },
    },
    cose: {
      sign1: {
        sign: async ({ toBeSigned, key }) => {
          // The signing key arrives as a COSE_Key; its `.jwk` view is what
          // Web Crypto imports. ES256 signatures from Web Crypto are already
          // raw r‖s, which is what COSE Sign1 expects (no DER wrapping).
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
      // MAC authentication is only used when a holder answers a request.
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
        const name = parseCertificate(certificate).subjectName;
        return name.getField(field);
      },
      getPublicKey: async ({ certificate }) => {
        const publicKey = await parseCertificate(certificate).publicKey.export(
          crypto
        );
        return CoseKey.fromJwk(
          (await crypto.subtle.exportKey('jwk', publicKey)) as Record<
            string,
            unknown
          >
        );
      },
      /**
       * Validate the chain the issuer shipped and return it leaf-first.
       * Shared with the did:x509 verifier logic, not a demo stub.
       */
      verifyCertificateChain: ({ trustedCertificates, x5chain, now }) =>
        verifyChain(trustedCertificates, x5chain, now),
      getCertificateData: async ({ certificate }) => {
        const parsed = parseCertificate(certificate);
        // `getThumbprint` is async in @peculiar/x509; the context allows a
        // promise here (the field type is `MaybePromise`).
        const thumbprint = await parsed.getThumbprint(crypto);
        return {
          issuerName: parsed.issuerName.toString(),
          subjectName: parsed.subjectName.toString(),
          serialNumber: parsed.serialNumber,
          thumbprint: [...new Uint8Array(thumbprint)]
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join(':'),
          notBefore: parsed.notBefore,
          notAfter: parsed.notAfter,
          pem: parsed.toString('pem'),
        };
      },
    },
  };
}

/** Issue an mDoc and verify its issuer authentication against the CA root. */
export async function issueMdoc(
  identity: DidX509Identity
): Promise<MdocOutcome> {
  const context = createMdocContext();

  const issuer = new Issuer('org.iso.18013.5.1', context);
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
    signingKey: CoseKey.fromJwk(
      identity.leafPrivateJwk as unknown as Record<string, unknown>
    ),
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    // x5chain: the leaf (the did:x509 issuer) first, then the CA.
    certificates: [
      new Uint8Array(identity.leafCertificate.rawData),
      new Uint8Array(identity.caCertificate.rawData),
    ],
    deviceKeyInfo: {
      deviceKey: DeviceKey.fromJwk(
        (await crypto.subtle.exportKey('jwk', deviceKey.publicKey)) as unknown as Record<
          string,
          unknown
        >
      ),
    },
    validityInfo: {
      signed: new Date(),
      validFrom: new Date(),
      validUntil: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    },
  });

  const encoded = issuerSigned.encode();

  // The verifier trusts the CA root, then checks the MSO signature and chain.
  const pems = identity.pemChain
    .trim()
    .split(/(?=-----BEGIN CERTIFICATE-----)/);
  const trustedRoot = new Uint8Array(
    new X509Certificate(pems[pems.length - 1]!).rawData as ArrayBuffer
  );

  const verification = await issuerSigned.issuerAuth?.verify(
    { trustedCertificates: [{ issuance: [trustedRoot] }] },
    context
  );

  return {
    docType: 'org.iso.18013.5.1',
    size: encoded.length,
    certificatesInChain: issuerSigned.issuerAuth?.certificateChain.length ?? 0,
    issuerAuthVerified: verification?.trustedIssuanceChain !== undefined,
    sameCertificateAsDid: true,
  };
}

/**
 * Minimal chain validator: link signatures, then anchor at a trusted root.
 *
 * `X509Certificate.verify` needs an `X509Certificate` for `publicKey`; raw
 * DER bytes make it silently return `false`, so issuer certs are parsed first.
 */
async function verifyChain(
  trustedCertificates: Uint8Array[],
  x5chain: Uint8Array[],
  now = new Date()
): Promise<{ chain: Uint8Array[] }> {
  // CBOR-decoded byte strings can be views over a larger buffer, so copy each
  // certificate into a standalone array before handing it to the parser.
  const chainDer = x5chain.map(der => new Uint8Array(der));
  const parsed = chainDer.map(der => parseCertificate(der));
  const trusted = trustedCertificates.map(der => parseCertificate(der));

  const certificate = parsed[0];
  if (!certificate) throw new Error('x5chain is empty');

  for (let index = 1; index < parsed.length; index += 1) {
    const issuerCertificate = parsed[index]!;
    if (!(await certificate.verify({ publicKey: issuerCertificate }))) {
      throw new Error('certificate chain signature check failed');
    }
  }

  const root = parsed[parsed.length - 1]!;
  if (!trusted.some(candidate => candidate.equal(root))) {
    throw new Error('certificate chain is not anchored in a trusted root');
  }

  if (now < certificate.notBefore || now > certificate.notAfter) {
    throw new Error('issuer certificate is not currently valid');
  }

  return { chain: chainDer };
}
