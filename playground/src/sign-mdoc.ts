// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * mDoc (ISO/IEC 18013-5) signing and verification.
 *
 * mDoc is certificate-based by design, which is why it pairs so naturally
 * with did:x509: the document signer's certificate *is* the DID. The chain
 * rides in the COSE `x5chain`, so a verifier recovers the issuer from the
 * document itself — no out-of-band trust material.
 *
 * ## Key-type constraint
 *
 * This implementation signs ES256, so the leaf key must be EC P-256. COSE
 * supports many algorithms, but only ES256 is wired to the Web Crypto context
 * built here; a P-384 or Ed25519 identity is rejected with a clear reason
 * rather than producing a document that verifies nowhere.
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

import type { SigningIdentity } from './lib/identity.ts';
import type { CredentialTemplate } from './credentials.ts';

/** True when this identity's leaf key can sign an ES256 mDoc. */
export function supportsMdoc(identity: SigningIdentity): boolean {
  return identity.leafPublicJwk.kty === 'EC' && identity.leafPublicJwk.crv === 'P-256';
}

/**
 * Copy bytes into a standalone array.
 *
 * `@peculiar/x509` wants `AsnEncodedType`, but bytes from CBOR (or a
 * `Uint8Array` view over a larger buffer) are typed as
 * `Uint8Array<ArrayBufferLike>`. Copying satisfies the type and gives the
 * parser an array it owns, which matters because CBOR byte strings can be
 * views into a bigger allocation.
 */
function parseCertificate(der: Uint8Array): X509Certificate {
  return new X509Certificate(new Uint8Array(der) as unknown as BufferSource);
}

/** The mDoc security context: everything runs on Web Crypto. */
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
          // Web Crypto's ES256 output is already raw r‖s, which is what COSE
          // Sign1 expects — no DER unwrapping needed.
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
      /**
       * Provide the certificate's validity period so the framework can check
       * the document signer was valid at signing time. Returning placeholder
       * values here would silently disable that check.
       */
      getCertificateData: async ({ certificate }) => {
        const parsed = parseCertificate(certificate);
        const thumbprintBytes = new Uint8Array(
          await crypto.subtle.digest(
            'SHA-256',
            new Uint8Array(parsed.rawData as ArrayBuffer)
          )
        );
        const thumbprint = [...thumbprintBytes]
          .map(byte => byte.toString(16).padStart(2, '0'))
          .join('');
        return {
          issuerName: parsed.issuer,
          subjectName: parsed.subject,
          serialNumber: parsed.serialNumber,
          thumbprint,
          notBefore: parsed.notBefore,
          notAfter: parsed.notAfter,
          pem: parsed.toString('pem'),
        };
      },
    },
  } as MdocContext;
}

export interface MdocSignInput {
  identity: SigningIdentity;
  template: CredentialTemplate;
  claims: Record<string, string>;
  /** Raw DER chain, leaf first; placed in the COSE x5chain. */
  chainDer: Uint8Array[];
}

export interface MdocSignResult {
  /** The encoded mDoc, base64-encoded for transport and display. */
  base64: string;
  /** Encoded byte length. */
  size: number;
  /** Live verification against the chain's own root. */
  verified: boolean;
}

/** Issue an mDoc signed by the identity's leaf key, with its chain embedded. */
export async function signMdocCredential(
  input: MdocSignInput
): Promise<MdocSignResult> {
  const { identity, template, claims, chainDer } = input;

  const privateKey = identity.leafPrivateJwk;
  if (!privateKey) {
    throw new Error('This identity has no private key, so it cannot sign.');
  }
  if (!supportsMdoc(identity)) {
    throw new Error(
      `mDoc here signs with ES256, which needs an EC P-256 key; this ` +
        `identity's leaf key is ${identity.leafPublicJwk.kty} ` +
        `${identity.leafPublicJwk.crv ?? ''}. Issue JSON-LD or SD-JWT ` +
        `instead, or generate a P-256 identity.`
    );
  }

  const context = createMdocContext();
  const namespace = template.namespace ?? template.docType ?? 'org.iso.18013.5.1';
  const docType = template.docType ?? 'org.iso.18013.5.1';

  const issuer = new Issuer(docType, context);
  issuer.addIssuerNamespace(namespace, {
    ...claims,
    issue_date: new Date().toISOString().slice(0, 10),
    expiry_date: new Date(Date.now() + 365 * 24 * 3600 * 1000)
      .toISOString()
      .slice(0, 10),
  });

  const deviceKey = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const issuerSigned = await issuer.sign({
    signingKey: CoseKey.fromJwk(
      privateKey as unknown as Record<string, unknown>
    ),
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    // x5chain: the leaf (the did:x509 issuer) first, then its CA.
    certificates: chainDer,
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

  // Verify against the chain's own root before returning, so a document that
  // does not verify never reaches the UI as a success.
  const trustedRoot = chainDer[chainDer.length - 1]!;
  const verification = await issuerSigned.issuerAuth?.verify(
    { trustedCertificates: [{ issuance: [trustedRoot] }] },
    context
  );

  return {
    base64: base64Of(encoded),
    size: encoded.length,
    verified: verification?.trustedIssuanceChain !== undefined,
  };
}

export interface MdocVerifyResult {
  signatureValid: boolean;
  /** base64url DER chain recovered from the COSE x5chain, leaf first. */
  x5c: string[];
  /** The issuer DID implied by the chain (mDoc carries no `iss` field). */
  issuerDid: string;
}

export interface MdocVerifyOptions {
  /**
   * The subject attribute to anchor the DID on.
   *
   * mDoc carries no issuer identifier of its own — the DID has to be derived
   * from the chain, so the caller states which subject attribute it expects.
   * `CN` is the conventional choice and matches how the playground mints DIDs.
   */
  subjectAttribute?: 'CN' | 'O' | 'OU' | 'C' | 'ST' | 'L';
}

/**
 * Verify an encoded mDoc and recover its issuer.
 *
 * The chain is read from the COSE `x5chain`; the DID is then derived from it
 * (anchored on the CA), and the MSO signature is checked against the leaf.
 *
 * Unlike JSON-LD and SD-JWT, mDoc has no issuer field to compare against, so
 * the returned `issuerDid` *is* the derived DID — there is no separate
 * "claimed" value for it to disagree with.
 */
export async function verifyMdocCredential(
  base64: string,
  options: MdocVerifyOptions = {}
): Promise<MdocVerifyResult> {
  const { DeviceResponse, IssuerSigned } = await import('@owf/mdoc');
  const { identityFromX5c, deriveDidForAttribute } = await import(
    './lib/issuer.ts'
  );
  const { b64url } = await import('@didx509/core');

  const bytes = new Uint8Array(
    atob(base64)
      .split('')
      .map(c => c.charCodeAt(0))
  );

  // An mDoc is just the IssuerSigned structure; a DeviceResponse wraps one.
  let issuerSigned: InstanceType<typeof IssuerSigned>;
  try {
    issuerSigned = IssuerSigned.decode(bytes);
  } catch {
    const response = DeviceResponse.decode(bytes);
    const document = response.documents?.[0];
    if (!document) {
      throw new Error('The mDoc payload contains no document.');
    }
    issuerSigned = document.issuerSigned;
  }

  const chain = issuerSigned.issuerAuth?.certificateChain ?? [];
  if (chain.length === 0) {
    throw new Error(
      'The mDoc carries no x5chain, so its issuer cannot be recovered from ' +
        'the document alone.'
    );
  }

  const x5c = chain.map(der => b64url(new Uint8Array(der)));
  const subjectAttribute = options.subjectAttribute ?? 'CN';
  const issuerDid = await deriveDidForAttribute(x5c, subjectAttribute);
  const identity = await identityFromX5c(x5c, issuerDid);

  const context = createMdocContext();
  const trustedRoot = new Uint8Array(chain[chain.length - 1]!);
  let signatureValid = false;
  try {
    const verification = await issuerSigned.issuerAuth?.verify(
      { trustedCertificates: [{ issuance: [trustedRoot] }] },
      context
    );
    signatureValid = verification?.trustedIssuanceChain !== undefined;
  } catch {
    signatureValid = false;
  }

  void identity;
  return { signatureValid, x5c, issuerDid };
}

/** Base64-encode bytes (not base64url: mDocs travel as plain base64). */
function base64Of(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Minimal chain validator: link signatures, then anchor at a trusted root.
 *
 * `X509Certificate.verify` needs an `X509Certificate` for `publicKey`; raw
 * DER bytes make it silently return `false`, so issuers are parsed first.
 */
async function verifyChain(
  trustedCertificates: Uint8Array[],
  x5chain: Uint8Array[],
  now = new Date()
): Promise<{ chain: Uint8Array[] }> {
  const chainDer = x5chain.map(der => new Uint8Array(der));
  const parsed = chainDer.map(der => parseCertificate(der));
  const trusted = trustedCertificates.map(der => parseCertificate(der));

  for (let index = 0; index < parsed.length - 1; index += 1) {
    const subject = parsed[index]!;
    const issuer = parsed[index + 1]!;
    const valid = await subject.verify({ publicKey: issuer.publicKey });
    if (!valid) {
      throw new Error(
        `Certificate ${index} is not signed by certificate ${index + 1}.`
      );
    }
  }

  const root = parsed[parsed.length - 1]!;
  const anchored = trusted.some(candidate =>
    arraysEqual(
      new Uint8Array(candidate.rawData as ArrayBuffer),
      new Uint8Array(root.rawData as ArrayBuffer)
    )
  );
  if (!anchored) {
    throw new Error('The chain does not anchor at a trusted root.');
  }

  const leaf = parsed[0]!;
  if (leaf.notBefore > now || leaf.notAfter < now) {
    throw new Error('The leaf certificate is outside its validity period.');
  }

  return { chain: chainDer };
}

/** Byte-wise equality for two arrays of the same length. */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
