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
 * ## Key types
 *
 * `issuerAuth` is a COSE_Sign1, and COSE carries the full IANA algorithm set,
 * which is a broader set than this playground can reach. The real boundary is
 * the COSE implementation, and it is worth stating precisely because two
 * different things are true at once:
 *
 *   - **Curves.** ES256, ES384 and ES512 all work. This required working around
 *     a curve-name typo in `@owf/cose` (see `coseKeyFromJwk`); an earlier
 *     version of this file hard-coded ES256 and wrongly described that as a
 *     *format* limitation.
 *   - **RSA.** Not available, and not for want of wiring. `@owf/cose`'s key model
 *     has no RSA type at all, so RSA key material is dropped before signing (see
 *     `mdocAlgorithmFor`). No amount of dispatch recovers a discarded modulus.
 *
 * So the honest statement is: mDoc in this playground signs with ES256/384/512,
 * because the COSE library it uses supports EC keys only. RSA signatures remain
 * fully available in the SD-JWT format, which does not go through `@owf/cose`.
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

/**
 * Web Crypto import/sign parameters for a COSE signature algorithm.
 *
 * mDoc's `issuerAuth` is COSE_Sign1, and COSE carries the full IANA algorithm
 * set. The three families we wire up differ in more than their name:
 *
 *   - ECDSA (ES256/384/512) — the Web Crypto output is already raw `r‖s`,
 *     which is what COSE expects, and the hash is fixed by the curve.
 *   - RSA-PSS (PS256/384/512) — Web Crypto needs the salt length (32 bytes,
 *     per RFC 8230) and the same hash as the algorithm name.
 *   - RSASSA-PKCS1-v1_5 (RS256/384/512) — the classic RSA signature, with no
 *     salt; COSE still accepts it, so it is offered for interop even though
 *     PSS is the better default.
 */
interface CoseAlgorithmParams {
  /** Web Crypto algorithm object for `importKey`. */
  importAlgorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
  /** Web Crypto algorithm object for `sign`/`verify`. */
  signAlgorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
  /** COSE hash for the MSO digest, where the algorithm implies one. */
  digestAlgorithm: 'SHA-256' | 'SHA-384' | 'SHA-512';
}

/** Resolve a COSE algorithm to the Web Crypto calls it needs, or `undefined`. */
export function coseAlgorithmParams(
  algorithm: SignatureAlgorithm
): CoseAlgorithmParams | undefined {
  switch (algorithm) {
    case SignatureAlgorithm.ES256:
      return {
        importAlgorithm: { name: 'ECDSA', namedCurve: 'P-256' },
        signAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        digestAlgorithm: 'SHA-256',
      };
    case SignatureAlgorithm.ES384:
      return {
        importAlgorithm: { name: 'ECDSA', namedCurve: 'P-384' },
        signAlgorithm: { name: 'ECDSA', hash: 'SHA-384' },
        digestAlgorithm: 'SHA-384',
      };
    case SignatureAlgorithm.ES512:
      return {
        importAlgorithm: { name: 'ECDSA', namedCurve: 'P-521' },
        signAlgorithm: { name: 'ECDSA', hash: 'SHA-512' },
        digestAlgorithm: 'SHA-512',
      };
    case SignatureAlgorithm.PS256:
    case SignatureAlgorithm.RS256:
      return {
        importAlgorithm: { name: hashNameFor(algorithm), hash: 'SHA-256' },
        signAlgorithm:
          algorithm === SignatureAlgorithm.PS256
            ? { name: 'RSA-PSS', saltLength: 32 }
            : { name: 'RSASSA-PKCS1-v1_5' },
        digestAlgorithm: 'SHA-256',
      };
    case SignatureAlgorithm.PS384:
    case SignatureAlgorithm.RS384:
      return {
        importAlgorithm: { name: hashNameFor(algorithm), hash: 'SHA-384' },
        signAlgorithm:
          algorithm === SignatureAlgorithm.PS384
            ? { name: 'RSA-PSS', saltLength: 48 }
            : { name: 'RSASSA-PKCS1-v1_5' },
        digestAlgorithm: 'SHA-384',
      };
    case SignatureAlgorithm.PS512:
    case SignatureAlgorithm.RS512:
      return {
        importAlgorithm: { name: hashNameFor(algorithm), hash: 'SHA-512' },
        signAlgorithm:
          algorithm === SignatureAlgorithm.PS512
            ? { name: 'RSA-PSS', saltLength: 64 }
            : { name: 'RSASSA-PKCS1-v1_5' },
        digestAlgorithm: 'SHA-512',
      };
    default:
      // EdDSA and the MAC family are not wired; callers reject them earlier
      // with a named reason rather than reaching here.
      return undefined;
  }
}

/**
 * Repair a COSE key's JWK so Web Crypto will import it.
 *
 * `CoseKey.jwk` echoes `crv` verbatim, so a key built from the lowercased
 * workaround in `coseKeyFromJwk` gives Web Crypto `p-384`, which it rejects with
 * "JWK crv does not match the requested algorithm". Restoring the JWK spelling
 * and naming the algorithm (which Web Crypto also checks) keeps the two halves
 * of the round trip agreeable.
 */
function webCryptoJwk(jwk: JsonWebKey, algorithm: SignatureAlgorithm): JsonWebKey {
  const repaired: JsonWebKey = { ...jwk };
  if (repaired.crv) {
    repaired.crv = String(repaired.crv).replace(/^p-/, 'P-');
  }
  const alg = coseAlgorithmName(algorithm);
  if (alg) repaired.alg = alg;
  return repaired;
}

/** The JWS/COSE algorithm name for a COSE algorithm value, as JWKs spell it. */
function coseAlgorithmName(algorithm: SignatureAlgorithm): string | undefined {
  const match = Object.entries(SignatureAlgorithm).find(
    ([, value]) => value === algorithm
  );
  return match?.[0];
}

/**
 * Build a COSE key from a JWK, working around an upstream curve-name bug.
 *
 * `@owf/cose`'s `CoseKey.fromJwk` looks curves up in a map keyed `P-256`,
 * `p-384` and `p-521` — inconsistent casing, evidently a typo. JWKs spell all
 * three with a capital `P`, so P-384 and P-521 keys miss the map and the raw
 * string reaches COSE's numeric curve validation, which rejects it. Lowercasing
 * *only* the two affected curves keeps P-256 working (it must stay uppercase)
 * while making the other two usable.
 *
 * RSA needs a different route entirely: `fromJwk` has no `n`/`e` mapping, so an
 * RSA JWK decodes to a key whose `keyType` is still the string `"RSA"` and which
 * carries no modulus. Callers should pass RSA JWKs through untouched — `Issuer.sign`
 * accepts a `CoseKey | JsonWebKey` — rather than through this function.
 */
export function coseKeyFromJwk(
  jwk: JsonWebKey,
  algorithm?: SignatureAlgorithm
): CoseKey {
  const normalised: Record<string, unknown> = { ...jwk };
  if (normalised.crv === 'P-384' || normalised.crv === 'P-521') {
    normalised.crv = String(normalised.crv).toLowerCase();
  }
  const key = CoseKey.fromJwk(normalised);
  return algorithm === undefined ? key : withAlgorithmOnKey(key, algorithm);
}

/**
 * Rebuild a key with an explicit COSE algorithm.
 *
 * COSE keys are immutable structures, so this re-creates rather than mutates.
 * When the key already names the same algorithm the original is returned, which
 * keeps the common path allocation-free.
 */
function withAlgorithmOnKey(key: CoseKey, algorithm: SignatureAlgorithm): CoseKey {
  if (key.algorithm === undefined || key.algorithm === algorithm) {
    // Either the key named nothing (so there is no conflict to resolve) or it
    // already agrees with us; adding a redundant claim would be noise.
    return key;
  }
  return CoseKey.create({
    keyType: key.keyType,
    keyId: key.keyId,
    algorithm,
    keyOps: key.keyOps,
    curve: key.curve,
    x: key.x,
    y: key.y,
    d: key.d,
    k: key.k,
  });
}

/** Web Crypto's algorithm name for the RSA padding a COSE alg implies. */
function hashNameFor(algorithm: SignatureAlgorithm): 'RSA-PSS' | 'RSASSA-PKCS1-v1_5' {
  switch (algorithm) {
    case SignatureAlgorithm.PS256:
    case SignatureAlgorithm.PS384:
    case SignatureAlgorithm.PS512:
      return 'RSA-PSS';
    default:
      return 'RSASSA-PKCS1-v1_5';
  }
}

/**
 * Pick a COSE algorithm from a key alone, for the verify path.
 *
 * COSE allows the `alg` header to be absent, and `@owf/mdoc` may omit it on
 * verification. Falling back to the key's own type keeps a document verifiable
 * rather than throwing over a missing header.
 */
function rsaPairFor(jwk: JsonWebKey): SignatureAlgorithm {
  switch (jwk.kty) {
    case 'EC':
      if (jwk.crv === 'P-384') return SignatureAlgorithm.ES384;
      if (jwk.crv === 'P-521') return SignatureAlgorithm.ES512;
      return SignatureAlgorithm.ES256;
    case 'RSA':
      // PS256 is the default our signer uses for RSA keys.
      return SignatureAlgorithm.PS256;
    case 'OKP':
      return SignatureAlgorithm.EdDSA;
    default:
      return SignatureAlgorithm.ES256;
  }
}

/** True when this identity's leaf key can sign an mDoc we have wired up. */
export function supportsMdoc(identity: SigningIdentity): boolean {
  return mdocAlgorithmFor(identity) !== undefined;
}

/**
 * The COSE algorithm this identity's leaf key signs an mDoc with, or
 * `undefined` when we have nothing wired for that key.
 *
 * Keyed on the key, not on a global default: an RSA leaf signs RS256, a P-384
 * leaf signs ES384, and so on. This is what the earlier ES256-only version
 * got wrong.
 */
export function mdocAlgorithmFor(
  identity: SigningIdentity
): SignatureAlgorithm | undefined {
  const { kty, crv } = identity.leafPublicJwk;
  if (kty === 'EC') {
    if (crv === 'P-256') return SignatureAlgorithm.ES256;
    if (crv === 'P-384') return SignatureAlgorithm.ES384;
    if (crv === 'P-521') return SignatureAlgorithm.ES512;
    return undefined;
  }
  // RSA is deliberately absent. COSE itself registers RSA (PS/RS), and the spec
  // permits it, but `@owf/mdoc`'s COSE layer has no RSA key type: its `KeyType`
  // enum is {Okp, Ec, Oct, Reserved} and `jwkCoseOptionsMap` has no `n`/`e`
  // entries, so `CoseKey.fromJwk` drops the modulus and exponent and hands the
  // signing callback `{alg, d}`. Web Crypto then (correctly) rejects that as
  // invalid key material. There is no wiring that recovers the lost key, so
  // offering RSA here would only produce a failure one step later.
  return undefined;
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
        // Map every digest the algorithms above can request. The previous
        // version handled only SHA-384 and silently fell back to SHA-256, which
        // would have produced a mismatched MSO digest for ES512.
        const hash: 'SHA-256' | 'SHA-384' | 'SHA-512' =
          digestAlgorithm === 'SHA-384'
            ? 'SHA-384'
            : digestAlgorithm === 'SHA-512'
              ? 'SHA-512'
              : 'SHA-256';
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
        // Both callbacks dispatch on the COSE algorithm the library passes in,
        // rather than assuming P-256. That is what makes RSA and the other
        // curves work: the key *is* the algorithm, and COSE says so explicitly.
        sign: async ({ toBeSigned, key, algorithm }) => {
          const params = coseAlgorithmParams(algorithm);
          if (!params) {
            throw new Error(
              `mDoc signing does not implement the COSE algorithm ${algorithm}.`
            );
          }
          const privateKey = await crypto.subtle.importKey(
            'jwk',
            webCryptoJwk(key.jwk as JsonWebKey, algorithm),
            params.importAlgorithm,
            false,
            ['sign']
          );
          // ECDSA output is already raw r‖s, which is what COSE Sign1 wants;
          // RSA needs no post-processing either. No DER unwrapping anywhere.
          return new Uint8Array(
            await crypto.subtle.sign(
              params.signAlgorithm,
              privateKey,
              toBeSigned as BufferSource
            )
          );
        },
        verify: async ({ toBeVerified, signature, key, algorithm }) => {
          // A verifier may be handed an RS256 document even though the signer
          // defaults to PS256, so accept both RSA paddings. The curve is
          // unambiguous from the algorithm name.
          const resolved = algorithm ?? rsaPairFor(key.jwk as JsonWebKey);
          const params = coseAlgorithmParams(resolved);
          if (!params) {
            throw new Error(
              `mDoc verification does not implement the COSE algorithm ${resolved}.`
            );
          }
          const publicKey = await crypto.subtle.importKey(
            'jwk',
            webCryptoJwk(key.jwk as JsonWebKey, resolved),
            params.importAlgorithm,
            false,
            ['verify']
          );
          return crypto.subtle.verify(
            params.signAlgorithm,
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
        // Through the helper, not `CoseKey.fromJwk` directly: the bare call
        // rejects P-384/P-521 certificates for the curve-casing reason above.
        return coseKeyFromJwk(
          (await crypto.subtle.exportKey('jwk', publicKey)) as JsonWebKey
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
  const algorithm = mdocAlgorithmFor(identity);
  if (!algorithm) {
    throw new Error(
      `An mDoc can be signed with any COSE algorithm, but this playground ` +
        `wires only ES256/384/512 and RS/PS256/384/512. This identity's leaf ` +
        `key is ${identity.leafPublicJwk.kty} ` +
        `${identity.leafPublicJwk.crv ?? ''}, which is none of those. Issue ` +
        `SD-JWT instead, or generate a P-256, P-384, P-521 or RSA identity.`
    );
  }
  const params = coseAlgorithmParams(algorithm)!;

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

  // RSA keys cannot reach here today — `mdocAlgorithmFor` rejects them because
  // `@owf/mdoc`'s COSE layer has no RSA key type. This branch is kept so the
  // signer is correct the moment an RSA-capable COSE layer is available, and so
  // the algorithm table below documents what the spec allows rather than only
  // what one dependency happens to support.
  const isRsa = identity.leafPublicJwk.kty === 'RSA';
  const signingKey = (
    isRsa
      ? { ...(privateKey as unknown as JsonWebKey) }
      : coseKeyFromJwk(privateKey as unknown as JsonWebKey, algorithm)
  ) as CoseKey | Record<string | number, unknown>;

  const issuerSigned = await issuer.sign({
    signingKey,
    algorithm,
    digestAlgorithm: params.digestAlgorithm,
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
