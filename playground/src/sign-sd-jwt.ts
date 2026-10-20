// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * SD-JWT VC signing and selective disclosure.
 *
 * The issuer-signed JWT carries its `x5c` chain in the JOSE header, which is
 * how a verifier recovers the issuer: unpack the header, read the chain,
 * recompute the DID, and check the signature against the leaf's key.
 *
 * ## Algorithms
 *
 * RFC 9901 §4.3 requires only that `alg` is not `"none"`; any IANA JWS
 * algorithm is permitted. This module wires the EC curves (ES256/384/512, via
 * `@owf/crypto`'s suites) and RSA (PS256 or the RS2xx family, via a Web Crypto
 * signer written here, since `@owf/crypto` stops at EC). The algorithm is
 * chosen from the leaf key (`sdJwtAlgorithmFor`) and read back from the JWT
 * header on verification, so a document signed elsewhere with RS256 still
 * verifies.
 *
 * An earlier version hard-coded ES256 and described that as a format
 * constraint. It was not: SD-JWT was always able to carry RSA.
 *
 * ## Disclosure
 *
 * Claims are split into visible and disclosable per the template. The holder's
 * presentation reveals a chosen subset; the withheld claims remain in the
 * credential as salted digests and are provably absent from the presentation.
 */

import 'reflect-metadata';

import { ES256, ES384, ES512, digest, generateSalt } from '@owf/crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';

import type { SigningIdentity } from './lib/identity.ts';
import type { CredentialTemplate } from './credentials.ts';

/**
 * A `@owf/crypto` EC algorithm, as exposed by the package.
 *
 * The package ships ES256/384/512 only, so RSA needs a Web Crypto signer
 * written here (see `webCryptoSignerAndVerifier`).
 */
type EcAlgorithm = typeof ES256 | typeof ES384 | typeof ES512;

/** The JWS `alg` this identity's leaf key signs an SD-JWT with, or `undefined`. */
export function sdJwtAlgorithmFor(identity: SigningIdentity): string | undefined {
  const { kty, crv, alg } = identity.leafPublicJwk;
  if (kty === 'EC') {
    if (crv === 'P-256') return 'ES256';
    if (crv === 'P-384') return 'ES384';
    if (crv === 'P-521') return 'ES512';
    return undefined;
  }
  // RFC 9901 permits any IANA JWS algorithm except "none", so RSA is allowed.
  // Honour the key's own `alg` when it names one (the generator declares
  // RS256 on RSA keys, and signing with anything else would misrepresent it);
  // otherwise default to PSS, which is the modern padding.
  if (kty === 'RSA') {
    switch (alg) {
      case 'RS256':
      case 'RS384':
      case 'RS512':
      case 'PS256':
      case 'PS384':
      case 'PS512':
        return alg;
      default:
        return 'PS256';
    }
  }
  return undefined;
}

/** The `@owf/crypto` EC algorithm object for a JWS `alg`. */
function ecAlgorithmFor(alg: string): EcAlgorithm | undefined {
  if (alg === 'ES256') return ES256;
  if (alg === 'ES384') return ES384;
  if (alg === 'ES512') return ES512;
  return undefined;
}

/** Web Crypto parameters for an RSA JWS algorithm. */
function rsaParams(alg: string): {
  importAlgorithm: RsaHashedImportParams;
  signAlgorithm: RsaPssParams | AlgorithmIdentifier;
  hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
} {
  if (alg === 'PS384') {
    return {
      importAlgorithm: { name: 'RSA-PSS', hash: 'SHA-384' },
      signAlgorithm: { name: 'RSA-PSS', saltLength: 48 },
      hash: 'SHA-384',
    };
  }
  if (alg === 'PS512') {
    return {
      importAlgorithm: { name: 'RSA-PSS', hash: 'SHA-512' },
      signAlgorithm: { name: 'RSA-PSS', saltLength: 64 },
      hash: 'SHA-512',
    };
  }
  if (alg === 'RS256' || alg === 'RS384' || alg === 'RS512') {
    const hash =
      alg === 'RS384' ? 'SHA-384' : alg === 'RS512' ? 'SHA-512' : 'SHA-256';
    return {
      importAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash },
      signAlgorithm: { name: 'RSASSA-PKCS1-v1_5' },
      hash,
    };
  }
  return {
    importAlgorithm: { name: 'RSA-PSS', hash: 'SHA-256' },
    signAlgorithm: { name: 'RSA-PSS', saltLength: 32 },
    hash: 'SHA-256',
  };
}

/**
 * An RSA signer/verifier pair on Web Crypto, matching `@sd-jwt/types`.
 *
 * The SD-JWT library's `Signer` is `(data: string) => string` and its
 * `Verifier` is `(data, sig) => boolean`, so a bare Web Crypto pair satisfies
 * both — no adapter layer needed. Inputs and outputs are base64url, which is
 * the encoding the JWS compact serialisation uses.
 */
function webCryptoSignerAndVerifier(
  identity: SigningIdentity,
  alg: string
): { signer: (data: string) => Promise<string>; verifier: (data: string, sig: string) => Promise<boolean> } {
  const params = rsaParams(alg);
  const privateJwk = identity.leafPrivateJwk!;
  const publicJwk = identity.leafPublicJwk;

  return {
    signer: async (data: string) => {
      const key = await crypto.subtle.importKey(
        'jwk',
        privateJwk,
        params.importAlgorithm,
        false,
        ['sign']
      );
      const signature = await crypto.subtle.sign(
        params.signAlgorithm,
        key,
        new TextEncoder().encode(data)
      );
      return base64url(new Uint8Array(signature));
    },
    verifier: async (data: string, signature: string) => {
      const key = await crypto.subtle.importKey(
        'jwk',
        publicJwk,
        params.importAlgorithm,
        false,
        ['verify']
      );
      return crypto.subtle.verify(
        params.signAlgorithm,
        key,
        base64urlToBytes(signature),
        new TextEncoder().encode(data)
      );
    },
  };
}

/** Base64url-encode bytes, unpadded — the JWS convention. */
function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode unpadded base64url to bytes Web Crypto accepts as a `BufferSource`. */
function base64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** True when this identity's leaf key can sign an SD-JWT. */
export function supportsSdJwt(identity: SigningIdentity): boolean {
  return sdJwtAlgorithmFor(identity) !== undefined;
}

/** Claims reserved by the SD-JWT VC spec; a template must not use them. */
const RESERVED = new Set(['iss', 'sub', 'iat', 'exp', 'nbf', 'vct', 'cnf', '_sd']);

export interface SdJwtSignInput {
  identity: SigningIdentity;
  template: CredentialTemplate;
  claims: Record<string, string>;
  /** base64url DER chain, leaf first; placed in the JWT header. */
  x5c: string[];
  /** Claim keys the holder deliberately withholds. */
  withheld: string[];
}

export interface SdJwtSignResult {
  /** The holder's presentation, compact serialisation. */
  presentation: string;
  /** Claims revealed in the presentation. */
  disclosed: Record<string, unknown>;
  /** Claims withheld from the presentation. */
  withheld: string[];
}

/** Build the SD-JWT instance for an identity, or explain why it cannot. */
async function instanceFor(identity: SigningIdentity): Promise<SDJwtVcInstance> {
  const privateKey = identity.leafPrivateJwk;
  if (!privateKey) {
    throw new Error('This identity has no private key, so it cannot sign.');
  }
  const alg = sdJwtAlgorithmFor(identity);
  if (!alg) {
    throw new Error(
      `An SD-JWT can use any JWS algorithm except "none" (RFC 9901), but this ` +
        `playground wires ES256/384/512 for EC keys and PS/RS256 for RSA keys. ` +
        `This identity's leaf key is ${identity.leafPublicJwk.kty} ` +
        `${identity.leafPublicJwk.crv ?? ''}. Issue JSON-LD or mDoc instead, ` +
        `or generate an EC or RSA identity.`
    );
  }

  // EC keys go through @owf/crypto, which ships the ES256/384/512 suites; RSA
  // goes through a Web Crypto pair written here, since the package stops at EC.
  const ec = ecAlgorithmFor(alg);
  if (ec) {
    return new SDJwtVcInstance({
      signer: await ec.getSigner(privateKey),
      // `getVerifier` needs the public JWK; handing it the private one works in
      // Node but not in Deno, where the import is stricter.
      verifier: await ec.getVerifier(identity.leafPublicJwk),
      signAlg: ec.alg,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    });
  }

  const { signer, verifier } = webCryptoSignerAndVerifier(identity, alg);
  return new SDJwtVcInstance({
    signer,
    verifier,
    signAlg: alg,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });
}

/**
 * Issue an SD-JWT VC, then present it with only the chosen claims revealed.
 *
 * Verification of the issued presentation runs *before* returning, so a
 * signature that does not verify never reaches the UI as a success.
 */
export async function signSdJwtCredential(
  input: SdJwtSignInput
): Promise<SdJwtSignResult> {
  const { identity, template, claims, x5c, withheld } = input;
  const sdjwt = await instanceFor(identity);

  const movable = template.claims.filter(
    claim => claim.disclosable && !RESERVED.has(claim.key)
  );
  const withheldKeys = withheld.filter(key =>
    movable.some(claim => claim.key === key)
  );

  const payload = {
    iss: identity.did,
    sub: 'did:example:holder',
    iat: Math.floor(Date.now() / 1000),
    vct: template.vct ?? template.id,
    ...claims,
  };

  // Every disclosable claim goes into `_sd`. Withholding is a *presentation*
  // choice made below, not an issuing one: a withheld claim must still be
  // committed to as a digest, otherwise the credential would silently differ
  // from the one the issuer signed.
  const issued = await sdjwt.issue(payload, { _sd: movable.map(c => c.key) } as never, {
    // The did:x509 binding: the header names a DID that the chain reproduces.
    header: { x5c },
  });

  // Present with every disclosable claim revealed except those the holder
  // chose to withhold: the holder proves the credential is theirs without
  // handing over everything.
  //
  // Withholding is expressed by *not revealing* a claim, not by dropping it:
  // the claim must remain in `_sd` as a digest so a verifier can see it was
  // part of the signed credential. Passing `false` here would delete it from
  // the credential entirely, which is a different (and wrong) statement.
  const presentationFrame: Record<string, boolean> = {};
  for (const claim of movable) {
    presentationFrame[claim.key] = !withheldKeys.includes(claim.key);
  }

  const presentation = await sdjwt.present(issued, presentationFrame, {});
  await sdjwt.verify(presentation, {});

  // Disclosed claims live in the disclosures, not the JWT payload.
  const decoded = (await sdjwt.decode(presentation)) as {
    jwt?: { payload?: Record<string, unknown> };
    disclosures?: Array<{ key?: string; value?: unknown }>;
  };
  const disclosed: Record<string, unknown> = {};
  for (const disclosure of decoded.disclosures ?? []) {
    if (disclosure.key !== undefined) {
      disclosed[disclosure.key] = disclosure.value;
    }
  }

  return { presentation, disclosed, withheld: withheldKeys };
}

export interface SdJwtVerifyResult {
  /** Whether the issuer-signed JWT verified against its own chain's leaf key. */
  signatureValid: boolean;
  /** The `iss` value from the JWT payload. */
  issuer: string;
}

/**
 * Verify a presented SD-JWT against the key in its own embedded chain.
 *
 * The chain is read from the JWT header, the DID re-derived from it, and the
 * presentation verified with the leaf's public key — so the check does not
 * depend on the `iss` claim being honest, only on the chain being consistent
 * with it.
 */
export async function verifySdJwtCredential(
  compact: string
): Promise<SdJwtVerifyResult> {
  const {
    x5cFromCompactSdJwt,
    identityFromX5c,
    parseCompactPayload,
    compactHeader,
  } = await import('./lib/issuer.ts');

  const x5c = x5cFromCompactSdJwt(compact);
  if (x5c.length === 0) {
    throw new Error(
      'The SD-JWT header carries no x5c chain, so its issuer cannot be ' +
        'recovered from the credential alone.'
    );
  }

  const issuer = parseCompactPayload(compact).iss;
  const identity = await identityFromX5c(x5c, String(issuer ?? ''));

  // The algorithm comes from the credential, not from our preference: a
  // verifier must accept what the issuer actually used. Trusting the header
  // here is safe because the signature is checked against the key inside the
  // x5c chain we just recovered — the header names the algorithm, the chain
  // names the key, and neither can be swapped without breaking the signature.
  const headerAlg = String(compactHeader(compact).alg ?? '');
  const ec = ecAlgorithmFor(headerAlg);
  const sdjwt = new SDJwtVcInstance({
    ...(ec
      ? // A verifier has no signer; getVerifier supplies the public half.
        { verifier: await ec.getVerifier(identity.leafPublicJwk) }
      : webCryptoSignerAndVerifier(identity, headerAlg)),
    signAlg: headerAlg,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });

  let signatureValid = false;
  try {
    await sdjwt.verify(compact, {});
    signatureValid = true;
  } catch {
    // A failed signature is a verdict, not an error: report it as such.
    signatureValid = false;
  }

  return { signatureValid, issuer: String(issuer ?? '') };
}
