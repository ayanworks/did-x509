// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * SD-JWT VC signing and selective disclosure.
 *
 * The issuer-signed JWT carries its `x5c` chain in the JOSE header, which is
 * how a verifier recovers the issuer: unpack the header, read the chain,
 * recompute the DID, and check the signature against the leaf's key.
 *
 * ## Key-type constraint
 *
 * SD-JWT here is ES256, so the leaf key must be EC P-256. A P-384 or Ed25519
 * identity cannot use this format — the crypto backend would either reject
 * the key or, worse, sign with the wrong algorithm. `supportsSdJwt` reports
 * this up front so the UI can disable the format instead of failing at the
 * last step.
 *
 * ## Disclosure
 *
 * Claims are split into visible and disclosable per the template. The holder's
 * presentation reveals a chosen subset; the withheld claims remain in the
 * credential as salted digests and are provably absent from the presentation.
 */

import 'reflect-metadata';

import { ES256, digest, generateSalt } from '@owf/crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';

import type { SigningIdentity } from './lib/identity.ts';
import type { CredentialTemplate } from './credentials.ts';

/** True when this identity's leaf key can sign an ES256 SD-JWT. */
export function supportsSdJwt(identity: SigningIdentity): boolean {
  return identity.leafPublicJwk.kty === 'EC' && identity.leafPublicJwk.crv === 'P-256';
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
  if (!supportsSdJwt(identity)) {
    throw new Error(
      `SD-JWT here signs with ES256, which needs an EC P-256 key; this ` +
        `identity's leaf key is ${identity.leafPublicJwk.kty} ` +
        `${identity.leafPublicJwk.crv ?? ''}. Issue JSON-LD or mDoc instead, ` +
        `or generate a P-256 identity.`
    );
  }

  return new SDJwtVcInstance({
    signer: await ES256.getSigner(privateKey),
    // `getVerifier` needs the public JWK; handing it the private one works in
    // Node but not in Deno, where the import is stricter.
    verifier: await ES256.getVerifier(identity.leafPublicJwk),
    signAlg: ES256.alg,
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
  const { x5cFromCompactSdJwt, identityFromX5c, parseCompactPayload } =
    await import('./lib/issuer.ts');

  const x5c = x5cFromCompactSdJwt(compact);
  if (x5c.length === 0) {
    throw new Error(
      'The SD-JWT header carries no x5c chain, so its issuer cannot be ' +
        'recovered from the credential alone.'
    );
  }

  const issuer = parseCompactPayload(compact).iss;
  const identity = await identityFromX5c(x5c, String(issuer ?? ''));

  const sdjwt = new SDJwtVcInstance({
    // A verifier has no signer; ES256.getVerifier supplies the public half.
    verifier: await ES256.getVerifier(identity.leafPublicJwk),
    signAlg: ES256.alg,
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
