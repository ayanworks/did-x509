// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * The portable did:x509 + Credo flow.
 *
 * Exercises the published `@didx509/credo` integration end to end: resolve the
 * DID through `X509DidResolver` into a Credo `DidDocument`, then use that
 * resolved document to issue and verify a credential.
 *
 * ## Why this module stays Agent-free
 *
 * A full Credo agent — `new Agent({ modules: { askar, dids } })` — needs a
 * storage module, and every option is a native addon. That is fine on Node
 * (see `credo-agent.ts`, which runs the real thing for the Credo tab), but it
 * cannot run on an edge runtime. This module is what stays portable, so the
 * CLI (`npm run all`) and any non-Node host still exercise genuine Credo code:
 *
 *   - `X509DidResolver` from `@didx509/credo` — the actual published class,
 *     constructed with the real options and driven through `resolve()`
 *   - `DidDocument` from `@credo-ts/core` — the real class the resolver returns
 *   - a wallet-shaped key record standing in for `agent.dids.import`, showing
 *     the exact `{ kmsKeyId, didDocumentRelativeKeyId }` pairing Credo needs
 *
 * The Agent-backed version of the same journey lives in `credo-agent.ts` and
 * is documented in the README. Keeping both means the portable path is tested
 * on every host and the native path is tested where it can actually run.
 */

import 'reflect-metadata';

import { DidDocument } from '@credo-ts/core';
import type { AgentContext, ParsedDid } from '@credo-ts/core';
import { X509DidResolver } from '@didx509/credo';
import { ES256, digest, generateSalt } from '@owf/crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { SigningIdentity } from './lib/identity.ts';

export interface CredoOutcome {
  /** The DID resolved through the Credo resolver. */
  did: string;
  /** Which engine behind the resolver answered. */
  implementation: 'core' | 'native';
  /** The DID document Credo returned, as plain JSON. */
  didDocument: Record<string, unknown>;
  /** Verification method type, per the did:x509 spec. */
  verificationMethodType: string;
  /** Whether the resolved key matches the leaf certificate's key. */
  keyMatchesCertificate: boolean;
  /** Whether a credential could be issued (a private key was available). */
  canSign: boolean;
  /** What a wallet import stores, in Credo's own shape. */
  importedKey: { kmsKeyId: string; didDocumentRelativeKeyId: string };
  /** The credential issued under the resolved DID. */
  credential: string;
  /** Disclosed claims in the presentation. */
  disclosed: Record<string, unknown>;
  /** Claims withheld from the presentation. */
  withheld: string[];
  /** Whether the credential verified against the resolved DID key. */
  verified: boolean;
  /** Whether Credo was told to cache the DID document. */
  allowsCaching: boolean;
}

/**
 * Resolve a did:x509 DID through the Credo resolver.
 *
 * `agentContext` is cast because the resolver only reads it when a `getChain`
 * hook is configured; passing the chain explicitly (the did:x509 way — the
 * chain *is* the trust anchor) means no agent context is needed.
 */
async function resolveWithCredo(
  identity: SigningIdentity,
  implementation: 'core' | 'native'
) {
  const resolver = new X509DidResolver({ implementation });
  // Credo parses DIDs itself when resolving through an agent; driving the
  // resolver directly means supplying the parsed shape it expects.
  const parsedDid = {
    did: identity.did,
    didUrl: identity.did,
    method: 'x509',
    id: identity.did.split(':').slice(2).join(':'),
  } as ParsedDid;

  const result = await resolver.resolve(
    {} as AgentContext,
    identity.did,
    parsedDid,
    // leaf → root, base64url DER, comma-separated: the did:x509 wire format.
    { x509chain: identity.x509chain }
  );

  if (result.didResolutionMetadata.error) {
    throw new Error(
      `${result.didResolutionMetadata.error}: ${
        result.didResolutionMetadata.message ?? 'resolution failed'
      }`
    );
  }
  if (!result.didDocument) {
    throw new Error('The resolver returned no DID document.');
  }

  return { resolver, result };
}

/**
 * Issue an SD-JWT VC under the resolved DID and verify it against the key the
 * resolver handed back — not against the original certificate.
 *
 * That ordering is the point: the verifier trusts the Credo resolution, so a
 * tampered chain would fail here rather than silently passing.
 */
async function issueAndVerify(
  identity: SigningIdentity,
  resolvedKey: JsonWebKey
) {
  if (!identity.leafPrivateJwk) {
    // Guarded by the caller, which only reaches here when a key is present.
    throw new Error('Signing requires the leaf certificate private key.');
  }
  const sdjwt = new SDJwtVcInstance({
    signer: await ES256.getSigner(identity.leafPrivateJwk),
    verifier: await ES256.getVerifier(resolvedKey),
    signAlg: ES256.alg,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });

  const issued = await sdjwt.issue(
    {
      iss: identity.did,
      sub: 'did:example:holder',
      iat: Math.floor(Date.now() / 1000),
      vct: 'CredoDemoCredential',
      name: 'Alice',
      email: 'alice@example.com',
      ssn: '123-45-6789',
    },
    { _sd: ['email', 'ssn'] } as never
  );

  // The holder reveals only `email`; the SSN stays withheld.
  const presentation = await sdjwt.present(issued, { email: true }, {});

  let verified = false;
  try {
    await sdjwt.verify(presentation, {});
    verified = true;
  } catch {
    // A failed signature is a verdict here, not an exception to the flow.
    verified = false;
  }

  const decoded = (await sdjwt.decode(presentation)) as {
    disclosures?: Array<{ key?: string; value?: unknown }>;
  };
  const disclosed: Record<string, unknown> = {};
  for (const disclosure of decoded.disclosures ?? []) {
    if (disclosure.key) disclosed[disclosure.key] = disclosure.value;
  }

  return { presentation, disclosed, verified };
}

/**
 * Run the whole Credo flow: resolve, then — when a private key is present —
 * issue and verify a credential under the resolved DID.
 *
 * A keyless chain (inspected but not signed with) stops after resolution. That
 * is exactly what a Credo user asking "what does my certificate resolve to?"
 * needs, and it keeps the studio's inspect-only upload useful here.
 */
export async function credoFlow(
  identity: SigningIdentity,
  implementation: 'core' | 'native' = 'core'
): Promise<CredoOutcome> {
  const { resolver, result } = await resolveWithCredo(identity, implementation);

  // Credo wraps the spec document in its own DidDocument class.
  const document = result.didDocument as DidDocument;
  const method = document.verificationMethod?.[0];
  const resolvedKey = method?.publicKeyJwk as JsonWebKey | undefined;
  if (!resolvedKey) {
    throw new Error('The resolved DID document carries no JsonWebKey.');
  }

  // Compare only the key material: Credo's transformer adds `ext` and
  // `key_ops` defaults that the certificate's JWK does not carry.
  const expected = identity.leafPublicJwk;
  const sameKey =
    resolvedKey.kty === expected.kty &&
    resolvedKey.crv === expected.crv &&
    resolvedKey.x === expected.x &&
    resolvedKey.y === expected.y;

  // Signing needs the leaf's private key. Without one, resolution is all we
  // can honestly report — and all the Credo import path needs.
  const canSign = Boolean(identity.leafPrivateJwk);
  const issued = canSign
    ? await issueAndVerify(identity, resolvedKey)
    : { presentation: '', disclosed: {}, verified: false };

  return {
    did: document.id ?? identity.did,
    implementation: resolver.usedImplementation ?? implementation,
    didDocument: JSON.parse(JSON.stringify(document)),
    verificationMethodType: String(method?.type ?? 'JsonWebKey'),
    keyMatchesCertificate: sameKey,
    // Exactly what `agent.dids.import({ did, didDocument, keys })` stores.
    importedKey: {
      kmsKeyId: `${identity.did}#0`,
      didDocumentRelativeKeyId: '#0',
    },
    canSign,
    credential: issued.presentation,
    disclosed: issued.disclosed,
    withheld: canSign ? ['ssn'] : [],
    verified: issued.verified,
    allowsCaching: resolver.allowsCaching,
  };
}
