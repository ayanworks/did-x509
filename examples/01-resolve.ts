// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * 01 — Resolve a did:x509 DID.
 *
 * Run: npm run resolve
 *
 * Two ways to consume did:x509 in a JS/TS project:
 *   1. `resolveDidFromPem` — direct call, no did-resolver needed
 *   2. the W3C did-resolution plugin — plug into any `did-resolver` based app
 */

// @peculiar/x509's CJS build needs the reflect-metadata polyfill.
import 'reflect-metadata';

import { getDidX509Resolver, resolveDidFromPem } from '@didx509/core';
import { Resolver } from 'did-resolver';
import { createIdentity } from './lib/identity.ts';

const identity = await createIdentity();
console.log('DID:         ', identity.did);
console.log('x509chain:   ', `${identity.x509chain.slice(0, 48)}…`);

// 1. Direct resolution — verify the chain, match the DID, build the document.
const document = await resolveDidFromPem(identity.did, identity.pemChain);
console.log('\nDID document (direct):');
console.log(JSON.stringify(document, null, 2));

// 2. W3C did-resolution plugin — same result through the standard API.
const resolver = new Resolver(getDidX509Resolver());
const result = await resolver.resolve(identity.did, {
  x509chain: identity.x509chain,
});
console.log('\nSame DID via the did-resolver plugin:', result.didDocument?.id);

// The DID document's publicKeyJwk is the leaf certificate's public key —
// this is what verifiers use to check credentials signed by this DID.
const jwk = result.didDocument?.verificationMethod?.[0]?.publicKeyJwk;
console.log('Verification key:', jwk?.kty, jwk?.crv ?? '');
