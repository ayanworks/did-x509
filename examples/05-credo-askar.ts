// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * 05 — Import a did:x509 identity into a Credo wallet (Askar) and sign a
 * credential with the wallet-managed key.
 *
 * Run: npm run credo
 *
 * This is the full Credo integration, including a real `Agent`:
 *
 *   1. start an agent with an in-memory Askar wallet and the X509DidResolver
 *   2. resolve the did:x509 DID through `agent.dids.resolve(...)`
 *   3. import the leaf certificate's key into the wallet
 *   4. `agent.dids.import(...)` the DID document with that key binding
 *   5. read the DID + key back out of the wallet
 *   6. issue an SD-JWT VC signed by the wallet key, `iss` = the did:x509 DID
 *   7. verify the credential by re-resolving the DID
 *
 * ## Node only — and why
 *
 * Credo's storage backends are native addons. Askar ships prebuilt binaries for
 * Node, and this script uses them. The same code **cannot** run on Deno or on
 * an edge runtime, because `ffi-napi` / the Askar `.node` addon have no
 * portable build. The deployed playground (`playground/`) therefore stops at
 * the resolver layer and says so; this example is where the wallet lives.
 *
 * The other two gotchas, both encoded below:
 *
 *   - import `@openwallet-foundation/askar-nodejs` **first**, for its
 *     registration side effect — `NativeAskar` is only usable once the addon
 *     has registered itself
 *   - pass the current `AskarModule` shape: `{ askar, store: { id, key,
 *     database: { type: 'sqlite', config: { inMemory: true } } } }`
 */

// The native binding must be imported before anything reads `NativeAskar`.
import '@openwallet-foundation/askar-nodejs';
// @peculiar/x509's CJS build needs the reflect-metadata polyfill.
import 'reflect-metadata';

import { Agent, ConsoleLogger, DidsModule, LogLevel } from '@credo-ts/core';
import { agentDependencies } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import { NativeAskar } from '@openwallet-foundation/askar-nodejs';
import { X509DidResolver } from '@didx509/credo';
import { createIdentity } from './lib/identity.ts';

const WALLET_ID = 'did-x509-askar-demo';
const WALLET_KEY = 'did-x509-askar-demo-key-0000000';

// The CA-issued identity: the DID, the chain and the leaf's key pair. Created
// before the agent because the resolver's chain provider closes over it.
const identity = await createIdentity();

// --- 1. Start the agent ----------------------------------------------------

const agent = new Agent({
  config: {
    label: 'did-x509-askar',
    logger: new ConsoleLogger(LogLevel.Off),
    // No `walletConfig` here: in Credo 0.7 the wallet is configured by the
    // storage module's `store` option below.
  },
  dependencies: agentDependencies,
  modules: {
    askar: new AskarModule({
      askar: NativeAskar,
      store: {
        id: WALLET_ID,
        key: WALLET_KEY,
        // In-memory SQLite: the wallet disappears when the process exits,
        // which is what a demo wants. Swap `inMemory` for `path` to persist.
        database: { type: 'sqlite', config: { inMemory: true } },
      },
    }),
    dids: new DidsModule({
      resolvers: [
        // `jsonWebKey2020VerificationMethod` makes the document consumable by
        // Credo's own signing APIs, and `getChain` supplies the chain to code
        // paths that resolve without passing `x509chain` (Credo's verification
        // does exactly that). Both are explained at steps 6 and 7 below.
        new X509DidResolver({
          jsonWebKey2020VerificationMethod: true,
          getChain: () => identity.x509chain,
        }),
      ],
    }),
  },
});

await agent.initialize();
console.log('1. agent initialized with an in-memory Askar wallet');
console.log('   issuer DID:', identity.did);

// --- 2-4. Resolve the CA-derived DID and import it into the wallet ---------

// The did:x509 resolver needs the chain on every call: the chain *is* the
// trust anchor, which is also why the resolver sets `allowsCaching = false`.
const { didDocument, didResolutionMetadata } = await agent.dids.resolve(
  identity.did,
  { x509chain: identity.x509chain }
);
if (didResolutionMetadata.error || !didDocument) {
  throw new Error(
    `Resolution failed: ${didResolutionMetadata.error ?? 'no document'}`
  );
}
console.log('2. resolved via agent.dids.resolve');
console.log('   verification method:', didDocument.verificationMethod?.[0]?.id);

// Put the certificate's private key into the wallet under a KMS key id.
// Credo derives the public JWK from the private one; there is no `publicJwk`
// argument in Credo 0.7.
const walletKey = await agent.kms.importKey({
  privateJwk: identity.leafPrivateJwk,
});
const kmsKeyId = walletKey.keyId;
console.log('3. leaf key imported into Askar:', kmsKeyId);

// Bind the DID document to that key. `didDocumentRelativeKeyId` is relative to
// the DID — `#0` for the single verification method above.
const didDocumentRelativeKeyId = didDocument.verificationMethod![0]!.id.replace(
  didDocument.id,
  ''
);
await agent.dids.import({
  did: identity.did,
  didDocument,
  keys: [{ kmsKeyId, didDocumentRelativeKeyId }],
  overwrite: true,
});
console.log(
  `4. did + key binding imported (${didDocumentRelativeKeyId} → ${kmsKeyId})`
);

// --- 5. Read it back out ---------------------------------------------------

const stored = await agent.dids.getCreatedDids({ method: 'x509' });
console.log('5. dids in the wallet:', stored.length);
for (const record of stored) console.log('   ', record.did);

const storedKey = await agent.kms.getPublicKey({ keyId: kmsKeyId });
const keyMatchesCertificate =
  storedKey.x === identity.leafPublicJwk.x &&
  storedKey.y === identity.leafPublicJwk.y;
console.log(
  '   wallet public key matches the certificate:',
  keyMatchesCertificate
);

// --- 6. Issue an SD-JWT VC signed by the wallet key ------------------------

const signed = await agent.sdJwtVc.sign({
  payload: {
    vct: 'https://example.com/credentials/membership',
    // `iss` is taken from the DID issuer below.
    sub: 'did:example:holder',
    name: 'Alice',
    email: 'alice@example.com',
    ssn: '123-45-6789',
  },
  // Binding the issuer to the DID means Credo signs with the wallet key that
  // step 4 associated with it — the certificate key never leaves the wallet.
  // The `#0` fragment is required: it is how Credo finds the key.
  //
  // This only works because the resolver was constructed with
  // `jsonWebKey2020VerificationMethod: true`. The did:x509 spec emits
  // `type: "JsonWebKey"`, which Credo's key-mapping layer does not recognise
  // (it knows `JsonWebKey2020`); without the flag, signing here throws
  // `Unsupported key did from verification method type 'JsonWebKey'`.
  issuer: { method: 'did', didUrl: didDocument.verificationMethod![0]!.id },
  disclosureFrame: { _sd: ['email', 'ssn'] },
});
console.log('\n6. issued an SD-JWT VC signed by the wallet key');
console.log('   compact (disclosures truncated):');
console.log('  ', signed.compact.split('~')[0] + '~<disclosures>');

// --- 7. Verify by re-resolving the DID -------------------------------------

const presentation = await agent.sdJwtVc.present({
  sdJwtVc: signed.compact,
  presentationFrame: { email: true },
});

const verification = await agent.sdJwtVc.verify({
  compactSdJwtVc: presentation,
  // Trust this specific did:x509 DID. Because the resolver has no caching, the
  // DID is re-resolved from the chain on each verification, so trust still
  // traces back to the CA rather than to this script.
  trustedIssuers: [{ method: 'did', issuance: identity.did }],
  disableStatusValidation: true,
});
console.log('\n7. verification:', verification.isValid ? 'VALID' : 'INVALID');
if (!verification.isValid) {
  console.error('   error:', verification.error.message);
  await agent.shutdown();
  process.exit(1);
}
console.log('   disclosed claims:', JSON.stringify(verification.sdJwtVc.prettyClaims));

await agent.shutdown();

if (!keyMatchesCertificate) {
  console.error('\nWallet key did not match the certificate — aborting.');
  process.exit(1);
}
console.log('\n✓ did:x509 DID + keys imported into Askar and used to sign');
