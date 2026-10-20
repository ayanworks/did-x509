# did:x509 examples

Runnable examples showing how to consume `did:x509` from a JavaScript or
TypeScript project — resolving DIDs and signing credentials with a
certificate-backed identity.

Every example generates its own throwaway CA + leaf certificate chain at
startup, derives the `did:x509` DID from it, and then does something useful
with that identity. That mirrors the real-world flow: you already hold a
CA-issued certificate, and the DID falls out of it — no blockchain, no
registration.

## The examples

| Script | Run | What it shows |
| --- | --- | --- |
| `01-resolve.ts` | `npm run resolve` | Resolve a `did:x509` DID two ways: the direct `resolveDidFromPem` call and the W3C `did-resolver` plugin. |
| `02-jsonld.ts` | `npm run sign:jsonld` | Issue and verify a **JSON-LD Verifiable Credential** (Data Integrity, `eddsa-rdfc-2022`) whose issuer is the did:x509 DID. |
| `03-sd-jwt.ts` | `npm run sign:sd-jwt` | Issue and verify an **SD-JWT VC** (ES256) with selective disclosure, signed by the leaf certificate key. |
| `04-mdoc.ts` | `npm run sign:mdoc` | Issue and verify an **mDoc** (ISO/IEC 18013-5, the mDL profile) whose `x5chain` carries the same certificate the DID names. |
| `05-credo-askar.ts` | `npm run credo` | Import the did:x509 identity into a **Credo wallet backed by Askar**: resolve the DID, import the certificate key, `agent.dids.import` the DID + key binding, then sign and verify an SD-JWT VC with the wallet-managed key. |

Run them all at once:

```bash
npm install
npm run all
```

Requires **Node.js 22.18+** (the examples are plain TypeScript executed
directly by Node's type stripping, and `@owf/mdoc` targets modern runtimes).

> **`05` is Node-only.** Askar is a native addon, so that example cannot run on
> Deno or an edge runtime. The other four are portable. See
> [The Credo / Askar example](#05--credo-and-the-askar-wallet) below.

## What each example demonstrates

### 01 — Resolution

The DID document is derived from the certificate chain:

```ts
import { resolveDidFromPem } from '@didx509/core';

const document = await resolveDidFromPem(did, pemChain);
// document.verificationMethod[0].publicKeyJwk === leaf certificate public key
```

The same result is available through the standard `did-resolver` API, with the
certificate chain passed as the `x509chain` resolution option:

```ts
import { Resolver } from 'did-resolver';
import { getDidX509Resolver } from '@didx509/core';

const resolver = new Resolver(getDidX509Resolver());
const result = await resolver.resolve(did, { x509chain });
```

### 02 — JSON-LD credentials

The issuer's credential is signed with the leaf certificate's Ed25519 key and
verified against the key in the DID document, which the verifier re-derives
from the certificate chain. `lib/did-x509-key.ts` bridges the did:x509
verification method (`type: "JsonWebKey"`) to Digital Bazaar's Data Integrity
key suites.

### 03 — SD-JWT VC

The issuer identifier (`iss`) is the did:x509 DID and the signing key is the
certificate's P-256 key. Selectively disclosable claims (`email`, `ssn`) are
withheld unless the holder chooses to reveal them, and the verifier can check
the JWT signature against the DID document key.

### 04 — mDoc

mDoc is certificate-based by design, so it pairs naturally with did:x509: the
document signer's certificate *is* the DID. The example implements the
`MdocContext` on Web Crypto, signs the MSO with the leaf key, ships the
`x5chain`, and validates that chain against a trusted root during
verification.

### 05 — Credo and the Askar wallet

This is the full Credo integration, with a real `Agent`:

```ts
const agent = new Agent({
  config: { walletConfig: { id, key } },
  dependencies: agentDependencies,
  modules: {
    askar: new AskarModule({
      askar: NativeAskar,
      store: { id, key, database: { type: 'sqlite', config: { inMemory: true } } },
    }),
    dids: new DidsModule({
      resolvers: [
        new X509DidResolver({
          jsonWebKey2020VerificationMethod: true,
          getChain: () => identity.x509chain,
        }),
      ],
    }),
  },
});
```

It then resolves the DID, imports the certificate's key with
`agent.kms.importKey`, binds the DID document to it with `agent.dids.import`,
signs an SD-JWT VC with `agent.sdJwtVc.sign` (the key never leaves the wallet),
and verifies it.

Three things are worth knowing before you copy this:

- **It is Node-only.** Askar is a native addon (`ffi-napi` / a prebuilt
  `.node`), so this cannot run on Deno or an edge runtime. The deployed
  playground therefore stops at the resolver layer; the wallet lives here.
- **Import `@openwallet-foundation/askar-nodejs` first.** It registers the
  native binding as a side effect, and `NativeAskar` is unusable until it has.
- **Two resolver options are needed.** Credo's key-mapping layer only knows
  `JsonWebKey2020`, not the spec's `JsonWebKey`, so
  `jsonWebKey2020VerificationMethod: true` is required for signing to resolve
  the key. And Credo's verification path resolves the DID without passing the
  `x509chain` option, so `getChain` supplies it. Both are opt-in, so the
  resolver's default output stays byte-for-byte identical to the reference
  resolver.

## Shared helpers

| File | Purpose |
| --- | --- |
| `lib/identity.ts` | Generates the demo CA + leaf chain (P-256 or Ed25519) and derives the `did:x509` DID. |
| `lib/did-x509-key.ts` | Converts a did:x509 `JsonWebKey` verification method into an Ed25519 Data Integrity key pair. |

## Notes

- These examples are illustrative, not production hardening. The demo
  certificates are short-lived and generated in memory.
- The JSON-LD document loader serves the well-known contexts from local copies
  and falls back to the network for anything else; a production verifier
  should cache those instead.
- `@peculiar/x509`'s CommonJS build needs the `reflect-metadata` polyfill,
  which each entry point imports first.
