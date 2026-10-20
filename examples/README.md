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

Run them all at once:

```bash
npm install
npm run all
```

Requires **Node.js 22.18+** (the examples are plain TypeScript executed
directly by Node's type stripping, and `@owf/mdoc` targets modern runtimes).

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
