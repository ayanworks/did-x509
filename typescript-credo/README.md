# @didx509/credo

[did:x509](https://github.com/microsoft/did-x509) method registry for
[credo-ts](https://credebl.id) — resolve `did:x509` decentralized identifiers
inside Credo agents, backed by Microsoft's reference resolver.

```ts
import { DidsModule, KeyDidResolver } from '@credo-ts/core';
import { X509DidResolver } from '@didx509/credo';

const agent = new Agent({
  modules: {
    dids: new DidsModule({
      resolvers: [new X509DidResolver(), new KeyDidResolver()],
    }),
  },
  // ...
});

// did:x509 resolution requires the issuer's certificate chain:
const { didDocument } = await agent.dids.resolve(did, {
  x509chain: 'MIGr...base64url-DER...,MIGr...next-cert...',
});
```

## What is did:x509?

`did:x509` anchors a DID in an X.509 certificate chain instead of a
blockchain. The DID string encodes the chain's SHA-256 fingerprint plus
the subject fields you choose to trust (e.g.
`did:x509:0:sha256:<fingerprint>::subject:CN:Engineering`), so anyone holding
the matching certificate chain can cryptographically prove control of the DID
— no ledger required. This package wraps Microsoft's official
[didx509cpp](https://github.com/microsoft/didx509cpp) reference resolver
(through [`@didx509/native`](https://www.npmjs.com/package/@didx509/native))
with a pure-TypeScript fallback
([`@didx509/core`](https://www.npmjs.com/package/@didx509/core)).

## Installation

```bash
npm install @didx509/credo @didx509/native
```

| Package | Role |
| --- | --- |
| `@didx509/credo` | This package — the Credo `DidResolver` implementation |
| `@didx509/native` | **(optional)** Microsoft's C++ resolver as a Node-API addon — prebuilt binaries, faster |
| `@didx509/core` | Pure TypeScript resolver — installed automatically, used when the native addon is unavailable |

`@didx509/native` is an optional peer dependency: without it the resolver
transparently falls back to `@didx509/core`. Both engines share the same
conformance suite (the official did:x509 test vectors), so behaviour is
identical.

## Usage

### Resolving

did:x509 is the one DID method where resolution needs the certificate chain
alongside the DID — the chain *is* the trust anchor. Pass it as the
`x509chain` resolution option (a comma-separated list of base64url-encoded
DER certificates, ordered leaf → root):

```ts
const result = await agent.dids.resolve(did, {
  x509chain: chain.join(','), // leaf first, root last
});

if (result.didResolutionMetadata.error) {
  console.error(result.didResolutionMetadata.error, result.didResolutionMetadata.message);
} else {
  console.log(result.didDocument?.verificationMethod);
}
```

### Chain provider (registry lookups)

If your application stores the chain server-side, register a `getChain` hook
so resolutions (including Credo's internal verification helpers, which do not
forward resolution options) can fetch it automatically:

```ts
new X509DidResolver({
  getChain: async (did, agentContext) => {
    // Look the chain up in your database, registry, header, ...
    return (await chainStore.get(did))?.join(',');
  },
});
```

### Choosing the engine

```ts
new X509DidResolver();                          // 'auto' (default): native if loadable, else core
new X509DidResolver({ implementation: 'native' }); // require the addon (throws when missing)
new X509DidResolver({ implementation: 'core' });   // pure TypeScript, no addon needed
```

## Credo integration example (agent-controller)

In [credebl/agent-controller](https://github.com/credebl/agent-controller),
register the resolver where the agent modules are assembled
(`src/cliAgent.ts`):

```diff
+import { X509DidResolver } from '@didx509/credo';

 const dids = new DidsModule({
   resolvers: [
+    new X509DidResolver(),
     new KeyDidResolver(),
     new WebDidResolver(),
     // ...
   ],
 });
```

## Caveats

- **No DID caching.** `allowsCaching` is `false`: the same `did:x509` can
  resolve to different documents for different chains, so Credo's DID-based
  cache must never apply. Each resolution validates the chain.
- **Signing flows.** Credo's verification helpers resolve DID documents
  without forwarding resolution options. Use the `getChain` hook (above) or
  import the DID + keys into the wallet with `agent.dids.import` before
  signing credentials with a did:x509 identifier.
- **Verification method type.** did:x509 documents use `JsonWebKey`
  verification methods (per the spec). Credo's JSON-LD (`Ed25519Signature2018`)
  suites only accept `Ed25519VerificationKey2018/2020` — for JSON-LD
  credentials, prefer the Data Integrity cryptosuites or SD-JWT/mDoc formats.

## Specification & references

- [did:x509 specification](https://github.com/microsoft/did-x509) (Microsoft,
  registered with the W3C DID Working Group)
- [didx509cpp](https://github.com/microsoft/didx509cpp) — the C++ reference
  implementation this package wraps
- [npm: @didx509/native](https://www.npmjs.com/package/@didx509/native) ·
  [npm: @didx509/core](https://www.npmjs.com/package/@didx509/core)

## License

MIT — see [LICENSE](./LICENSE).
