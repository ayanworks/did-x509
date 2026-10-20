# did:x509

This repository contains the specification and reference implementations of the did:x509 [DID](https://www.w3.org/TR/did-core/) method. It aims to achieve interoperability between existing X.509 solutions and Decentralized Identifiers (DIDs) to support operational models in which a full transition to DIDs is not achievable or desired yet. It is registered as a [DID method](https://w3c.github.io/did-extensions/methods/) with the did-wg in the W3C.

## Why did:x509?

If you already hold an X.509 certificate from a CA — whether public PKI, enterprise PKI, or Fulcio/Sigstore — you already have a DID. No blockchain, no new key infrastructure, no additional registration.

```
CA-issued X.509 cert ──► did:x509 DID ──► Use across decentralized trust infrastructure
```

This enables you to:
- **Issue verifiable credentials** using your DID as the issuer identifier
- **Verify credentials** presented by holders with CA-backed identity
- **Register in trust registries** using your cert-derived DID
- **Sign software artifacts** (Fulcio/Sigstore) with a DID identity
- **Bridge enterprise PKI** to decentralized identity workflows

See the [Practical Guide](typescript/docs/practical-guide.md) for real-world workflows.

## Specification

See [specification.md](specification.md).

## Reference Implementations

| Language | Maintainer | Location |
|----------|-----------|----------|
| TypeScript (pure TS) | [AyanWorks](https://github.com/ayanworks) | [`typescript/`](typescript/) |
| TypeScript (native, wraps Microsoft's C++) | [AyanWorks](https://github.com/ayanworks) | [`typescript-native/`](typescript-native/) |
| TypeScript (credo-ts module) | [AyanWorks](https://github.com/ayanworks) | [`typescript-credo/`](typescript-credo/) |

### TypeScript (@didx509/core)

Cross-runtime package (Node.js, Deno, Bun, browser, React Native). Derives DIDs from your existing CA-issued certificates.

```bash
cd typescript
npm install
npm test
```

```typescript
import { resolveDidFromPem } from '@didx509/core';

const doc = await resolveDidFromPem(did, pemChain);
console.log(doc.verificationMethod[0].publicKeyJwk);
```

- **[Practical Guide](typescript/docs/practical-guide.md)** — Cert-to-DID extraction, issuing, verifying, trust registries
- **[Getting Started](typescript/docs/getting-started.md)** — Installation and basic usage
- **[API Reference](typescript/docs/api-reference.md)** — Complete function signatures and types

### TypeScript, native (@didx509/native)

Same API as `@didx509/core`, but every resolution runs inside Microsoft's C++ reference implementation (`didx509cpp`) through a Node-API addon — identical behaviour to the reference, verified against all 220 official test vectors on every CI build. For Node.js, Electron, Bun, and Deno; browsers and React Native keep using `@didx509/core`.

```bash
cd typescript-native
npm install
REQUIRE_CORE=true npm test
```

```typescript
import { resolveDidFromPem } from '@didx509/native';

const doc = await resolveDidFromPem(did, pemChain);
```

- **[Package README](typescript-native/README.md)** — Overview, platform support, quick start
- **[Migration from @didx509/core](typescript-native/docs/migration.md)** — Including the generated list of known behaviour differences (19 cases where `@didx509/core` accepts chains the C++ resolver rejects)
- **[Architecture](typescript-native/docs/architecture.md)** — How the wrapper works and how parity is tested

### TypeScript, credo-ts module (@didx509/credo)

Use `did:x509` inside a [credo-ts](https://credo.js.org) agent. The resolver plugs into `DidsModule`, so any part of the framework that resolves DIDs — including the verification helpers used when signing and verifying credentials — can work with certificate-backed identities.

```typescript
import { Agent, DidsModule } from '@credo-ts/core';
import { X509DidResolver } from '@didx509/credo';

const agent = new Agent({
  config: { /* ... */ },
  modules: {
    dids: new DidsModule({ resolvers: [new X509DidResolver()] }),
  },
});

// Resolve with the issuer's certificate chain supplied out-of-band.
const result = await agent.dids.resolve(did, { x509chain });
```

Resolution runs on `@didx509/core` by default, or on the native `@didx509/native` addon when it is installed (selectable with `implementation: 'auto' | 'native' | 'core'`).

- **[Package README](typescript-credo/README.md)** — Wiring, resolver options, and caveats

## Usage examples

Runnable end-to-end examples live in [`examples/`](examples/) — each one generates a throwaway CA + leaf certificate chain, derives the `did:x509` DID, and then uses it:

```bash
cd examples
npm install
npm run all
```

| Script | Run | What it shows |
|--------|-----|---------------|
| [`01-resolve.ts`](examples/01-resolve.ts) | `npm run resolve` | Resolving a DID directly and through the `did-resolver` plugin |
| [`02-jsonld.ts`](examples/02-jsonld.ts) | `npm run sign:jsonld` | Issuing and verifying a JSON-LD Verifiable Credential (Data Integrity, `eddsa-rdfc-2022`) |
| [`03-sd-jwt.ts`](examples/03-sd-jwt.ts) | `npm run sign:sd-jwt` | Issuing and verifying an SD-JWT VC (ES256) with selective disclosure |
| [`04-mdoc.ts`](examples/04-mdoc.ts) | `npm run sign:mdoc` | Issuing and verifying an mDoc (ISO/IEC 18013-5) with the certificate in the `x5chain` |

See [`examples/README.md`](examples/README.md) for a walkthrough of each.

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).

## Credits

- **Specification**: did:x509 method specification by Microsoft Corporation (Maik Riechert, Antoine Delignat-Lavaud)
- **TypeScript implementation**: Contributed by [AyanWorks](https://github.com/ayanworks)

### Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft's Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
