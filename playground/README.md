# did:x509 playground

An interactive playground for `did:x509`: resolve a DID from a certificate
chain, then sign credentials with the certificate's own key. Every flow runs
end to end — issue **and** verify — on Web Crypto, so there is no mocked
cryptography anywhere.

Two views, one codebase:

- **Certificate Studio** — load a chain, read its certificates, see the DID,
  pick a credential type, sign it, and verify it.
- **Credo flow** — drive a real Credo `Agent` with an Askar wallet: resolve the
  chain into a Credo `DidDocument`, import the certificate key, bind the DID to
  it, issue a credential with the wallet-managed key, and verify.
- **Smoke tests** — the five self-contained flows the CLI runs, for quick
  parity checks.

## What it demonstrates

| Flow | What happens |
| --- | --- |
| **Resolve** | Builds a throwaway CA + leaf chain, derives the `did:x509` DID from the CA fingerprint and the leaf's CN, and recovers the DID document. |
| **JSON-LD VC** | Issues a Data Integrity credential (`eddsa-rdfc-2022`, Ed25519 leaf key) and verifies it against the DID document re-derived from the chain. |
| **SD-JWT VC** | Issues an ES256 SD-JWT VC with selective disclosure, presents only `email`, withholds `ssn`, and verifies the JWT signature against the DID document key. |
| **mDoc** | Issues an ISO/IEC 18013-5 mDoc with an `x5chain`, then validates the MSO signature and anchors the chain at the trusted CA root. |
| **Credo** | Resolves through `@didx509/credo` into a Credo `DidDocument` and verifies a credential signed under the resolved DID. |

In the Certificate Studio, the credential-format dropdown offers exactly the
formats the loaded key can sign: an **Ed25519** leaf key can sign **JSON-LD**
(Data Integrity); a **P-256** leaf key can sign **SD-JWT VC** and **mDoc**.
The UI states the reason when a format is unavailable, so a missing option is
never a silent failure.

## Run it locally

Requires **Node.js 22.18 or newer** (the code uses native TypeScript
stripping, so there is no build step for the playground itself).

```sh
cd playground

# Install dependencies (npm 11+ will ask about native install scripts;
# see "Native dependencies" below).
npm install

# Run every flow in-process (no server) — this is what CI runs.
npm run all

# Start the HTTP server on http://localhost:8000
npm start

# Type-check everything
npm run check

# With the server running, drive the real Credo Agent end to end
npm start &
npm run smoke:credo
```

`npm run all` prints a per-flow summary and exits non-zero if any verification
fails, which is how the CI smoke test catches regressions.

The playground links `@didx509/core` and `@didx509/credo` to the sibling
packages via `file:` dependencies, so build those first:

```sh
cd ../typescript && npm run build
cd ../typescript-credo && npm run build
```

### Native dependencies

The **Credo flow** needs the native Askar addon. The install-script approvals
are recorded in `package.json` (`allowScripts`), so a plain install builds it:

```sh
npm install
```

npm 11+ blocks install scripts by default, which would leave Askar, cbor-extract
and koffi unbuilt. If your npm ignores `allowScripts`, approve and rebuild
explicitly:

```sh
npm install-scripts approve @openwallet-foundation/askar-nodejs
npm install-scripts approve cbor-extract
npm install-scripts approve koffi
npm rebuild
```

If the addon cannot be built, the playground still starts: the Credo tab
detects it (via `/api/credo-agent/status`) and shows an explanation instead of
the flow. The Certificate Studio and the Smoke tests work everywhere.

## HTTP API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Landing page (self-contained HTML, no build step). |
| `GET` | `/api/health` | Liveness probe. |
| `GET` | `/api/flows` | List of available flow names. |
| `GET` | `/api/catalogue` | Credential templates + generator options. |
| `POST` | `/api/generate` | Generate a throwaway CA + leaf chain. |
| `POST` | `/api/upload` | Parse an uploaded chain (and optional key). |
| `POST` | `/api/sign` | Sign a credential with a selected identity. |
| `POST` | `/api/verify` | Verify a credential and recover its issuer. |
| `POST` | `/api/credo-resolve` | Resolve a chain through `@didx509/credo` (portable). |
| `GET` | `/api/credo-agent/status` | Whether the native Askar backend is available. |
| `POST` | `/api/credo-agent/run` | Run the full seven-step Credo Agent flow. |
| `POST` | `/api/credo-agent/reset` | Shut down this session's Agent and wallet. |
| `POST` | `/api/run/:flow` | Run one flow, where `:flow` is `resolve`, `jsonld`, `sd-jwt`, `mdoc`, or `credo`. |
| `POST` | `/api/run` | Run all five flows. |

Flow responses are `{ "results": [ ... ] }` (or `{ "error": "..." }` with a
non-2xx status). The Credo Agent endpoints are only advertised when the native
backend loads.

### Credo Agent sessions

One Credo `Agent` per browser, keyed by an `httpOnly` session cookie
(`didx509_credo_sid`). Wallets are **in-memory SQLite**, so they cost real
resources while they live: sessions are evicted after 15 minutes idle, capped
at 24 concurrent agents, and shut down on process exit. Nothing is written to
disk, and one visitor's imported DIDs are never visible to another.

## Layout

```
playground/
  package.json       # npm scripts + dependencies
  tsconfig.json      # type-checking only; Node strips types at runtime
  src/
    main.ts          # Node entry point — the ONLY host-specific file
    server.ts        # host-agnostic fetch handler + landing page
    cli.ts           # `npm run all` — runs every flow, no HTTP
    smoke-credo.ts   # `npm run smoke:credo` — drives a live Agent over HTTP
    flows.ts         # the five flows, returning plain JSON-safe data
    studio.ts        # Certificate Studio: generate/upload/sign/verify
    studio-script.ts # the browser script (embedded into the page)
    credo.ts         # @didx509/credo resolve + credential flow (portable)
    credo-agent.ts   # real Credo Agent + Askar wallet (Node only)
    credo-session.ts # per-browser Agent sessions + eviction
    jsonld.ts        # JSON-LD VC signing/verification (loaded lazily)
    sd-jwt.ts        # SD-JWT VC signing + selective disclosure (lazy)
    mdoc.ts          # mDoc issuance + issuer-auth verification (lazy)
    untyped-modules.d.ts # stubs for the untyped JSON-LD dependencies
    lib/
      identity.ts    # throwaway CA + leaf generator → DID, chain, JWKs
      did-x509-key.ts# bridges a did:x509 JWK to the Ed25519 DI suite
```

The `lib/` helpers mirror `examples/lib/` deliberately — the playground is
deployed as its own app and must not depend on the examples package's
`node_modules` or on files outside `playground/`.

`server.ts` exports a plain `fetch`-shaped handler and performs no I/O of its
own, so porting to another host means replacing `main.ts`. The handler is
already bound two ways: `main.ts` uses `node:http`. A Cloudflare Worker would
export `{ fetch: handleRequest }` instead, with no changes to the flows.

The signing modules and `credo.ts` are imported dynamically from `flows.ts` so
the heavy stacks (Digital Bazaar, `@owf/*`, `@credo-ts/core`) are only loaded
for the flow that needs them.

## The Credo flow

The Credo tab is a genuine Credo integration, not a re-implementation:

1. **Start a Credo Agent** with an Askar wallet (`AskarModule` + `NativeAskar`,
   in-memory SQLite).
2. **Resolve the DID** through `agent.dids.resolve(did, { x509chain })`, which
   routes to the published `X509DidResolver` from `@didx509/credo`.
3. **Import the certificate key** into the wallet with `agent.kms.importKey`,
   then read it back and compare it against the certificate.
4. **Bind the DID to the key** with `agent.dids.import({ did, didDocument,
   keys })`.
5. **Inspect the wallet** — the DIDs and key type Askar is holding.
6. **Issue an SD-JWT VC** with `agent.sdJwtVc.sign`, using the wallet-managed
   key. The certificate key never leaves the wallet.
7. **Verify** with `agent.sdJwtVc.verify`, disclosing one claim and withholding
   another. The verifier re-resolves the DID from the chain, so trust still
   traces back to the CA.

Two Credo details are worth knowing if you adapt this:

- The resolver is constructed with `jsonWebKey2020VerificationMethod: true`,
  because Credo's key-mapping layer knows `JsonWebKey2020` but not the spec's
  `JsonWebKey`.
- Credo's verification re-resolves the DID **without** forwarding the
  `x509chain` option, so the session remembers each chain by DID and the
  resolver's `getChain` hook supplies it. See `credo-agent.ts`.

Because a chain can be resolved without a private key, the studio also exposes
`POST /api/credo-resolve`, which returns the DID document plus the exact
`{ kmsKeyId, didDocumentRelativeKeyId }` pair `agent.dids.import` stores — so
an uploaded certificate can be checked against Credo without being able to
sign.

## Notes and pitfalls

- **`import 'reflect-metadata'` must come first.** `@peculiar/x509` uses
  tsyringe for DI, and its CJS build throws if the polyfill is not loaded
  before the package. Every entry path imports it first.
- **Native Askar is Node-only.** `@openwallet-foundation/askar-nodejs` must be
  imported *before* anything reads `NativeAskar`, for its registration side
  effect. It has no build for Deno or an edge runtime, which is why the Credo
  Agent is gated behind a capability check.
- **A fresh chain is generated per request.** The demo certificates live only
  in memory and are valid for 24 hours, so nothing is stored and nothing
  expires. Uploaded material is re-sent by the browser each time and is not
  retained server-side.
- **Explicit EC parameters.** Certificates whose SPKI uses explicit curve
  parameters (some OpenSSL defaults) fail `publicKey.export()`. Real-world CA
  certificates use named curves and are unaffected. If you generate a test
  certificate with OpenSSL, pass `-pkeyopt ec_param_enc:named_curve`.
