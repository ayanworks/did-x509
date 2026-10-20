# did:x509 playground

An interactive playground for `did:x509`: resolve a DID from a certificate
chain, then sign credentials with the certificate's own key. Every flow runs
end to end — issue **and** verify — on Web Crypto, so there is no mocked
cryptography anywhere.

Live at **<https://didx509-playground.deno.dev>** (replace with the real URL
after the first deploy).

## What it demonstrates

| Flow | What happens |
| --- | --- |
| **Resolve** | Builds a throwaway CA + leaf chain, derives the `did:x509` DID from the CA fingerprint and the leaf's CN, and recovers the DID document. |
| **JSON-LD VC** | Issues a Data Integrity credential (`eddsa-rdfc-2022`, Ed25519 leaf key) and verifies it against the DID document re-derived from the chain. |
| **SD-JWT VC** | Issues an ES256 SD-JWT VC with selective disclosure, presents only `email`, withholds `ssn`, and verifies the JWT signature against the DID document key. |
| **mDoc** | Issues an ISO/IEC 18013-5 mDoc with an `x5chain`, then validates the MSO signature and anchors the chain at the trusted CA root. |

## Run it locally

Requires [Deno](https://deno.com) 2.x.

```sh
cd playground

# Run every flow in-process (no server) — this is what CI runs.
deno task all

# Start the HTTP server on http://localhost:8000
deno task start

# Type-check everything
deno task check
```

`deno task all` prints a per-flow summary and exits non-zero if any
verification fails, which is how the CI smoke test catches regressions.

## HTTP API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Landing page (self-contained HTML, no build step). |
| `GET` | `/api/health` | Liveness probe. |
| `GET` | `/api/flows` | List of available flow names. |
| `POST` | `/api/run/:flow` | Run one flow, where `:flow` is `resolve`, `jsonld`, `sd-jwt`, or `mdoc`. |
| `POST` | `/api/run` | Run all four flows. |

Each response is `{ "results": [ ... ] }` (or `{ "error": "..." }` with a
non-2xx status).

## Layout

```
playground/
  deno.json          # import map (npm: specifiers) + tasks + deploy config
  src/
    main.ts          # Deno entry point — the ONLY host-specific file
    server.ts        # host-agnostic fetch handler + landing page
    cli.ts           # `deno task all` — runs every flow, no HTTP
    flows.ts         # the four flows, returning plain JSON-safe data
    jsonld.ts        # JSON-LD VC signing/verification (loaded lazily)
    sd-jwt.ts        # SD-JWT VC signing + selective disclosure (lazy)
    mdoc.ts          # mDoc issuance + issuer-auth verification (lazy)
    lib/
      identity.ts    # throwaway CA + leaf generator → DID, chain, JWKs
      did-x509-key.ts# bridges a did:x509 JWK to the Ed25519 DI suite
```

The `lib/` helpers mirror `examples/lib/` deliberately — the playground is
deployed as its own app and must not depend on the examples package's
`node_modules` or on files outside `playground/`.

The `@didx509/core` entry in the import map points at the **built**
`../typescript/dist/index.js`, so run `npm run build` in `typescript/` first
(the CI job does this). Importing the TypeScript source directly does not work
because core's ESM sources use `.js` specifiers that Deno resolves only with
`--sloppy-imports`.

`server.ts` exports a plain `fetch`-shaped handler and performs no I/O of its
own, so porting to another host means replacing `main.ts` — for a Cloudflare
Worker that is `export default { fetch: handleRequest }` — with no changes to
the flows.

The three signing modules are imported dynamically from `flows.ts` so the
heavy stacks (Digital Bazaar, `@owf/*`) are only loaded for the flow that
needs them. That keeps cold starts short, which matters on an edge host.

## Deploy

The app targets **Deno Deploy**. `deno.json` carries the app config:

```jsonc
{
  "deploy": { "runtime": { "type": "dynamic", "entrypoint": "./src/main.ts" } }
}
```

To deploy, create an app in the [Deno Deploy console](https://console.deno.com)
pointing at this repository with `playground` as the app directory, or deploy
from the CLI:

```sh
cd playground
deno deploy create   # first time
deno deploy deploy   # subsequent deploys
```

> **Note on the platform.** Deno announced on 9 October 2026 that the Deno
> team is joining Cloudflare and that **Deno Deploy will operate for roughly
> six months before shutting down** (around April 2027). The playground is
> still built for it, but is deliberately kept host-agnostic: all did:x509
> logic lives in `flows.ts` plus the signing modules, and only `main.ts` knows
> about Deno. Moving to Cloudflare Workers is an entry-point swap plus a build
> config, not a rewrite. Prefer `npm:` specifiers (already used throughout) and
> avoid Deno-only APIs outside `main.ts`.

## Notes and pitfalls

- **`import 'reflect-metadata'` must come first.** `@peculiar/x509` uses
  tsyringe for DI, and its CJS build throws if the polyfill is not loaded
  before the package. Every entry path imports it first.
- **A fresh chain is generated per request.** The demo certificates live only
  in memory and are valid for 24 hours, so nothing is stored and nothing
  expires.
- **CJS interop.** On Deno, `@peculiar/x509` resolves to its CJS build and
  reaches `require` through Node compat. This works, but it is the single
  highest-risk dependency for any new host — re-verify it on the target
  platform.
- **Explicit EC parameters.** Certificates whose SPKI uses explicit curve
  parameters (some OpenSSL defaults) fail `publicKey.export()` on Deno.
  Real-world CA certificates use named curves and are unaffected. If you
  generate a test certificate with OpenSSL, pass
  `-pkeyopt ec_param_enc:named_curve`.
