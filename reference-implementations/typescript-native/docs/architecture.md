# Architecture

## Why wrap instead of port

The did:x509 specification has two reference-quality implementations to
choose from when you need one in TypeScript:

1. Port the C++ logic to TypeScript (what `@didx509/core` did), or
2. Wrap the C++ implementation and call it (what this package does).

This package takes option 2, recorded in
`docs/adr/ADR-002-wrap-didx509cpp.md`. In short: a wrapper cannot drift from
upstream, because there is no second implementation to drift. Spec updates
arrive as a submodule bump plus a test run — not as a re-audit of hand-written
certificate code.

## The layers

```
┌─────────────────────────────────────────────┐
│  Your code                                  │
├─────────────────────────────────────────────┤
│  TypeScript API        src/*.ts             │  argument checks, JSON parsing,
│                                             │  option aliases, error classes
├─────────────────────────────────────────────┤
│  Node-API glue         native/addon.cpp     │  strings in/out, sync + async
│                                             │  workers, Promise plumbing
├─────────────────────────────────────────────┤
│  C ABI shim            shim/didx509_shim.cpp│  C++ exceptions → error strings,
│                                             │  PEM chain splitting
├─────────────────────────────────────────────┤
│  didx509cpp            third_party/         │  the real work: certificate
│  (git submodule)       didx509cpp/          │  parsing, chain verification,
│                                             │  predicate matching
└─────────────────────────────────────────────┘
```

Each layer is deliberately boring:

- **TypeScript API** validates arguments, runs the two option spellings
  (`ignoreTime` / `skipValidityPeriodCheck`) through one path, parses the
  JSON the resolver produced, and wraps failures in `Didx509Error`. It does
  zero certificate work.
- **Node-API glue** passes UTF-8 strings across the JS boundary. The async
  functions use `Napi::AsyncWorker`, so validation runs on the libuv thread
  pool and servers stay responsive.
- **C ABI shim** exists so no C++ exception ever crosses into JavaScript.
  `didx509::resolve()` throwing becomes a `0` return code plus a heap
  string; `didx509_free()` releases it. Four exported functions total:
  `didx509_resolve`, `didx509_resolve_jwk`, `didx509_free`,
  `didx509_version`.
- **didx509cpp** is vendored as a git submodule pinned to an exact commit.
  Its header-only C++20 code talks to OpenSSL ≥ 3.3.

## Linking

- **OpenSSL is linked statically** in published prebuilds
  (`-DDIDX509_STATIC_OPENSSL=ON`), so end users do not need OpenSSL
  installed and never pick up an incompatible system version. Local dev
  builds may link Homebrew's dylib — harmless, since they are not
  redistributed.
- The addon targets **N-API version 8**, which Node 18+, Electron, and Bun
  all support without per-version rebuilds.
- **Prebuilds** are built in CI per platform and shipped inside the npm
  tarball under `prebuilds/<platform>-<arch>/`. At install time
  `scripts/install.cjs` first tries `node-gyp-build` (finds a prebuilt
  binary) and only compiles from source when that fails. `npm install
  --ignore-scripts` therefore still yields a working package wherever a
  prebuild exists.

## How parity is tested

Parity is not a claim; it is a test run. Three suites on every CI job:

1. **220 official specification vectors** (`test/vectors.test.ts`), pulled
   from the pinned submodule so they can never disagree with the C++ code
   being tested. Mirrors upstream's own harness: vectors run with
   `ignoreTime: true`, error vectors must throw (message text is not part of
   the contract), document vectors must deep-equal the expected document,
   and `resolveJwk` must equal the document's JWK. Result: **220/220**.

2. **Cross-implementation diff** (`test/diff-parity.test.ts`) runs the same
   220 vectors through `@didx509/core` and records every divergence in
   `test/core-divergences.json`. That file is the single source of truth for
   the "known differences" section of `docs/migration.md` — a test asserts
   each entry is mentioned there, and `npm run parity:report` regenerates
   both. Current state: 112 of 220 vectors behave differently, 19 of them
   cases where `@didx509/core` accepts what the C++ resolver rejects.

3. **API/binding/plugin suites** cover error-message verbatim-ness,
   sync/async equivalence, argument checks, concurrency (50 parallel
   resolutions), a memory-growth guard over 2000 resolutions, and the
   did-resolver plugin's success and error shapes.

## Versioning

- The npm package follows semver.
- Error **messages** are upstream's output and follow the bundled
  submodule commit — they may change in any release. Never match on them.
- Bumping `third_party/didx509cpp` requires: the vector suite to stay at
  220/220 (or an explicit test update if upstream changes its harness),
  `npm run sync:commit` (regenerates the `DIDX509CPP_COMMIT` file so
  tarball installs report the real upstream commit — a test fails if it
  goes stale), and a `parity:report` run if core's behaviour relative to
  upstream shifted.
