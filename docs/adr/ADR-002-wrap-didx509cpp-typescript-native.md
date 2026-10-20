# ADR-002: did:x509 TypeScript — Wrap didx509cpp Instead of Porting It

## Status

Accepted

Supersedes the direction of ADR-001 for the TypeScript ecosystem specifically:
where ADR-001 proposed a Rust rewrite as the single rigorous core, this ADR
takes the lower-effort route for TypeScript — wrap Microsoft's C++ reference
implementation directly. ADR-001 (Rust, mobile/WASM targets) remains proposed
and unaffected outside this scope.

## Context

The repository ships two TypeScript-shaped options for `did:x509`:

1. **`@didx509/core`** — a full TypeScript port of the specification using
   `@peculiar/x509`. Works everywhere (browsers, React Native, Node), but
   validation is partial: no name constraints, no policy constraints, no
   algorithm security levels. Running it against the 220 official
   specification vectors shows **112 divergences** from the C++ reference
   implementation, including **19 cases where it accepts chains the C++
   resolver rejects** — i.e. security-relevant gaps, not just cosmetic
   differences.
2. **`didx509cpp`** (Microsoft, MIT) — the C++ reference implementation:
   header-only C++20 over OpenSSL ≥ 3.3, full RFC 5280 path validation, and
   it carries the official vector suite in its own tests.

We need a TypeScript-usable implementation whose behaviour is *identical* to
the reference. The core risk in any second implementation is drift: every
certificate-handling line written by hand is a line that can silently
disagree with upstream when the spec evolves.

## Options Considered

### Option A: Port the C++ logic into TypeScript (status quo — `@didx509/core`)
- Single language, runs in every runtime, no build toolchain for users
- Behavioural gaps measured at 112/220 vectors; closing them means
  hand-implementing name constraints, policy processing, fulcio selectors,
  strict-mode rules — and re-auditing them on every upstream change
- Drift is discovered late, by external reports

### Option B: Wrap didx509cpp with a native addon  ✅ chosen
- Zero duplicated logic: the wrapper contains no certificate code at all
- Parity is a test run, not a review: the upstream vector suite ships
  inside the package (pinned submodule) and 220/220 must pass on every CI
  build
- Upstream fixes and spec updates arrive as a submodule bump
- Costs: a C++ toolchain for source builds (mitigated by prebuilt
  binaries), no browser/React Native support, error messages become
  upstream-controlled public API

### Option C: Rewrite the core in Rust (ADR-001)
- One Rust codebase could later target WASM and mobile
- Does not close the parity gap faster than Option B, and is a larger
  investment with its own port-drift risk against the C++ reference
- Remains proposed for mobile/WASM ambitions; out of scope here

## Decision

Build **`@didx509/native`** (`reference-implementations/typescript-native/`)
as a thin wrapper around a git-submodule-pinned `didx509cpp`:

- **Binding:** Node-API (N-API v8) addon via `node-addon-api`, built with
  `cmake-js`, four-function C ABI shim (`didx509_resolve`,
  `didx509_resolve_jwk`, `didx509_free`, `didx509_version`) that converts
  C++ exceptions to error strings so nothing throws across the ABI.
- **Distribution:** prebuilt binaries for macOS (arm64/x64), Linux
  glibc/musl (x64/arm64), and Windows x64, shipped in `prebuilds/` and
  located at runtime by `node-gyp-build`; OpenSSL 3.3+ built from source in
  CI and linked **statically** into redistributable binaries. Install falls
  back to a local source build (CMake ≥ 3.18, C++20 compiler).
- **API parity with `@didx509/core`:** same function names, argument order,
  and result types; `skipValidityPeriodCheck` accepted as an alias of
  `ignoreTime` so existing call sites migrate by changing the import line.
- **Side-by-side, not replacement:** `@didx509/core` remains the
  browser/React Native offering; the migration guide documents every known
  behavioural difference, generated from the test suite
  (`test/core-divergences.json` → `docs/migration.md`) so the list cannot go
  stale.

## Consequences

### Positive
- Behaviour is identical to the C++ reference by construction; 220/220
  official vectors pass on every CI build
- No second certificate implementation to audit or keep in sync; upstream
  updates are a submodule bump plus a test run
- The measured core-vs-reference gap (112 vectors, 19 security-relevant)
  becomes documented, tracked data instead of unknown risk
- Users keep the familiar `@didx509/core` API surface

### Negative
- Native toolchain required when no prebuild matches (documented in
  `docs/troubleshooting.md`)
- Browsers and React Native stay on `@didx509/core` — two packages to carry
- Error message strings are now public API controlled by upstream; the semver
  policy says they may change with any submodule bump, and code must catch
  `Didx509Error` rather than match text
- CI is heavier: per-platform builds, OpenSSL built from source (cached by
  version) because Ubuntu 24.04 ships OpenSSL 3.0 < 3.3

### Risks
- Upstream `didx509cpp` releases are infrequent; a pinned-commit workflow
  (`didx509Version()` for provenance) makes staleness visible
- Deno support depends on FFI + local `node_modules` and has a known
  `deno compile` limitation (denoland/deno#36596); verified manually rather
  than in CI initially
