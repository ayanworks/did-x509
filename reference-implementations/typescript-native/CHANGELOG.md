# Changelog

All notable changes to `@didx509/native` are documented here. The package
follows [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-10-20

First release.

### Added

- Native resolution of `did:x509` identifiers via Microsoft's
  [didx509cpp](https://github.com/microsoft/didx509cpp), pinned as a git
  submodule (commit recorded by `didx509Version()`).
- `resolveDidFromPem` / `resolveDidFromPemSync` — full DID document, PEM
  chain input.
- `resolveJwk` / `resolveJwkSync` — leaf public key as a JWK.
- `getDidX509Resolver()` — did-resolver plugin with the same result shapes
  as `@didx509/core`.
- `x509ChainToPem` / `derCertificateToPem` — chain format conversion.
- `Didx509Error` — thrown for every resolution failure, message verbatim
  from C++.
- `ignoreTime` option with `skipValidityPeriodCheck` as a compatible alias.
- Prebuilt binaries for macOS (arm64/x64), Linux glibc (x64/arm64), Linux
  musl (x64), and Windows x64; automatic source build as a fallback.
- Test suites: 220/220 official specification vectors, cross-implementation
  parity report, API, binding, and plugin tests.
