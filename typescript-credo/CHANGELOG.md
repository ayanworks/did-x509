# Changelog

All notable changes to `@didx509/credo` are documented here. The package
follows [Semantic Versioning](https://semver.org/).

`@didx509/credo` depends on `@didx509/core`, so a breaking change in `core`
requires a matching release here — see
[CONTRIBUTING.md](../CONTRIBUTING.md#cutting-a-release).

## [0.1.1] — 2026-11-04

Maintenance release. No API or behavioural changes.

### Changed

- Ship `CHANGELOG.md` in the published tarball, so the changelog linked from
  the release notes is also available on npm (#32).
- Use the `git+https://` form of `repository.url`, which is what npm expects
  when it renders the repository link.
- README: the install instructions no longer imply `@didx509/native` is
  available. It is an optional peer dependency that has not shipped yet, so
  the documented install uses the pure-TypeScript resolver in
  `@didx509/core` (#32).

## [0.1.0] — 2026-10-21

First release.

### Added

- `X509DidResolver` — a Credo `DidResolver` for `did:x509`, usable with
  `DidsModule`.
- Resolution through `@didx509/core`, with `@didx509/native` used
  automatically when it is installed.
- The `implementation` option (`'auto' | 'native' | 'core'`) to choose the
  resolver engine.
- The `jsonWebKey2020VerificationMethod` option, off by default.
