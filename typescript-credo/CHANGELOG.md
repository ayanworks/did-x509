# Changelog

All notable changes to `@didx509/credo` are documented here. The package
follows [Semantic Versioning](https://semver.org/).

`@didx509/credo` depends on `@didx509/core`, so a breaking change in `core`
requires a matching release here — see
[CONTRIBUTING.md](../CONTRIBUTING.md#cutting-a-release).

## [0.1.2] — 2026-11-04

Maintenance release.

### Changed

- Test against `@credo-ts/core` 0.7.4. It is a dev dependency; the peer range
  stays `^0.7.0` because 0.7.4 is a patch release within it (#39).
- Depend on `@didx509/core` `^0.1.2` (the `file:` link is rewritten at publish
  time, #42).

### Documentation

- `@didx509/native` has shipped, so the README no longer describes it as
  unpublished. It is an optional peer dependency, and installing it needs no
  code change (#42).

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
