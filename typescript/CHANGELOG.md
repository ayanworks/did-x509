# Changelog

All notable changes to `@didx509/core` are documented here. The package
follows [Semantic Versioning](https://semver.org/).

## [0.1.1] — 2026-11-04

Maintenance release. No API or behavioural changes.

### Changed

- Ship `CHANGELOG.md` in the published tarball, so the changelog linked from
  the release notes is also available on npm (#32).
- Use the `git+https://` form of `repository.url`, which is what npm expects
  when it renders the repository link.

## [0.1.0] — 2026-10-21

First release.

### Added

- `resolveDidFromPem` / `resolveDidFromPemSync` — derive a DID Document from
  an X.509 certificate chain, and resolve it against a chain.
- `loadPemCertificateChain` / `decodeCertificate` — parse PEM chains and
  decode certificates.
- `verifyCertificateChain` — chain validation with optional validity-period
  and CA fingerprint checks.
- `extractPublicKeyAsJwk` — the leaf public key as a JWK.
- `getDidX509Resolver()` — a did-resolver plugin, with a `DIDX509Resolver`
  class for direct use.
- The `didx509` CLI — `didx509 resolve`, `didx509 convert`, `didx509 encode`.
- Subject-value encoding helpers, and the `jsonWebKey2020VerificationMethod`
  resolver option.
