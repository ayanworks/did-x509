# Changelog

All notable changes to `@didx509/core` are documented here. The package
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Unsupported EC curves now fail with an actionable error instead of Web
  Crypto's runtime-specific `NotSupportedError: Unrecognized namedCurve`.
  `secp256k1` certificates — which the C++ reference resolver rejects as
  `unsupported EC key curve` — now report
  `unsupported EC curve "secp256k1" in <role>: did:x509 supports P-256, P-384 and P-521`.
  The check covers every certificate in the chain and `extractPublicKeyAsJwk`.

### Documentation

- Document the supported key types (EC P-256/P-384/P-521, RSA, Ed25519) and
  the `secp256k1` limitation in the README, getting-started guide and API
  reference.

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
