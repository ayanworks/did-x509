# ADR-001: did:x509 Core — Adopt Rust with Tiered Multi-Platform Targets

## Status

Proposed

## Context

The `did:x509` specification has two reference implementations:

1. **didx509cpp** (Microsoft C++ with OpenSSL) — full RFC 5280 path validation, strict mode, security levels
2. **@didx509/core** (AyanWorks TypeScript with @peculiar/x509) — partial chain verification, broad platform support, CLI, did-resolver plugin

The TypeScript implementation is developer-friendly but lacks cryptographic rigor (no name constraints, policy constraints, algorithm security levels, strict mode). The C++ is rigorous but header-only with OpenSSL — impossible to use from TS without a native addon.

We need a single core that is:
- Cryptographically rigorous (RFC 5280 compliant)
- Deployable on web, Node.js, React Native, iOS, Android, macOS, Linux, Windows
- Published as a standard npm package
- Maintainable from one codebase

## Options Considered

### Option A: Enhance TypeScript implementation directly
- Zero build tooling changes
- Existing browser support
- No access to RFC 5280 path validation libraries — would need to reimplement from scratch
- JavaScript not available on iOS/Android natively
- Performance overhead for certificate chain verification

### Option B: Wrap didx509cpp (C++) via FFI
- Reuses Microsoft's production-grade validation
- Header-only C++ requires a C shim layer
- Requires OpenSSL system dependency
- Prebuilt .node binaries needed for every platform + Node.js ABI version
- Impossible on web browsers
- Impossible on React Native Hermes engine

### Option C: Pure Rust core → WASM + native bindings
- Single Rust codebase targets every platform
- `no_std`-compatible pure-Rust crates exist (`x509-cert`, `x509-verify`, `ring`) — no OpenSSL needed
- WASM works in browsers + Node.js
- `uniffi-rs` (Mozilla) generates Kotlin/Swift bindings for mobile
- `cargo-ndk` + `cargo-xcode` for native Android/iOS/macOS
- Requires learning Rust for contributors
- WASM has ~2x overhead vs native for hot paths (acceptable for infrequent DID resolution)

## Decision

Adopt **Option C: Pure Rust core** with a tiered multi-platform strategy.

### Tiered Strategy

```
Rust Core Library (@didx509/rust-core)
├── Tier 1: WASM build (wasm-pack)
│   └── @didx509/wasm → npm package for Web + Node.js
├── Tier 2: Mobile native (uniffi-rs + cargo-ndk + cargo-xcode)
│   ├── Android AAR → Kotlin/Java
│   └── Swift Package → iOS/macOS
├── Tier 3: Desktop native
│   ├── Linux .so / macOS .dylib / Windows .dll
│   └── C FFI headers via cbindgen
└── TypeScript wrapper (@didx509/core)
    ├── Default: fast TS-only path (current)
    ├── strictMode: true → WASM backend (Tier 1)
    ├── React Native → native module (Tier 2)
    └── Electron → native module (Tier 3)
```

### Verification Strategy

The Rust core will be verified against a shared test suite that covers:
- didx509cpp unit tests
- did:x509 spec test vectors (synthetic chain from specification.md)
- All existing TypeScript tests (parity check)

A cargo xtask command or GitHub Actions matrix will run the same test vectors across WASM, native, and the existing TS implementation.

## Consequences

### Positive
- One core validation engine across all platforms
- Cryptographically rigorous (pure Rust crypto, no OpenSSL dependency)
- WASM works in browsers; native libs work outside browsers
- TS @didx509/core stays as the easy default; strict mode is opt-in
- Build pipeline is CI-automated (no manual per-platform releases)

### Negative
- Contributors need Rust knowledge for the core
- WASM adds ~300 KB to bundle size for the strict mode path
- Initial development investment (~2–4 weeks for Phase 1)

### Risks
- `x509-verify` crate maturity: currently experimental. Fallback: use `x509-parser` + `ring` for signature verification, implement path validation manually using `x509-cert` types.
- WASM compilation of `ring` on Windows: known to work via `wasm-pack`.
