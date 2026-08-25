# Phase-wise Implementation: Rust/WASM Core for @didx509

## Phase 0 — Foundation

**Goal**: Set up the Rust workspace, CI pipeline, and dependency graph.

- [ ] Create `reference-implementations/rust/` Cargo workspace
- [ ] Add Rust dependencies: `x509-cert`, `x509-parser` (verify feature), `ring`, `serde`, `serde_json`
- [ ] Add WASM dependencies: `wasm-bindgen`, `js-sys`, `getrandom` (wasm feature)
- [ ] Set up `cbindgen.toml` + `uniffi.toml` for future native bindings
- [ ] CI: `cargo test`, `cargo clippy`, `cargo fmt` check on every PR
- [ ] CI: `wasm-pack build` + `wasm-pack test` on Node.js + headless Chrome

## Phase 1 — DID Parsing + Predicate Validation

**Goal**: Port the DID string parsing and all four predicate types to Rust. WASM bindings expose `check_did()`.

- [ ] Implement `DidX509` struct: `parse(did: &str) -> ParsedDid`
- [ ] Implement CA fingerprint matching (sha256/sha384/sha512)
- [ ] Implement `subject` predicate with percent-decoding + duplicate field rejection
- [ ] Implement `san` predicate (email/dns/uri types)
- [ ] Implement `eku` predicate with OID comparison
- [ ] Implement `fulcio-issuer` predicate
- [ ] Unit tests: all spec test vectors + didx509cpp test cases
- [ ] WASM bindings: `check_did(did, decoded_chain_json) -> bool`

## Phase 2 — Certificate Chain Model + Verification

**Goal**: Full RFC 5280 path validation in Rust. WASM bindings expose `verify_chain()`.

- [ ] Implement `decode_certificate(der_bytes) -> DecodedCert` in Rust
- [ ] Implement RFC 5280 path validation:
  - Signature chain verification (RSA + ECDSA P-256/P-384/P-521)
  - Basic constraints check (CA bit, path length)
  - Key usage per-certificate enforcement
  - Name constraints (if present)
  - Policy constraints (if present)
  - Validity period check (with skip option)
  - Security level 2 equivalent (RSA >= 2048, ECC >= 224)
  - Strict mode (X509_V_FLAG_X509_STRICT equivalent)
- [ ] Implement `fulcio_issuer` as recognized extension for critical-extension processing
- [ ] Unit tests: valid chains, invalid signatures, expired certs, short chains, wrong issuer
- [ ] WASM bindings: `verify_chain(chain_json) -> bool`

## Phase 3 — DID Document Generation + WASM Package

**Goal**: Full `resolve()` pipeline in WASM. Publish `@didx509/wasm` to npm.

- [ ] Implement public key -> JWK conversion (RSA + EC P-256/P-384/P-521)
- [ ] Implement key usage -> authentication/assertionMethod/keyAgreement logic
- [ ] Implement DID Document JSON construction
- [ ] WASM bindings: `resolve(did, pem_chain, ignore_time) -> String`
- [ ] Publish `@didx509/wasm` npm package via `wasm-pack publish`
- [ ] TypeScript wrapper: `strictMode` option in `@didx509/core`
- [ ] Integration test: TS calls WASM backend, result matches existing TS output

## Phase 4 — React Native + Expo Support

**Goal**: Rust compiles to Android `.so` + iOS `.a` static libs. React Native turbo module wraps them.

- [ ] Implement `#[no_mangle] pub extern "C"` C API surface
- [ ] Compile Rust to `arm64-v8a`, `armeabi-v7a`, `x86_64` for Android via `cargo-ndk`
- [ ] Compile Rust to `aarch64-apple-ios`, `x86_64-apple-ios` for iOS via `cargo-xcode`
- [ ] Generate Kotlin bindings via `uniffi-rs` -> Android AAR
- [ ] Generate Swift bindings via `uniffi-rs` -> Swift Package
- [ ] React Native turbo module wrapping Android AAR + iOS XCFramework
- [ ] Expo module plugin
- [ ] Example: React Native app using `@didx509/core` with `strictMode: true`

## Phase 5 — Desktop Native + Electron

**Goal**: N-API addon for Node.js desktop apps. Standalone Swift Package for macOS.

- [ ] N-API addon from Rust `.so`/`.dylib`/`.dll` via `napi-rs`
- [ ] `@didx509/native` npm package (prebuilt platform binaries)
- [ ] Electron demo app
- [ ] macOS Swift Package demo app

## Phase 6 — CI/CD + Release Automation

**Goal**: Fully automated build and release for all tiers.

- [ ] GitHub Actions: `wasm-pack build` on all platforms
- [ ] GitHub Actions: `cargo-ndk` Android builds on ubuntu
- [ ] GitHub Actions: `cargo-xcode` iOS builds on macOS
- [ ] GitHub Actions: N-API prebuild via `napi-rs` with ghrelease uploads
- [ ] Shared test data: port didx509cpp test PEMs to `shared-test-data/`
- [ ] Smoke test: all reference implementations (Python, TS, Rust/WASM) pass same test vectors
