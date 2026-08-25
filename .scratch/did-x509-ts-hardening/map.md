# Map: did:x509 TS Hardening — didx509cpp Parity

Label: wayfinder:map

> **MIGRATED**: this effort now lives on GitHub Issues — map: https://github.com/ayanworks/did-x509/issues/4 (tickets #5–#11). This local copy is a frozen snapshot of charting state; do not update it.

## Destination

`@didx509/core` (TypeScript) hardened in place to match Microsoft's didx509cpp cryptographic rigor: resolver-plugin validation bypass closed, RFC 5280 verification gaps closed to the agreed policy, semantic divergences (subject multi-values, percent-decoding, aliasing) resolved by explicit policy, and a ratified implementation spec describing every change — verified by test parity with didx509cpp vectors. Pure-TS stack retained; output format stays `cid/v1` + `JsonWebKey` (intentional modernization, not a bug).

## Notes

- Tracker: local-markdown (`.scratch/did-x509-hardening/`). GitHub Issues are disabled on this repo.
- This is a change-in-place effort: tickets resolve design decisions AND unblocking tasks; execution of the final spec happens after the map clears.
- Key reference material:
  - C++ ground truth: https://github.com/microsoft/didx509cpp (`didx509cpp.h`, header-only, OpenSSL path engine)
  - Local TS code: `reference-implementations/typescript/src/`
  - Spec: `specification.md` (DRAFT v0, TrustOverIP)
  - Prior context: `docs/adr/ADR-001-rust-tiered-platform-strategy.md` — Rust core remains *Proposed* and OUT OF SCOPE here; this hardening is valuable regardless of whether ADR-001 ever ratifies.
- Skills to consult when working tickets: /grilling, /domain-modeling for HITL tickets; /research for research tickets; /prototype if an API-shape question needs a concrete artifact.

## Decisions so far

- [Destination + scope](../../docs/) — charting session with repo owner: destination is parity-hardened pure-TS implementation; cid/v1 + JsonWebKey output kept as intentional modernization; Rust/WASM out of scope.

## Not yet specified

- Name-constraint handling depth: full parse-and-enforce vs fail-closed on presence of any nameConstraints extension — cannot be specified until the verification-depth policy ticket resolves what engine we build on.
- Browser-support restructure specifics (sync fingerprint makes pipeline Node-only today): async-pipeline shape, bundle impact — graduates once the verification architecture ticket resolves which crypto primitives we call where.
- Dependency-stack consequences (reflect-metadata burden, pkijs version pinning) if pkijs' chain-validation engine is adopted — graduates from the architecture research.
- Media-type negotiation for the did-resolver plugin (currently hardcoded `application/did+ld+json`; spec says request-selected, registered default `application/did`) — small conformance item, specify after API-contract ticket.
- Release/version strategy for breaking behavior changes (v0.2 semver policy, changelog discipline).

## Out of scope

- Rust/WASM core per ADR-001 — separate future effort; ADR stays Proposed.
- Revocation (CRL/OCSP) — spec leaves optional to applications.
- HTTP binding / x5c header transport layers — live outside this library.
- Matching didx509cpp's DID Document output format (`did/v1` + jws-2020 suite) — decided against; cid/v1 + JsonWebKey kept.
