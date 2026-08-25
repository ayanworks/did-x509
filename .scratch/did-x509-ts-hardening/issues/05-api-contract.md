# 05 — Trust model, time handling, error taxonomy & API contract

Type: grilling
Status: open

## Question

Decide the resolver's outward-facing contract so consumers and tests can rely on stable behavior:

1. **Time model**: replace skip-all-or-wall-clock with didx509cpp-parity `ignoreTime` flag? Add explicit validation-time parameter (spec permits context-relevant time, e.g., signing time)? How does it thread through plugin options?
2. **Error taxonomy**: C++ throws exceptions with stable lowercase substrings consumed by its tests. Define our error codes/messages (parse errors vs verification failures vs predicate failures), what surfaces via did-resolver metadata (`invalidDid...` vs `notFound` — today everything collapses to notFound).
3. **JWK minimalism**: strip WebCrypto extras (`key_ops`, `alg`, `ext`) to emit spec-minimal JWKs like C++? Verify EC coordinate padding correctness for leading-zero x/y with regression vectors.
4. **Browser support**: resolve the Node-only sync fingerprint inside decodeCertificate — async pipeline everywhere, lazy hashing, or dual paths? (Interacts with ticket 02 findings on where crypto primitives run.)
5. **API additions**: expose `verify(chain)` and validated-chain return (C++ `resolve_chain` equivalent) as public API? Keep `verifyCertificateIssuedBy` private?

Output: API-contract decision list; feeds implementation spec and plugin media-type fog item.
