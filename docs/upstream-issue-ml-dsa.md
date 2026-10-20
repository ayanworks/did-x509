# Draft issue for `microsoft/didx509cpp`

Post with:

```bash
gh issue create \
  --repo microsoft/didx509cpp \
  --title "Support ML-DSA (post-quantum) public keys and signatures" \
  --body-file docs/upstream-issue-ml-dsa.md
```

Target: <https://github.com/microsoft/didx509cpp/issues/new>

---

## Title

Support ML-DSA (post-quantum) public keys and signatures

## Body

### Summary

`didx509cpp` currently resolves certificates containing RSA, EC (P-256/P-384/P-521), and
Ed25519 keys. Certificates using **ML-DSA** (FIPS 204, the NIST post-quantum signature
standard) are rejected with `unsupported key base id` from `UqX509::public_jwk()`.

ML-DSA certificates are now being issued in practice, and the JOSE/COSE representation
is standardized, so it would be valuable for the reference implementation to support
them.

### Current behaviour

`didx509cpp.h`, in `UqX509::public_jwk()` (~line 1122):

```cpp
auto base_id = EVP_PKEY_base_id(pk);
switch (base_id)
{
  case EVP_PKEY_RSA:      { ... }
  case EVP_PKEY_EC:       { ... }  // P-256, P-384, P-521
  case EVP_PKEY_ED25519:  { ... }
  default:
    throw std::runtime_error("unsupported key base id");
}
```

An ML-DSA certificate therefore fails resolution even though OpenSSL 3.5+ can parse and
verify it.

### Why this is now actionable

1. **OpenSSL support exists.** OpenSSL 3.5 added ML-DSA; 3.6 exposes
   `EVP_PKEY_ML_DSA_44` / `_65` / `_87` (`openssl/evp.h`), the provider algorithms
   `id-ml-dsa-{44,65,87}`, and the NIDs `NID_ML_DSA_{44,65,87}`. The current
   requirement is already OpenSSL 3.3+, so a version guard would be needed for
   `3.5 <= OpenSSL < ...` but no new dependency is introduced.
2. **The JWK encoding is standardized.** RFC 9964 ("ML-DSA for JOSE and COSE",
   May 2026) registers a new key type `AKP` (Algorithm Key Pair):

   - `"kty"`: `"AKP"` (REQUIRED)
   - `"alg"`: `"ML-DSA-44"` | `"ML-DSA-65"` | `"ML-DSA-87"` (REQUIRED)
   - `"pub"`: the raw ML-DSA public key (REQUIRED), base64url-encoded

   Example from RFC 9964 §3:

   ```json
   {
     "kid": "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o",
     "kty": "AKP",
     "alg": "ML-DSA-44",
     "pub": "unH59k4Ru..."
   }
   ```

   This mirrors the existing `OKP`/Ed25519 handling (`kty`, `crv`, `x`), so it fits the
   current structure closely.

### Sizes (RFC 9964, Table 1 / FIPS 204 Table 2)

| Algorithm   | Private key (expanded) | Public key | Signature |
|-------------|------------------------|------------|-----------|
| ML-DSA-44   | 2560                   | 1312       | 2420      |
| ML-DSA-65   | 4032                   | 1952       | 3309      |
| ML-DSA-87   | 4896                   | 2592       | 4627      |

The public key is the value of `"pub"`. Note these are substantially larger than
existing key types (Ed25519 `x` is 32 bytes), which may matter for document size.

### Suggested implementation

**1. Public key extraction** — ML-DSA has no `OSSL_PKEY_PARAM_*_PUB` parameter; the
public key is obtained with `EVP_PKEY_get_raw_public_key()`, exactly as the Ed25519
branch already does:

```cpp
case EVP_PKEY_ML_DSA_44:
case EVP_PKEY_ML_DSA_65:
case EVP_PKEY_ML_DSA_87: {
  const char* crv =
    base_id == EVP_PKEY_ML_DSA_44 ? "ML-DSA-44" :
    base_id == EVP_PKEY_ML_DSA_65 ? "ML-DSA-65" : "ML-DSA-87";
  const size_t expected =
    base_id == EVP_PKEY_ML_DSA_44 ? 1312 :
    base_id == EVP_PKEY_ML_DSA_65 ? 1952 : 2592;

  std::vector<uint8_t> raw_key(expected);
  size_t raw_key_size = raw_key.size();
  if (EVP_PKEY_get_raw_public_key(pk, raw_key.data(), &raw_key_size) != 1)
    throw std::runtime_error(
      "ML-DSA public key extraction failed: " + error_string(ERR_get_error()));
  if (raw_key_size != expected)
    throw std::runtime_error("invalid ML-DSA public key size");

  r += R"("kty":"AKP",)";
  r += R"("alg":")" + std::string(crv) + R"(",)";
  r += R"("pub":")" + to_base64url(raw_key) + R"(")";
  break;
}
```

**2. Signature verification** — the signature path would need an ML-DSA case. ML-DSA
signatures are verified with `EVP_DigestVerify*` in one-shot mode over the TBS bytes
(the algorithm hashes internally; there is no separate digest), and the empty context
string is required per RFC 9964 §5.

**3. Build guard** — `case` labels for `EVP_PKEY_ML_DSA_*` do not exist before
OpenSSL 3.5, so the branch should be compiled conditionally, e.g.
`#if OPENSSL_VERSION_NUMBER >= 0x30500000L`. Possibly worth declaring a minimum
OpenSSL of 3.5 if unconditionally supporting ML-DSA is preferred.

**4. Test vectors** — would need fixture certificates. As a reference, `openssl`
3.5+ can generate a self-signed ML-DSA certificate:

```sh
openssl req -x509 -new -newkey mldsa65 -nodes -keyout key.pem -out cert.pem \
  -subj "/C=US/CN=ML-DSA Test" -days 365
```

### Compatibility considerations

- Emitting `kty: "AKP"` changes the resolver's output shape for these certificates.
  Consumers that only understand `RSA`/`EC`/`OKP` will need to add `AKP`. This is
  inherent to RFC 9964 and not avoidable, but it is worth calling out explicitly in
  the release notes as a new capability rather than a breaking change (no existing
  certificate changes behaviour).
- RFC 9964 deliberately omits `HashML-DSA`; only the pure ML-DSA variants would apply.

### Question

Would a PR for this be welcome? I am happy to prepare one, including the build guard,
the JWK branch, the verification path, and test fixtures, in whatever shape fits the
project's conventions. If you would prefer to scope it differently — for example,
public key extraction only, without signature verification — I would be glad to hear
your preference before opening a PR.

### References

- RFC 9964 — ML-DSA for JOSE and COSE: <https://www.rfc-editor.org/rfc/rfc9964.html>
- RFC 9881 — Algorithm Identifiers for ML-DSA (X.509): <https://www.rfc-editor.org/rfc/rfc9881.html>
- NIST FIPS 204: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>
- OpenSSL 3.5 release notes (ML-DSA support)
