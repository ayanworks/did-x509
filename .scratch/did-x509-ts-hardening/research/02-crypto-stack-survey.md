# Ticket 02 — Crypto Stack Survey (did:x509 TS hardening)

**Date:** 2026-08-23
**Scope:** How close can pure TypeScript get to the did:x509 C++ reference behavior (OpenSSL `auth_level=2`, `X509_V_FLAG_X509_STRICT`, `CHECK_SS_SIGNATURE`, `PARTIAL_CHAIN`, keyCertSign enforcement, fail-on-unrecognized-critical-extensions, name/policy constraints)?

**Versions surveyed** (verified against npm registry and installed `node_modules` on 2026-08-23):

| Package | Version | Released | License | Notes |
|---|---|---|---|---|
| pkijs | **3.4.0** (= npm `latest`) | 2026-03-18 | BSD-3-Clause | what we ship |
| @peculiar/x509 | **2.0.0** (= npm `latest`) | 2026-03-23 | MIT | what we ship |
| asn1js | ^3.0.6 (transitive of pkijs) | — | BSD-3-Clause | |
| tsyringe / reflect-metadata | 4.10.0 / 0.2.2 | — | MIT / Apache-2.0 | DI burden of @peculiar/x509 |
| node-forge | 1.4.0 | 2026-03-24 | BSD-3-Clause OR GPL-2.0 | evaluated, rejected |
| micro509 | 0.14.0 | 2026-07-29 | MIT | evaluated, too immature |
| @sigstore/core / @sigstore/verify | 4.0.1 / 4.1.2 | 2026-06-25 / 2026-08-04 | Apache-2.0 | evaluated as pattern donor |
| jsrsasign | 11.1.5 | 2026-08-14 | MIT | evaluated, rejected |

---

## Summary table — capability x approach

Legend: YES = implements; PARTIAL = partial or buggy; NO = absent.

| Capability | Hand-rolled (current TS) | pkijs 3.4.0 `CertificateChainValidationEngine` | @peculiar/x509 2.0 alone | Recommended: hand-rolled + targeted fixes |
|---|---|---|---|---|
| Adjacent-pair signature verify (WebCrypto) | YES | YES (`defaultFindIssuer`) | YES (`cert.verify()`) | keep |
| Issuer<->subject name chaining | YES (string compare) | PARTIAL exact DER-byte compare (case/order-sensitive) | PARTIAL string compare | keep + normalize |
| Trust anchor = last supplied cert (spec Read step 2) | YES (leaf-first order) | NO (expects leaf LAST in `certs`) | NO (chain builder only) | keep |
| Validity window | YES | YES (`basicCheck`, resultCode 8) | YES (fields only) | keep |
| BasicConstraints CA=true on non-leaf | PARTIAL: only checked if extension present (missing BC passes!) | YES (`checkForCA` resultCode 7) | NO | fix: require BC+CA for non-leaf |
| pathLenConstraint enforcement | PARTIAL: enforced but off-by-one false-rejects | **NO — parsed, never enforced** | NO | fix indexing (`pathLen < i-1`) |
| keyUsage.keyCertSign on issuers | NO | YES (resultCode 3/4) | NO | add (~15 LOC) |
| cRLSign when CRLs used | n/a | YES (resultCode 5) | NO | optional |
| Unrecognized critical extension fail-closed | NO | **NO in practice** (see 1.2) | YES buildable from raw API | add allowlist per spec step 2 |
| Name constraints processing | NO | PARTIAL (permitted/excluded subtrees, quirky matchers) | NO (raw parse via asn1-x509) | defer; fail-closed criticality covers risk |
| Certificate policies / policy mappings / inhibit anyPolicy | NO | PARTIAL (ported state machine, lightly exercised) | policies OID list only | defer |
| Revocation (CRL/OCSP) | NO | PARTIAL (only certs you supply; silent skip if none) | NO | out of scope (spec leaves to app) |
| Security floor RSA>=2048 / ECC>=224 (auth_level=2) | NO | NO | YES buildable via exported CryptoKey | add |
| SHA-1 / MD5 signature rejection | NO | NO | YES buildable via signatureAlgorithm name/OID | add |
| Self-signed root signature check (CHECK_SS_SIGNATURE) | NO | PARTIAL (self-sig verified during findIssuer) | NO | add (~5 LOC) |
| Path building among arbitrary certs | n/a (spec chain is explicit) | YES (its main value) | YES (`X509ChainBuilder`, no validation) | not needed |
| Duplicate-extension rejection | NO | NO | NO | add (~10 LOC) |
| Browser / WASM-free | YES | YES | YES (+tsyringe/reflect-metadata) | keep |
| Marginal bundle cost | 0 | ~0 (already imported) | already dep | 0 |
| Maintenance risk | ours | low-med (active but engine frozen since ~2019) | low | ours |

---

## Q1 — pkijs `CertificateChainValidationEngine`

### 1.1 What it actually implements

Verified by reading the installed 3.4.0 bundle (`node_modules/pkijs/build/index.es.js`, class at line 14496) and cross-checking current master (`src/CertificateChainValidationEngine.ts`). The two are functionally identical for this class; the engine has not materially changed since the 2019 async refactor (commit `f12853a`, PR #156 era).

Implemented:

- **Path building**: recursive issuer discovery via AKI/SKI match, then authorityCertIssuer/serialNumber, then issuer/subject DN equality; candidate issuers filtered by signature verification (`defaultFindIssuer`). Self-signed cert whose self-signature verifies terminates the path.
- **Signature verification**: every child is verified against each candidate issuer's SPKI via `crypto.verifyWithPublicKey` (RSA PKCS#1, RSA-PSS incl. salt/hash params, ECDSA with DER->raw conversion).
- **Validity window**: all certs vs `checkDate` (resultCode 8).
- **Name chaining**: adjacent issuer/subject equality (resultCode 10).
- **CA checks (`checkForCA`)** for non-leaf certs:
  - unparseable critical extension -> resultCode 6;
  - keyCertSign set without BasicConstraints -> resultCode 3;
  - CA=true + keyUsage present without keyCertSign -> resultCode 4;
  - cRLSign required on CRL issuers -> resultCode 5;
  - non-leaf without CA=true -> resultCode 7.
- **Revocation**: CRL + OCSP *only from arrays you pass in*; throws `ChainValidationCode.noRevocation` if data was supplied but insufficient; silently skips if you supply none.
- **Policy processing**: initial policy set, policy mappings (incl. anyPolicy-mapping ban), policyConstraints (requireExplicitPolicy / inhibitPolicyMapping with pending counters), inhibitAnyPolicy, authorized/user policy intersection — a recognizable port of RFC 5280 §6.1.3–6.1.5.
- **Name constraints**: permitted/excluded subtrees grouped by GeneralName type (rfc822, DNS, directoryName, URI, IP), accumulated down the path.

### 1.2 What it does NOT implement (gaps that matter to us)

1. **pathLenConstraint is never enforced.** It is parsed into the `BasicConstraints` ASN.1 model (index.es.js:1658–1745) and never read again. Grep of both 3.4.0 and current master confirms zero reads outside parsing. A root declaring pathLen=0 above an intermediate+leaf validates fine.
2. **Unrecognized critical extensions are NOT rejected in practice.** The check `if (extension.critical && !extension.parsedValue)` (line 14749) looks like RFC 5280 §6.1.4(k)/(l) handling, but `ExtensionValueFactory.fromBER` returns the *raw parsed ASN.1 object* (truthy) for any unknown OID (lines 7352–7408); only malformed DER yields null. So an attacker-supplied certificate with an arbitrary critical extension sails through. Additionally, `checkForCA` — where this check lives — runs only on non-leaf certs (`basicCheck` skips index 0), so even the theoretical case is exempted on leaves.
3. **No security floor.** Nothing rejects SHA-1 signatures, MD5, small RSA moduli, or weak curves. OpenSSL `auth_level=2` equivalents are absent.
4. **Leaf assumed last.** `sort()` takes `localCerts[localCerts.length - 1]` as the leaf (line 14942). Our chains are leaf-first per spec; adopting CCVE requires reversing input and re-testing.
5. **Shortest-path heuristic.** Among candidate paths reaching a trusted cert, only the shortest is validated (lines 14969–14979). RFC 5280 accepts if ANY path validates; shortest-path can produce false negatives (interop, not security).
6. **Exact byte name comparison.** `RelativeDistinguishedNames.isEqual` walks attributes and compares DER encodings (`valueBeforeDecodeView`), i.e., case-, spacing-, and order-sensitive — stricter than RFC 5280 §7 matching rules. Fails legitimate chains with e.g. PrintableString vs UTF8String re-encodings of the same name.
7. **Quirky constraint matchers.** `compareDNSName` uses `localeCompare` (locale-dependent, not guaranteed ASCII case-insensitive); URI matching splits on `/`; directoryName matching is a loose subsequence walk; GeneralSubtree minimum/maximum fields are ignored.
8. **No duplicate-extension detection**, no EKU chain awareness, no basic-constraints requirement on the leaf side of issuers beyond `checkForCA`, no AIA fetching (fine for us).

### 1.3 Maintenance state (Aug 2026)

- Repo active: last push 2026-08-14; not archived; 1,396 stars; 85 open issues. npm downloads ~33.5M/month.
- Release cadence 3.x: 3.1.0 (2024-06), 3.2.x (2024-07), 3.2.5 (2025-03), 3.3.0–3.3.3 (2025-10→11), 3.4.0 (2026-03). Changelogs are dependency bumps, website fixes, OCSP extension-parsing corrections, and one SPKI import improvement (RSA-PSS). **Zero validation-engine changes in the entire v3 line.**
- License: BSD-3-Clause per package.json (GitHub shows "NOASSERTION" due to LICENSE formatting).
- The old NIST PKITS conformance example harness has been removed from the repo's examples tree; there is no published RFC 5280 conformance evidence for the current engine.

---

## Q2 — @peculiar/x509 API surface

### 2.1 Criticality

Yes. Every extension object extends `Extension` (build/x509.es.js:520) exposing:
- `type` — dotted OID string,
- `critical` — boolean (from `onInit`: `asn.critical`),
- `value` — raw extnValue ArrayBuffer,
- `rawData` — full DER of the Extension TLV.

`cert.extensions` returns ALL extensions regardless of whether a wrapper class exists: `ExtensionFactory.create` falls back to the generic base `Extension` for unregistered OIDs (x509.es.js:1619). So a **fail-closed critical-extension check is fully buildable from its API alone**:

```ts
const PERMITTED_CRITICAL = new Set([
  '2.5.29.15', // keyUsage
  '2.5.29.17', // subjectAltName (in JSON model)
  '2.5.29.19', // basicConstraints
  '2.5.29.30', // nameConstraints
  '2.5.29.31', // cRLDistributionPoints (non-critical in practice)
  '2.5.29.32', // certificatePolicies
  '2.5.29.33', // policyMappings
  '2.5.29.36', // policyConstraints
  '2.5.29.54', // inhibitAnyPolicy
  '2.5.29.37', // extKeyUsage (eku predicate)
]);
for (const cert of chain)
  for (const ext of cert.extensions)
    if (ext.critical && !PERMITTED_CRITICAL.has(ext.type) && ext.type !== FULCIO_ISSUER_OID)
      throw new Error(`Unsupported critical extension ${ext.type} on certificate`);
```
This mirrors spec "Read" step 2 exactly (fulcio_issuer treated as recognized).

### 2.2 Name-constraint subtrees

There is no `NameConstraintsExtension` wrapper class in @peculiar/x509 (grep confirms absence). However its dependency `@peculiar/asn1-x509` exports the `NameConstraints` ASN.1 type, so subtrees are reachable via `AsnConvert.parse(ext.value, NameConstraints)` without pkijs.

### 2.3 certPolicies

Yes — `CertificatePolicyExtension` exposes `policies: string[]` (policy OIDs) (x509.es.js:1634).

### 2.4 Other relevant facts

- `X509ChainBuilder.build()` only builds chains (subject==issuer string match + AKI/SKI + signature filter); it performs **no** CA/pathLen/expiry/constraint validation.
- `PublicKey.export()` returns a WebCrypto `CryptoKey` — `algorithm.modulusLength` for RSA, `algorithm.namedCurve` for ECDSA — which is exactly what we need for the auth-level floor (Q4).
- `cert.signatureAlgorithm` maps the OID to WebCrypto names (e.g. `"SHA-256"` variants), enabling hash-floor checks; direct OID checks are also possible off `cert.asn.signatureAlgorithm.algorithm`.
- v2 still uses tsyringe (`injectable()`, `container`) and its README instructs consumers to `import "reflect-metadata"` before use; our package carries `reflect-metadata` ^0.2.2 for this reason (currently only imported in `test/setup.ts`).

---

## Q3 — Alternative libraries doing serious X.509 path validation in JS/TS

| Library | Verdict | Details |
|---|---|---|
| **node-forge** 1.4.0 | Reject | `verifyCertificateChain()` had a basicConstraints bypass (GHSA-2328-f5f3-gj25, published 2026-03-24; certs with NEITHER basicConstraints NOR keyUsage accepted as CAs) fixed in 1.4.0. Essentially unmaintained cadence since 2022 (149M dl/mo is legacy inertia); ships its own JS bignum crypto instead of WebCrypto. Same bug class we are hardening against. |
| **micro509** 0.14.0 | Watch, don't adopt | Zero-dependency TS PKI toolkit, pure WebCrypto, typed `verifyCertificateChain` with purpose/identity/CRL/OCSP, ESM-only, MIT. Appealing shape, but first-release-era: ~800 downloads/month, no audit trail, no ecosystem proof. Re-evaluate in 12 months. |
| **@sigstore/core 4.0.1 + @sigstore/verify 4.1.2** | Pattern donor | Production-grade precedent (npm provenance verification): hand-rolled minimal ASN.1 parser + X.509 model, ZERO dependencies, Apache-2.0, WebCrypto for signatures. Their chain verifier enforces CA bit on non-leafs, name chaining, validity-at-timestamp, AND correct pathLen (`pathLength < i - 1`, packages/verify/src/key/certificate.ts). Scope is Fulcio-specific: trust anchors come from the Sigstore CA bundle, no keyCertSign/critical-ext/name-constraint/policy processing. Not directly reusable for did:x509 trust semantics, but proves the minimal-custom approach and gives us the correct pathLen formula. |
| **jsrsasign** 11.1.5 | Reject | Actively released but huge legacy surface, own crypto stack, history of CVEs in parsers; chain validation story is thin; would add a second crypto universe to our deps. |
| **@fidm/x509**, **x509** (npm) | Dead | Unchanged since 2019/2018. |
| **OpenSSL WASM** (`openssl-browser` w/ OpenSSL 3.5.2; jedisct1/openssl-wasm for WASI) | Reject for core lib | Only way to literally reach OpenSSL STRICT parity in-browser, but multi-MB wasm payload, CLI-ish APIs, async module init, and conflicts with our WASM-free goal. Viable future opt-in for server-side parity testing only. |
| **Node built-ins** (`crypto.X509Certificate`, `tls.checkServerIdentity`) | Partial | Node-only (breaks browser target), and `X509Certificate.verify()` checks single signatures only — no path validation. Not applicable as primary path. |

Bundle-size context (measured locally, unminified ESM builds, gzip):

| Module | raw | gzip |
|---|---|---|
| pkijs full build (already a direct dep) | 774 KB | 88 KB |
| @peculiar/x509 | 135 KB | 22 KB |
| asn1js | 112 KB | 17 KB |
| @peculiar/asn1-x509 (es2015 total) | 56 KB | ~10 KB est. |
| @peculiar/asn1-schema | 42 KB | ~9 KB est. |
| reflect-metadata | 42 KB | 6.8 KB |

---

## Q4 — Security-floor enforcement in pure TS (auth_level=2 equivalent)

OpenSSL level 2 = 112-bit floor: RSA/DSA/DH >= 2048 bits, ECC >= 224 bits, RC4 excluded; SHA-1 and MD5 signatures are already excluded at level 1 (<80-bit preimage/security margin). `check_auth_level()` applies the key floor to issuer keys and the sig-alg floor to everything except the anchor. In TS we can simply apply both floors to every cert (slightly stricter than OpenSSL, simpler, defensible).

Practical pattern using metadata we already have:

```ts
// 1) Signature-algorithm floor — map OIDs once, reject explicitly.
//    Prefer OID checks over WebCrypto names: they work even if the
//    algorithm provider mapping drifts.
const REJECTED_SIG_OIDS = new Set([
  '1.2.840.113549.1.1.4',  // md5WithRSAEncryption
  '1.2.840.113549.1.1.5',  // sha1WithRSAEncryption
  '1.2.840.10045.4.1',     // ecdsa-with-SHA1
  '1.2.840.10040.4.3',     // dsa-with-sha1
  '1.2.840.113549.1.1.2',  // md2WithRSAEncryption
]);

function assertSigAlgorithmOk(cert: X509Certificate): void {
  const oid = cert.asn.signatureAlgorithm.algorithm;
  if (REJECTED_SIG_OIDS.has(oid)) throw new Error(`Weak signature algorithm ${oid}`);
}

// 2) Key-size floor — via exported CryptoKey (WebCrypto-normalized):
async function assertKeyStrengthOk(cert: X509Certificate): Promise<void> {
  const key = await cert.publicKey.export();
  const alg = key.algorithm as JsonWebKey & { modulusLength?: number; namedCurve?: string };
  switch (alg.name) {
    case 'RSASSA-PKCS1-v1_5':
    case 'RSA-PSS':
    case 'RSA-OAEP':
      if ((alg.modulusLength ?? 0) < 2048) throw new Error('RSA key < 2048 bits');
      break;
    case 'ECDSA': {
      // P-256/P-384/P-521 OK; anything else (P-192, secp192k1...) fails closed.
      // Note: P-224 satisfies auth_level=2 but is unavailable in WebCrypto;
      // treat as unsupported rather than weakening the floor.
      const ok = ['P-256', 'P-384', 'P-521'].includes(alg.namedCurve ?? '');
      if (!ok) throw new Error(`EC curve ${alg.namedCurve} below policy`);
      break;
    }
    default:
      break; // Ed25519 etc.: fine; extend deliberately, never default-allow blindly
  }
}
```

Notes:
- `publicKey.export()` normalizes curve names, so we do not need our own OID-to-bits table for the common cases; fall back to reading `subjectPublicKeyInfo.algorithm.algorithm` OIDs (id-secp192r1 = 1.2.840.10045.3.1.1, etc.) for curves WebCrypto cannot import.
- Apply to **all** certs including the trust anchor (superset of OpenSSL behavior, which exempts the anchor's sig-alg check).
- This composes cleanly with our existing `verifyCertificateChain` loop; cost is a handful of lines and zero new dependencies.

---

## Q5 — Recommendation matrix and rationale

Options considered:

| Criterion | A: keep hand-rolled + targeted fixes | B: adopt pkijs CCVE | C: add new dep (micro509 / forge / wasm) |
|---|---|---|---|
| Bundle size | +0 (we already ship pkijs; fixes are code we write) | +0 today, but locks us to full pkijs build forever | micro509 +~200KB unpacked; forge ~1MB; wasm multi-MB |
| reflect-metadata/tsyringe burden | unchanged now; can shrink later by dropping @peculiar/x509 | unchanged | varies; none for forge/micro509 |
| Browser/WASM-free | yes | yes | forge/micro509 yes; wasm no |
| Reach OpenSSL auth_level=2 + STRICT | reaches ~95% with ~150 LOC (everything except exotic STRICT corner rules like empty-name/SAN-empty checks) | reaches less: no pathLen, no security floor, critical-ext check ineffective, plus leaf-last ordering mismatch | wasm variant = 100% parity but unacceptable payload/API |
| Matches did:x509 spec semantics (explicit chain, last-cert anchor, fulcio criticality carve-out) | natural fit | fights us: builds its own paths, picks shortest, different anchor conventions | micro509: different trust model; forge: known bypass history |
| Auditability | small, ours, testable against MS vectors | 1,900-line engine with dead-code criticality check and frozen maintenance surface | external audit trail varies |
| Risk of regressions | medium (we must port tests) | medium-high (behavior differences surface as interop surprises) | high (immaturity or abandonment) |

### Recommendation: Option A — keep the hand-rolled verifier, close the gap list below.

Rationale:

1. **The spec hands us a fully ordered chain.** did:x509 resolution receives `x509chain` (or `x5c`) with the trust anchor as the last element. There is nothing to discover, so CCVE's main value-add (path building/AKI-SKI search across arbitrary pools) is unused complexity. The Microsoft references validate the *supplied* chain too (the Python ref even compares supplied vs verified DER to prevent substitution).
2. **CCVE does not get us to the target.** Its three most security-relevant gaps (no pathLen enforcement, ineffective unrecognized-critical-extension rejection, no algorithm/key-strength floor) are exactly the deltas between our current code and the C++ reference. Adopting it would still leave us writing those checks ourselves — around the engine, against a leaf-last API, with shortest-path and byte-exact-name quirks to absorb.
3. **The remaining distance is small and cheap in pure TS.** Concretely, to reach parity with the reference behavior we should:
   - require `BasicConstraints` with `cA=true` on every non-leaf cert even when the extension is absent (today's `if (bcExt)` silently passes BC-less intermediates — the same bug class as node-forge GHSA-2328-f5f3-gj25);
   - fix the pathLen off-by-one: current `bcExt.pathLength < i` falsely rejects valid chains (e.g. root pathLen=1 above intermediate+leaf); correct bound is `pathLen < i - 1` (same formula sigstore-js uses);
   - enforce `keyUsage.keyCertSign` on issuers whenever keyUsage is present (and treat absent keyUsage per RFC 5280 profile requirements for CA certs under a strict flag);
   - add the fail-closed unrecognized-critical-extension allowlist per spec Read step 2 (fulcio_issuer treated as recognized);
   - add the auth-level floor from Q4 (RSA>=2048, ECC curve allowlist, SHA-1/MD5 rejection);
   - verify the self-signature of a self-signed anchor (CHECK_SS_SIGNATURE equivalent);
   - reject duplicate extension OIDs within one certificate (RFC 5280 §4.2 MUST NOT);
   - normalize name comparison (case/space-insensitive per RFC 5280 §7, or compare canonical DER) so legit re-encodings don't false-fail;
   - keep revocation out of scope (spec assigns it to relying-party policy), but structure the verifier so callers can plug it in later.
4. **Pattern donors reduce the work.** sigstore-js demonstrates the minimal-dep approach in production and supplies the correct pathLen logic; the Microsoft Python reference supplies the exact critical-extension allowlist and flag semantics; dididx509cpp documents the precise OpenSSL parameters we are emulating.
5. **Dependencies stay put for now.** Keep pkijs (already imported for TBS extraction) and @peculiar/x509. A worthwhile follow-up ticket: drop the pkijs import entirely (use `cert.tbs` / `AsnConvert` from @peculiar/asn1-* instead) and evaluate shedding tsyringe/reflect-metadata by consuming @peculiar/asn1-x509 directly — that removes the DI burden and shrinks the shipped graph, but is orthogonal to the security hardening and should not block it.

Parity assessment after Option A: signature math identical (WebCrypto), path semantics equal-or-stricter than the reference for the explicit-chain use case, security floor equal (applied to all certs vs OpenSSL's anchor exemption), criticality handling per spec. Residual gaps vs literal OpenSSL X509_STRICT: obscure structural lint checks (empty issuer DN, SAN-non-empty rules, explicit EC params presence) — document them as known deltas, or cherry-pick the cheap ones (empty-DN check is trivial).

---

## Sources

- pkijs source read locally: `node_modules/pkijs/build/index.es.js` v3.4.0 (CertificateChainValidationEngine L14496–15605; ExtensionValueFactory L7352–7408; Extension L7417–7513; BasicConstraints L1658–1745; RelativeDistinguishedNames.isEqual L395–420; verifyWithPublicKey L6669–6731; Certificate.verify L9200–9212)
- pkijs master `src/CertificateChainValidationEngine.ts` (confirms unchanged behavior): https://github.com/PeculiarVentures/PKI.js/blob/master/src/CertificateChainValidationEngine.ts
- pkijs releases/issues: https://github.com/PeculiarVentures/PKI.js/releases (v3.4.0, 2026-03-18), repo stats via GitHub API 2026-08-23
- npm registry data (versions/dates/downloads): registry.npmjs.org queries 2026-08-23 (pkijs 33.5M dl/mo; @peculiar/x509 39.0M; node-forge 149M; micro509 800)
- @peculiar/x509 v2.0.0 source read locally (`node_modules/@peculiar/x509/build/x509.es.js`); README reflect-metadata note; https://github.com/PeculiarVentures/x509
- node-forge advisory: https://github.com/digitalbazaar/forge/security/advisories/GHSA-2328-f5f3-gj25 ; OSV https://osv.dev/vulnerability/GHSA-2328-f5f3-gj25
- sigstore-js chain verification: https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/key/certificate.ts (pathLen `i - 1` logic), `packages/core/src/x509/cert.ts` (zero-dep parser)
- micro509: https://github.com/kjanat/micro509 , npm 0.14.0 (2026-07-29)
- did:x509 C++ reference (auth_level=2 + flags): https://github.com/microsoft/didx509cpp/blob/main/didx509cpp.h (L1219–1231)
- did:x509 Python reference (OpenSSL store flags, critical-extension allowlist): https://github.com/microsoft/did-x509/blob/main/didx509/didx509.py (commit 530aa6e, 2026-08-04); original hand-rolled version preserved in commit b55be46 (2022)
- did:x509 specification, DID Resolution step 2 (critical-extension rule): https://github.com/microsoft/did-x509/blob/main/specification.md
- OpenSSL security levels: https://docs.openssl.org/3.0/man3/SSL_CTX_set_security_level/ ; OpenBSD man page table (level 2 = 112-bit, RSA 2048, ECC 224; SHA1/MD5 signatures forbidden at level 1)
- OpenSSL x509_vfy.c (check_auth_level, unrecognized-critical handling): https://github.com/openssl/openssl/blob/master/crypto/x509/x509_vfy.c
