# 02 — pkijs/@peculiar RFC 5280 capability survey → recommended verification architecture

Type: research
Status: open
Blocked by:

## Question

Our hand-rolled chain verification (adjacent-signature loop + partial basic constraints) cannot reach didx509cpp's rigor (auth_level≈2, X509_STRICT, keyCertSign, critical-extension failure, constraints). Before deciding enforcement policy, establish what the existing dependency stack can give us:

- What does `pkijs` `CertificateChainValidationEngine` actually implement (signatures, basic constraints, key usage, name/policy constraints, criticality, expiry, trust anchors)? Version status, known gaps, maintenance state.
- Does `@peculiar/x509` expose enough extension detail (criticality flags, name-constraint subtrees, policy OIDs) to build fail-closed checks without dropping to raw pkijs?
- Is there any maintained pure-JS/TS library that does OpenSSL-grade path validation (e.g., x509 libraries on npm)? If so, compare license, size, browser compatibility.
- Security-floor enforcement without OpenSSL: practical approach to enforce RSA≥2048 / ECC≥224 / hash-strength floors and reject weak algorithms (sha1) in TS.
- Recommendation: keep hand-rolled + targeted fixes vs adopt pkijs engine vs new dependency — with tradeoffs (bundle size, reflect-metadata burden, browser support).

Findings land as a research doc linked from this ticket; the recommendation feeds the verification-policy grilling ticket.
