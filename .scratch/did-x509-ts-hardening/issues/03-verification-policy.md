# 03 — Verification depth & constraint enforcement policy

Type: grilling
Status: open
Blocked by: 02

## Question

Given the crypto-stack survey (ticket 02), decide the enforcement matrix this library ships with — the TS analogue of didx509cpp's OpenSSL settings:

- **keyCertSign**: require KU.keyCertSign on issuing certs? (C++ gets it via strict path validation; we currently never check.)
- **BasicConstraints**: reject CAs missing BC entirely (current code silently accepts)? Enforce leaf non-CA?
- **Critical extensions**: fail on unrecognized critical extensions per spec step 2, treating fulcio-issuer OID as recognized? (We never read criticality today.)
- **Root trust semantics**: verify root self-signature (C++ CHECK_SS_SIGNATURE) or accept last-cert-as-anchor (current)? Support caller-supplied external roots / PARTIAL_CHAIN-style anchoring?
- **Security floor**: enforce RSA≥2048/ECC≥224/hash-strength floor + reject sha1/MD5 signatures (auth_level≈2)?
- **Name/policy constraints**: full enforcement, or fail-closed on presence if engine support is impractical in TS? (Fog item graduates here.)
- **Strict-mode surface**: do we expose any of this behind options (e.g., `verificationPolicy`), or make the strict behavior unconditional?

Output: agreed enforcement matrix table (check → enforce/reject-on-presence/skip), recorded as answer; becomes the core of the implementation spec.
