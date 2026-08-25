# 01 — Security hotfixes valid under every architecture

Type: task
Status: open

## Question

Two defects in `@didx509/core` are exploitable/fragile regardless of any architectural decision this map will make. Do them now, before policy questions resolve:

1. **Resolver plugin bypasses all cryptography** (did-resolver-plugin.ts): `getDidX509Resolver()` runs `loadX509Chain → decodeCertificate → checkDidX509 → build` and never calls `verifyCertificateChain`. Any chain whose predicates match resolves with zero signature/expiry/constraint validation. Fix: invoke full chain verification on the plugin path (with option pass-through for validity-period skip), plus a regression test proving a tampered/failing chain yields `notFound`.

2. **ECDSA/RSA signature conversion heuristic** (x509.ts:360): `sigArray[0] === 0x30` misclassifies ~1/256 of RSA signatures as DER-ECDSA and corrupts verification. Fix: branch on the certificate's actual `signatureAlgorithm` from @peculiar parsing instead of byte-sniffing, plus negative tamper tests for both RSA and ECDSA chains.

Resolution = both fixes merged with tests green; answer records what changed and any resulting facts later tickets depend on (e.g., whether the plugin needs an options surface for time-skipping).
