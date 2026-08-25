# 06 — Test-vector parity infrastructure

Type: task
Status: open

## Question

didx509cpp's unit suite encodes hard-won edge cases our TS tests lack (NUL-truncation spoofing, wildcard non-expansion, SAN→CN fallback rejection, custom-OID subjects, UTF-8 lossless compare, EC leading-zero padding, sha384/sha512 pins, provided-roots regression). Build the shared parity harness now so every later decision lands with tests:

1. Inventory didx509cpp `test/test-data/*.pem` fixtures; port the portable ones into `shared-test-data/` (alongside existing ms-code-signing/fulcio PEMs).
2. Extract the assertion catalog from their `unit_tests.cpp` into a checklist mapping each C++ case → TS equivalent (exists / missing / N-A-because-output-format-differs).
3. Add the missing negative test scaffolding in the TS suite (tamper matrix, malformed DID corpus, plugin-path regression hook) ready to receive policy-driven cases.
4. Note which vectors need synthetic generation (e.g., name-constraint certs) for later phases.

Resolution = harness merged; answer records fixture inventory + gap checklist that tickets 03–07 will consume.
