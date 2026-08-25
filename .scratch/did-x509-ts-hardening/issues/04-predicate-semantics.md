# 04 — Predicate semantics policy (subjects, decoding, aliasing)

Type: grilling
Status: open

## Question

Resolve each semantic divergence between our TS predicates and didx509cpp, against specification.md's ABNF:

1. **Multi-valued subject attributes**: C++ matches if ANY value equals (map<string,vector<string>>); TS takes only the first value AND hard-throws on repeated attribute OIDs ("duplicates not allowed"). Spec says duplicates "not supported" — does that mean reject resolution or ignore extras? Pick: any-match / first-only / reject.
2. **Percent-decoding leniency**: C++ (curl-style) passes malformed `%XX` through literally; TS `decodeURIComponent` throws URIError, aborting resolution. Which matches spec ABNF intent? Consider security implications of each (lenient enables spoof-ish edge cases? strict causes DoS-by-malformed-DID).
3. **S→ST state aliasing**: adopt C++ normalization (S→ST before compare + post-normalization duplicate rejection) or stay literal?
4. **Charset validation**: validate base64url charset of fingerprint at parse time (C++ defers to mismatch error; TS has no check)? Enforce idchar grammar anywhere?
5. **Embedded-NUL defense**: worth explicit length-safe comparison tests in TS (JS strings preserve NULs natively — is anything actually vulnerable)?
6. **SAN types**: keep email/dns/uri only (reject ipaddress/other like C++) — confirm or extend.

Output: decision per item with spec citation, recorded as ticket answer; feeds implementation spec.
