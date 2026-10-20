# Moving from @didx509/core to @didx509/native

Both packages resolve the same DIDs. They even share the same function
names, so switching is mostly a one-line import change.

The difference is what happens inside:

- **@didx509/core** does everything in TypeScript. It is fast to install and
  runs anywhere (browsers, React Native), but it cuts some corners.
- **@didx509/native** calls Microsoft's C++ resolver
  ([didx509cpp](https://github.com/microsoft/didx509cpp)). It checks
  certificate chains exactly the way the C++ reference implementation does.

## The import swap

```ts
// before
import { resolveDidFromPem, getDidX509Resolver } from '@didx509/core';

// after
import { resolveDidFromPem, getDidX509Resolver } from '@didx509/native';
```

Everything else — function names, argument order, the DID document shape,
the did-resolver plugin — is the same in both packages.

## What changes

1. **You need a native binary.** Node.js, Electron, Bun, and Deno are
   supported. Browsers and React Native are not — keep using
   `@didx509/core` there. See the platform table in the README.

2. **Error messages change.** You now get the exact message the C++
   resolver produced. Treat messages as human-readable text only — never
   compare them with `===` in code. The error *class* is also different:
   catch `Didx509Error` from `@didx509/native` instead of a plain
   `Error`.

3. **The option is called `ignoreTime`.** The old name
   (`skipValidityPeriodCheck`) still works, so most call sites do not
   need changes:

   ```ts
   await resolveDidFromPem(did, pem, { ignoreTime: true });
   // also still valid:
   await resolveDidFromPem(did, pem, { skipValidityPeriodCheck: true });
   ```

4. **Results get stricter.** Chains that `@didx509/core` accepted may now
   be rejected, and some documents may differ. That is the point: the
   native package follows the C++ reference implementation. The full list
   of known differences is below.

## Known differences from @didx509/core

Both packages are run against the same 220 official did:x509 test vectors
on every CI build. This list is generated from those runs
(`npm run parity:report`), so it cannot drift from reality.

If a line says @didx509/native would **reject** something, that is the C++
resolver following the specification — plan for it when you migrate.

<!-- core-divergences:begin -->
**112 of 220 test vectors behave differently** in @didx509/core:

### accepted although the C++ resolver rejects them (be careful — these are the risky ones) (19)

- `critical-fulcio-issuer-extension-is-rejected`
- `fulcio-selector-critical-issuer-unselected`
- `fulcio-selector-critical-token-subject-unselected`
- `fulcio-selector-der-constructed-unselected`
- `fulcio-selector-der-ia5-string-unselected`
- `fulcio-selector-der-indefinite-unselected`
- `fulcio-selector-der-invalid-utf8-unselected`
- `fulcio-selector-der-nonminimal-unselected`
- `fulcio-selector-der-raw-utf8-unselected`
- `fulcio-selector-der-trailing-unselected`
- `fulcio-selector-der-truncated-unselected`
- `issuer-without-basic-constraints-is-rejected`
- `issuer-without-key-cert-sign-is-rejected`
- `san-othername-malformed-entry-fails-when-unselected`
- `san-othername-unregistered-entry-fails-unselected-noncritical-san`
- `san-outside-permitted-subtree-is-rejected`
- `san-within-excluded-subtree-is-rejected`
- `unknown-critical-extension-is-rejected`
- `unsupported-certificate-san-type`

### rejected although the C++ resolver accepts them (81)

- `did-url-fragment-is-removed-from-document-id`
- `eku`
- `fulcio-issuer-with-email-san`
- `fulcio-issuer-with-uri-san`
- `fulcio-selector-algorithm-prefixed-digest`
- `fulcio-selector-all-fields-opaque-forward`
- `fulcio-selector-all-fields-opaque-reverse`
- `fulcio-selector-independent-dual-legacy-first-both`
- `fulcio-selector-independent-dual-legacy-first-v2`
- `fulcio-selector-independent-dual-v2-first-both`
- `fulcio-selector-independent-dual-v2-first-v2`
- `fulcio-selector-leading-zero-identifier`
- `fulcio-selector-lowercase-percent-escapes-preserve-document-id`
- `fulcio-selector-opaque-runner`
- `fulcio-selector-opaque-visibility`
- `fulcio-selector-real-pydantic-ai-all-fields-and-existing-predicates`
- `fulcio-selector-real-pydantic-ai-build-config-digest`
- `fulcio-selector-real-pydantic-ai-build-config-uri`
- `fulcio-selector-real-pydantic-ai-build-signer-digest`
- `fulcio-selector-real-pydantic-ai-build-signer-uri`
- `fulcio-selector-real-pydantic-ai-build-trigger`
- `fulcio-selector-real-pydantic-ai-deployment-environment`
- `fulcio-selector-real-pydantic-ai-issuer`
- `fulcio-selector-real-pydantic-ai-run-invocation-uri`
- `fulcio-selector-real-pydantic-ai-runner-environment`
- `fulcio-selector-real-pydantic-ai-source-repository-digest`
- `fulcio-selector-real-pydantic-ai-source-repository-identifier`
- `fulcio-selector-real-pydantic-ai-source-repository-owner-identifier`
- `fulcio-selector-real-pydantic-ai-source-repository-owner-uri`
- `fulcio-selector-real-pydantic-ai-source-repository-ref`
- `fulcio-selector-real-pydantic-ai-source-repository-uri`
- `fulcio-selector-real-pydantic-ai-source-repository-visibility-at-signing`
- `fulcio-selector-real-pydantic-ai-token-subject`
- `fulcio-selector-real-sigstore-js-build-config-digest`
- `fulcio-selector-real-sigstore-js-build-config-uri`
- `fulcio-selector-real-sigstore-js-build-signer-digest`
- `fulcio-selector-real-sigstore-js-build-signer-uri`
- `fulcio-selector-real-sigstore-js-build-trigger`
- `fulcio-selector-real-sigstore-js-issuer`
- `fulcio-selector-real-sigstore-js-run-invocation-uri`
- `fulcio-selector-real-sigstore-js-runner-environment`
- `fulcio-selector-real-sigstore-js-source-repository-digest`
- `fulcio-selector-real-sigstore-js-source-repository-identifier`
- `fulcio-selector-real-sigstore-js-source-repository-owner-identifier`
- `fulcio-selector-real-sigstore-js-source-repository-owner-uri`
- `fulcio-selector-real-sigstore-js-source-repository-ref`
- `fulcio-selector-real-sigstore-js-source-repository-uri`
- `fulcio-selector-real-sigstore-js-source-repository-visibility-at-signing`
- `fulcio-selector-real-sigstore-js-token-subject`
- `fulcio-selector-real-staging-legacy-issuer`
- `fulcio-selector-reserved-and-utf8-token`
- `fulcio-selector-san-and-token-subject-remain-separate`
- `fulcio-selector-uri-existing-escape`
- `fulcio-selector-v2-only-issuer`
- `fulcio-selector-valid-replacement-character`
- `intermediate-ca`
- `multiple-predicates`
- `path-length-permits-exact-depth`
- `root-ca`
- `san`
- `san-othername-critical-empty-subject`
- `san-othername-critical-without-fulcio-extensions`
- `san-othername-duplicates-and-repeated-predicates`
- `san-othername-encoded-reserved-characters`
- `san-othername-long-form-der-length`
- `san-othername-lowercase-percent-escapes`
- `san-othername-mixed-san-othername-predicate`
- `san-othername-multibyte-utf8`
- `san-othername-multiple-entries-match-nonfirst-value`
- `san-othername-noncritical-without-fulcio-extensions`
- `san-othername-single-decode-matches-literal-percent`
- `san-othername-valid-replacement-character`
- `san-othername-with-issuer-v2-and-token-subject-without-legacy-issuer`
- `san-othername-with-legacy-issuer`
- `sha384-ca-fingerprint`
- `sha512-ca-fingerprint`
- `specification-eku-predicate`
- `specification-fulcio-issuer-and-san`
- `specification-intermediate-ca-fingerprint`
- `specification-root-ca-fingerprint`
- `subject-predicate-supports-dotted-oid`

### produce a different DID document (12)

- `certificate-validity-periods-are-not-checked`
- `critical-certificate-policies-extension-is-accepted`
- `fulcio-issuer-extension-is-accepted-when-not-critical`
- `fulcio-selector-empty-extension-is-retained`
- `fulcio-selector-independent-dual-legacy-first-legacy`
- `fulcio-selector-independent-dual-v2-first-legacy`
- `issuer-with-key-cert-sign-is-accepted`
- `key-agreement-only-leaf`
- `path-length-permits-excess-headroom`
- `san-othername-mixed-san-existing-predicates`
- `san-within-permitted-subtree`
- `unknown-non-critical-extension-is-ignored`
<!-- core-divergences:end -->
