# Release setup — trusted publishing

All three packages have had their first publish, so every future release can
go through GitHub Actions:

| Package | First published |
| --- | --- |
| `@didx509/core` | `0.1.0`, then `0.1.1`, then `0.1.2` |
| `@didx509/credo` | `0.1.0`, then `0.1.1`, then `0.1.2` |
| `@didx509/native` | `0.1.0`, then `0.1.1` |

The one-time manual publish existed only because npm trusted publishing is
configured on a *package's* settings page, and that page does not exist until
the package does. A brand-new package will still need one manual publish
before a trusted publisher can be added for it.

---

## 1. Add a trusted publisher for each package

npmjs.com → Packages → the package → **Settings** → **Trusted publishing** →
**GitHub Actions**:

| Package | Organization | Repository | Workflow filename |
| --- | --- | --- | --- |
| `@didx509/core` | `ayanworks` | `did-x509` | `publish.yml` |
| `@didx509/credo` | `ayanworks` | `did-x509` | `publish.yml` |
| `@didx509/native` | `ayanworks` | `did-x509` | `prebuild.yml` |

Leave the environment blank and allow **`npm publish`**.

**Timing matters:** a new trusted-publisher configuration expires if it does
not complete a successful publish within **2 days**. Add it when you are close
to the next release, or it will need to be deleted and recreated.

## 2. Remove token-based publishing

There must be no `NPM_TOKEN` / `NODE_AUTH_TOKEN` secret in the repository. npm
prefers a token over OIDC when one is present, and a stale or non-npm token
produces confusing auth failures (typically a `404` on `PUT`) instead of an
obvious "no trusted publisher" error.

Optionally, after the first successful OIDC publish, turn on
**Settings → Publishing access → Require 2FA and disallow tokens** for each
package. This blocks token-based publishing entirely while leaving trusted
publishers working.

## 3. Publish by pushing a tag

Only pushed tags publish. Each tag must carry the `v` before the version:

```bash
git tag -s core-v0.1.2 -m "core-v0.1.2"
git push origin core-v0.1.2
```

The trigger patterns are `core-v*`, `credo-v*` and `native-v*`. A
`workflow_dispatch` run executes the same build, lint, test and pack steps but
**does not publish**, so it is safe to use as a dry run.

Publish `@didx509/core` before `@didx509/credo`, because credo's published
manifest is rewritten to depend on the core version from the checkout.
`@didx509/native` is independent.

If the version is already on npm, the publish step logs that and skips it, and
the workflow continues to the release job. Re-running a tag build is therefore
safe and still creates the GitHub release.

## 4. Verify

```bash
npm view @didx509/core version
npm view @didx509/credo dependencies
npm view @didx509/native version
```

The tag build also creates the matching GitHub release. A successful publish
appears in the npm CLI output as:

```
+ @didx509/core@0.1.2
```

---

## Troubleshooting

- **`404 Not Found - PUT https://registry.npmjs.org/@didx509%2f...`** — no
  trusted publisher matches this repository + workflow filename, the
  configuration expired, or a token secret is set and npm tried it first.
- **`ENEEDAUTH`** — the workflow is missing `id-token: write`, or it is not
  running on a GitHub-hosted runner. Trusted publishing does not work on
  self-hosted runners.
- **`403 cannot publish over the previously published versions`** — the
  version already exists. The workflow guards against this; if you see it,
  the guard was bypassed (for example by publishing by hand first).
- **Release job skipped** — the publish job must succeed. With the idempotency
  guard, an already-published version does not fail the job.
