# First release — manual publish (then OIDC)

`@didx509/core` and `@didx509/credo` have never been published, so npm
trusted publishing (OIDC) cannot publish them: a trusted publisher is
configured on the *package's* settings page, and that page does not exist
until the package does.

So version 0.1.0 is published by hand. Everything after that goes through
`publish.yml` with no token at all.

---

## 1. Log in

```bash
npm login          # interactive; your account needs 2FA
npm whoami         # should print your username
```

Your account must be a member of the `didx509` org with write access.

## 2. Publish `core` first

`@didx509/credo` depends on `@didx509/core`, so core must exist first.

```bash
cd /Users/ajayjadhav/workspace/ayanworks/did-x509-ts/typescript
npm publish --access public
```

npm will ask for your one-time password. Expected output ends with:

```
+ @didx509/core@0.1.0
```

Verify:

```bash
npm view @didx509/core version    # -> 0.1.0
```

## 3. Publish `credo`

The committed `typescript-credo/package.json` has
`"@didx509/core": "file:../typescript"`, which npm refuses to publish.
`publish.yml` rewrites it to `^0.1.0` on a throwaway copy. Do the same by
hand — **do not commit the rewrite**:

```bash
cd /Users/ajayjadhav/workspace/ayanworks/did-x509-ts/typescript-credo

# rewrite in place, publish, then restore
cp package.json /tmp/credo-package.json.bak
node -e "
const fs=require('fs'); const p=JSON.parse(fs.readFileSync('package.json','utf8'));
p.dependencies['@didx509/core']='^0.1.0';
fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n');
"

npm publish --access public

# restore the development link — this must stay `file:../typescript`
cp /tmp/credo-package.json.bak package.json
rm /tmp/credo-package.json.bak
git status --short          # must be clean
```

Verify:

```bash
npm view @didx509/credo version                    # -> 0.1.0
npm view @didx509/credo dependencies               # -> { '@didx509/core': '^0.1.0' }
```

## 4. Confirm the published packages actually work

```bash
cd /tmp && rm -rf smoke && mkdir smoke && cd smoke
npm init -y
npm install @didx509/core @didx509/credo
node --input-type=module -e "
import { X509DidResolver } from '@didx509/credo';
import * as core from '@didx509/core';
console.log('credo:', typeof X509DidResolver, '| core exports:', Object.keys(core).length);
"
npx didx509 encode 'CN=test'      # -> CN%3Dtest
```

## 5. Turn on OIDC for every future release

For **each** package (`@didx509/core`, `@didx509/credo`, and
`@didx509/native` when it is published):

1. npmjs.com → Packages → the package → **Settings** → **Trusted publisher**
2. Provider: **GitHub Actions**
3. Organization or user: `ayanworks`
4. Repository: `did-x509`
5. Workflow filename: `publish.yml` (`prebuild.yml` for `@didx509/native`)
6. Allowed actions: allow **`npm publish`**

Afterwards, publishing is a tag push:

```bash
git tag -s core-v0.1.1 -m "core-v0.1.1"
git push origin core-v0.1.1
```

**Timing matters:** a new trusted-publisher configuration expires if it
does not complete a successful publish within **2 days**. Add the
configuration when you are close to the next release, or it will need to
be deleted and recreated.

## 6. Optional hardening, once OIDC works

npmjs.com → the package → Settings → **Publishing access** → *Require 2FA
and disallow tokens*. This blocks token-based publishing entirely while
leaving trusted publishers working.

---

## Notes

- **Don't re-push the `core-v0.1.0` tag** until the trusted publisher is
  configured. It currently points at a commit whose workflow would fail
  with `ENEEDAUTH`, since no trusted publisher exists yet.
- Publishing is irreversible for a given version. A version can be
  unpublished within 72 hours, but the name and version are burned.
- The `didx509` CLI ships with `@didx509/core` as the `didx509` binary.
