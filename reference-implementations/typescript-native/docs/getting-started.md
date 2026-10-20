# Getting started

## Install

```bash
npm install @didx509/native
```

That's it. On supported platforms you get a prebuilt binary — no compiler
needed. If there is no prebuilt binary for your machine, the install script
builds one on the spot (see [troubleshooting](troubleshooting.md) if that
fails).

Check that everything worked:

```ts
import { didx509Version } from '@didx509/native';

console.log('built against didx509cpp', didx509Version());
```

## Your first resolution

A `did:x509` identifier embeds a rule (for example "the certificate subject
must contain CN=Leaf") plus a hash of the issuing CA certificate. To resolve
it you supply the certificate chain, and the resolver checks that the chain
satisfies the rule.

```ts
import { readFileSync } from 'node:fs';
import { resolveDidFromPem } from '@didx509/native';

const did = 'did:x509:0:sha256:AxW_2uMZc-Bn8tjYEWsJOZj8OfgQFdoeQuX7G-evxkg::subject:CN:Leaf';
const pemChain = readFileSync('chain.pem', 'utf8'); // leaf first, then intermediates

try {
  const document = await resolveDidFromPem(did, pemChain);
  console.log(document.id);
  console.log(document.verificationMethod[0].publicKeyJwk);
} catch (error) {
  // error is a Didx509Error with the C++ resolver's message
  console.error(error.message);
}
```

Rules of thumb:

- The PEM string must contain the full chain, **leaf certificate first**.
- Failures throw `Didx509Error`. The message comes verbatim from the C++
  resolver — read it, log it, but never compare it against a fixed string.
- Prefer the async `resolveDidFromPem` in servers; it runs validation off
  the main thread. `resolveDidFromPemSync` exists for scripts and tests.

### Synchronous version

```ts
import { resolveDidFromPemSync } from '@didx509/native';

const document = resolveDidFromPemSync(did, pemChain);
```

### Just the public key

```ts
import { resolveJwk } from '@didx509/native';

const jwk = await resolveJwk(did, pemChain);
```

## Using it with did-resolver

The plugin follows the standard did-resolver interface. The certificate
chain travels in the `x509chain` option as comma-separated, base64url-encoded
DER certificates (leaf first):

```ts
import { Resolver } from 'did-resolver';
import { getDidX509Resolver, x509ChainToPem } from '@didx509/native';

const resolver = new Resolver(getDidX509Resolver());

const result = await resolver.resolve(did, { x509chain });

if (result.didDocument) {
  console.log(result.didDocument);
} else {
  console.error(result.didResolutionMetadata.error, result.didResolutionMetadata.message);
}
```

If you already have a PEM chain and a base64url chain string,
`x509ChainToPem()` converts between the two formats.

## Options

Every resolve function accepts an options object:

```ts
// Check certificate validity periods (the default):
await resolveDidFromPem(did, pemChain);

// Skip them — for example when auditing a historical DID whose
// certificates have since expired:
await resolveDidFromPem(did, pemChain, { ignoreTime: true });
```

`skipValidityPeriodCheck` is accepted as an alias for `ignoreTime`, so call
sites written against `@didx509/core` keep working unchanged.

## Running in other runtimes

### Electron

Works out of the box. The binary is built with N-API, so it does not need
rebuilding when Electron updates its Node version. If your packaging step
skips install scripts, ship the `prebuilds/` folder — it is part of the
package.

### Bun

```bash
bun install @didx509/native
```

```ts
import { resolveDidFromPem } from '@didx509/native';
```

### Deno

Deno can load the package through its npm compatibility layer, but native
code needs permission to talk to the OS (FFI) and the files must exist on
disk (no remote-only caching):

```bash
deno run --allow-ffi --node-modules-dir=auto script.ts
```

```ts
import { resolveDidFromPem } from 'npm:@didx509/native';
```

Two caveats, so you are not surprised:

- `deno compile` has a known issue with native addons
  ([denoland/deno#36596](https://github.com/denoland/deno/issues/36596)) —
  run scripts with the Deno CLI instead of a single-file executable.
- If resolution fails with a "could not load the native resolver binary"
  message, check that `node_modules/` exists next to your script — the
  binary lives inside it.

### Browsers and React Native

Not supported — there is no way to run a native Node addon there. Use
`@didx509/core` in those environments; the API is interchangeable (see
[migration.md](migration.md)).

## Next steps

- [API reference](api-reference.md) — every function, typed
- [Migration guide](migration.md) — switching from `@didx509/core`
- [Troubleshooting](troubleshooting.md) — build and load errors
