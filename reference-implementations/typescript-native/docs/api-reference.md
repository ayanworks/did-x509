# API reference

All error-throwing functions reject/throw `Didx509Error`. Messages come
verbatim from the C++ resolver and may change when the bundled upstream
commit changes — read them, never match against them.

## `resolveDidFromPem(did, pemChain, options?)`

Resolves a `did:x509` DID from a PEM certificate chain.

```ts
import { resolveDidFromPem } from '@didx509/native';

const document = await resolveDidFromPem(
  'did:x509:0:sha256:...::subject:CN:Leaf',
  pemChainString,
  { ignoreTime: true }
);
```

| Parameter | Type | Description |
|---|---|---|
| `did` | `string` | The `did:x509` identifier. Fragments (`#key-1`) are allowed and ignored for matching. Paths (`/...`) and queries (`?...`) are rejected. |
| `pemChain` | `string` | One or more PEM certificates concatenated together, **leaf first**. |
| `options` | `ResolveOptions?` | See [Options](#options). |

Returns `Promise<DidDocument>`. Throws `Didx509Error` when the chain does
not satisfy the DID (including a `TypeError` for wrong argument types).

## `resolveDidFromPemSync(did, pemChain, options?)`

Same as `resolveDidFromPem`, but blocking. Validation runs on the current
thread — fine in scripts, avoid in request handlers.

```ts
const document = resolveDidFromPemSync(did, pemChain);
```

## `resolveJwk(did, pemChain, options?)`

Resolves and returns only the leaf certificate's public key as a JWK.

```ts
const jwk = await resolveJwk(did, pemChain);
// { kty: 'EC', crv: 'P-256', x: '...', y: '...' }
```

## `resolveJwkSync(did, pemChain, options?)`

Blocking version of `resolveJwk`.

## `getDidX509Resolver()`

Returns a did-resolver plugin object. Requires the optional `did-resolver`
peer dependency.

```ts
import { Resolver } from 'did-resolver';
import { getDidX509Resolver } from '@didx509/native';

const resolver = new Resolver(getDidX509Resolver());
const result = await resolver.resolve(did, { x509chain });
```

The chain option (`x509chain`) is a comma-separated list of base64url-encoded
DER certificates, leaf first — the format the W3C DID resolution spec uses.

Result shapes:

| Situation | `didDocument` | `didResolutionMetadata` |
|---|---|---|
| Success | the DID document | `{ contentType: 'application/did+ld+json' }` |
| `x509chain` missing or not a string | `null` | `{ error: 'invalidDidResolutionOptions', message: 'x509chain resolution option is required' }` |
| Chain does not satisfy the DID (or is unusable) | `null` | `{ error: 'notFound', message: '<C++ error>' }` |

## `x509ChainToPem(x509chain)`

Converts the did-resolver chain format into PEM, so you can pass the same
value to both the plugin and the direct resolve functions:

```ts
import { x509ChainToPem } from '@didx509/native';

const pem = x509ChainToPem('MIIBzjCC...,MIIBhTCC...');
const document = await resolveDidFromPem(did, pem);
```

Throws `Didx509Error` if the chain contains an empty entry.

## `derCertificateToPem(der)`

Wraps raw DER bytes as a PEM certificate string.

```ts
const pem = derCertificateToPem(derBytes);
```

## `didx509Version()`

Returns the [didx509cpp](https://github.com/microsoft/didx509cpp) commit this
binary was built against:

```ts
import { didx509Version } from '@didx509/native';

console.log(didx509Version()); // "3024ef9dbc5f3aed0c335e6ec5733c53ccd56db1"
```

Useful in bug reports and audit logs.

## `Didx509Error`

```ts
import { Didx509Error, resolveDidFromPem } from '@didx509/native';

try {
  await resolveDidFromPem(did, pemChain);
} catch (error) {
  if (error instanceof Didx509Error) {
    console.error('resolution failed:', error.message);
  }
}
```

`error.name` is `'Didx509Error'`. The message is produced by the C++
resolver.

## Types

```ts
import type {
  DidDocument,
  DidResolutionResult,
  JsonWebKey,
  ResolveOptions,
  VerificationMethod,
} from '@didx509/native';
```

These types are shared with `@didx509/core`, so documents and results are
assignable across the two packages.

### `ResolveOptions`

| Option | Type | Default | Description |
|---|---|---|---|
| `ignoreTime` | `boolean` | `false` | Skip certificate validity-period checks. Use for historical or audit resolutions. |
| `skipValidityPeriodCheck` | `boolean` | `false` | Alias of `ignoreTime` (the `@didx509/core` spelling). If both are set, `ignoreTime` wins. |
