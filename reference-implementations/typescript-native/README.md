# @didx509/native

Resolve `did:x509` identifiers from TypeScript — powered directly by
Microsoft's C++ resolver
([didx509cpp](https://github.com/microsoft/didx509cpp)).

This package is a thin wrapper. It does not re-implement any of the
certificate logic; every resolution runs in the same C++ code the reference
implementation uses. That means results stay in lockstep with upstream, bug
fixes and spec updates arrive as a submodule bump, and there is no second
implementation to keep in sync.

## Which package should I use?

| | `@didx509/core` | `@didx509/native` (this package) |
|---|---|---|
| Written in | pure TypeScript | TypeScript + C++ (Microsoft's resolver) |
| Runs in | browsers, React Native, Node, Deno, Bun | Node.js, Electron, Bun, Deno (with FFI) |
| Install | always works | prebuilt binary, or C++ toolchain to build |
| Certificate checks | good, with known gaps (see [docs/migration.md](docs/migration.md)) | full — identical to the C++ reference |

If you need browsers or React Native, use `@didx509/core`. If you want the
strictest possible validation on a server, use this package. Both expose the
same function names, so switching is a one-line import change.

## Quick start

```bash
npm install @didx509/native
```

```ts
import { resolveDidFromPem } from '@didx509/native';

const did = 'did:x509:0:sha256:AxW_2uMZc-Bn8tjYEWsJOZj8OfgQFdoeQuX7G-evxkg::subject:CN:Leaf';
const pemChain = `-----BEGIN CERTIFICATE-----
...your chain here, leaf first...
-----END CERTIFICATE-----`;

const document = await resolveDidFromPem(did, pemChain);
console.log(document.verificationMethod[0].publicKeyJwk);
```

### With did-resolver

```ts
import { Resolver } from 'did-resolver';
import { getDidX509Resolver } from '@didx509/native';

const resolver = new Resolver(getDidX509Resolver());
const result = await resolver.resolve(did, {
  x509chain: 'base64url_der_leaf,base64url_der_intermediate,...',
});
```

## Documentation

- [Getting started](docs/getting-started.md) — install, first resolve,
  running in Node, Deno, Bun, and Electron
- [API reference](docs/api-reference.md) — every function and option
- [Migration from @didx509/core](docs/migration.md) — what changes, plus the
  generated list of known behaviour differences
- [Troubleshooting](docs/troubleshooting.md) — build problems and their fixes
- [Architecture](docs/architecture.md) — how the wrapper works and how parity
  is tested
- [Changelog](CHANGELOG.md)

## Platform support

| Platform | Status |
|---|---|
| macOS (arm64, x64) | ✅ prebuilt binary |
| Linux glibc (x64, arm64) | ✅ prebuilt binary |
| Linux musl / Alpine (x64) | ✅ prebuilt binary |
| Windows (x64) | ✅ prebuilt binary |
| Electron | ✅ prebuilt (N-API, no rebuild per Electron version) |
| Bun | ✅ prebuilt |
| Deno | ✅ with `--allow-ffi` and a local `node_modules` (see [getting started](docs/getting-started.md)) |
| Browsers | ❌ use `@didx509/core` |
| React Native | ❌ use `@didx509/core` |

No prebuilt binary for your machine? The install script compiles from source
automatically — you need CMake ≥ 3.18, a C++20 compiler, and OpenSSL ≥ 3.3.

## Guarantees

- **220/220 official test vectors pass.** The suite ships inside this
  package (pulled from the pinned upstream submodule) and runs on every CI
  build. A change that breaks even one vector fails the build.
- **Error messages are upstream's, verbatim.** Do not match on message
  text — treat it as human-readable output only.
- **The upstream commit is inspectable:**

  ```ts
  import { didx509Version } from '@didx509/native';
  console.log(didx509Version()); // e.g. "3024ef9dbc5f3aed0c335e6ec5733c53ccd56db1"
  ```

## Contributing

See the repository's `docs/adr/ADR-002` for the design decision behind
wrapping instead of porting. Run `npm test` before pushing; run
`npm run parity:report` only when the known-differences list should change.

## License

MIT. The bundled [didx509cpp](https://github.com/microsoft/didx509cpp)
sources are MIT, © Microsoft Corporation. The did:x509 specification is by
Microsoft Corporation.
