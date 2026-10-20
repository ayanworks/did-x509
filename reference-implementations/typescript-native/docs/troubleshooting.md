# Troubleshooting

## "could not load the native resolver binary"

The addon did not compile during install and no prebuilt binary matched your
machine.

1. Force a source build and read the output:

   ```bash
   npm install --build-from-source
   ```

2. Make sure the three tools below are installed, then retry.

### Toolchain requirements

| Tool | Version | Check with |
|---|---|---|
| CMake | ≥ 3.18 | `cmake --version` |
| C++20 compiler | recent | `clang++ --version` or `g++ --version` |
| OpenSSL | ≥ 3.3 | `openssl version` |

Per platform:

```bash
# macOS (Homebrew)
brew install cmake openssl@3

# Ubuntu / Debian — the system OpenSSL may be too old (3.0 < 3.3),
# so build OpenSSL from source or use a PPA such as
# https://launchpad.net/~ondrej/+archive/ubuntu/php
sudo apt install cmake build-essential

# Windows
# Install Visual Studio Build Tools + CMake, and OpenSSL (e.g. via
# vcpkg or the official installer), then set OPENSSL_ROOT_DIR.
```

### Pointing at a custom OpenSSL

If CMake picks up the wrong OpenSSL (or none), set `OPENSSL_ROOT_DIR`:

```bash
OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 npm install --build-from-source
# Windows (PowerShell)
$env:OPENSSL_ROOT_DIR = 'C:\OpenSSL-v33'; npm install --build-from-source
```

On macOS the script already finds Homebrew's `openssl@3` automatically.

## "didx509cpp.h not found" during a source build

The upstream sources are missing. In a git checkout run:

```bash
git submodule update --init
```

If you installed from npm this should not happen — report it as a packaging
bug.

## The install compiles even though prebuilds exist

Your platform has no prebuilt binary. Check the platform table in the
[README](../README.md). Builds are cached under `build/` — later installs
skip compilation while that folder is intact.

To skip compilation entirely (for example in CI with a warm cache):

```bash
npm install --ignore-scripts
```

The loader still finds `prebuilds/` at runtime.

## Electron rebuild warnings

You do not need `electron-rebuild`. The binary uses N-API (version 8), which
stays compatible across Node and Electron versions. If a tool insists on
rebuilding, `npm install --build-from-source` produces a working binary.

## Deno: "could not load the native resolver binary"

- Pass `--allow-ffi` and `--node-modules-dir=auto` (or ensure a local
  `node_modules/` exists). The loader looks for the binary on the real
  filesystem, not in Deno's module cache.
- `deno compile` single-file executables do not bundle native addons
  ([denoland/deno#36596](https://github.com/denoland/deno/issues/36596)).
  Use the Deno CLI instead.

## Wrong version reported by `didx509Version()`

The function reports the pinned `didx509cpp` submodule commit at build time.
Run `git submodule update --init` and rebuild to pick up a bump.

## Resolution fails with "certificate chain verification failed: certificate has expired"

That is correct behaviour — the chain is outside its validity period. If you
really do want to resolve anyway (historical documents, audits):

```ts
await resolveDidFromPem(did, pemChain, { ignoreTime: true });
```

## A chain that works with @didx509/core is rejected here

Possibly the C++ resolver doing its job more strictly. The generated list of
known differences lives in [migration.md](migration.md). Compare your chain
against the official test vectors, and if you believe the C++ resolver is
wrong, report it upstream at
[microsoft/didx509cpp](https://github.com/microsoft/didx509cpp/issues).

## Reporting a bug

Include:

```ts
import { didx509Version } from '@didx509/native';
console.log(process.platform, process.arch, didx509Version());
```

plus the exact error message and, if possible, the certificate chain
(remember it may contain sensitive data — strip private information first).
