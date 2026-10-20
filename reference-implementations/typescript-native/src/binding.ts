// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Loads the compiled Node-API addon.
 *
 * The addon lives either in `prebuilds/` (shipped with the npm package) or
 * in `build/Release/` (compiled from source during install).
 */

import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The raw Node-API addon. Every function mirrors the C++ shim. */
export interface NativeBinding {
  /** Resolves to a DID document JSON string, or rejects with the C++ error. */
  resolve(pemChain: string, did: string, ignoreTime: boolean): Promise<string>;
  /** Synchronous variant of `resolve`. */
  resolveSync(pemChain: string, did: string, ignoreTime: boolean): string;
  /** Resolves to the leaf public key as a JWK JSON string. */
  resolveJwk(pemChain: string, did: string, ignoreTime: boolean): Promise<string>;
  /** Synchronous variant of `resolveJwk`. */
  resolveJwkSync(pemChain: string, did: string, ignoreTime: boolean): string;
  /** The upstream didx509cpp commit this binary was built from. */
  version(): string;
}

function packageRoot(): string {
  // In `src/` during development and in `dist/` after a build — both sit
  // exactly one level below the package root, where prebuilds/ lives.
  const here =
    typeof __dirname !== 'undefined'
      ? __dirname
      : dirname(fileURLToPath(import.meta.url));
  return join(here, '..');
}

function loadBinding(): NativeBinding {
  const root = packageRoot();
  try {
    // `__dirname` is the format discriminator: in the CJS build it is
    // defined and Node's real `require` is used; in the ESM build it is
    // undefined and we go through createRequire (esbuild rewrites bare
    // `require` calls in ESM output, but that branch never runs there).
    const nodeRequire =
      typeof __dirname !== 'undefined'
        ? require
        : createRequire(import.meta.url);
    return nodeRequire('node-gyp-build')(root) as NativeBinding;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(
      '@didx509/native: could not load the native resolver binary.\n' +
        `  Searched in: ${root}\n` +
        '  Reinstall the package, or force a source build with:\n' +
        '    npm install --build-from-source\n' +
        '  See docs/troubleshooting.md for the toolchain requirements.\n' +
        `  Underlying error: ${detail}`
    );
  }
}

/** The loaded native addon. */
export const binding: NativeBinding = loadBinding();
