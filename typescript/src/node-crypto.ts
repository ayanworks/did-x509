// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Node's synchronous `node:crypto`, when the runtime has it.
 *
 * `decodeCertificate` is synchronous, so the fingerprint path needs a
 * synchronous hash — the async Web Crypto API cannot be used there.
 *
 * `createRequire` from `node:module` provides that synchronous loader in both
 * module systems, but it needs an absolute path/URL to anchor resolution:
 * `__filename` in CommonJS builds and `import.meta.url` in ESM builds. Both
 * are read behind feature checks because each identifier is absent in the
 * other format, and a bare `require(...)` is avoided entirely — esbuild would
 * rewrite it into a `__require` shim that throws at call time in ESM output.
 *
 * `node:module` is a Node built-in, so browser/Deno bundlers keep it external
 * and only Node-compat runtimes resolve it. Everywhere else, or in the
 * unlikely case the anchor is unavailable, the guarded call returns null and
 * callers fall back to `computeFingerprintAsync` (Web Crypto).
 */

import { createRequire } from 'node:module';

type NodeCrypto = typeof import('node:crypto');

let cached: NodeCrypto | null | undefined;

/** Load `node:crypto` synchronously, or return null when unavailable. */
export function getNodeCrypto(): NodeCrypto | null {
  if (cached !== undefined) return cached ?? null;

  cached = null;
  try {
    cached = createRequire(currentModuleLocation())('node:crypto');
  } catch {
    // No Node built-ins (browser, Deno without node compat, …): the caller
    // falls back to the async Web Crypto fingerprint.
    cached = null;
  }

  return cached ?? null;
}

/**
 * The current module's absolute location, formatted for `createRequire`.
 *
 * A `createRequire` anchor cannot be shared as a module constant here because
 * only one of the two expressions exists per build format.
 */
function currentModuleLocation(): string | URL {
  // CommonJS build: __filename is defined by the loader.
  if (typeof __filename === 'string') return __filename;
  // ESM build: import.meta.url is a file URL string.
  return import.meta.url;
}
