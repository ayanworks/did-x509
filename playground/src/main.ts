// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Deno entry point — the only host-specific file in the playground.
 *
 * A Cloudflare Worker would replace this with
 * `export default { fetch: handleRequest }`; `handleRequest` itself is
 * portable and needs no changes.
 */

import { handleRequest } from './server.ts';

if (import.meta.main) {
  Deno.serve(handleRequest);
}
