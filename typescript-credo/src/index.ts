// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * @didx509/credo - did:x509 method registry for credo-ts.
 *
 * Register the resolver in your agent's DidsModule:
 *
 * ```ts
 * import { DidsModule } from '@credo-ts/core';
 * import { X509DidResolver } from '@didx509/credo';
 *
 * const agent = new Agent({
 *   modules: {
 *     dids: new DidsModule({
 *       resolvers: [new X509DidResolver(), new KeyDidResolver()],
 *     }),
 *   },
 * });
 * ```
 */

export { X509DidResolver } from './x509-did-resolver.js';
export type {
  Didx509Implementation,
  X509DidResolverOptions,
} from './x509-did-resolver.js';
