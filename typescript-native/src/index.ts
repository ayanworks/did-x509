// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * @didx509/native - native binding for the did:x509 DID method.
 *
 * A TypeScript wrapper around Microsoft's didx509cpp resolver
 * (https://github.com/microsoft/didx509cpp), so behaviour stays in lockstep
 * with the C++ reference implementation instead of being re-implemented.
 */

// Resolution (backed by the native addon)
export {
  resolveDidFromPem,
  resolveDidFromPemSync,
  resolveJwk,
  resolveJwkSync,
  didx509Version,
} from './didx509.js';

// did-resolver plugin (optional peer dependency)
export { getDidX509Resolver } from './did-resolver-plugin.js';

// Errors
export { Didx509Error } from './errors.js';

// Chain conversion helpers
export { x509ChainToPem, derCertificateToPem } from './pem.js';

// Types
export type {
  DidDocument,
  DidResolutionResult,
  JsonWebKey,
  ResolveOptions,
  VerificationMethod,
} from './types.js';
