// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * did-resolver compatible plugin for did:x509.
 *
 * Usage:
 * ```ts
 * import { Resolver } from 'did-resolver';
 * import { getDidX509Resolver } from '@didx509/native';
 *
 * const resolver = new Resolver(getDidX509Resolver());
 * const result = await resolver.resolve(
 *   'did:x509:0:sha256:...',
 *   { x509chain: 'base64url_der1,base64url_der2,...' }
 * );
 * ```
 *
 * The behaviour matches the @didx509/core plugin exactly — only the
 * validation engine differs (native C++ instead of pure TypeScript).
 */

import { resolveDidFromPem } from './didx509.js';
import { x509ChainToPem } from './pem.js';
import type { DidDocument, DidResolutionResult } from './types.js';

/**
 * Minimal type for did-resolver's DIDResolutionOptions.
 * We avoid a hard dependency on did-resolver types.
 */
interface DidResolutionOptions {
  [key: string]: unknown;
}

/**
 * DID resolver function type (simplified).
 */
type DIDResolver = (
  did: string,
  parsed: { did: string; id: string; method: string; identifier: string },
  resolver: unknown,
  options: DidResolutionOptions
) => Promise<DidResolutionResult>;

/**
 * Returns a resolver object compatible with did-resolver's Resolver class.
 */
export function getDidX509Resolver(): { x509: DIDResolver } {
  return {
    x509: async (
      did: string,
      _parsed: unknown,
      _resolver: unknown,
      options: DidResolutionOptions
    ): Promise<DidResolutionResult> => {
      const x509chain = options['x509chain'];

      if (!x509chain || typeof x509chain !== 'string') {
        return {
          didResolutionMetadata: {
            error: 'invalidDidResolutionOptions',
            message: 'x509chain resolution option is required',
          },
          didDocument: null,
          didDocumentMetadata: {},
        };
      }

      try {
        const didDocument: DidDocument = await resolveDidFromPem(
          did,
          x509ChainToPem(x509chain)
        );
        return {
          didResolutionMetadata: { contentType: 'application/did+ld+json' },
          didDocument,
          didDocumentMetadata: {},
        };
      } catch (error) {
        const message =
          error instanceof Error ? error.message : String(error);
        return {
          didResolutionMetadata: {
            error: 'notFound',
            message,
          },
          didDocument: null,
          didDocumentMetadata: {},
        };
      }
    },
  };
}
