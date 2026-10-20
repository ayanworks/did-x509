// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * The did-resolver plugin must behave exactly like the @didx509/core
 * plugin — same success shape, same error metadata, same option handling.
 */

import { Resolver } from 'did-resolver';
import { describe, expect, test } from 'vitest';
import { getDidX509Resolver } from '../src/index.js';
import { timeValidVector } from './helpers.js';

const x509chain = timeValidVector.input.chain.join(',');
const plugin = getDidX509Resolver();

function callPlugin(did: string, options: Record<string, unknown>) {
  return plugin.x509(
    did,
    { did, id: did, method: 'x509', identifier: 'test' },
    undefined,
    options
  );
}

describe('did-resolver plugin', () => {
  test('resolves through the did-resolver Resolver', async () => {
    const resolver = new Resolver(getDidX509Resolver());
    const result = await resolver.resolve(timeValidVector.input.did, {
      x509chain,
    });
    expect(result.didDocument).toEqual(timeValidVector.output.document);
    expect(result.didResolutionMetadata.contentType).toBe(
      'application/did+ld+json'
    );
    expect(result.didDocumentMetadata).toEqual({});
  });

  test('a missing x509chain option is reported clearly', async () => {
    const result = await callPlugin(timeValidVector.input.did, {});
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe(
      'invalidDidResolutionOptions'
    );
    expect(result.didResolutionMetadata.message).toBe(
      'x509chain resolution option is required'
    );
  });

  test('an unusable chain is reported as notFound', async () => {
    const result = await callPlugin(timeValidVector.input.did, {
      x509chain: 'not-a-certificate',
    });
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(String(result.didResolutionMetadata.message).length).toBeGreaterThan(0);
  });

  test('a DID that does not match the chain is reported as notFound', async () => {
    const mismatchedDid = `did:x509:0:sha256:${'A'.repeat(43)}::subject:CN:Leaf`;
    const result = await callPlugin(mismatchedDid, { x509chain });
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(String(result.didResolutionMetadata.message).length).toBeGreaterThan(0);
  });
});
