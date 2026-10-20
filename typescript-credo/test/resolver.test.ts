// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * The X509DidResolver must behave exactly like the @didx509/core and
 * @didx509/native did-resolver plugins — same success shape, same error
 * metadata — wrapped in a Credo DidDocument instance.
 */

import { DidDocument } from '@credo-ts/core';
import type { AgentContext, ParsedDid } from '@credo-ts/core';
import { describe, expect, test } from 'vitest';
import { X509DidResolver } from '../src/index.js';
import { timeValidChain, timeValidVector } from './helpers.js';

const did = timeValidVector.input.did;
const agentContext = {} as AgentContext;

function parsedDid(identifier = 'test'): ParsedDid {
  return { did, id: did, method: 'x509', identifier } as ParsedDid;
}

describe('X509DidResolver', () => {
  test('resolves a valid chain to a Credo DidDocument', async () => {
    const resolver = new X509DidResolver({ implementation: 'core' });
    const result = await resolver.resolve(agentContext, did, parsedDid(), {
      x509chain: timeValidChain,
    });

    expect(result.didResolutionMetadata.contentType).toBe(
      'application/did+ld+json'
    );
    expect(result.didDocument).toBeInstanceOf(DidDocument);
    expect(result.didDocument?.id).toBe(
      (timeValidVector.output.document as { id: string }).id
    );
    expect(result.didDocumentMetadata).toEqual({});
    expect(resolver.usedImplementation).toBe('core');
  });

  test('resolved document matches the specification vector', async () => {
    const resolver = new X509DidResolver({ implementation: 'core' });
    const result = await resolver.resolve(agentContext, did, parsedDid(), {
      x509chain: timeValidChain,
    });

    // Credo's DidDocument transformer enriches publicKeyJwk with `ext` and
    // `key_ops` defaults — strip them before comparing to the spec vector.
    const document = JSON.parse(JSON.stringify(result.didDocument)) as {
      verificationMethod?: { publicKeyJwk?: Record<string, unknown> }[];
    };
    for (const method of document.verificationMethod ?? []) {
      if (method.publicKeyJwk) {
        delete method.publicKeyJwk['ext'];
        delete method.publicKeyJwk['key_ops'];
      }
    }
    expect(document).toEqual(timeValidVector.output.document);
  });

  test('resolves with the default (auto) implementation', async () => {
    const resolver = new X509DidResolver();
    const result = await resolver.resolve(agentContext, did, parsedDid(), {
      x509chain: timeValidChain,
    });

    expect(result.didDocument).toBeInstanceOf(DidDocument);
  });

  test('reports invalidDidResolutionOptions when the chain is missing', async () => {
    const resolver = new X509DidResolver();
    const result = await resolver.resolve(agentContext, did, parsedDid(), {});

    // Same error metadata as the @didx509/core and @didx509/native plugins.
    expect(result.didResolutionMetadata.error).toBe(
      'invalidDidResolutionOptions'
    );
    expect(result.didResolutionMetadata.message).toBe(
      'x509chain resolution option is required'
    );
    expect(result.didDocument).toBeNull();
  });

  test('chain provider supplies the chain when the option is absent', async () => {
    const seen: string[] = [];
    const resolver = new X509DidResolver({
      implementation: 'core',
      getChain: (chainDid) => {
        seen.push(chainDid);
        return timeValidChain;
      },
    });

    const result = await resolver.resolve(agentContext, did, parsedDid(), {});
    expect(result.didDocument).toBeInstanceOf(DidDocument);
    expect(seen).toEqual([did]);
  });

  test('chain provider returning undefined falls back to the error', async () => {
    const resolver = new X509DidResolver({
      implementation: 'core',
      getChain: () => undefined,
    });

    const result = await resolver.resolve(agentContext, did, parsedDid(), {});
    expect(result.didResolutionMetadata.error).toBe(
      'invalidDidResolutionOptions'
    );
  });

  test('reports notFound for a garbage chain', async () => {
    const resolver = new X509DidResolver({ implementation: 'core' });
    const result = await resolver.resolve(agentContext, did, parsedDid(), {
      x509chain: 'bm90LWEtY2VydA',
    });

    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(result.didDocument).toBeNull();
  });

  test('reports notFound when the DID does not match the chain', async () => {
    const resolver = new X509DidResolver({ implementation: 'core' });
    const mismatchedDid = 'did:x509:0:sha256:deadbeef::subject:CN:Other';
    const result = await resolver.resolve(
      agentContext,
      mismatchedDid,
      parsedDid(),
      { x509chain: timeValidChain }
    );

    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(result.didDocument).toBeNull();
  });

  test("implementation: 'core' never touches the native addon", async () => {
    const resolver = new X509DidResolver({ implementation: 'core' });
    await resolver.resolve(agentContext, did, parsedDid(), {
      x509chain: timeValidChain,
    });
    expect(resolver.usedImplementation).toBe('core');
  });

  test("implementation: 'native' without the addon fails loudly", async () => {
    // @didx509/native is not a dependency of this package — explicit request
    // for the native engine must throw an actionable error.
    const resolver = new X509DidResolver({ implementation: 'native' });
    await expect(
      resolver.resolve(agentContext, did, parsedDid(), {
        x509chain: timeValidChain,
      })
    ).rejects.toThrow(/@didx509\/native could not be loaded/);
  });

  test('rejects an unknown implementation option', () => {
    expect(
      () => new X509DidResolver({ implementation: 'wasm' as 'auto' })
    ).toThrow(/Unknown implementation/);
  });
});
