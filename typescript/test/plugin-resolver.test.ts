// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { getDidX509Resolver } from '../src/did-resolver-plugin.js';
import { loadPemCertificateChain } from '../src/x509.js';
import { b64url } from '../src/encoding.js';
import { tamperSerialNumber } from './helpers/certificates.js';

const TEST_DATA_DIR = resolve(import.meta.dirname, '../shared-test-data');
const msChainPem = readFileSync(
  resolve(TEST_DATA_DIR, 'ms-code-signing.pem'),
  'utf-8'
);
const fulcioEmailChainPem = readFileSync(
  resolve(TEST_DATA_DIR, 'fulcio-email.pem'),
  'utf-8'
);

// Pins the intermediate CA of ms-code-signing.pem with a subject predicate
// that still matches after serial-number tampering (subject bytes untouched).
const MS_INTERMEDIATE_PINNED_DID =
  'did:x509:0:sha256:VtqHIq_ZQGb_4eRZVHOkhUiSuEOggn1T-32PSu7R4Ys::subject:CN:Microsoft%20Corporation';

/** Encode a PEM chain as the plugin's `x509chain` resolution option. */
function pemToX509ChainOption(pem: string): string {
  return loadPemCertificateChain(pem)
    .map(c => b64url(new Uint8Array(c.rawData)))
    .join(',');
}

/** Invoke the plugin's resolver directly. */
function resolverResult(
  did: string,
  x509chain: string,
  options?: Record<string, unknown>
) {
  const resolver = getDidX509Resolver();
  const parsed = {
    did: 'x509',
    id: did,
    method: 'x509',
    identifier: did.slice('did:x509:'.length),
  };
  return resolver.x509(did, parsed, {}, { x509chain, ...options });
}

describe('getDidX509Resolver', () => {
  it('requires the x509chain option', async () => {
    const result = await resolverResult(
      MS_INTERMEDIATE_PINNED_DID,
      undefined as unknown as string
    );
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe(
      'invalidDidResolutionOptions'
    );
  });

  it('resolves a valid chain end-to-end (fulcio email)', async () => {
    const result = await resolverResult(
      'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::san:email:igarcia%40suse.com',
      pemToX509ChainOption(fulcioEmailChainPem),
      { skipValidityPeriodCheck: true }
    );
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(
      'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::san:email:igarcia%40suse.com'
    );
    expect(result.didDocument?.verificationMethod).toHaveLength(1);
  });

  // Regression: the plugin previously skipped all cryptographic verification.
  // A chain whose predicates matched resolved even with a broken signature.
  it('rejects a chain whose leaf signature fails despite matching predicates', async () => {
    const chain = loadPemCertificateChain(msChainPem);
    const tamperedLeaf = tamperSerialNumber(chain[0]!);
    const tamperedChainOption = [tamperedLeaf, chain[1]!, chain[2]!]
      .map(c => b64url(new Uint8Array(c.rawData)))
      .join(',');

    const result = await resolverResult(
      MS_INTERMEDIATE_PINNED_DID,
      tamperedChainOption,
      { skipValidityPeriodCheck: true }
    );

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(String(result.didResolutionMetadata.message)).toContain(
      'signature verification failed'
    );
  });

  it('rejects a reversed chain', async () => {
    const reversed = pemToX509ChainOption(msChainPem).split(',').reverse().join(',');
    const result = await resolverResult(MS_INTERMEDIATE_PINNED_DID, reversed, {
      skipValidityPeriodCheck: true,
    });
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
  });

  // Regression: the plugin previously performed no validity-period check, so
  // an expired chain resolved unconditionally. Now it fails by default and
  // only succeeds when the caller explicitly opts out.
  it('rejects an expired chain unless skipValidityPeriodCheck is set', async () => {
    const chainOption = pemToX509ChainOption(msChainPem);

    const expired = await resolverResult(MS_INTERMEDIATE_PINNED_DID, chainOption);
    expect(expired.didDocument).toBeNull();
    expect(expired.didResolutionMetadata.error).toBe('notFound');
    expect(String(expired.didResolutionMetadata.message)).toContain(
      'not valid'
    );

    const skipped = await resolverResult(
      MS_INTERMEDIATE_PINNED_DID,
      chainOption,
      { skipValidityPeriodCheck: true }
    );
    expect(skipped.didResolutionMetadata.error).toBeUndefined();
    expect(skipped.didDocument?.verificationMethod).toHaveLength(1);
  });
});
