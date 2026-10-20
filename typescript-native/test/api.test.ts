// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/** Behaviour of the public API surface (errors, options, argument checks). */

import { describe, expect, test } from 'vitest';
import { binding } from '../src/binding.js';
import { Didx509Error, resolveDidFromPem, resolveDidFromPemSync, resolveJwkSync } from '../src/index.js';
import { chainToPem, goodVector } from './helpers.js';

const ignoreTime = { ignoreTime: true } as const;
const pem = chainToPem(goodVector.input.chain);

/** A DID that does not match the fixture chain (CA fingerprint mismatch). */
const mismatchedDid = `did:x509:0:sha256:${'A'.repeat(43)}::subject:CN:Leaf`;

describe('public API', () => {
  test('sync and async produce the same document', async () => {
    const syncDocument = resolveDidFromPemSync(goodVector.input.did, pem, ignoreTime);
    const asyncDocument = await resolveDidFromPem(goodVector.input.did, pem, ignoreTime);
    expect(asyncDocument).toEqual(syncDocument);
  });

  test('error messages come through verbatim from the native layer', () => {
    let rawMessage = '';
    try {
      binding.resolveSync(pem, mismatchedDid, true);
      expect.fail('the native layer should have thrown');
    } catch (error) {
      rawMessage = (error as Error).message;
    }
    expect(rawMessage).not.toBe('');

    let publicError: unknown;
    try {
      resolveDidFromPemSync(mismatchedDid, pem, ignoreTime);
      expect.fail('resolution should have failed');
    } catch (error) {
      publicError = error;
    }
    expect(publicError).toBeInstanceOf(Didx509Error);
    expect((publicError as Didx509Error).name).toBe('Didx509Error');
    expect((publicError as Didx509Error).message).toBe(rawMessage);
  });

  test('non-string arguments throw a TypeError', async () => {
    expect(() =>
      resolveDidFromPemSync(123 as unknown as string, pem)
    ).toThrow(TypeError);
    expect(() =>
      resolveDidFromPemSync(goodVector.input.did, undefined as unknown as string)
    ).toThrow(TypeError);
    await expect(
      resolveDidFromPem(undefined as unknown as string, pem)
    ).rejects.toThrow(TypeError);
  });

  test('an empty chain is rejected with a clear message', () => {
    expect(() =>
      resolveDidFromPemSync(goodVector.input.did, '')
    ).toThrow('no certificate chain');
  });

  test('malformed PEM fails with a Didx509Error', () => {
    let error: unknown;
    try {
      resolveDidFromPemSync(goodVector.input.did, 'this is not a PEM chain');
      expect.fail('resolution should have failed');
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(Didx509Error);
    expect((error as Error).message.length).toBeGreaterThan(0);
  });

  test('non-did:x509 DIDs are rejected', () => {
    expect(() =>
      resolveDidFromPemSync('did:web:example.com', pem, ignoreTime)
    ).toThrow(Didx509Error);
  });

  test('DID URL paths and queries are rejected', () => {
    expect(() =>
      resolveDidFromPemSync(`${goodVector.input.did}/path`, pem, ignoreTime)
    ).toThrow(Didx509Error);
    expect(() =>
      resolveDidFromPemSync(`${goodVector.input.did}?q=1`, pem, ignoreTime)
    ).toThrow(Didx509Error);
  });

  test('resolveJwk returns the document public key', () => {
    const document = resolveDidFromPemSync(goodVector.input.did, pem, ignoreTime);
    expect(resolveJwkSync(goodVector.input.did, pem, ignoreTime)).toEqual(
      document.verificationMethod[0]!.publicKeyJwk
    );
  });
});
