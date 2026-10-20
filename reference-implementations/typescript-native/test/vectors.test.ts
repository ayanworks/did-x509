// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Runs the didx509cpp specification vector suite (220 vectors).
 *
 * This mirrors upstream's own harness (unit_tests.cpp, "did:x509
 * specification vectors"):
 *
 *  - The vectors do not check certificate validity periods, so every run
 *    uses `ignoreTime: true`.
 *  - Error vectors only assert that resolution *fails*. The spec suite's
 *    `output.error` text is descriptive and is not part of the C++
 *    resolver's contract.
 *  - Document vectors must match exactly (deep equal), and `resolveJwk`
 *    must return the document's `verificationMethod[0].publicKeyJwk`.
 */

import { describe, expect, test } from 'vitest';
import { Didx509Error, resolveDidFromPem, resolveDidFromPemSync, resolveJwkSync } from '../src/index.js';
import type { DidDocument, VerificationMethod } from '../src/types.js';
import { chainToPem, goodVector, vectorById, vectorCount, vectors } from './helpers.js';

const ignoreTime = { ignoreTime: true } as const;

describe('didx509cpp specification vectors', () => {
  test('the suite ships 220 vectors', () => {
    expect(vectors).toHaveLength(vectorCount);
  });

  for (const vector of vectors) {
    test(vector.id, async () => {
      const pem = chainToPem(vector.input.chain);
      const did = vector.input.did;

      if (vector.output.error !== undefined) {
        // Must fail — message text is not asserted (matching upstream).
        expect(() => resolveDidFromPemSync(did, pem, ignoreTime)).toThrow(
          Didx509Error
        );
        await expect(resolveDidFromPem(did, pem, ignoreTime)).rejects.toBeInstanceOf(
          Didx509Error
        );
        return;
      }

      const expected = vector.output.document!;
      expect(resolveDidFromPemSync(did, pem, ignoreTime)).toEqual(expected);
      expect(await resolveDidFromPem(did, pem, ignoreTime)).toEqual(expected);

      // resolveJwk returns exactly the document's leaf JWK.
      const verificationMethod = (expected as unknown as {
        verificationMethod: VerificationMethod[];
      }).verificationMethod[0]!;
      expect(resolveJwkSync(did, pem, ignoreTime)).toEqual(
        verificationMethod.publicKeyJwk
      );
    });
  }

  test('duplicate certificate subject attribute is rejected', () => {
    // Repeated attribute types are rejected, not matched against any value.
    const vector = vectorById('duplicate-certificate-subject-attribute');
    const pem = chainToPem(vector.input.chain);
    const otherDid =
      vector.input.did.slice(0, vector.input.did.lastIndexOf('::')) +
      '::subject:CN:Other';

    for (const did of [vector.input.did, otherDid]) {
      expect(() => resolveDidFromPemSync(did, pem, ignoreTime)).toThrow(
        /duplicate attribute: CN/
      );
    }
  });

  test('validity periods are enforced unless ignored', async () => {
    const vector = vectorById('certificate-validity-periods-are-not-checked');
    const pem = chainToPem(vector.input.chain);
    const did = vector.input.did;

    // Explicit opt-out works (both spellings of the option) ...
    expect(resolveDidFromPemSync(did, pem, { ignoreTime: true })).toBeDefined();
    expect(
      resolveDidFromPemSync(did, pem, { skipValidityPeriodCheck: true })
    ).toBeDefined();

    // ... but the default and the async form must fail on an expired chain.
    expect(() => resolveDidFromPemSync(did, pem)).toThrow(
      /certificate chain verification failed/
    );
    await expect(resolveDidFromPem(did, pem)).rejects.toThrow(
      /certificate chain verification failed/
    );
  });

  test('fragments are ignored for document ids and predicates', () => {
    const pem = chainToPem(goodVector.input.chain);
    const document = resolveDidFromPemSync(
      `${goodVector.input.did}#key-1`,
      pem,
      ignoreTime
    ) as DidDocument;
    expect(document.id).toBe(goodVector.input.did);
  });
});
