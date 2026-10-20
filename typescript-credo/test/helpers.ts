// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/** Shared fixtures for the test suite. */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadX509Chain, resolveDid } from '@didx509/core';

export interface Vector {
  id: string;
  input: { did: string; chain: string[] };
  output: { error?: string; document?: Record<string, unknown> };
}

/** Package root (the test directory sits directly below it). */
export const packageRoot = fileURLToPath(new URL('..', import.meta.url));

/**
 * The did:x509 specification test vectors. They ship inside the pinned
 * didx509cpp submodule (used by the sibling @didx509/native suite), so this
 * suite can never drift from the C++ reference implementation.
 */
export const vectors: Vector[] = JSON.parse(
  readFileSync(
    path.join(
      packageRoot,
      '..',
      'typescript-native',
      'third_party',
      'didx509cpp',
      'test',
      'test-data',
      'test-vectors.json'
    ),
    'utf8'
  )
);

/**
 * Find a vector whose chain is currently time-valid. The spec vector set
 * includes expired chains (they must fail resolution), so a fixture is picked
 * at run time — the same approach the @didx509/native plugin suite uses.
 */
async function findTimeValidVector(): Promise<Vector> {
  for (const vector of vectors) {
    if (vector.output.document === undefined) continue;
    try {
      await resolveDid(vector.input.did, loadX509Chain(vector.input.chain.join(',')));
      return vector;
    } catch {
      // Expired chain or upstream mismatch — try the next vector.
    }
  }
  throw new Error('No time-valid success vector found in test-vectors.json');
}

export const timeValidVector = await findTimeValidVector();
export const timeValidChain = timeValidVector.input.chain.join(',');
