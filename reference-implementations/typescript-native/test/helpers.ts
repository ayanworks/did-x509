// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/** Shared fixtures for the test suite. */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveDidFromPemSync } from '../src/index.js';
import { x509ChainToPem } from '../src/pem.js';

export interface Vector {
  id: string;
  input: { did: string; chain: string[] };
  output: { error?: string; document?: Record<string, unknown> };
}

/** Package root (the test directory sits directly below it). */
export const packageRoot = fileURLToPath(new URL('..', import.meta.url));

/**
 * The did:x509 specification test vectors. They ship inside the pinned
 * didx509cpp submodule so this suite can never drift from the C++ code
 * it validates.
 */
export const vectors: Vector[] = JSON.parse(
  readFileSync(
    path.join(
      packageRoot,
      'third_party/didx509cpp/test/test-data/test-vectors.json'
    ),
    'utf8'
  )
);

/** Upstream asserts exactly 220 vectors — a bump there must be intentional here too. */
export const vectorCount = 220;

/** A vector whose output is a DID document (used as a happy-path fixture). */
export const goodVector: Vector =
  vectors.find((vector) => vector.output.document !== undefined) ?? vectors[0]!;

/**
 * The first document vector whose certificate chain is currently within its
 * validity period. The did-resolver plugin has no time-override option
 * (same as @didx509/core), so plugin tests must use a live chain.
 */
export const timeValidVector: Vector = findTimeValidVector();

function findTimeValidVector(): Vector {
  for (const vector of vectors) {
    if (vector.output.document === undefined) {
      continue;
    }
    try {
      resolveDidFromPemSync(vector.input.did, chainToPem(vector.input.chain));
      return vector;
    } catch {
      // expired chain — keep looking
    }
  }
  throw new Error('no time-valid document vector found in test-vectors.json');
}

/** Looks up a vector by id, failing fast when upstream renamed it. */
export function vectorById(id: string): Vector {
  const vector = vectors.find((candidate) => candidate.id === id);
  if (!vector) {
    throw new Error(`test vector "${id}" not found in test-vectors.json`);
  }
  return vector;
}

/** Converts a vector's base64url DER chain into a PEM chain string. */
export function chainToPem(chain: string[]): string {
  return x509ChainToPem(chain.join(','));
}
