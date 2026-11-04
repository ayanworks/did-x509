// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  loadPemCertificateChain,
  verifyCertificateChain,
  computeFingerprintAsync,
} from '../src/x509.js';
import { resolveDidFromPem } from '../src/didx509.js';

const TEST_DATA_DIR = resolve(import.meta.dirname, '../shared-test-data');

const readChain = (name: string): string =>
  readFileSync(resolve(TEST_DATA_DIR, name), 'utf-8');

const pathlen0ChainPem = readChain('pathlen0-chain.pem');
const boundaryChainPem = readChain('pathlen-boundary-chain.pem');
const violationChainPem = readChain('pathlen-violation-chain.pem');

/**
 * RFC 5280 §4.2.1.9: `pathLenConstraint` is the maximum number of
 * non-self-issued intermediate CAs that may follow the certificate in the
 * path. The end-entity (leaf) certificate does not count, so an issuing CA
 * directly above the leaf may carry `pathlen:0`.
 */
describe('basic constraints path length (RFC 5280 §4.2.1.9)', () => {
  it('accepts an issuing CA with pathlen:0 (root -> CA -> leaf)', async () => {
    const chain = loadPemCertificateChain(pathlen0ChainPem);
    expect(chain).toHaveLength(3);

    await expect(verifyCertificateChain(chain, true)).resolves.toBeUndefined();
  });

  it('resolves a DID whose issuing CA has pathlen:0', async () => {
    const chain = loadPemCertificateChain(pathlen0ChainPem);
    const rootFingerprint = await computeFingerprintAsync(
      chain[chain.length - 1]!,
      'sha256'
    );
    const did = `did:x509:0:sha256:${rootFingerprint}::subject:CN:pathlen0.example`;

    const doc = await resolveDidFromPem(did, pathlen0ChainPem, {
      skipValidityPeriodCheck: true,
    });

    expect(doc.id).toBe(did);
  });

  it('accepts pathlen equal to the number of intermediates below', async () => {
    // root -> int1 (pathlen:1) -> int2 (pathlen:0) -> leaf
    const chain = loadPemCertificateChain(boundaryChainPem);
    expect(chain).toHaveLength(4);

    await expect(verifyCertificateChain(chain, true)).resolves.toBeUndefined();
  });

  it('still rejects a real path length violation', async () => {
    // root (pathlen:0) -> intermediate -> leaf: the root may not issue a CA.
    const chain = loadPemCertificateChain(violationChainPem);

    await expect(verifyCertificateChain(chain, true)).rejects.toThrow(
      'Certificate 2 basic constraints: path length constraint violated'
    );
  });
});
