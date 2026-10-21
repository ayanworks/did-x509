// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Checks against the BUILT output rather than `src/`.
 *
 * Every other test runs against TypeScript source through vitest, so a
 * packaging mistake — a wrong `exports` path, a missing file, an `import.meta`
 * that only works in one format — stays invisible until someone installs the
 * published tarball. These tests import the real `dist` entry points in both
 * module systems and run the one code path that differs between them:
 * `node-crypto.ts`, which anchors `createRequire` on `__filename` in CJS and
 * `import.meta.url` in ESM. esbuild warns about that `import.meta` during the
 * CJS build (it is unreachable there), so the sync fingerprint is asserted in
 * both formats to keep the warning honest.
 *
 * Skipped when `dist/` is absent, so `npm test` still works on a fresh clone
 * before the first build.
 */

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const packageRoot = resolve(import.meta.dirname, '..');
const distEsm = resolve(packageRoot, 'dist/index.js');
const distCjs = resolve(packageRoot, 'dist/index.cjs');
const cliEsm = resolve(packageRoot, 'dist/cli.js');
const msChainPem = readFileSync(
  resolve(packageRoot, 'shared-test-data/ms-code-signing.pem'),
  'utf-8'
);

/** The leaf's fingerprint in `ms-code-signing.pem`, from the test data. */
const EXPECTED_LEAF_FINGERPRINT = 'UXBZJ2K9iZ6KYBN7WzuRXxqz-3CB2nKpuhEYghJPDww';

/**
 * The CA fingerprint used as the DID identifier. Note this is the *root*'s
 * fingerprint, not the leaf's — a did:x509 DID names the issuing CA.
 */
const EXPECTED_CA_FINGERPRINT = 'hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE';

const built = existsSync(distEsm) && existsSync(distCjs);
const require_ = createRequire(import.meta.url);

describe.skipIf(!built)('built output', () => {
  /** The ESM build, imported as the package entry point would be. */
  async function loadEsm(): Promise<{
    loadPemCertificateChain: (pem: string) => unknown[];
    computeFingerprint: (cert: unknown, alg: string) => string;
    computeFingerprintAsync: (cert: unknown, alg: string) => Promise<string>;
  }> {
    return (await import(pathToFileURL(distEsm).href)) as never;
  }

  /** The CJS build, required as `require('@didx509/core')` would be. */
  function loadCjs(): {
    loadPemCertificateChain: (pem: string) => unknown[];
    computeFingerprint: (cert: unknown, alg: string) => string;
    computeFingerprintAsync: (cert: unknown, alg: string) => Promise<string>;
  } {
    return require_(distCjs) as never;
  }

  describe('sync fingerprint (the format-dependent path)', () => {
    it('works in the ESM build', async () => {
      const mod = await loadEsm();
      const chain = mod.loadPemCertificateChain(msChainPem);
      expect(mod.computeFingerprint(chain[0], 'sha256')).toBe(
        EXPECTED_LEAF_FINGERPRINT
      );
    });

    it('works in the CJS build', () => {
      const mod = loadCjs();
      const chain = mod.loadPemCertificateChain(msChainPem);
      expect(mod.computeFingerprint(chain[0], 'sha256')).toBe(
        EXPECTED_LEAF_FINGERPRINT
      );
    });

    it('agrees with the async Web Crypto path in both builds', async () => {
      for (const mod of [await loadEsm(), loadCjs()]) {
        const chain = mod.loadPemCertificateChain(msChainPem);
        expect(await mod.computeFingerprintAsync(chain[0], 'sha256')).toBe(
          EXPECTED_LEAF_FINGERPRINT
        );
      }
    });

    it('produces the digest for a certificate, not an empty input', async () => {
      // Guards against the anchor silently resolving to nothing, which yields
      // the well-known hash of the empty string rather than throwing.
      const emptyHash = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';
      for (const mod of [await loadEsm(), loadCjs()]) {
        const chain = mod.loadPemCertificateChain(msChainPem);
        expect(mod.computeFingerprint(chain[0], 'sha256')).not.toBe(emptyHash);
      }
    });
  });

  describe('the didx509 CLI', () => {
    it('is built with a shebang so it can be executed', () => {
      expect(existsSync(cliEsm)).toBe(true);
      expect(readFileSync(cliEsm, 'utf-8').startsWith('#!/usr/bin/env node')).toBe(
        true
      );
    });

    it('encodes a subject value', () => {
      const out = execFileSync(process.execPath, [cliEsm, 'encode', 'CN=x'], {
        encoding: 'utf-8',
      });
      expect(out.trim()).toBe('CN%3Dx');
    });

    it('converts a PEM chain to JSON', () => {
      const out = execFileSync(
        process.execPath,
        [cliEsm, 'convert', resolve(packageRoot, 'shared-test-data/ms-code-signing.pem')],
        { encoding: 'utf-8' }
      );
      const parsed = JSON.parse(out) as Array<{ subject: { CN?: string } }>;
      expect(parsed).toHaveLength(3);
      expect(parsed[0]?.subject.CN).toBe('Microsoft Corporation');
    });

    it('resolves a DID against a chain', () => {
      const out = execFileSync(
        process.execPath,
        [
          cliEsm,
          'resolve',
          `did:x509:0:sha256:${EXPECTED_CA_FINGERPRINT}::subject:CN:Microsoft%20Corporation`,
          '--chain',
          resolve(packageRoot, 'shared-test-data/ms-code-signing.pem'),
          '--skip-validity-period-check',
        ],
        { encoding: 'utf-8' }
      );
      const doc = JSON.parse(out) as { id: string };
      expect(doc.id).toContain('did:x509:0:sha256:');
    });
  });
});

describe.skipIf(!existsSync(cliEsm))('published entry points', () => {
  it('exposes the CLI, ships the docs, and matches the trusted-publisher repo URL', () => {
    // The manifest must expose the CLI and ship the docs the README links to,
    // or `npm publish` ships a package whose documented commands are missing.
    const pkg = require_(resolve(packageRoot, 'package.json')) as {
      bin?: Record<string, string>;
      files?: string[];
      exports?: Record<string, unknown>;
      repository?: { url?: string };
    };
    expect(pkg.bin?.didx509).toBe('dist/cli.js');
    expect(pkg.files).toContain('docs');
    expect(Object.keys(pkg.exports ?? {})).toContain('./cli');
    // Trusted publishing requires an exact match with the GitHub repository;
    // npm silently normalizes a bare https URL, which would fail that match.
    expect(pkg.repository?.url).toBe('git+https://github.com/ayanworks/did-x509.git');
  });
});
