// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/** Tests for the native layer itself: loading, concurrency, memory, provenance. */

import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { binding } from '../src/binding.js';
import { resolveDidFromPem, resolveDidFromPemSync } from '../src/index.js';
import { chainToPem, goodVector, packageRoot } from './helpers.js';

const ignoreTime = { ignoreTime: true } as const;
const pem = chainToPem(goodVector.input.chain);

describe('native binding', () => {
  test('a usable binary was found', () => {
    // If loading had failed, importing ../src/binding.js would already
    // have thrown — reaching this test proves the addon is present.
    expect(typeof binding.resolve).toBe('function');
    expect(typeof binding.resolveSync).toBe('function');
    expect(typeof binding.resolveJwk).toBe('function');
    expect(typeof binding.version).toBe('function');
  });

  test('version matches the pinned submodule commit', () => {
    let head = '';
    try {
      head = execSync('git rev-parse HEAD', {
        cwd: path.join(packageRoot, 'third_party', 'didx509cpp'),
        encoding: 'utf8',
      }).trim();
    } catch {
      // Not a git checkout (for example an npm tarball) — accept any value.
    }
    if (head === '') {
      expect(binding.version()).not.toBe('');
      return;
    }
    expect(binding.version()).toBe(head);
    // The DIDX509CPP_COMMIT file is what tarball installs report; it must
    // never go stale (regenerate with `npm run sync:commit`).
    const commitFile = readFileSync(
      path.join(packageRoot, 'DIDX509CPP_COMMIT'),
      'utf8'
    ).trim();
    expect(commitFile).toBe(head);
  });

  test('concurrent async resolutions all produce the right document', async () => {
    const runs = await Promise.all(
      Array.from({ length: 50 }, () =>
        resolveDidFromPem(goodVector.input.did, pem, ignoreTime)
      )
    );
    for (const document of runs) {
      expect(document).toEqual(goodVector.output.document);
    }
  });

  test('repeated sync resolutions do not leak memory', () => {
    // Warm up allocator arenas first so the measurement is stable.
    for (let i = 0; i < 200; i++) {
      resolveDidFromPemSync(goodVector.input.did, pem, ignoreTime);
    }
    const before = process.memoryUsage().rss;
    for (let i = 0; i < 2000; i++) {
      resolveDidFromPemSync(goodVector.input.did, pem, ignoreTime);
    }
    const growth = process.memoryUsage().rss - before;
    // A per-call leak would add multiple megabytes here.
    expect(growth).toBeLessThan(64 * 1024 * 1024);
  });
});
