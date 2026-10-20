// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Cross-implementation parity: runs the same 220 upstream vectors through
 * @didx509/core (pure TypeScript) and records every divergence in
 * `test/core-divergences.json`.
 *
 * That file is the single source of truth for the "known differences"
 * section of docs/migration.md (a test below keeps them in sync).
 *
 * Regenerate after intentional changes with:  npm run parity:report
 * CI requires @didx509/core to be present:   REQUIRE_CORE=true npm test
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { afterAll, describe, expect, test } from 'vitest';
// @didx509/core relies on tsyringe, which requires this polyfill to be
// loaded before the package is imported (core's own test setup does the same).
import 'reflect-metadata';
import { chainToPem, packageRoot, vectors } from './helpers.js';

type Reason = 'unexpected-failure' | 'unexpected-success' | 'document-mismatch';
type Divergences = Record<string, Reason>;

const allowlistPath = path.join(packageRoot, 'test', 'core-divergences.json');
const migrationDocPath = path.join(packageRoot, 'docs', 'migration.md');
const update = process.env.UPDATE_CORE_DIVERGENCES === 'true';
const requireCore = process.env.REQUIRE_CORE === 'true';

const allowlist: Divergences = existsSync(allowlistPath)
  ? (JSON.parse(readFileSync(allowlistPath, 'utf8')) as Divergences)
  : {};
const actual: Divergences = {};

let core: typeof import('@didx509/core') | null = null;
try {
  core = await import('@didx509/core');
} catch {
  core = null;
}

if (!core && requireCore) {
  throw new Error(
    '@didx509/core could not be imported. Build it first:\n' +
      '  cd reference-implementations/typescript && npm ci && npm run build'
  );
}

describe.skipIf(!core)('core (pure TS) vs upstream vectors', () => {
  for (const vector of vectors) {
    test(`core: ${vector.id}`, async () => {
      const pem = chainToPem(vector.input.chain);
      let divergence: Reason | null = null;

      try {
        const document = await core!.resolveDidFromPem(
          vector.input.did,
          pem,
          { skipValidityPeriodCheck: true }
        );
        if (vector.output.error !== undefined) {
          divergence = 'unexpected-success';
        } else if (
          !isDeepStrictEqual(document, vector.output.document)
        ) {
          divergence = 'document-mismatch';
        }
      } catch {
        if (vector.output.error === undefined) {
          divergence = 'unexpected-failure';
        }
      }

      if (divergence !== null) {
        actual[vector.id] = divergence;
      }

      if (update) {
        return;
      }
      if (divergence !== null) {
        expect(
          allowlist[vector.id],
          `new divergence for "${vector.id}" — run: npm run parity:report`
        ).toBe(divergence);
      } else {
        expect(
          allowlist[vector.id],
          `"${vector.id}" no longer diverges — run: npm run parity:report`
        ).toBeUndefined();
      }
    });
  }

  test('migration.md documents every known divergence', () => {
    if (update) {
      // The report run regenerates the section in afterAll().
      return;
    }
    if (!existsSync(migrationDocPath)) {
      expect.fail('docs/migration.md is missing');
    }
    const migration = readFileSync(migrationDocPath, 'utf8');
    for (const id of Object.keys(allowlist)) {
      expect(
        migration.includes(id),
        `docs/migration.md must mention divergence "${id}"`
      ).toBe(true);
    }
  });

  test('every allowlist entry still corresponds to a real vector', () => {
    const ids = new Set(vectors.map((vector) => vector.id));
    for (const id of Object.keys(allowlist)) {
      expect(ids.has(id), `allowlist references unknown vector "${id}"`).toBe(
        true
      );
    }
  });
});

afterAll(() => {
  if (!update || !core) {
    return;
  }
  const sorted = Object.fromEntries(
    Object.entries(actual).sort(([a], [b]) => a.localeCompare(b))
  );
  writeFileSync(allowlistPath, `${JSON.stringify(sorted, null, 2)}\n`);
  console.log(
    `core-divergences.json updated: ${Object.keys(sorted).length} entr${
      Object.keys(sorted).length === 1 ? 'y' : 'ies'
    }`
  );
  regenerateMigrationSection(sorted);
});

/** Keeps the human-written migration guide's appendix in sync with the data. */
function regenerateMigrationSection(divergences: Divergences): void {
  if (!existsSync(migrationDocPath)) {
    console.warn('docs/migration.md not found — skipped divergence section');
    return;
  }
  const groups: Array<[Reason, string]> = [
    [
      'unexpected-success',
      'accepted although the C++ resolver rejects them (be careful — these are the risky ones)',
    ],
    [
      'unexpected-failure',
      'rejected although the C++ resolver accepts them',
    ],
    ['document-mismatch', 'produce a different DID document'],
  ];
  const lines: string[] = [];
  const total = Object.keys(divergences).length;
  lines.push('');
  lines.push(
    `**${total} of 220 test vectors behave differently** in @didx509/core:`
  );
  lines.push('');
  for (const [reason, heading] of groups) {
    const ids = Object.keys(divergences).filter(
      (id) => divergences[id] === reason
    );
    if (ids.length === 0) {
      continue;
    }
    lines.push(`### ${heading} (${ids.length})`);
    lines.push('');
    for (const id of ids.sort((a, b) => a.localeCompare(b))) {
      lines.push(`- \`${id}\``);
    }
    lines.push('');
  }

  const document = readFileSync(migrationDocPath, 'utf8');
  const begin = '<!-- core-divergences:begin -->';
  const end = '<!-- core-divergences:end -->';
  const startIndex = document.indexOf(begin);
  const endIndex = document.indexOf(end);
  if (startIndex === -1 || endIndex === -1) {
    console.warn(
      'docs/migration.md is missing core-divergences markers — skipped'
    );
    return;
  }
  const updated =
    document.slice(0, startIndex + begin.length) +
    lines.join('\n') +
    document.slice(endIndex);
  writeFileSync(migrationDocPath, updated);
  console.log('docs/migration.md divergence section regenerated');
}
