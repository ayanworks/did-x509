// Copyright (c) AyanWorks. Licensed under the MIT License.
//
// Runtime smoke test shared by the Bun and Deno CI jobs: imports the built
// dist/ entry the way an application would, resolves one specification
// vector, and checks the result. Run after `npm run build`:
//
//   bun scripts/runtime-smoke.mjs
//   deno run --allow-ffi --allow-read --allow-env \
//       --node-modules-dir=auto scripts/runtime-smoke.mjs

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

const { resolveDidFromPemSync, didx509Version } = await import(
  pathToFileURL(join(pkgRoot, 'dist', 'index.js')).href
);

function chainToPem(chain) {
  return chain
    .map((entry) => {
      const b64 = entry.replace(/-/g, '+').replace(/_/g, '/');
      const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
      const lines = Buffer.from(b64 + pad, 'base64')
        .toString('base64')
        .match(/.{1,64}/g);
      return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
    })
    .join('\n');
}

const vectors = JSON.parse(
  readFileSync(
    join(
      pkgRoot,
      'third_party/didx509cpp/test/test-data/test-vectors.json'
    ),
    'utf8'
  )
);
const vector = vectors.find((entry) => entry.output.document !== undefined);

const document = resolveDidFromPemSync(
  vector.input.did,
  chainToPem(vector.input.chain),
  { ignoreTime: true }
);

if (!isDeepStrictEqual(document, vector.output.document)) {
  throw new Error(`runtime-smoke: document mismatch for vector ${vector.id}`);
}

console.log(
  `runtime-smoke: ok — resolved ${vector.id} (didx509cpp ${didx509Version().slice(0, 7)})`
);
