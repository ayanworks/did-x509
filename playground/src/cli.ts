// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * CLI entry point — runs every flow in-process, with no HTTP server.
 *
 * This is what CI exercises (`deno task all`): it proves the flows work on
 * the Deno runtime without needing a port or a network. Any `npm:` download
 * still happens, so it also catches dependency-resolution regressions.
 */

import { runAll } from './flows.ts';

/** Print a result, hiding large opaque payloads behind a size note. */
function printResult(result: {
  flow: string;
  title: string;
  summary: string;
  did: string;
  details: Record<string, unknown>;
}): void {
  const { document, credential, ...rest } = result.details;
  console.log(`\n▸ ${result.title}`);
  console.log(`  ${result.summary}`);
  console.log(`  did: ${result.did}`);

  for (const [key, value] of Object.entries(rest)) {
    console.log(`  ${key}: ${JSON.stringify(value)}`);
  }
  if (document) {
    console.log(`  document: ${JSON.stringify(document).length} bytes`);
  }
  if (credential) {
    console.log(
      `  credential: ${(typeof credential === 'string'
        ? credential
        : JSON.stringify(credential)
      ).length} bytes`
    );
  }
}

const results = await runAll();

console.log('AYANWORKS · did:x509 playground — all flows (Deno)');
for (const result of results) {
  printResult(result);
}

// Fail loudly if any verification did not pass, so CI catches regressions.
const failures = results.filter(result => {
  const verified =
    result.flow === 'jsonld'
      ? result.details.verified
      : result.flow === 'sd-jwt'
        ? result.details.verified
        : result.flow === 'mdoc'
          ? result.details.issuerAuthVerified
          : true;
  return !verified;
});

if (failures.length > 0) {
  console.error(`\n✗ ${failures.length} flow(s) failed to verify`);
  for (const failure of failures) {
    console.error(`  - ${failure.flow}`);
  }
  Deno.exit(1);
}

console.log(`\n✓ all ${results.length} flows verified`);
