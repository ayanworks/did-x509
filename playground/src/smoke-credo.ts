// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Credo Agent smoke test — the one flow the CLI cannot cover.
 *
 * `npm run all` runs the portable flows in-process and deliberately never
 * starts an Agent, because an Agent needs a wallet and a wallet needs a
 * storage backend. This script talks to a *running* playground instead
 * (`npm start`), so it exercises the real thing end to end: Agent startup,
 * Askar key import, DID import, SD-JWT issuance from the wallet key, and
 * verification with the DID re-resolved from the chain.
 *
 * It is what the CI `playground` job runs after booting the server, which is
 * why it fails loudly if the native backend is missing rather than skipping.
 *
 * Usage:
 *   npm start            # in one shell
 *   npm run smoke:credo  # in another
 *
 * `BASE_URL` overrides the default `http://localhost:8000`.
 */

import type { CredoAgentResult } from './credo-agent.ts';
import type { IdentityReport } from './studio.ts';

const BASE = process.env.BASE_URL ?? 'http://localhost:8000';

/** The session cookie, carried across requests the way a browser would. */
let cookie = '';

async function api<T = Record<string, any>>(
  path: string,
  body?: Record<string, unknown>
): Promise<T> {
  const response = await fetch(BASE + path, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(cookie ? { cookie } : {}),
    },
    body: JSON.stringify(body ?? {}),
  });
  const setCookie = response.headers.getSetCookie?.() ?? [];
  if (setCookie.length) cookie = setCookie[0].split(';')[0];

  const payload = (await response.json()) as T & { error?: string };
  if (!response.ok) {
    throw new Error(`${path} → HTTP ${response.status}: ${payload.error ?? ''}`);
  }
  return payload;
}

/** A tiny check runner: collect failures, report at the end. */
const failures: string[] = [];
function check(label: string, actual: unknown, expected: unknown = true): void {
  const ok = actual === expected;
  console.log(`  ${ok ? '✓' : '✗'} ${label}: ${JSON.stringify(actual)}`);
  if (!ok) failures.push(`${label} (expected ${JSON.stringify(expected)})`);
}

async function main() {
  console.log(`Credo Agent smoke test against ${BASE}`);

  // 0. The server must be up and the native backend must have loaded.
  const health = await (await fetch(`${BASE}/api/health`)).json() as { status: string };
  check('server health', health.status, 'ok');

  const status = await (await fetch(`${BASE}/api/credo-agent/status`)).json() as {
    available: boolean;
  };
  if (!status.available) {
    throw new Error(
      'The native Askar backend is unavailable, so the Credo Agent cannot ' +
        'run. Approve the install scripts and `npm rebuild`, or this check ' +
        'is meaningless.'
    );
  }
  check('native Askar backend available', status.available);

  // 1. Generate a P-256 chain, exactly as the Studio's Generate button does.
  //    P-256 because SD-JWT signing in Credo is ES256.
  const { identity } = await api<{ identity: IdentityReport }>('/api/generate', {
    caSubject: { C: 'US', O: 'AyanWorks', CN: 'AyanWorks Test Root CA' },
    leafSubject: { C: 'US', O: 'Acme Corp', OU: 'Engineering', CN: 'Acme Engineering' },
    caAlgorithm: 'P-256',
    leafAlgorithm: 'P-256',
    validityDays: 30,
    didSubjectAttribute: 'CN',
  });
  console.log(`  · chain DID: ${identity.did}`);
  check('generated chain has a private key', identity.keyPresent);

  // 2. Run the seven steps.
  const { result } = await api<{ result: CredoAgentResult }>('/api/credo-agent/run', {
    chainPem: identity.pemChain,
    keyPem: identity.keyPem,
    didSubjectAttribute: 'CN',
  });

  check('agent uses an in-memory wallet', result.agent.storage, 'sqlite (in-memory)');
  check('resolved DID matches the chain', result.resolution.did, identity.did);
  check(
    'verification method is JsonWebKey2020 (Credo-mappable)',
    result.resolution.verificationMethodType,
    'JsonWebKey2020'
  );
  check('wallet key matches the certificate', result.import.keyMatchesCertificate);
  check('DID bound to the key', result.binding.didDocumentRelativeKeyId, '#0');
  check('the wallet holds exactly one did:x509 DID', result.wallet.dids.length, 1);
  check('credential signed by the wallet key', result.issuance.signedByWalletKey);
  check('credential verifies', result.verification.valid);
  check(
    'the disclosed claim came through',
    result.verification.disclosed.email,
    'alice@example.com'
  );
  check('the withheld claim stayed hidden', result.verification.withheld.join(','), 'ssn');
  if (result.verification.error) {
    failures.push(`verification error: ${result.verification.error}`);
  }

  // 3. Reset must end the session cleanly.
  const reset = await api<{ ok: boolean }>('/api/credo-agent/reset');
  check('wallet reset', reset.ok);

  if (failures.length) {
    console.error(`\n✗ Credo Agent smoke test failed (${failures.length}):`);
    for (const failure of failures) console.error(`  - ${failure}`);
    process.exit(1);
  }
  console.log('\n✓ Credo Agent: all seven steps verified');
}

main().catch((error: Error) => {
  console.error(`\n✗ ${error.message}`);
  process.exit(1);
});
