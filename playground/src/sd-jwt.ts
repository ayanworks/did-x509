// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Flow 3 — SD-JWT Verifiable Credential with selective disclosure.
 *
 * The issuer identifier (`iss`) is the did:x509 DID and the signing key is
 * the leaf certificate's P-256 key. The holder discloses one claim and
 * withholds the other, and the verifier checks the JWT signature against the
 * key resolved from the DID.
 */

import 'reflect-metadata';

import { ES256, digest, generateSalt } from '@owf/crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { DidX509Identity } from './lib/identity.ts';

export interface SdJwtOutcome {
  /** The selectively disclosed presentation (safe to display). */
  credential: string;
  /** Claims the holder chose to reveal. */
  disclosed: Record<string, unknown>;
  /** Claims deliberately withheld from the presentation. */
  withheld: string[];
  /** Whether the presentation verified. Tanstack-free boolean. */
  verified: boolean;
}

const WITHHELD = ['ssn'] as const;
const DISCLOSED = ['email'] as const;

/** Issue an SD-JWT VC, then present and verify a selective disclosure. */
export async function issuePresentation(
  identity: DidX509Identity
): Promise<SdJwtOutcome> {
  const sdjwt = new SDJwtVcInstance({
    signer: await ES256.getSigner(identity.leafPrivateJwk),
    verifier: await ES256.getVerifier(identity.leafPublicJwk),
    signAlg: ES256.alg,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });

  const issued = await sdjwt.issue(
    {
      iss: identity.did,
      sub: 'did:example:holder',
      iat: Math.floor(Date.now() / 1000),
      vct: 'DemoCredential',
      name: 'Alice',
      email: 'alice@example.com',
      ssn: '123-45-6789',
    },
    // `name` stays visible; the rest is disclosable per-claim.
    { _sd: ['email', 'ssn'] }
  );

  // The holder reveals only `email` — never the SSN.
  const presentation = await sdjwt.present(issued, { email: true });
  // `verify` throws on a bad signature and returns the decoded JWT on
  // success, so reaching this line means the presentation is valid.
  await sdjwt.verify(presentation, {});
  // `decode` returns `{ jwt, disclosures, kbJwt }`.
  const decoded = (await sdjwt.decode(presentation)) as {
    jwt?: { payload?: Record<string, unknown> };
    disclosures?: Array<{ key?: string; value?: unknown }>;
  };

  // Disclosed claims live in `disclosures`, not in the JWT payload.
  const revealed: Record<string, unknown> = {};
  for (const disclosure of decoded.disclosures ?? []) {
    if (disclosure.key && DISCLOSED.includes(disclosure.key as 'email')) {
      revealed[disclosure.key] = disclosure.value;
    }
  }

  return {
    credential: presentation,
    disclosed: revealed,
    withheld: [...WITHHELD],
    verified: true,
  };
}
