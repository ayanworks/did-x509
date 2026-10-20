// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * 03 — Issue and verify an SD-JWT Verifiable Credential signed by a
 * did:x509 issuer (ES256 — the leaf certificate carries a P-256 key).
 *
 * Run: npm run sign:sd-jwt
 *
 * did:x509 pairs neatly with SD-JWT VC: the issuer identifier is the DID,
 * the signing key is the leaf certificate's key, and a verifier checks the
 * JWT signature against the key in the resolved DID document.
 */

// @peculiar/x509's CJS build needs the reflect-metadata polyfill.
import 'reflect-metadata';

import { resolveDidFromPem } from '@didx509/core';
import { ES256, digest, generateSalt } from '@owf/crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { createIdentity } from './lib/identity.ts';

// --- Issuer side -----------------------------------------------------------

const identity = await createIdentity(); // P-256 leaf key
console.log('Issuer DID:  ', identity.did);

// The signing key is the certificate's private key, handed over as a JWK —
// the same shape the DID document exposes publicly.
const sdjwt = new SDJwtVcInstance({
  signer: await ES256.getSigner(identity.leafPrivateJwk),
  verifier: await ES256.getVerifier(identity.leafPublicJwk),
  signAlg: ES256.alg,
  hasher: digest,
  hashAlg: 'sha-256',
  saltGenerator: generateSalt,
});

const credential = await sdjwt.issue(
  {
    iss: identity.did,
    sub: 'did:example:holder',
    iat: Math.floor(Date.now() / 1000),
    vct: 'DemoCredential',
    name: 'Alice',
    email: 'alice@example.com',
    ssn: '123-45-6789',
  },
  // Selective disclosure: name stays visible, email + ssn are disclosable.
  { _sd: ['email', 'ssn'] }
);

console.log('\nIssued SD-JWT VC (disclosures truncated):');
console.log(credential.split('~').slice(0, 1)[0] + '~<disclosures>');

// --- Holder / verifier side ------------------------------------------------

// Holder discloses only `email` (never the ssn).
const presentation = await sdjwt.present(credential, { email: true });

const verified = await sdjwt.verify(presentation, {});
console.log('\nVerified:', verified ? 'true' : 'false');
if (!verified) {
  console.error('Verification failed');
  process.exit(1);
}

const decoded = await sdjwt.decode(presentation);
console.log('Disclosed payload:');
console.log(JSON.stringify(decoded, null, 2));

// The issuer DID is trust-anchored in the certificate chain: resolve it and
// confirm the signing key matches the DID document.
const didDocument = await resolveDidFromPem(identity.did, identity.pemChain);
const documentKey = didDocument.verificationMethod![0].publicKeyJwk as {
  x?: string;
  y?: string;
};
console.log(
  '\nSigning key matches the DID document:',
  documentKey.x === identity.leafPublicJwk['x'] &&
    documentKey.y === identity.leafPublicJwk['y']
);
