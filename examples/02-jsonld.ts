// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * 02 — Issue and verify a JSON-LD Verifiable Credential signed by a
 * did:x509 issuer (Data Integrity, `eddsa-rdfc-2022` cryptosuite).
 *
 * Run: npm run sign:jsonld
 *
 * The issuer's leaf certificate carries an Ed25519 key; the credential is
 * signed by that key, and the verifier re-derives trust from the certificate
 * chain: resolve the DID with the chain, then check the proof against the
 * DID document's publicKeyJwk.
 */

// @peculiar/x509's CJS build needs the reflect-metadata polyfill.
import 'reflect-metadata';

import { DataIntegrityProof } from '@digitalbazaar/data-integrity';
import {
  constants as diConstants,
  contexts as diContexts,
} from '@digitalbazaar/data-integrity-context';
import { cryptosuite } from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import * as credentialsContext from '@digitalbazaar/credentials-context';
import * as securityContext from '@digitalbazaar/security-context';
import jsigs from 'jsonld-signatures';
import * as vc from '@digitalbazaar/vc';
import { resolveDidFromPem } from '@didx509/core';
import { createIdentity } from './lib/identity.ts';
import { ed25519KeyFromDidX509 } from './lib/did-x509-key.ts';

const { AssertionProofPurpose } = jsigs.purposes;

// --- Issuer side -----------------------------------------------------------

// Ed25519 leaf key: the same key material the certificate carries.
const identity = await createIdentity({ curve: 'Ed25519' });
console.log('Issuer DID:  ', identity.did);

// A document loader that resolves did:x509 DIDs from the certificate chain
// and serves the JSON-LD contexts it needs.
const documentLoader = await createDidX509Loader(identity.did, identity.pemChain);

const credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    // A small application context for the credential's own terms.
    {
      degree: 'https://example.edu/vocab#degree',
      name: 'https://schema.org/name',
      UniversityDegreeCredential:
        'https://example.edu/vocab#UniversityDegreeCredential',
      BachelorDegree: 'https://example.edu/vocab#BachelorDegree',
    },
  ],
  id: 'http://example.edu/credentials/733',
  type: ['VerifiableCredential', 'UniversityDegreeCredential'],
  issuer: identity.did,
  issuanceDate: new Date().toISOString(),
  credentialSubject: {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    degree: { name: 'Computer Science', type: 'BachelorDegree' },
  },
};

const key = await ed25519KeyFromDidX509(
  {
    id: identity.verificationMethodId,
    type: 'JsonWebKey',
    controller: identity.did,
    publicKeyJwk: identity.leafPublicJwk,
  },
  identity.leafPrivateJwk as { d?: string }
);

const signer = key.signer();
// The Data Integrity proof checks the *signer's* claimed algorithm; the
// Ed25519 suite instance does not set it, so it is declared here.
signer.algorithm = 'Ed25519';

const signed = await vc.issue({
  credential,
  suite: new DataIntegrityProof({
    signer,
    cryptosuite,
  }),
  purpose: new AssertionProofPurpose(),
  documentLoader,
});

console.log('\nSigned credential (proof removed for brevity):');
const { proof: _proof, ...unsignedPart } = signed;
console.log(JSON.stringify(unsignedPart, null, 2));
console.log('Proof:', JSON.stringify(signed.proof, null, 2));

// --- Verifier side ---------------------------------------------------------

// The verifier needs nothing but the credential, the DID and the issuer's
// certificate chain: resolve the DID document from the chain, verify the
// Data Integrity proof against the DID document's key.
const verifyLoader = await createDidX509Loader(identity.did, identity.pemChain);
const verification = await vc.verifyCredential({
  credential: signed,
  suite: new DataIntegrityProof({ cryptosuite }),
  purpose: new AssertionProofPurpose(),
  documentLoader: verifyLoader,
});

console.log('\nVerified:', verification.verified);
if (!verification.verified) {
  console.error(JSON.stringify(verification.results, null, 2));
  process.exit(1);
}

// --- Helpers ---------------------------------------------------------------

/**
 * A document loader that:
 *  - serves the W3C credentials / security / Data Integrity contexts from
 *    local copies, falling back to the network for anything else
 *  - resolves did:x509 DIDs by validating the issuer's certificate chain
 *    (exactly what a real verifier does with a chain received out-of-band)
 */
async function createDidX509Loader(did: string, pemChain: string) {
  const didDocument = await resolveDidFromPem(did, pemChain);
  const documents = new Map<string, unknown>([
    [
      'https://www.w3.org/2018/credentials/v1',
      credentialsContext.contexts.get('https://www.w3.org/2018/credentials/v1'),
    ],
    [
      diConstants.DATA_INTEGRITY_CONTEXT_V2_URL,
      diContexts.get(diConstants.DATA_INTEGRITY_CONTEXT_V2_URL),
    ],
    [
      'https://w3id.org/security/v1',
      securityContext.contexts.get('https://w3id.org/security/v1'),
    ],
    [
      'https://w3id.org/security/v2',
      securityContext.contexts.get('https://w3id.org/security/v2'),
    ],
    [did, didDocument],
    [`${did}#0`, didDocument.verificationMethod![0]],
  ]);

  return async (url: string) => {
    const document = documents.get(url);
    if (document) return { documentUrl: url, document };
    // Fall back to the network for anything not pinned above — in practice
    // the did:x509 context (https://www.w3.org/ns/cid/v1). Production
    // verifiers should cache these instead.
    const response = await fetch(url, {
      headers: { accept: 'application/ld+json, application/json' },
    });
    if (!response.ok) {
      throw new Error(`Unable to load ${url}: HTTP ${response.status}`);
    }
    return { documentUrl: url, document: await response.json() };
  };
}
