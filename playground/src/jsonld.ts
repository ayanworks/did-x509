// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Flow 2 — JSON-LD Verifiable Credential (Data Integrity, `eddsa-rdfc-2022`).
 *
 * Kept separate from `flows.ts` so the heavy Digital Bazaar stack is only
 * loaded when this flow actually runs, which keeps playground cold starts
 * short (every millisecond matters on an edge host).
 */

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
import { ed25519KeyFromDidX509 } from './lib/did-x509-key.ts';
import type { DidX509Identity } from './lib/identity.ts';

const { AssertionProofPurpose } = jsigs.purposes;

export type DocumentLoader = (url: string) => Promise<{
  documentUrl: string;
  document: unknown;
}>;

/**
 * Serves the well-known JSON-LD contexts from local copies and resolves the
 * issuer's did:x509 DID from its certificate chain — exactly what a real
 * verifier does with a chain received out-of-band.
 *
 * Anything else falls back to the network (in practice the did:x509 context,
 * `https://www.w3.org/ns/cid/v1`).
 */
export async function createDocumentLoader(
  identity: DidX509Identity
): Promise<DocumentLoader> {
  const didDocument = await resolveDidFromPem(identity.did, identity.pemChain);
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
    [identity.did, didDocument],
    [`${identity.did}#0`, didDocument.verificationMethod![0]],
  ]);

  return async (url: string) => {
    const document = documents.get(url);
    if (document) return { documentUrl: url, document };

    const response = await fetch(url, {
      headers: { accept: 'application/ld+json, application/json' },
    });
    if (!response.ok) {
      throw new Error(`Unable to load ${url}: HTTP ${response.status}`);
    }
    return { documentUrl: url, document: await response.json() };
  };
}

/** Build the demo credential, signed by the leaf certificate's Ed25519 key. */
export async function issueCredential(
  identity: DidX509Identity,
  documentLoader: DocumentLoader
): Promise<Record<string, unknown>> {
  const credential = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
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
  // The Data Integrity proof checks the signer's claimed algorithm; the
  // Ed25519 suite instance does not set it, so it is declared here.
  signer.algorithm = 'Ed25519';

  return vc.issue({
    credential,
    suite: new DataIntegrityProof({ signer, cryptosuite }),
    purpose: new AssertionProofPurpose(),
    documentLoader,
  });
}

/** Verify the credential against the DID document re-derived from the chain. */
export async function verifyCredential(
  credential: Record<string, unknown>,
  documentLoader: DocumentLoader
): Promise<boolean> {
  const verification = await vc.verifyCredential({
    credential,
    suite: new DataIntegrityProof({ cryptosuite }),
    purpose: new AssertionProofPurpose(),
    documentLoader,
  });
  return verification.verified;
}
