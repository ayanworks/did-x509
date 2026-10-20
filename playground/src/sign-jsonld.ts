// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * JSON-LD credential signing (`eddsa-rdfc-2022` Data Integrity proof).
 *
 * Two things make this more than a thin wrapper:
 *
 *   1. **The signing key must be Ed25519.** The `eddsa-rdfc-2022` suite is
 *      defined for Ed25519 only, so an identity whose leaf key is ECDSA or RSA
 *      cannot use this format. Rather than failing opaquely inside the suite,
 *      the key type is checked here and the caller is told which format to
 *      use instead.
 *
 *   2. **The chain is embedded in the proof, not just attached.** The `x5c`
 *      list is injected through the suite's own `updateProof` hook, which runs
 *      *before* the signing data is derived. That means the chain is covered
 *      by `proofValue` — tampering with it invalidates the signature. An
 *      after-the-fact `proof.x5c = ...` would look identical but prove
 *      nothing, which is the trap this avoids.
 *
 * `x5c` also has to be declared in the credential's own `@context`, because
 * the proof is canonicalised and JSON-LD refuses to expand an undefined term.
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
import type { SigningIdentity } from './lib/identity.ts';
import type {
  ClaimField,
  CredentialTemplate,
} from './credentials.ts';

const { AssertionProofPurpose } = jsigs.purposes;

type DocumentLoader = (url: string) => Promise<{
  documentUrl: string;
  document: unknown;
}>;

/**
 * A document loader that serves the DID document derived from the chain.
 *
 * The DID document is not fetched from a network: it is recomputed from the
 * signing chain, which is what makes the whole flow self-contained and equally
 * at home on an edge runtime with no outbound access.
 */
export async function createDocumentLoader(
  identity: SigningIdentity
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
    if (document !== undefined) {
      return { documentUrl: url, document };
    }
    // Anything else (in practice only the JSON-LD context for a custom term)
    // falls back to the network, matching the core resolver's behaviour.
    const response = await fetch(url, {
      headers: { accept: 'application/ld+json, application/json' },
    });
    return { documentUrl: url, document: await response.json() };
  };
}

/**
 * Build the JSON-LD context for a credential template.
 *
 * Custom claim terms need definitions or expansion fails, so each claim is
 * mapped to a placeholder vocabulary under the issuer's control. `x5c` is the
 * exception: it reuses the security vocabulary's own definition, which keeps
 * the proof interoperable with other Data Integrity implementations.
 */
function contextFor(template: CredentialTemplate): unknown[] {
  const claimTerms: Record<string, string> = {};
  for (const claim of template.claims) {
    claimTerms[claim.key] = `https://example.org/vocab#${claim.key}`;
  }

  return [
    'https://www.w3.org/2018/credentials/v1',
    {
      ...claimTerms,
      x5c: 'https://w3id.org/security#x5c',
      ...(template.types ?? []).reduce<Record<string, string>>((acc, type) => {
        acc[type] = `https://example.org/vocab#${type}`;
        return acc;
      }, {}),
    },
  ];
}

/**
 * True when this identity's leaf key can sign an `eddsa-rdfc-2022` proof.
 *
 * Exported so the UI can disable JSON-LD for non-Ed25519 identities rather
 * than discovering the incompatibility only when signing is attempted.
 */
export function supportsJsonLd(identity: SigningIdentity): boolean {
  return identity.leafPublicJwk.kty === 'OKP' && identity.leafPublicJwk.crv === 'Ed25519';
}

export interface JsonLdSignInput {
  identity: SigningIdentity;
  template: CredentialTemplate;
  claims: Record<string, string>;
  /** base64url DER chain, leaf first; embedded in the proof. */
  x5c: string[];
  verificationMethodId: string;
}

/** Sign a credential with a Data Integrity proof carrying the x5c chain. */
export async function signJsonLdCredential(
  input: JsonLdSignInput
): Promise<Record<string, unknown>> {
  const { identity, template, claims, x5c, verificationMethodId } = input;

  const privateKey = identity.leafPrivateJwk;
  if (!privateKey) {
    throw new Error('This identity has no private key, so it cannot sign.');
  }
  if (!supportsJsonLd(identity)) {
    throw new Error(
      `The eddsa-rdfc-2022 suite signs with Ed25519 only; this identity's ` +
        `leaf key is ${identity.leafPublicJwk.kty} ` +
        `${identity.leafPublicJwk.crv ?? ''}. Issue SD-JWT or mDoc instead, ` +
        `or generate an Ed25519 identity.`
    );
  }

  const credential: Record<string, unknown> = {
    '@context': contextFor(template),
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', ...(template.types ?? [])],
    issuer: identity.did,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: 'did:example:holder',
      ...claims,
    },
  };

  const key = await ed25519KeyFromDidX509(
    {
      id: verificationMethodId,
      type: 'JsonWebKey',
      controller: identity.did,
      publicKeyJwk: identity.leafPublicJwk,
    },
    privateKey as { d?: string }
  );

  const signer = key.signer();
  // The Data Integrity proof checks the signer's claimed algorithm; the
  // Ed25519 suite instance does not set it, so it is declared here.
  signer.algorithm = 'Ed25519';

  const suite = new DataIntegrityProof({ signer, cryptosuite } as never);
  // Inject x5c through the suite's extension hook so it is part of the signed
  // data. Assigning to `proof.x5c` after signing would leave it unprotected.
  (
    suite as unknown as {
      updateProof: (args: {
        proof: Record<string, unknown>;
      }) => Promise<Record<string, unknown>>;
    }
  ).updateProof = async ({ proof }) => ({ ...proof, x5c });

  const documentLoader = await createDocumentLoader(identity);
  return vc.issue({
    credential,
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader,
  });
}

/**
 * Verify a JSON-LD credential against the DID document in its own chain.
 *
 * The DID is re-derived from the embedded `x5c`, so verification does not
 * trust the credential's `issuer` field on its own — that field only selects
 * which document to load, and the document itself comes from the chain.
 */
export async function verifyJsonLdCredential(
  credential: Record<string, unknown>
): Promise<boolean> {
  const proof = credential.proof as { x5c?: string[] } | undefined;
  const x5c = proof?.x5c;
  const issuer = String(credential.issuer ?? '');

  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new Error(
      'The credential proof carries no x5c chain, so its issuer cannot be ' +
        'recovered from the credential alone.'
    );
  }

  // Rebuild the identity from the credential's own chain rather than reusing
  // the signer's in-memory state: this is what a third-party verifier has.
  const { identityFromX5c } = await import('./lib/issuer.ts');
  const identity = await identityFromX5c(x5c, issuer);
  const documentLoader = await createDocumentLoader(identity);

  const verification = await vc.verifyCredential({
    credential,
    suite: new DataIntegrityProof({ cryptosuite } as never),
    purpose: new AssertionProofPurpose(),
    documentLoader,
  });
  return verification.verified;
}

export type { ClaimField };
