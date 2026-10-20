// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * The five did:x509 flows the playground exercises.
 *
 * Everything here is runtime-portable: Web Crypto, `@didx509/core`, and the
 * signing stacks. No Deno, Node, or Cloudflare APIs appear in this file, so
 * the same functions back the local CLI, the HTTP server, and any future
 * host. Only the server entry point and the Credo Agent modules are
 * host-specific.
 *
 * Each flow starts from a fresh throwaway CA + leaf chain. The demo
 * certificates are generated in memory and never leave the process.
 *
 * Note that the `credo` flow here resolves through `@didx509/credo` only — it
 * does not start an Agent. The full Agent + Askar wallet journey lives in
 * `credo-agent.ts` and is driven by the Credo tab, because it needs a native
 * addon that a portable runtime cannot load. `npm run all` stays portable.
 */

import 'reflect-metadata';

import { resolveDidFromPem } from '@didx509/core';
import { createIdentity, type DidX509Identity } from './lib/identity.ts';

export interface FlowResult {
  /** Stable identifier for the flow. */
  flow: 'resolve' | 'jsonld' | 'sd-jwt' | 'mdoc' | 'credo';
  /** Human-readable title. */
  title: string;
  /** One-line summary of what happened. */
  summary: string;
  /** The issuer DID for this run. */
  did: string;
  /** Structured details to render (already JSON-safe). */
  details: Record<string, unknown>;
}

/** Prepare a fresh demo identity; shared by every flow. */
export async function newIdentity(
  options: { commonName?: string; curve?: 'P-256' | 'Ed25519' } = {}
): Promise<DidX509Identity> {
  return createIdentity(options);
}

/**
 * Flow 1 — resolve the DID from the certificate chain.
 *
 * Shows both supported entry points: the direct function and the W3C
 * `did-resolver` plugin, which take the same chain.
 */
export async function resolveFlow(): Promise<FlowResult> {
  const identity = await newIdentity();
  const document = await resolveDidFromPem(identity.did, identity.pemChain);

  const key = document.verificationMethod?.[0]?.publicKeyJwk as {
    kty?: string;
    crv?: string;
  };

  return {
    flow: 'resolve',
    title: 'Resolve a did:x509 DID',
    summary: 'Recovered the DID document from a certificate chain.',
    did: identity.did,
    details: {
      verificationMethods: document.verificationMethod?.length ?? 0,
      keyType: `${key?.kty ?? '?'} ${key?.crv ?? ''}`.trim(),
      chainLength: identity.pemChain.split('-----BEGIN CERTIFICATE-----').length - 1,
      document,
    },
  };
}

/**
 * Flow 2 — issue and verify a JSON-LD Verifiable Credential.
 *
 * The credential is signed with the leaf certificate's Ed25519 key
 * (`eddsa-rdfc-2022`), and the verifier re-derives trust by resolving the
 * DID from the chain and checking the proof against its key.
 */
export async function jsonldFlow(): Promise<FlowResult> {
  const identity = await newIdentity({ curve: 'Ed25519' });
  const { createDocumentLoader, issueCredential, verifyCredential } =
    await import('./jsonld.ts');

  const documentLoader = await createDocumentLoader(identity);
  const credential = await issueCredential(identity, documentLoader);
  const verified = await verifyCredential(credential, documentLoader);

  return {
    flow: 'jsonld',
    title: 'JSON-LD Verifiable Credential',
    summary: verified
      ? 'Issued a Data Integrity credential and verified it.'
      : 'Credential verification failed.',
    did: identity.did,
    details: {
      cryptosuite: 'eddsa-rdfc-2022',
      verified,
      credential,
    },
  };
}

/**
 * Flow 3 — issue and verify an SD-JWT VC with selective disclosure.
 *
 * The holder discloses one claim and withholds the other; the verifier
 * checks the JWT signature against the key in the DID document.
 */
export async function sdJwtFlow(): Promise<FlowResult> {
  const identity = await newIdentity();
  const { issuePresentation } = await import('./sd-jwt.ts');

  const result = await issuePresentation(identity);
  const document = await resolveDidFromPem(identity.did, identity.pemChain);
  const documentKey = document.verificationMethod?.[0]?.publicKeyJwk as {
    x?: string;
  };

  return {
    flow: 'sd-jwt',
    title: 'SD-JWT Verifiable Credential',
    summary: result.verified
      ? 'Issued an SD-JWT VC and verified a selective disclosure.'
      : 'SD-JWT verification failed.',
    did: identity.did,
    details: {
      disclosed: result.disclosed,
      withheld: result.withheld,
      verified: result.verified,
      signingKeyMatchesDid: documentKey?.x === identity.leafPublicJwk['x'],
      credential: result.credential,
    },
  };
}

/**
 * Flow 4 — issue and verify an mDoc (ISO/IEC 18013-5).
 *
 * mDoc is certificate-based by design, so the document signer's certificate
 * *is* the DID. The verifier validates the `x5chain` against a trusted root.
 */
export async function mdocFlow(): Promise<FlowResult> {
  const identity = await newIdentity();
  const { issueMdoc } = await import('./mdoc.ts');

  const result = await issueMdoc(identity);

  return {
    flow: 'mdoc',
    title: 'mDoc (ISO/IEC 18013-5)',
    summary: result.issuerAuthVerified
      ? 'Issued an mDoc and verified its issuer authentication.'
      : 'mDoc issuer authentication failed.',
    did: identity.did,
    details: {
      docType: result.docType,
      size: result.size,
      certificatesInChain: result.certificatesInChain,
      issuerAuthVerified: result.issuerAuthVerified,
      sameCertificateAsDid: result.sameCertificateAsDid,
    },
  };
}

/**
 * Flow 5 — did:x509 through the Credo resolver plugin.
 *
 * Resolution and credential issuing both go through the real
 * `X509DidResolver` and Credo's `DidDocument`, so the playground exercises the
 * published `@didx509/credo` integration rather than a reimplementation.
 */
export async function credoFlow(): Promise<FlowResult> {
  const identity = await newIdentity();
  const { credoFlow: runCredo } = await import('./credo.ts');

  const result = await runCredo(identity, 'core');

  return {
    flow: 'credo',
    title: 'Credo integration (@didx509/credo)',
    summary: result.canSign
      ? result.verified
        ? 'Resolved the DID through Credo and verified a credential signed under it.'
        : 'Credo credential verification failed.'
      : 'Resolved the DID through Credo and produced the wallet import record.',
    did: result.did,
    details: {
      implementation: result.implementation,
      verificationMethodType: result.verificationMethodType,
      keyMatchesCertificate: result.keyMatchesCertificate,
      allowsCaching: result.allowsCaching,
      importedKey: result.importedKey,
      disclosed: result.disclosed,
      withheld: result.withheld,
      verified: result.verified,
      canSign: result.canSign,
      didDocument: result.didDocument,
      credential: result.credential,
    },
  };
}

/** Run every flow, in order. */
export async function runAll(): Promise<FlowResult[]> {
  const results: FlowResult[] = [];
  results.push(await resolveFlow());
  results.push(await jsonldFlow());
  results.push(await sdJwtFlow());
  results.push(await mdocFlow());
  results.push(await credoFlow());
  return results;
}

/** Map of flow name to runner, for the HTTP API. */
export const FLOWS = {
  resolve: resolveFlow,
  jsonld: jsonldFlow,
  'sd-jwt': sdJwtFlow,
  mdoc: mdocFlow,
  credo: credoFlow,
} as const;

export type FlowName = keyof typeof FLOWS;
