// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Certificate Studio — the six-step flow behind the playground UI.
 *
 *   1. generate a test CA/leaf chain, or accept an uploaded one
 *   2. inspect every certificate in the chain
 *   3. derive the did:x509 DID from the chain
 *   4. sign a chosen credential type with the DID's key
 *   5. show the signed payload
 *   6. verify it and recover the issuer from the credential itself
 *
 * Everything here is runtime-portable: Web Crypto and `@didx509/core` only,
 * no Deno or Node APIs. The HTTP layer just marshals JSON in and out.
 *
 * ## No session state
 *
 * Nothing is retained between calls. Each request carries the material it
 * needs — for signing, that means the PEM chain and private key again. This
 * matches the playground's existing "nothing is stored" guarantee: there is no
 * server-side store to leak, and no cleanup to get wrong.
 */

import 'reflect-metadata';

import type { X509Certificate } from '@peculiar/x509';

import {
  signCredential,
  verifyCredentialPayload,
  TEMPLATES,
  didDocumentOf,
  type CredentialFormat,
  type CredentialTemplate,
  type SignedCredential,
  type VerificationOutcome,
} from './credentials.ts';
import {
  generateIdentity,
  subjectToString,
  webCryptoAlgorithm,
  type GenAlgorithm,
  type SubjectInput,
} from './lib/generate.ts';
import type { CertificateView } from './lib/cert-parse.ts';
import type { SigningIdentity } from './lib/identity.ts';
import {
  parseUploadedIdentity,
  splitCertificates,
  type SubjectAttribute,
  type UploadedIdentity,
} from './lib/upload.ts';

/** Everything the UI needs to know about a loaded identity. */
export interface IdentityReport {
  origin: 'generated' | 'uploaded';
  did: string;
  verificationMethodId: string;
  /** Certificate detail views, leaf first. */
  certificates: CertificateView[];
  /** PEM of the chain, for display and re-use in later requests. */
  pemChain: string;
  /**
   * PEM of the leaf private key, when one is available.
   *
   * Returned for generated identities so the browser can re-send it with a
   * signing request — nothing is retained server-side between calls, so the
   * client is the only place the key can live. Uploaded identities never
   * echo their key back.
   */
  keyPem?: string;
  /** base64url DER chain, leaf first. */
  x509chain: string;
  leafPublicJwk: JsonWebKey;
  /** Whether signing is possible (a private key is present). */
  keyPresent: boolean;
  keyType?: string;
  keyFormat?: string;
  /** The subject attribute the DID pins. */
  didSubjectAttribute: SubjectAttribute;
  /** Formats this identity's key can actually sign, so the UI disables the rest. */
  signableFormats: CredentialFormat[];
  /** The DID document derived from the chain, for display. */
  didDocument: Record<string, unknown>;
  warnings: string[];
}

/** Which formats an identity's leaf key can sign, by key type. */
export function signableFormatsFor(identity: SigningIdentity): CredentialFormat[] {
  const formats: CredentialFormat[] = [];
  const { kty, crv } = identity.leafPublicJwk;

  // EDSA-RDFC-2022 is Ed25519-only; SD-JWT and mDoc here are ES256-only.
  if (kty === 'OKP' && crv === 'Ed25519') formats.push('jsonld');
  if (kty === 'EC' && crv === 'P-256') formats.push('sd-jwt', 'mdoc');
  return formats;
}

/** Serialise an already-built identity for the UI. */
async function report(
  identity: SigningIdentity & {
    certificates?: CertificateView[];
    keyPresent?: boolean;
    keyType?: string;
    keyFormat?: string;
    keyPem?: string;
    warnings?: string[];
    didSubjectAttribute?: SubjectAttribute;
  },
  origin: 'generated' | 'uploaded',
  certificates: CertificateView[]
): Promise<IdentityReport> {
  const didDocument = (await didDocumentOf(identity)) as unknown as Record<
    string,
    unknown
  >;

  return {
    origin,
    did: identity.did,
    verificationMethodId: identity.verificationMethodId,
    certificates,
    pemChain: identity.pemChain,
    keyPem: identity.keyPem,
    x509chain: identity.x509chain,
    leafPublicJwk: identity.leafPublicJwk,
    keyPresent: Boolean(identity.leafPrivateJwk),
    keyType: identity.keyType,
    keyFormat: identity.keyFormat,
    didSubjectAttribute: identity.didSubjectAttribute ?? 'CN',
    signableFormats: signableFormatsFor(identity),
    didDocument,
    warnings: identity.warnings ?? [],
  };
}

export interface GenerateRequest {
  caSubject: SubjectInput;
  leafSubject: SubjectInput;
  caAlgorithm: GenAlgorithm;
  leafAlgorithm: GenAlgorithm;
  validityDays?: number;
  didSubjectAttribute?: SubjectAttribute;
}

/**
 * Generate a test CA + leaf chain and report on it.
 *
 * The generated chain needs its certificate views built here, because a
 * generated identity has no PEM to re-parse — it already holds the parsed
 * certificates.
 */
export async function studioGenerate(
  request: GenerateRequest
): Promise<IdentityReport> {
  const generated = await generateIdentity({
    caSubject: request.caSubject,
    leafSubject: request.leafSubject,
    caAlgorithm: request.caAlgorithm,
    leafAlgorithm: request.leafAlgorithm,
    validityDays: request.validityDays ?? 24,
    didSubjectAttribute: request.didSubjectAttribute ?? 'CN',
  });

  const { buildCertificateView } = await import('./lib/cert-parse.ts');
  const chain = [generated.leafCertificate, generated.caCertificate];
  const views = await Promise.all(
    chain.map((certificate, index) =>
      buildCertificateView(certificate, index, chain.length)
    )
  );

  return report(
    {
      ...generated,
      didSubjectAttribute: request.didSubjectAttribute ?? 'CN',
      keyPem: generated.leafPrivatePem,
      // A generated identity always has a key; label its type for the UI.
      keyType: request.leafAlgorithm,
      keyFormat: 'PKCS#8',
    },
    'generated',
    views
  );
}

export interface UploadRequest {
  /** PEM chain, leaf first. */
  chainPem: string;
  /** PEM private key of the leaf; optional (inspect-only without it). */
  keyPem?: string;
  didSubjectAttribute?: SubjectAttribute;
}

/** Parse an uploaded chain (and optional key) and report on it. */
export async function studioUpload(
  request: UploadRequest
): Promise<IdentityReport> {
  const uploaded: UploadedIdentity = await parseUploadedIdentity(
    request.chainPem,
    request.keyPem ?? '',
    request.didSubjectAttribute ?? 'CN'
  );

  return report(uploaded, 'uploaded', uploaded.certificates);
}

export interface SignRequestBody {
  /** PEM chain, leaf first — re-sent because nothing is retained. */
  chainPem: string;
  /** PEM private key of the leaf. */
  keyPem: string;
  didSubjectAttribute?: SubjectAttribute;
  format: CredentialFormat;
  templateId: string;
  claims?: Record<string, string>;
  withheld?: string[];
}

/** Parse the identity, sign one credential, and return it with a preview. */
export async function studioSign(
  request: SignRequestBody
): Promise<{
  signed: SignedCredential;
  /** The verification of the credential we just signed, as a sanity check. */
  selfCheck: VerificationOutcome;
}> {
  const identity = await parseUploadedIdentity(
    request.chainPem,
    request.keyPem,
    request.didSubjectAttribute ?? 'CN'
  );

  const signed = await signCredential(identity, {
    format: request.format,
    templateId: request.templateId,
    claims: request.claims ?? {},
    withheld: request.withheld ?? [],
  });

  const selfCheck = await verifyCredentialPayload(signed.payload, request.format);
  return { signed, selfCheck };
}

export interface VerifyRequestBody {
  format: CredentialFormat;
  /** The signed credential: a JSON object for JSON-LD, a string otherwise. */
  payload: unknown;
}

/**
 * Verify a supplied credential and recover its issuer.
 *
 * Nothing about the original signing identity is needed: the chain travels in
 * the credential, which is the whole point of the exercise.
 */
export async function studioVerify(
  request: VerifyRequestBody
): Promise<VerificationOutcome> {
  if (request.payload === undefined || request.payload === null) {
    throw new Error('Provide the signed credential to verify.');
  }
  return verifyCredentialPayload(
    request.payload as string | Record<string, unknown>,
    request.format
  );
}

/**
 * The credential catalogue, with the claim defaults, for the UI.
 *
 * Passing this over the wire means the browser renders the form from the same
 * source of truth the signer uses, so the two cannot drift.
 */
export function credentialCatalogue(): Array<
  CredentialTemplate & { claimFields: CredentialTemplate['claims'] }
> {
  return TEMPLATES.map(template => ({
    ...template,
    claimFields: template.claims,
  }));
}

/** Supported key algorithms and subject fields, for the generate form. */
export function generateOptions(): {
  algorithms: GenAlgorithm[];
  subjectAttributes: SubjectAttribute[];
  exampleSubjects: { ca: string; leaf: string };
} {
  return {
    algorithms: ['P-256', 'P-384', 'P-521', 'Ed25519', 'RSA-2048', 'RSA-4096'],
    subjectAttributes: ['CN', 'O', 'OU', 'C', 'ST', 'L'],
    exampleSubjects: {
      ca: subjectToString({ C: 'US', O: 'AyanWorks', CN: 'AyanWorks Test Root CA' }),
      leaf: subjectToString({ C: 'US', O: 'Acme Corp', OU: 'Engineering', CN: 'Acme Engineering' }),
    },
  };
}

/** Re-exported so the CLI can share the server's option surface. */
export {
  webCryptoAlgorithm,
  splitCertificates,
  type X509Certificate,
};
