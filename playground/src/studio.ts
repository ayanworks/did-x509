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
import {
  FORMAT_ALGORITHMS,
  KEY_PROFILES,
  availabilityOf,
} from './lib/capabilities.ts';
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

/**
 * Which formats an identity's leaf key can sign.
 *
 * Delegated to the signers themselves rather than a key-type table here: an
 * earlier inline version drifted out of sync with (and understated) what
 * `sign-mdoc.ts` and `sign-sd-jwt.ts` can do, which is what produced the
 * "cannot sign any format" dead end for RSA and P-384/P-521 keys.
 *
 * The predicates are imported lazily, and `supports*` is a pure function of the
 * JWK, so this stays cheap to call on every request without dragging the
 * Digital Bazaar stack into a page that only resolves a DID.
 */
export async function signableFormatsFor(
  identity: SigningIdentity
): Promise<CredentialFormat[]> {
  const [jsonld, sdJwt, mdoc] = await Promise.all([
    import('./sign-jsonld.ts'),
    import('./sign-sd-jwt.ts'),
    import('./sign-mdoc.ts'),
  ]);
  const formats: CredentialFormat[] = [];
  if (jsonld.supportsJsonLd(identity)) formats.push('jsonld');
  if (sdJwt.supportsSdJwt(identity)) formats.push('sd-jwt');
  if (mdoc.supportsMdoc(identity)) formats.push('mdoc');
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
    signableFormats: await signableFormatsFor(identity),
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
 * Resolve a loaded chain through the Credo resolver, and report what a Credo
 * wallet would store for it.
 *
 * This is the didn't-quite-fit-a-step check for Credo users: it answers "what
 * does `agent.dids.resolve()` return for *my* certificate?" for an uploaded
 * chain. It runs the resolver in-process and is portable; the Credo *tab* goes
 * further and drives a real Agent — see `credo-agent.ts`.
 */
export async function studioCredoResolve(request: {
  chainPem: string;
  didSubjectAttribute?: SubjectAttribute;
  /** Which engine behind the resolver to use. */
  implementation?: 'core' | 'native';
}): Promise<{
  did: string;
  implementation: 'core' | 'native';
  didDocument: Record<string, unknown>;
  verificationMethodType: string;
  allowsCaching: boolean;
  importedKey: { kmsKeyId: string; didDocumentRelativeKeyId: string };
}> {
  const identity = await parseUploadedIdentity(
    request.chainPem,
    '',
    request.didSubjectAttribute ?? 'CN'
  );
  const { credoFlow } = await import('./credo.ts');
  const outcome = await credoFlow(identity, request.implementation ?? 'core');
  return {
    did: outcome.did,
    implementation: outcome.implementation,
    didDocument: outcome.didDocument,
    verificationMethodType: outcome.verificationMethodType,
    allowsCaching: outcome.allowsCaching,
    importedKey: outcome.importedKey,
  };
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

/**
 * The capability matrix, as data for the page.
 *
 * Built from `lib/capabilities.ts` rather than hard-coded in markup, so the
 * table the reader studies and the dropdown that actually gates signing cannot
 * disagree. Each cell carries the algorithm when it works, and the *reason* when
 * it does not — a reader deciding on a key type needs to know whether the limit
 * is the specification or this playground's COSE library.
 */
export function capabilityMatrix(): {
  formats: Array<{ id: CredentialFormat; spec: string; note: string }>;
  rows: Array<{
    genAlgorithm: string;
    label: string;
    description: string;
    cells: Array<{
      format: CredentialFormat;
      verdict: 'yes' | 'no' | 'spec';
      label: string;
      why: string;
    }>;
  }>;
} {
  const formats: CredentialFormat[] = ['jsonld', 'sd-jwt', 'mdoc'];
  return {
    formats: formats.map(format => ({
      id: format,
      // "allowed" is the spec list; showing it makes the implementation gap
      // legible instead of looking like an arbitrary "no".
      spec: FORMAT_ALGORITHMS[format].spec.join(', '),
      note: FORMAT_ALGORITHMS[format].note,
    })),
    rows: KEY_PROFILES.map(profile => ({
      genAlgorithm: profile.genAlgorithm,
      label: profile.label,
      description: profile.description,
      cells: formats.map(format => {
        const availability = availabilityOf(profile.genAlgorithm, format);
        if (availability.state === 'available') {
          return {
            format,
            verdict: 'yes' as const,
            label: availability.algorithm,
            why: '',
          };
        }
        // `spec-excluded` is the format's own rule; anything else is our limit.
        return {
          format,
          verdict:
            availability.state === 'spec-excluded'
              ? ('spec' as const)
              : ('no' as const),
          label: availability.state === 'spec-excluded' ? 'n/a' : 'not available',
          why: availability.reason,
        };
      }),
    })),
  };
}

/** Supported key algorithms and subject fields, for the generate form. */export function generateOptions(): {
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
  type SubjectAttribute,
  type X509Certificate,
};

/**
 * Turn a posted chain (+ key) into a `SigningIdentity`.
 *
 * The Credo tab reuses the Certificate Studio's chain, which the browser holds
 * and re-sends with every request — nothing is retained server-side.
 */
export async function identityFromRequest(request: {
  chainPem: string;
  keyPem: string;
  didSubjectAttribute?: SubjectAttribute;
}): Promise<SigningIdentity> {
  return parseUploadedIdentity(
    request.chainPem,
    request.keyPem,
    request.didSubjectAttribute ?? 'CN'
  );
}
