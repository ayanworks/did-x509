// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Parameterised credential signing and verification.
 *
 * The playground's original flows hardcoded one credential per format. Here
 * the caller chooses:
 *
 *   - **which identity signs** — generated or uploaded, with its own key type
 *   - **which credential type** — from a small catalogue of realistic VCs
 *   - **the claims** — edited per credential type
 *
 * Every signed credential carries the signing chain (`x5c`), so a verifier
 * recovers the issuer from the credential itself rather than from side
 * channel. See `lib/issuer.ts` for the verifier's half.
 *
 * ## Why this is one module and not three
 *
 * All three formats share the same padding: pick a signable key, build the
 * claims, sign, embed x5c. Splitting them would mean repeating the key
 * selection and error handling three times. The format-specific parts are
 * isolated in the `sign*` functions.
 */

import 'reflect-metadata';

import { b64url, resolveDidFromPem } from '@didx509/core';
import type { X509Certificate } from '@peculiar/x509';

import { extractIssuerDetails, type IssuerDetails } from './lib/issuer.ts';
import type { SigningIdentity } from './lib/identity.ts';

/** Credential formats the playground can issue. */
export type CredentialFormat = 'jsonld' | 'sd-jwt' | 'mdoc';

/** One editable claim in a credential template. */
export interface ClaimField {
  key: string;
  label: string;
  value: string;
  /** Claims the holder may withhold (SD-JWT only). */
  disclosable?: boolean;
}

/** A credential type the playground offers. */
export interface CredentialTemplate {
  id: string;
  label: string;
  description: string;
  /** JSON-LD `type` values (the first is always VerifiableCredential). */
  types?: string[];
  /** SD-JWT `vct`. */
  vct?: string;
  /** mDoc doctype and namespace. */
  docType?: string;
  namespace?: string;
  claims: ClaimField[];
  /** Formats this template can be issued in. */
  formats: CredentialFormat[];
}

/**
 * The credential catalogue.
 *
 * Each entry is a shape real deployments issue, not a toy: an education
 * credential, an employment badge, and an mDL. Claims are deliberately small
 * and readable so the point is the did:x509 binding, not the payload.
 */
export const TEMPLATES: CredentialTemplate[] = [
  {
    id: 'degree',
    label: 'University Degree',
    description: 'A completed degree, as issued by a university registrar.',
    types: ['UniversityDegreeCredential'],
    vct: 'UniversityDegreeCredential',
    docType: 'org.iso.18013.5.1',
    namespace: 'org.iso.18013.5.1.degree',
    formats: ['jsonld', 'sd-jwt', 'mdoc'],
    claims: [
      { key: 'name', label: 'Holder name', value: 'Alice Example' },
      { key: 'degree', label: 'Degree', value: 'BSc Computer Science' },
      { key: 'institution', label: 'Institution', value: 'Example University' },
      {
        key: 'graduationDate',
        label: 'Graduation date',
        value: '2026-06-30',
        disclosable: true,
      },
      {
        key: 'studentId',
        label: 'Student ID',
        value: 'S-2026-0042',
        disclosable: true,
      },
    ],
  },
  {
    id: 'employee',
    label: 'Employee Badge',
    description: 'An employment credential used for workplace access.',
    types: ['EmployeeBadgeCredential'],
    vct: 'EmployeeBadgeCredential',
    docType: 'org.iso.18013.5.1',
    namespace: 'org.iso.18013.5.1.employee',
    formats: ['jsonld', 'sd-jwt', 'mdoc'],
    claims: [
      { key: 'name', label: 'Holder name', value: 'Bob Example' },
      { key: 'employer', label: 'Employer', value: 'Acme Corporation' },
      { key: 'role', label: 'Role', value: 'Staff Engineer' },
      {
        key: 'employeeId',
        label: 'Employee ID',
        value: 'E-4471',
        disclosable: true,
      },
      {
        key: 'clearance',
        label: 'Clearance level',
        value: 'confidential',
        disclosable: true,
      },
    ],
  },
  {
    id: 'mdl',
    label: 'Mobile Driving Licence',
    description: 'An ISO/IEC 18013-5 mDL, the mDoc reference use case.',
    types: ['DrivingLicenceCredential'],
    vct: 'DrivingLicenceCredential',
    docType: 'org.iso.18013.5.1',
    namespace: 'org.iso.18013.5.1.mDL',
    formats: ['mdoc', 'sd-jwt'],
    claims: [
      { key: 'family_name', label: 'Family name', value: 'Doe' },
      { key: 'given_name', label: 'Given name', value: 'Alice' },
      { key: 'birth_date', label: 'Birth date', value: '1990-05-14' },
      { key: 'document_number', label: 'Licence number', value: 'DL-9931-2026' },
      {
        key: 'driving_privileges',
        label: 'Privileges',
        value: 'B',
        disclosable: true,
      },
    ],
  },
  {
    id: 'invoice',
    label: 'Commercial Invoice',
    description:
      'A cross-border trade invoice: seller, buyer, goods, and the ' +
      'Incoterm that fixes where risk and cost pass.',
    types: ['CommercialInvoiceCredential'],
    vct: 'CommercialInvoiceCredential',
    docType: 'org.iccwbo.ecta',
    namespace: 'org.iccwbo.ecta.invoice',
    formats: ['jsonld', 'sd-jwt', 'mdoc'],
    claims: [
      { key: 'invoiceNumber', label: 'Invoice number', value: 'INV-2026-00184' },
      { key: 'sellerName', label: 'Seller', value: 'Acme Exports Pvt Ltd' },
      { key: 'sellerCountry', label: 'Seller country (ISO 3166)', value: 'IN' },
      { key: 'buyerName', label: 'Buyer', value: 'Nordwind Handels GmbH' },
      { key: 'buyerCountry', label: 'Buyer country (ISO 3166)', value: 'DE' },
      { key: 'goodsDescription', label: 'Goods description', value: 'Cotton woven fabric, dyed' },
      {
        key: 'hsCode',
        label: 'HS commodity code',
        value: '5208.52',
        disclosable: true,
      },
      {
        key: 'invoiceValue',
        label: 'Invoice value',
        value: '18450.00 USD',
        disclosable: true,
      },
      { key: 'incoterms', label: 'Incoterms 2020', value: 'CIF Hamburg' },
      {
        key: 'paymentTerms',
        label: 'Payment terms',
        value: '30 days from bill of lading',
        disclosable: true,
      },
    ],
  },
  {
    id: 'shipping-bill',
    label: 'Shipping Bill',
    description:
      'A customs export declaration: what left the country, on which ' +
      'vessel, from which port, under whose authorisation.',
    types: ['ShippingBillCredential'],
    vct: 'ShippingBillCredential',
    docType: 'org.wco.declaration',
    namespace: 'org.wco.declaration.shippingBill',
    formats: ['jsonld', 'sd-jwt', 'mdoc'],
    claims: [
      { key: 'billNumber', label: 'Shipping bill number', value: 'SB-2026-7742130' },
      { key: 'exporterName', label: 'Exporter', value: 'Acme Exports Pvt Ltd' },
      { key: 'exporterIec', label: 'Exporter IEC', value: '0312045678' },
      { key: 'consigneeName', label: 'Consignee', value: 'Nordwind Handels GmbH' },
      { key: 'portOfLoading', label: 'Port of loading (UN/LOCODE)', value: 'INNSA' },
      { key: 'portOfDischarge', label: 'Port of discharge (UN/LOCODE)', value: 'DEHAM' },
      { key: 'vesselName', label: 'Vessel / voyage', value: 'MV Northern Star / 042E' },
      {
        key: 'containerNumber',
        label: 'Container number',
        value: 'MSCU7742130',
        disclosable: true,
      },
      { key: 'shipmentDate', label: 'Shipment date', value: '2026-11-04' },
      {
        key: 'declaredValue',
        label: 'Declared value (FOB)',
        value: '17980.00 USD',
        disclosable: true,
      },
    ],
  },
];

/** Look up a template by id, failing loudly on an unknown one. */
export function templateById(id: string): CredentialTemplate {
  const template = TEMPLATES.find(entry => entry.id === id);
  if (!template) {
    throw new Error(
      `Unknown credential type "${id}". Available: ${TEMPLATES.map(t => t.id).join(', ')}.`
    );
  }
  return template;
}

/** The signing chain as base64url DER, leaf first — the `x5c` payload. */
export function x5cOf(identity: SigningIdentity): string[] {
  return [identity.leafCertificate, identity.caCertificate].map(certificate =>
    b64url(new Uint8Array(certificate.rawData))
  );
}

/** Raw DER of the signing chain, leaf first — for COSE `x5chain`. */
export function chainDer(identity: SigningIdentity): Uint8Array[] {
  return [identity.leafCertificate, identity.caCertificate].map(
    certificate => new Uint8Array(certificate.rawData)
  );
}

/** A signed credential: the payload plus where its chain was embedded. */
export interface SignedCredential {
  format: CredentialFormat;
  templateId: string;
  /** The serialised credential, ready to copy. */
  payload: string | Record<string, unknown>;
  /** Human-readable summary of the payload for the UI. */
  preview: Record<string, unknown>;
  /** The chain as embedded in the credential. */
  x5c: string[];
}

export interface SignRequest {
  format: CredentialFormat;
  templateId: string;
  claims: Record<string, string>;
  /** Claims the holder withholds (SD-JWT only). */
  withheld?: string[];
}

/** Build the claim set from a template and the caller's overrides. */
function mergeClaims(
  template: CredentialTemplate,
  overrides: Record<string, string>
): Record<string, string> {
  const claims: Record<string, string> = {};
  for (const field of template.claims) {
    claims[field.key] = overrides[field.key] ?? field.value;
  }
  return claims;
}

/** Format-specific signing, dispatched by format. */
export async function signCredential(
  identity: SigningIdentity,
  request: SignRequest
): Promise<SignedCredential> {
  const template = templateById(request.templateId);

  if (!template.formats.includes(request.format)) {
    throw new Error(
      `"${template.label}" cannot be issued as ${request.format}. ` +
        `Supported: ${template.formats.join(', ')}.`
    );
  }

  const claims = mergeClaims(template, request.claims);
  const x5c = x5cOf(identity);
  const verificationMethodId = `${identity.did}#0`;

  switch (request.format) {
    case 'jsonld': {
      const { signJsonLdCredential } = await import('./sign-jsonld.ts');
      const payload = await signJsonLdCredential({
        identity,
        template,
        claims,
        x5c,
        verificationMethodId,
      });
      return {
        format: 'jsonld',
        templateId: template.id,
        payload,
        preview: {
          type: (payload.type as string[])?.join(', '),
          issuer: payload.issuer,
          credentialSubject: payload.credentialSubject,
        },
        x5c,
      };
    }
    case 'sd-jwt': {
      const { signSdJwtCredential } = await import('./sign-sd-jwt.ts');
      const result = await signSdJwtCredential({
        identity,
        template,
        claims,
        x5c,
        withheld: request.withheld ?? [],
      });
      return {
        format: 'sd-jwt',
        templateId: template.id,
        payload: result.presentation,
        preview: {
          vct: template.vct,
          issuer: identity.did,
          disclosed: result.disclosed,
          withheld: result.withheld,
        },
        x5c,
      };
    }
    case 'mdoc': {
      const { signMdocCredential } = await import('./sign-mdoc.ts');
      const result = await signMdocCredential({
        identity,
        template,
        claims,
        chainDer: chainDer(identity),
      });
      return {
        format: 'mdoc',
        templateId: template.id,
        payload: result.base64,
        preview: {
          docType: template.docType,
          namespace: template.namespace,
          claims,
          size: result.size,
        },
        x5c,
      };
    }
    default:
      throw new Error(`Unsupported format: ${request.format}`);
  }
}

/**
 * One named cryptographic check, so the UI can show the verifier's actual
 * working rather than a single opaque pass/fail.
 */
export interface VerificationCheck {
  /** Stable identifier, e.g. `signature`. */
  id: string;
  /** Human-readable name of the check. */
  label: string;
  passed: boolean;
  /** One line explaining what was checked and what came back. */
  detail: string;
  /**
   * True when the check could not be run at all (e.g. no chain to inspect).
   * Distinguishing "skipped" from "failed" matters: a missing chain should not
   * be reported as a forged signature.
   */
  skipped?: boolean;
}

/** What a verifier learns: the verdict, the issuer, and any error. */
export interface VerificationOutcome {
  format: CredentialFormat;
  /** The cryptographic verdict for the credential's own signature. */
  signatureValid: boolean;
  /** The issuer recovered from the credential's embedded chain. */
  issuer?: IssuerDetails;
  /** The individual checks behind `signatureValid`, in the order they ran. */
  checks: VerificationCheck[];
  error?: string;
}

/**
 * Verify a credential and recover its issuer.
 *
 * Two independent checks, reported separately because they fail for different
 * reasons:
 *
 *   1. **signatureValid** — the credential's signature verifies against the
 *      public key in its own embedded chain.
 *   2. **issuer.didMatchesChain** — the chain actually reproduces the DID the
 *      credential claims. A valid signature over a chain that does not match
 *      the asserted DID would mean an issuer misrepresenting itself.
 */
export async function verifyCredentialPayload(
  payload: string | Record<string, unknown>,
  format: CredentialFormat
): Promise<VerificationOutcome> {
  try {
    switch (format) {
      case 'jsonld': {
        const credential = payload as Record<string, unknown>;
        const x5c = (await import('./lib/issuer.ts')).x5cFromProof(credential);
        const { verifyJsonLdCredential } = await import('./sign-jsonld.ts');
        const signatureValid = await verifyJsonLdCredential(credential);
        const issuer = await extractIssuerDetails(
          x5c,
          String(credential.issuer ?? ''),
          'x5c (JSON-LD proof)'
        );
        return {
          format,
          signatureValid,
          issuer,
          checks: verificationChecks(credential, 'eddsa-rdfc-2022', x5c, issuer, signatureValid),
        };
      }
      case 'sd-jwt': {
        const compact = payload as string;
        const { x5cFromCompactSdJwt } = await import('./lib/issuer.ts');
        const x5c = x5cFromCompactSdJwt(compact);
        const { verifySdJwtCredential } = await import('./sign-sd-jwt.ts');
        const { signatureValid, issuer: iss } = await verifySdJwtCredential(compact);
        const issuer = await extractIssuerDetails(x5c, iss, 'x5c (JWT header)');
        return {
          format,
          signatureValid,
          issuer,
          checks: verificationChecks(compact, 'ES256', x5c, issuer, signatureValid),
        };
      }
      case 'mdoc': {
        const { verifyMdocCredential } = await import('./sign-mdoc.ts');
        const result = await verifyMdocCredential(payload as string);
        // mDoc has no issuer field: `issuerDid` is derived from the chain, so
        // the comparison below is trivially true by construction. It is still
        // run, because it validates that the chain reproduces a well-formed
        // did:x509 DID at all.
        const issuer = await extractIssuerDetails(
          result.x5c,
          result.issuerDid,
          'x5chain (COSE)'
        );
        return {
          format,
          signatureValid: result.signatureValid,
          issuer,
          checks: verificationChecks(payload as string, 'ES256', result.x5c, issuer, result.signatureValid),
        };
      }
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  } catch (error) {
    const message = (error as Error).message;
    // A failure to verify is still a result the verifier should see in full.
    // Re-derive whatever the payload itself reveals, so the checklist says
    // *which* check failed instead of collapsing everything into one line.
    const x5c = await inspectChain(payload, format);
    const issuer = x5c.length
      ? await extractIssuerDetails(x5c, claimedDidOf(payload, format), chainSourceOf(format)).catch(() => undefined)
      : undefined;
    return {
      format,
      signatureValid: false,
      issuer,
      checks: verificationChecks(
        payload,
        algorithmOf(format),
        x5c,
        issuer,
        false,
        message
      ),
      error: message,
    };
  }
}

/** The chain a payload carries, or `[]` — never throws. */
async function inspectChain(
  payload: string | Record<string, unknown>,
  format: CredentialFormat
): Promise<string[]> {
  try {
    const { x5cFromProof, x5cFromCompactSdJwt, x5cFromJoseHeader } =
      await import('./lib/issuer.ts');
    if (format === 'jsonld') return x5cFromProof(payload);
    if (format === 'mdoc') {
      // The COSE x5chain is only readable from a decodable mDoc; treat a
      // malformed one as carrying no chain.
      const { verifyMdocCredential } = await import('./sign-mdoc.ts');
      try {
        return (await verifyMdocCredential(payload as string)).x5c;
      } catch {
        return [];
      }
    }
    return x5cFromCompactSdJwt(payload as string);
  } catch {
    return [];
  }
}

/** The DID a payload claims, for display. Never throws. */
function claimedDidOf(
  payload: string | Record<string, unknown>,
  format: CredentialFormat
): string {
  try {
    if (format === 'jsonld') return String((payload as Record<string, unknown>).issuer ?? '');
    if (format === 'mdoc') return ''; // mDoc carries no issuer of its own.
    // SD-JWT: the `iss` claim sits in the (unverified) payload segment. A
    // tampered payload may not decode at all, in which case there is no
    // claimed DID to compare against.
    const segment = String(payload).split('~')[0].split('.')[1];
    if (!segment) return '';
    const json = atob(segment.replace(/-/g, '+').replace(/_/g, '/'));
    return String((JSON.parse(json) as { iss?: unknown }).iss ?? '');
  } catch {
    return '';
  }
}

/** Where a given format keeps its chain, for the display label. */
function chainSourceOf(format: CredentialFormat): 'x5c (JSON-LD proof)' | 'x5c (JWT header)' | 'x5chain (COSE)' {
  return format === 'jsonld'
    ? 'x5c (JSON-LD proof)'
    : format === 'mdoc'
      ? 'x5chain (COSE)'
      : 'x5c (JWT header)';
}

/** The signature algorithm a format uses here. */
function algorithmOf(format: CredentialFormat): string {
  return format === 'jsonld' ? 'eddsa-rdfc-2022' : 'ES256';
}

/**
 * Build the named checks shown to the verifier, in the order they are run.
 *
 * These report facts the verifier actually established, not a restatement of
 * the verdict: which algorithm was used, which key it was checked against, and
 * whether the chain the key came from reproduces the DID the credential claims.
 */
function verificationChecks(
  payload: string | Record<string, unknown>,
  algorithm: string,
  x5c: string[],
  issuer: IssuerDetails | undefined,
  signatureValid: boolean,
  failureReason?: string
): VerificationCheck[] {
  const checks: VerificationCheck[] = [];

  checks.push({
    id: 'chain',
    label: 'Chain embedded in the credential',
    passed: x5c.length > 0,
    detail: x5c.length
      ? `${x5c.length} certificate(s) recovered from the credential alone.`
      : 'No x5c chain found — the issuer cannot be recovered from the credential.',
    skipped: x5c.length === 0,
  });

  const leaf = issuer?.certificates[0];
  checks.push({
    id: 'signature',
    label: 'Issuer signature',
    passed: signatureValid,
    detail: signatureValid && leaf
      ? `Checked ${algorithm} against the leaf public key (${leaf.keyType}).`
      : failureReason
        ? `Could not be checked: ${failureReason}`
        : `Checked ${algorithm}; the signature did not verify.`,
    skipped: Boolean(failureReason) && !signatureValid,
  });

  if (issuer) {
    const hasClaim = Boolean(issuer.claimedDid);
    checks.push({
      id: 'did',
      label: 'DID matches the chain',
      passed: issuer.didMatchesChain && hasClaim,
      detail: !hasClaim
        ? `The credential's issuer DID could not be read, so it cannot be checked against the chain.`
        : issuer.didMatchesChain
          ? `The chain reproduces ${issuer.derivedDid}.`
          : `The credential claims ${issuer.claimedDid}, but the chain reproduces ${issuer.derivedDid}.`,
    });
  }

  // The leaf must be valid now for the signature to mean anything today.
  checks.push({
    id: 'validity',
    label: 'Issuer certificate in date',
    passed: Boolean(leaf) && !leaf!.expired && !leaf!.notYetValid,
    detail: leaf
      ? leaf.expired
        ? `The leaf expired on ${leaf.notAfter.slice(0, 10)}.`
        : leaf.notYetValid
          ? `The leaf is not valid before ${leaf.notBefore.slice(0, 10)}.`
          : `Valid ${leaf.notBefore.slice(0, 10)} to ${leaf.notAfter.slice(0, 10)}.`
      : 'No leaf certificate to check.',
    skipped: !leaf,
  });

  // The leaf must be permitted to sign credentials, or the signature is out
  // of scope for the certificate even though it verifies cryptographically.
  if (leaf) {
    checks.push({
      id: 'usage',
      label: 'Leaf permitted to sign',
      passed: leaf.extensions.canSign,
      detail: leaf.extensions.canSign
        ? `Key usage allows signing${leaf.signatureAlgorithm ? ` (${leaf.signatureAlgorithm})` : ''}.`
        : 'The leaf has no digitalSignature / nonRepudiation key usage.',
    });
  }

  // Withheld-claim integrity is SD-JWT specific: a disclosure that does not
  // hash to its digest means the holder substituted a claim value.
  //
  // `sdjwt.verify()` checks the disclosures as part of the same call as the
  // signature, so this cannot be reported as a separate pass: when the overall
  // verification failed it is unknown which of the two failed.
  if (algorithm === 'ES256' && typeof payload === 'string' && payload.includes('~')) {
    checks.push({
      id: 'disclosures',
      label: 'Disclosures match their digests',
      passed: signatureValid,
      skipped: !signatureValid,
      detail: signatureValid
        ? 'Each disclosed claim was hashed and compared to its signed digest.'
        : 'Not separately determined: verification failed before this could be checked alone.',
    });
  }

  return checks;
}

/** Resolve the DID document for an identity, for display. */
export async function didDocumentOf(identity: SigningIdentity) {
  return resolveDidFromPem(identity.did, identity.pemChain);
}

export type { X509Certificate };
