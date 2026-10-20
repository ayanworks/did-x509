// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Which signing algorithms each credential format permits, and which of those
 * this playground can actually produce.
 *
 * This module exists because those two things are not the same, and conflating
 * them caused a real bug. `sign-mdoc.ts` once documented "mDoc here signs
 * ES256, so the leaf key must be EC P-256" as though the *format* were
 * ES256-only. It is not — mDoc's `issuerAuth` is COSE_Sign1 and COSE carries the
 * full IANA algorithm set. The limitation was ours.
 *
 * Having corrected that, it is just as important not to overcorrect. Dropping
 * the ES256-only assumption made the other EC curves work, but it did **not**
 * make RSA work, and the reason is a hard one: `@owf/cose`, the COSE library
 * underneath `@owf/mdoc`, has no RSA key type. Its `KeyType` enum is
 * `{Okp, Ec, Oct, Reserved}` — no RSA — and its JWK mapping has no `n`/`e`
 * entries, so `CoseKey.fromJwk` silently drops an RSA modulus and exponent. A
 * signing callback written to accept RSA is never handed a usable key.
 *
 * So each format carries two lists:
 *
 *   - `spec`  — what the format allows, per its specification.
 *   - `wired` — what this playground can actually produce today.
 *
 * The UI offers the intersection with the loaded key's type, and when a format
 * is unavailable it says which of the two is the reason. That distinction is
 * the whole point of keeping both lists: "the spec does not allow this" and
 * "our dependency does not implement it" are different answers, and a reader
 * deserves to know which one they are getting.
 *
 * Sources, all normative except the last:
 *   - mDoc (ISO/IEC 18013-5): `issuerAuth` is COSE_Sign1; the signature
 *     algorithm is a COSE `alg` value from the IANA COSE Algorithms registry.
 *   - SD-JWT (RFC 9901 §4.3): the JWS `alg` header MUST NOT be "none"; any JWS
 *     algorithm identifier from the IANA registry is permitted.
 *   - JSON-LD Data Integrity (W3C `eddsa-rdfc-2022`): the cryptosuite is
 *     defined for Ed25519 only. This is a genuine format constraint.
 *   - `@owf/cose` `KeyType` and `jwkCoseKeyMap`: the implementation boundary,
 *     read from the package's own dist output rather than assumed.
 */

/** A signature algorithm, named the way JWKs and COSE both understand it. */
export type SigningAlgorithm =
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'EdDSA'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'RS256'
  | 'RS384'
  | 'RS512';

/** Credential formats this playground signs. */
export type FormatName = 'jsonld' | 'sd-jwt' | 'mdoc';

/** The key shapes our generator can produce, and Web Crypto can name. */
export interface KeyProfile {
  /** Matches `GenAlgorithm` in `lib/generate.ts`. */
  genAlgorithm: string;
  /** Label shown in the capability matrix. */
  label: string;
  /** JWK key type, e.g. `EC`, `OKP`, `RSA`. */
  kty: string;
  /** JWK curve, where the key type has one. */
  crv?: string;
  /** How the key type is described in the matrix, e.g. "EC P-256". */
  description: string;
}

/**
 * Every key profile the generator offers.
 *
 * A key appears here even when no format can use it, so the matrix can explain
 * the gap rather than omit the row and leave the reader wondering.
 */
export const KEY_PROFILES: KeyProfile[] = [
  {
    genAlgorithm: 'P-256',
    label: 'EC P-256',
    kty: 'EC',
    crv: 'P-256',
    description: 'ECDSA, 256-bit prime field',
  },
  {
    genAlgorithm: 'P-384',
    label: 'EC P-384',
    kty: 'EC',
    crv: 'P-384',
    description: 'ECDSA, 384-bit prime field',
  },
  {
    genAlgorithm: 'P-521',
    label: 'EC P-521',
    kty: 'EC',
    crv: 'P-521',
    description: 'ECDSA, 521-bit prime field',
  },
  {
    genAlgorithm: 'Ed25519',
    label: 'Ed25519',
    kty: 'OKP',
    crv: 'Ed25519',
    description: 'Edwards-curve EdDSA',
  },
  {
    genAlgorithm: 'RSA-2048',
    label: 'RSA-2048',
    kty: 'RSA',
    description: 'RSASSA-PKCS1-v1_5, 2048-bit modulus',
  },
  {
    genAlgorithm: 'RSA-4096',
    label: 'RSA-4096',
    kty: 'RSA',
    description: 'RSASSA-PKCS1-v1_5, 4096-bit modulus',
  },
];

/** Look up a profile by an identity's leaf public JWK. */
export function keyProfileFor(identity: {
  leafPublicJwk: JsonWebKey;
}): KeyProfile | undefined {
  const { kty, crv } = identity.leafPublicJwk;
  return KEY_PROFILES.find(
    profile => profile.kty === kty && (profile.crv ?? undefined) === (crv ?? undefined)
  );
}

/** Why a format is or is not available for a given key. */export type FormatAvailability =
  /** The key can sign this format today. */
  | { state: 'available'; algorithm: SigningAlgorithm }
  /** The spec allows it, but our dependency does not implement it. */
  | { state: 'implementation-gap'; reason: string }
  /** The format itself is not defined for this key type. */
  | { state: 'spec-excluded'; reason: string }
  /** No key type at all can produce it here (should not occur; a guard). */
  | { state: 'unavailable'; reason: string };

/** What each format permits per its spec, and what we have wired up. */
export const FORMAT_ALGORITHMS: Record<
  FormatName,
  { spec: SigningAlgorithm[]; wired: SigningAlgorithm[]; note: string }
> = {
  jsonld: {
    // W3C VC Data Integrity EdDSA cryptosuite: Ed25519 only, by definition.
    spec: ['EdDSA'],
    wired: ['EdDSA'],
    note: 'The eddsa-rdfc-2022 cryptosuite is defined for Ed25519 only.',
  },
  'sd-jwt': {
    // RFC 9901: any IANA JWS alg except "none".
    spec: [
      'ES256',
      'ES384',
      'ES512',
      'EdDSA',
      'PS256',
      'PS384',
      'PS512',
      'RS256',
      'RS384',
      'RS512',
    ],
    wired: ['ES256', 'ES384', 'ES512', 'RS256'],
    note: 'RFC 9901 permits any IANA JWS algorithm except "none". EC keys use ES256/384/512; RSA keys use RS256.',
  },
  mdoc: {
    // ISO/IEC 18013-5 issuerAuth is COSE_Sign1; `alg` is a COSE value.
    spec: [
      'ES256',
      'ES384',
      'ES512',
      'EdDSA',
      'PS256',
      'PS384',
      'PS512',
      'RS256',
      'RS384',
      'RS512',
    ],
    wired: ['ES256', 'ES384', 'ES512'],
    note: 'COSE permits the full IANA algorithm set, but @owf/cose implements EC keys only — it has no RSA key type, so RSA mDocs cannot be produced.',
  },
};

/** How each key type maps to an algorithm, per format. */
const KEY_ALGORITHMS: Record<
  string,
  Partial<Record<FormatName, SigningAlgorithm>>
> = {
  'P-256': { 'sd-jwt': 'ES256', mdoc: 'ES256' },
  'P-384': { 'sd-jwt': 'ES384', mdoc: 'ES384' },
  'P-521': { 'sd-jwt': 'ES512', mdoc: 'ES512' },
  Ed25519: { jsonld: 'EdDSA' },
  // RSA works for SD-JWT but not mDoc: see the module comment.
  'RSA-2048': { 'sd-jwt': 'RS256' },
  'RSA-4096': { 'sd-jwt': 'RS256' },
};

/**
 * Explain whether a key profile can sign a format, and if not, why.
 *
 * The three failure states are deliberately distinct. Collapsing them into a
 * single "not supported" is what made the original dropdown unhelpful: a reader
 * could not tell whether they had chosen a bad key or hit a library limit.
 */
export function availabilityOf(
  genAlgorithm: string,
  format: FormatName
): FormatAvailability {
  const profile = KEY_PROFILES.find(p => p.genAlgorithm === genAlgorithm);
  if (!profile) {
    return { state: 'unavailable', reason: `Unknown key type "${genAlgorithm}".` };
  }
  const algorithms = KEY_ALGORITHMS[genAlgorithm] ?? {};
  const algorithm = algorithms[format];
  if (algorithm) return { state: 'available', algorithm };

  // A key type with no algorithm for this format. Whether the *spec* would
  // allow one decides how the gap is described, so separate the two cases.
  const keyTypeAllowedBySpec =
    profile.kty === 'EC' ||
    profile.kty === 'RSA' ||
    (profile.kty === 'OKP' && profile.crv === 'Ed25519');

  if (!keyTypeAllowedBySpec) {
    return {
      state: 'spec-excluded',
      reason: `${profile.label} has no algorithm registered for ${format}.`,
    };
  }

  if (format === 'jsonld') {
    return {
      state: 'spec-excluded',
      reason: `${profile.label} is not Ed25519, and eddsa-rdfc-2022 is Ed25519 only.`,
    };
  }

  if (format === 'mdoc' && profile.kty === 'RSA') {
    return {
      state: 'implementation-gap',
      reason:
        'COSE allows RSA here, but @owf/cose (the COSE layer under @owf/mdoc) has no RSA key type, so it cannot carry an RSA mDoc. Use SD-JWT for RSA.',
    };
  }

  if (profile.kty === 'OKP') {
    return {
      state: 'implementation-gap',
      reason: `${format} permits EdDSA, but this playground's crypto backend ships no Ed25519 signing suite for ${format}.`,
    };
  }

  return {
    state: 'unavailable',
    reason: `No ${format} algorithm is wired for the ${profile.label} key.`,
  };
}

/**
 * A compact description of a format's algorithm story, for the page.
 *
 * Kept here rather than in markup so the matrix and the format dropdown cannot
 * drift apart: both read the same table.
 */
export function formatSummary(format: FormatName): string {
  return FORMAT_ALGORITHMS[format].note;
}

/* -------------------------------------------------------------------------
 * Credo / Askar compatibility
 *
 * A separate question from "what can this playground sign". The Studio signs
 * in-process with Web Crypto, which handles essentially any key Web Crypto can
 * import. The Credo flow instead hands the private key to **Askar**, through
 * Credo's KMS, and Askar's key support is much narrower.
 *
 * Read from `@credo-ts/askar`'s own `AskarKeyManagementService`:
 *
 *   - `isOperationSupported` accepts `importKey` only when `kty` is `EC` or
 *     `OKP` **and** the curve appears in `jwkCrvToAskarAlg`. Anything else
 *     returns false, which is why an RSA import fails at the KMS registry with
 *     "No key management service backend found that supports 'importKey'".
 *   - `jwkCrvToAskarAlg` covers secp256k1, P-256, P-384, X25519 and Ed25519.
 *     P-521 is absent.
 *   - `algToSigType` covers EdDSA, ES256K, ES256 and ES384 — so even if a
 *     P-521 key were importable, there would be no ES512 to sign with.
 *
 * This is an upstream limit, not our wiring, so it is surfaced rather than
 * worked around: the Studio keeps the full key range and the Credo tab says
 * plainly which keys it cannot take and why.
 * ---------------------------------------------------------------------- */

/** Whether the Credo (Askar-backed) flow can import and use a key type. */
export interface CredoKeySupport {
  supported: boolean;
  /** A short explanation, present when `supported` is false. */
  reason?: string;
}

/** The key types Askar's KMS accepts, as `GenAlgorithm` values. */
const ASKAR_SUPPORTED_KEYS = new Set(['P-256', 'P-384', 'Ed25519']);

/** Explain whether the Credo flow can use a generated key type. */
export function credoKeySupportFor(genAlgorithm: string): CredoKeySupport {
  if (ASKAR_SUPPORTED_KEYS.has(genAlgorithm)) return { supported: true };
  if (genAlgorithm === 'P-521') {
    return {
      supported: false,
      reason:
        'Askar (the wallet backing the Credo flow) has no P-521 support — P-521 is missing from its curve list, and it offers no ES512 signing. The Certificate Studio still signs P-521 credentials locally.',
    };
  }
  if (genAlgorithm.startsWith('RSA')) {
    return {
      supported: false,
      reason:
        'Askar (the wallet backing the Credo flow) cannot hold RSA keys — its KMS accepts only EC and OKP key types. The Certificate Studio still signs RSA credentials locally, using SD-JWT.',
    };
  }
  return {
    supported: false,
    reason: `Askar (the wallet backing the Credo flow) has no support for the ${genAlgorithm} key type.`,
  };
}

