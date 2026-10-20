// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Types for @didx509/native. The shapes match @didx509/core so the two
 * packages can be swapped without touching application code.
 */

/** A JSON Web Key (public key). */
export type JsonWebKey = Record<string, unknown>;

/** A DID document verification method. */
export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk: JsonWebKey;
}

/** A W3C DID document. */
export interface DidDocument {
  '@context': string;
  id: string;
  verificationMethod: VerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
}

/** Options accepted by the resolve functions. */
export interface ResolveOptions {
  /**
   * Skip certificate validity-period checks. Use this to resolve historical
   * DIDs (for example for audit purposes). Defaults to false.
   *
   * This is the same option as `skipValidityPeriodCheck` on @didx509/core —
   * either name works here, so existing call sites keep functioning.
   */
  ignoreTime?: boolean;
  /** Alias for `ignoreTime` (the @didx509/core spelling). */
  skipValidityPeriodCheck?: boolean;
}

/** A DID resolution result, as returned by the did-resolver plugin. */
export interface DidResolutionResult {
  didResolutionMetadata: Record<string, unknown>;
  didDocument: DidDocument | null;
  didDocumentMetadata: Record<string, unknown>;
}
