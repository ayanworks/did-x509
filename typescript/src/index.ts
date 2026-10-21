// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * @didx509/core - TypeScript implementation of the did:x509 DID method.
 *
 * Bridges X.509 certificate infrastructure with W3C Decentralized Identifiers.
 */

// `@peculiar/x509` pulls in `tsyringe`, whose CommonJS build throws unless the
// `reflect-metadata` polyfill is loaded first. Importing it here means consumers
// do not have to know that, and it is the first thing this package does — the
// polyfill has to run before `tsyringe`, which loading this entry point triggers.
import 'reflect-metadata';

// Core resolution
export {
  parseDid,
  checkDidX509,
  createDidDocument,
  resolveDid,
  resolveDidFromPem,
  convertChain,
} from './didx509.js';

// X.509 operations
export {
  loadPemCertificateChain,
  loadDerCertificateChain,
  loadX509Chain,
  decodeCertificate,
  verifyCertificateChain,
  extractPublicKeyAsJwk,
  computeFingerprint,
  computeFingerprintAsync,
  getKeyUsage,
} from './x509.js';

// Runtime capability probe (Node built-ins)
export { getNodeCrypto } from './node-crypto.js';

// Encoding utilities
export {
  b64url,
  b64urlDecode,
  pctEncode,
  pctDecode,
  parseNameString,
  oidToLabel,
} from './encoding.js';

// did-resolver plugin (optional)
export { getDidX509Resolver } from './did-resolver-plugin.js';

// Types
export type {
  CertificateFingerprint,
  CertificateName,
  CertificateExtensions,
  DecodedCertificate,
  DidDocument,
  VerificationMethod,
  ResolveOptions,
  FingerprintAlgorithm,
  PredicateName,
  ParsedDid,
} from './types.js';
