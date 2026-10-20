// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * The public resolve functions. All heavy lifting happens in Microsoft's
 * didx509cpp (the same code the C++ reference implementation runs); this
 * module only passes inputs through and shapes the results.
 */

import { binding } from './binding.js';
import { Didx509Error, toDidx509Error } from './errors.js';
import type { DidDocument, JsonWebKey, ResolveOptions } from './types.js';

function ignoreTimeFrom(options?: ResolveOptions): boolean {
  return Boolean(options?.ignoreTime ?? options?.skipValidityPeriodCheck);
}

function assertString(name: string, value: unknown): asserts value is string {
  if (typeof value !== 'string') {
    throw new TypeError(`${name} must be a string`);
  }
}

function parseJson<T>(json: string, what: string): T {
  try {
    return JSON.parse(json) as T;
  } catch {
    throw new Didx509Error(`the resolver returned invalid ${what} JSON`);
  }
}

/**
 * Resolves a did:x509 DID from a PEM certificate chain (leaf first).
 *
 * Throws a `Didx509Error` when the chain does not satisfy the DID — the
 * message is produced verbatim by the C++ resolver.
 *
 * ```ts
 * const doc = await resolveDidFromPem(
 *   'did:x509:0:sha256:...::subject:CN%3Dexample.com',
 *   readFileSync('chain.pem', 'utf8')
 * );
 * ```
 */
export async function resolveDidFromPem(
  did: string,
  pemChain: string,
  options?: ResolveOptions
): Promise<DidDocument> {
  assertString('did', did);
  assertString('pemChain', pemChain);
  let json: string;
  try {
    json = await binding.resolve(pemChain, did, ignoreTimeFrom(options));
  } catch (error) {
    throw toDidx509Error(error);
  }
  const document = parseJson<DidDocument>(json, 'DID document');
  if (typeof document.id !== 'string') {
    throw new Didx509Error('the resolver returned an invalid DID document');
  }
  return document;
}

/**
 * Synchronous variant of {@link resolveDidFromPem}. Runs the certificate
 * path validation on the current thread — fine for occasional resolutions,
 * prefer the async form in request handlers.
 */
export function resolveDidFromPemSync(
  did: string,
  pemChain: string,
  options?: ResolveOptions
): DidDocument {
  assertString('did', did);
  assertString('pemChain', pemChain);
  let json: string;
  try {
    json = binding.resolveSync(pemChain, did, ignoreTimeFrom(options));
  } catch (error) {
    throw toDidx509Error(error);
  }
  const document = parseJson<DidDocument>(json, 'DID document');
  if (typeof document.id !== 'string') {
    throw new Didx509Error('the resolver returned an invalid DID document');
  }
  return document;
}

/**
 * Resolves a did:x509 DID and returns only the leaf certificate's public
 * key as a JSON Web Key.
 */
export async function resolveJwk(
  did: string,
  pemChain: string,
  options?: ResolveOptions
): Promise<JsonWebKey> {
  assertString('did', did);
  assertString('pemChain', pemChain);
  let json: string;
  try {
    json = await binding.resolveJwk(pemChain, did, ignoreTimeFrom(options));
  } catch (error) {
    throw toDidx509Error(error);
  }
  return parseJson<JsonWebKey>(json, 'JWK');
}

/** Synchronous variant of {@link resolveJwk}. */
export function resolveJwkSync(
  did: string,
  pemChain: string,
  options?: ResolveOptions
): JsonWebKey {
  assertString('did', did);
  assertString('pemChain', pemChain);
  let json: string;
  try {
    json = binding.resolveJwkSync(pemChain, did, ignoreTimeFrom(options));
  } catch (error) {
    throw toDidx509Error(error);
  }
  return parseJson<JsonWebKey>(json, 'JWK');
}

/**
 * Returns the upstream didx509cpp commit this package was built against.
 * Useful for bug reports and audit records.
 */
export function didx509Version(): string {
  return binding.version();
}
