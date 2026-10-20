// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Helpers for turning base64url-encoded DER certificates (the `x509chain`
 * resolution option used by did-resolver) into the PEM format the C++
 * resolver expects.
 */

import { Didx509Error } from './errors.js';

/** Decodes one base64url-encoded value into raw bytes. */
function base64urlToBuffer(value: string): Buffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding =
    normalized.length % 4 === 0
      ? ''
      : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, 'base64');
}

/** Wraps raw DER bytes as a PEM certificate. */
export function derCertificateToPem(der: Uint8Array): string {
  const lines = Buffer.from(der).toString('base64').match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
}

/**
 * Converts an `x509chain` value (comma-separated base64url DER
 * certificates, leaf first) into a concatenated PEM chain.
 *
 * ```ts
 * const pem = x509ChainToPem('MIIBzjCC...,MIIBhTCC...');
 * ```
 */
export function x509ChainToPem(x509chain: string): string {
  return x509chain
    .split(',')
    .map((entry) => {
      const trimmed = entry.trim();
      if (trimmed === '') {
        throw new Didx509Error(
          'x509chain contains an empty certificate entry'
        );
      }
      return derCertificateToPem(base64urlToBuffer(trimmed));
    })
    .join('\n');
}
