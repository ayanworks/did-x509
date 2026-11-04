// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * `secp256k1` certificates are valid X.509, but did:x509 does not support
 * them: Web Crypto has no implementation of the curve, so Node's
 * `subtle.importKey` throws `NotSupportedError: Unrecognized namedCurve`, and
 * the C++ reference resolver (didx509cpp, wrapped by @didx509/native) rejects
 * the same chains with "unsupported EC key curve".
 *
 * These tests pin the actionable error that replaces Web Crypto's message.
 * The fixtures are generated with OpenSSL and are valid until 2126, so they
 * do not need regenerating; the tests skip the validity-period check anyway.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  loadPemCertificateChain,
  verifyCertificateChain,
  verifyCertificateIssuedBy,
  extractPublicKeyAsJwk,
} from '../src/x509.js';

const TEST_DATA_DIR = resolve(import.meta.dirname, '../shared-test-data');

function loadChain(name: string) {
  return loadPemCertificateChain(
    readFileSync(resolve(TEST_DATA_DIR, name), 'utf-8')
  );
}

const UNSUPPORTED_SECP256K1 =
  /unsupported EC curve "secp256k1".*did:x509 supports P-256, P-384 and P-521/;

describe('secp256k1 certificates', () => {
  it('rejects a secp256k1 leaf during chain verification', async () => {
    const chain = loadChain('secp256k1-leaf.pem');

    await expect(verifyCertificateChain(chain, true)).rejects.toThrow(
      /unsupported EC curve "secp256k1" in leaf certificate/
    );
  });

  it('rejects a secp256k1 CA and names its position in the chain', async () => {
    // A P-256 leaf signed by a secp256k1 root. The leaf itself is usable, so
    // only a check that covers every certificate in the chain catches this.
    const chain = loadChain('secp256k1-ca.pem');

    await expect(verifyCertificateChain(chain, true)).rejects.toThrow(
      /unsupported EC curve "secp256k1" in certificate at index 1/
    );
  });

  it('rejects a secp256k1 issuer key in verifyCertificateIssuedBy', async () => {
    const [leaf, issuer] = loadChain('secp256k1-ca.pem');

    await expect(
      verifyCertificateIssuedBy(leaf!, issuer!)
    ).rejects.toThrow(
      /unsupported EC curve "secp256k1" in issuer certificate/
    );
  });

  it('rejects a secp256k1 leaf key in extractPublicKeyAsJwk', async () => {
    const [leaf] = loadChain('secp256k1-leaf.pem');

    await expect(extractPublicKeyAsJwk(leaf!)).rejects.toThrow(
      UNSUPPORTED_SECP256K1
    );
  });
});
