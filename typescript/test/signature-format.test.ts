// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Regression tests for the signature-format branch in
 * `verifyCertificateIssuedBy` (exercised through `verifyCertificateChain`).
 *
 * X.509 stores ECDSA signatures in DER form, but Web Crypto needs raw r||s, so
 * the conversion must be driven by the certificate's declared signature
 * algorithm. The previous implementation sniffed the first byte for a DER
 * SEQUENCE tag (`0x30`), which misclassifies RSA signatures: RSA signature
 * values are essentially random byte strings, so roughly 1 in 256 begins with
 * `0x30` and was fed through a bogus DER→raw conversion, corrupting it.
 *
 * Certificates are generated fresh here so the tests do not depend on the
 * expiry of the checked-in fixtures, and the RSA case deliberately searches
 * for the colliding leading byte rather than waiting for it by chance.
 */

import { describe, it, expect } from 'vitest';
import {
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
  X509CertificateGenerator,
} from '@peculiar/x509';
import { verifyCertificateChain } from '../src/x509.js';
import { tamperSerialNumber } from './helpers/certificates.js';

const EC_P256: EcKeyGenParams = { name: 'ECDSA', namedCurve: 'P-256' };
const RSA_2048: RsaHashedKeyGenParams = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
};

/** A freshly generated self-signed root plus a leaf signed by it. */
interface GeneratedChain {
  chain: X509Certificate[];
  /** First byte of the leaf's signature, used by the byte-collision test. */
  leafSignatureFirstByte: number;
}

async function makeChain(
  algorithm: RsaHashedKeyGenParams | EcKeyGenParams
): Promise<GeneratedChain> {
  const now = new Date();
  const notBefore = new Date(now.getTime() - 60_000);
  const notAfter = new Date(now.getTime() + 60 * 60 * 1000);

  const caKeys = (await crypto.subtle.generateKey(algorithm, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const leafKeys = (await crypto.subtle.generateKey(algorithm, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;

  const ca = await X509CertificateGenerator.create({
    serialNumber: '01',
    subject: 'C=US,CN=Regression Root CA',
    issuer: 'C=US,CN=Regression Root CA',
    notBefore,
    notAfter,
    publicKey: caKeys.publicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm: algorithm,
    extensions: [],
  });

  const leaf = await X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'C=US,CN=Regression Leaf',
    issuer: 'C=US,CN=Regression Root CA',
    notBefore,
    notAfter,
    publicKey: leafKeys.publicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm: algorithm,
    extensions: [new KeyUsagesExtension(KeyUsageFlags.digitalSignature)],
  });

  const leafCert = new X509Certificate(leaf.rawData);
  return {
    chain: [leafCert, new X509Certificate(ca.rawData)],
    leafSignatureFirstByte: new Uint8Array(leafCert.signature)[0]!,
  };
}

/**
 * Generate RSA chains until the leaf's signature begins with `0x30`.
 *
 * This is the exact input the old byte heuristic got wrong. Expected to
 * succeed within a few hundred attempts (~1/256 chance per try); the cap is
 * only a guard against a pathological run.
 */
async function makeRsaChainWithSignatureByte(byte: number): Promise<X509Certificate[]> {
  for (let attempt = 0; attempt < 3000; attempt += 1) {
    const { chain, leafSignatureFirstByte } = await makeChain(RSA_2048);
    if (leafSignatureFirstByte === byte) return chain;
  }
  throw new Error(
    `could not generate an RSA chain whose signature starts with 0x${byte.toString(16)}`
  );
}

describe('verifyCertificateChain signature-format handling', () => {
  it('verifies a fresh ECDSA chain', async () => {
    const { chain } = await makeChain(EC_P256);
    await expect(verifyCertificateChain(chain, true)).resolves.toBeUndefined();
  });

  it('verifies a fresh RSA chain', async () => {
    const { chain } = await makeChain(RSA_2048);
    await expect(verifyCertificateChain(chain, true)).resolves.toBeUndefined();
  });

  // The regression that motivated the fix: an RSA signature whose first byte
  // happens to be the DER SEQUENCE tag. The old code ran the ECDSA DER→raw
  // conversion on it and verification failed for a valid chain.
  //
  // Generating RSA keypairs until the colliding byte appears is inherently
  // probabilistic (~1 in 256 per attempt), so this test gets its own generous
  // timeout rather than the suite default.
  it(
    'verifies a valid RSA chain whose signature begins with 0x30',
    { timeout: 60_000 },
    async () => {
      const chain = await makeRsaChainWithSignatureByte(0x30);
      await expect(verifyCertificateChain(chain, true)).resolves.toBeUndefined();
    }
  );

  it('rejects an RSA chain whose signed bytes were modified', async () => {
    const { chain } = await makeChain(RSA_2048);
    const tampered = tamperSerialNumber(chain[0]!);
    await expect(
      verifyCertificateChain([tampered, chain[1]!], true)
    ).rejects.toThrow('signature verification failed');
  });

  it('rejects an ECDSA chain whose signed bytes were modified', async () => {
    const { chain } = await makeChain(EC_P256);
    const tampered = tamperSerialNumber(chain[0]!);
    await expect(
      verifyCertificateChain([tampered, chain[1]!], true)
    ).rejects.toThrow('signature verification failed');
  });
});
