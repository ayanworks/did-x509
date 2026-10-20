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

/**
 * Attempt cap for the RSA leading-byte search.
 *
 * Each attempt succeeds with probability 1/256, so 10000 attempts leaves a
 * failure probability of (255/256)^10000 ≈ 10^-17 — small enough that a flake
 * means something is genuinely wrong rather than bad luck.
 */
const RSA_COLLISION_ATTEMPTS = 10_000;

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
 * This is the exact input the old byte heuristic got wrong. Each attempt has a
 * ~1/256 chance, so the loop is inherently probabilistic and must be given
 * enough headroom to be reliable on a slow CI runner.
 *
 * The CA keypair is generated once and reused: only the leaf's signature is
 * measured, so regenerating the CA per attempt would roughly double the cost
 * for no benefit. This matters because RSA keygen dominates the runtime, and
 * the search needs several hundred attempts on average.
 */
async function makeRsaChainWithSignatureByte(byte: number): Promise<X509Certificate[]> {
  const now = new Date();
  const notBefore = new Date(now.getTime() - 60_000);
  const notAfter = new Date(now.getTime() + 60 * 60 * 1000);

  const caKeys = (await crypto.subtle.generateKey(RSA_2048, true, [
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
    signingAlgorithm: RSA_2048,
    extensions: [],
  });
  const caCert = new X509Certificate(ca.rawData);

  for (let attempt = 0; attempt < RSA_COLLISION_ATTEMPTS; attempt += 1) {
    const leafKeys = (await crypto.subtle.generateKey(RSA_2048, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;

    const leaf = await X509CertificateGenerator.create({
      serialNumber: '02',
      subject: 'C=US,CN=Regression Leaf',
      issuer: 'C=US,CN=Regression Root CA',
      notBefore,
      notAfter,
      publicKey: leafKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: RSA_2048,
      extensions: [new KeyUsagesExtension(KeyUsageFlags.digitalSignature)],
    });
    const leafCert = new X509Certificate(leaf.rawData);

    if (new Uint8Array(leafCert.signature)[0] === byte) {
      return [leafCert, caCert];
    }
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
  // probabilistic (~1 in 256 per attempt), so this test needs a generous
  // timeout. RSA keygen dominates the cost at ~40ms per attempt on a busy CI
  // runner, and the expected number of attempts is ~256, so the timeout is set
  // well above the expected runtime rather than near it. An earlier 60s budget
  // was too tight and failed intermittently on CI.
  it(
    'verifies a valid RSA chain whose signature begins with 0x30',
    { timeout: 120_000 },
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

describe('verifyCertificateChain key-type coverage', () => {
  it('verifies a fresh P-384 chain', async () => {
    const { chain } = await makeChain({ name: 'ECDSA', namedCurve: 'P-384' });
    await expect(verifyCertificateChain(chain, true)).resolves.toBeUndefined();
  });

  // P-521 coordinates are 66 bytes, but ASN.1 encodes them minimally, so a
  // leading zero byte is dropped roughly half the time per coordinate. Sizing
  // the raw signature from `max(r.length, s.length)` therefore produced a
  // 130/131-byte buffer instead of 132 and failed verification. Generated
  // repeatedly because any single chain may happen to have no stripped byte.
  it('verifies fresh P-521 chains', async () => {
    for (let i = 0; i < 5; i += 1) {
      const { chain } = await makeChain({ name: 'ECDSA', namedCurve: 'P-521' });
      await expect(verifyCertificateChain(chain, true)).resolves.toBeUndefined();
    }
  });

  // The signature is checked against the issuer's key, so the coordinate size
  // must come from the issuer's curve. A P-256 leaf signed by a P-384 CA is
  // the shape produced by fulcio (and by any cross-signed/rotated PKI).
  it('verifies a P-256 leaf signed by a P-384 CA', async () => {
    const now = new Date();
    const notBefore = new Date(now.getTime() - 60_000);
    const notAfter = new Date(now.getTime() + 60 * 60 * 1000);

    const caKeys = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair;
    const leafKeys = (await crypto.subtle.generateKey(EC_P256, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;

    const ca = await X509CertificateGenerator.create({
      serialNumber: '01',
      subject: 'C=US,CN=Mixed-curve Root CA',
      issuer: 'C=US,CN=Mixed-curve Root CA',
      notBefore,
      notAfter,
      publicKey: caKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-384' },
      extensions: [],
    });

    const leaf = await X509CertificateGenerator.create({
      serialNumber: '02',
      subject: 'C=US,CN=Mixed-curve Leaf',
      issuer: 'C=US,CN=Mixed-curve Root CA',
      notBefore,
      notAfter,
      publicKey: leafKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-384' },
      extensions: [new KeyUsagesExtension(KeyUsageFlags.digitalSignature)],
    });

    await expect(
      verifyCertificateChain(
        [new X509Certificate(leaf.rawData), new X509Certificate(ca.rawData)],
        true
      )
    ).resolves.toBeUndefined();
  });

  it('verifies a fresh Ed25519 chain', async () => {
    const { chain } = await makeChain({ name: 'Ed25519' });
    await expect(verifyCertificateChain(chain, true)).resolves.toBeUndefined();
  });

  // RSA-PSS signs with the same `rsaEncryption` SPKI as PKCS#1 v1.5, so Web
  // Crypto imports the issuer key as RSASSA-PKCS1-v1_5 and rejects the pairing
  // of that key with the certificate's RSA-PSS signature algorithm. The key
  // must be re-imported as RSA-PSS while the signature algorithm (which
  // carries the salt length PSS verification requires) is passed through.
  it('verifies a fresh RSA-PSS chain (SHA-256)', async () => {
    const { chain } = await makeChain({
      name: 'RSA-PSS',
      hash: 'SHA-256',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      saltLength: 32,
    });
    await expect(verifyCertificateChain(chain, true)).resolves.toBeUndefined();
  });

  it('verifies a fresh RSA-PSS chain (SHA-512)', async () => {
    const { chain } = await makeChain({
      name: 'RSA-PSS',
      hash: 'SHA-512',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      saltLength: 64,
    });
    await expect(verifyCertificateChain(chain, true)).resolves.toBeUndefined();
  });

  it('rejects a P-521 chain whose signed bytes were modified', async () => {
    const { chain } = await makeChain({ name: 'ECDSA', namedCurve: 'P-521' });
    const tampered = tamperSerialNumber(chain[0]!);
    await expect(
      verifyCertificateChain([tampered, chain[1]!], true)
    ).rejects.toThrow('signature verification failed');
  });
});
