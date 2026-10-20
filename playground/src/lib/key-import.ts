// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Private-key import for uploaded identities.
 *
 * A real CA/leaf certificate upload comes with a private key in whatever
 * format the issuing toolchain produced. Web Crypto only accepts PKCS#8, so
 * this normalises the common PEM forms and works out the right import
 * parameters from the key itself, then hands back a JWK the signing stacks
 * already understand.
 *
 * Handled:
 *   - `PRIVATE KEY`      → PKCS#8 (OpenSSL 3.x, most modern tooling)
 *   - `RSA PRIVATE KEY`  → PKCS#1 (OpenSSL 1.x default), wrapped to PKCS#8
 *   - `EC PRIVATE KEY`   → SEC1, wrapped to PKCS#8
 *   - `ENCRYPTED PRIVATE KEY` → rejected with a clear message
 *
 * The curve is read from the key's own algorithm parameters rather than
 * guessed, because a P-384 key imported as P-256 fails with an opaque
 * "DataError" instead of naming the mismatch.
 */

import 'reflect-metadata';

import { parsePemBlocks } from './cert-parse.ts';

/** A signable key: the JWK plus what it needs to be imported again. */
export interface ImportedPrivateKey {
  /** Private JWK, as the signing stacks expect (`d` present). */
  privateJwk: JsonWebKey;
  /** Public JWK derived from the private key, for display and DID checks. */
  publicJwk: JsonWebKey;
  /** Web Crypto algorithm to re-import the private JWK with. */
  importAlgorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
  /** Which PEM form was supplied, for the UI. */
  format: string;
  keyType: string;
  keyCurve?: string;
}

/** Thrown for any key the playground cannot import, with a readable reason. */
export class KeyImportError extends Error {}

/**
 * Convert a PEM private key of any supported form into PKCS#8 DER.
 *
 * PKCS#1 and SEC1 are wrapped in a minimal PKCS#8 envelope
 * (`PrivateKeyInfo` with the matching algorithm OID) so a single Web Crypto
 * `importKey('pkcs8', ...)` call handles every input.
 */
function toPkcs8Der(pem: string): { der: ArrayBuffer; format: string } {
  const blocks = parsePemBlocks(pem);
  const block = blocks.find(b => b.label.endsWith('PRIVATE KEY'));

  if (!block) {
    throw new KeyImportError(
      'No private key found. Upload a PEM key (-----BEGIN PRIVATE KEY-----).'
    );
  }
  if (block.label === 'ENCRYPTED PRIVATE KEY') {
    throw new KeyImportError(
      'The private key is encrypted. Decrypt it first, e.g. ' +
        '`openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-plain.pem`.'
    );
  }
  if (block.label === 'PRIVATE KEY') {
    return { der: block.bytes.buffer as ArrayBuffer, format: 'PKCS#8' };
  }

  // PKCS#1 (`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`) are raw key
  // structures. Both are wrapped directly into a PKCS#8 envelope rather than
  // round-tripped through pkijs: the envelope is a fixed three-field SEQUENCE,
  // and building it by hand avoids depending on pkijs's ASN.1 object graph.
  if (block.label === 'RSA PRIVATE KEY') {
    return {
      der: wrapPkcs8(
        // rsaEncryption, with an explicit NULL parameter.
        [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
        [0x05, 0x00],
        block.bytes
      ),
      format: 'PKCS#1',
    };
  }
  if (block.label === 'EC PRIVATE KEY') {
    // SEC1 carries the curve OID inside its own `parameters` field, so the
    // algorithm identifier is copied out of the supplied structure rather
    // than guessed here.
    const parameters = sec1Parameters(block.bytes);
    return {
      der: wrapPkcs8(
        [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], // id-ecPublicKey
        parameters,
        block.bytes
      ),
      format: 'SEC1',
    };
  }

  throw new KeyImportError(`Unsupported private key label: ${block.label}`);
}

/** Encode a DER length prefix (definite, shortest form). */
function derLength(length: number): number[] {
  if (length < 0x80) return [length];
  const bytes: number[] = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

/** Wrap a tag-length-value body in an ASN.1 SEQUENCE. */
function sequence(...parts: Uint8Array[]): Uint8Array {
  const body = concat(parts);
  return new Uint8Array([0x30, ...derLength(body.length), ...body]);
}

/** Wrap a raw key body in a PKCS#8 `PrivateKeyInfo` envelope. */
function wrapPkcs8(
  algorithmOid: number[],
  parameters: number[] | Uint8Array,
  keyBytes: Uint8Array
): ArrayBuffer {
  const algId = sequence(
    new Uint8Array(algorithmOid),
    parameters instanceof Uint8Array
      ? parameters
      : new Uint8Array(parameters)
  );
  // The key material is an OCTET STRING wrapping the raw key structure.
  const keyOctets = new Uint8Array([
    0x04,
    ...derLength(keyBytes.length),
    ...keyBytes,
  ]);
  // PKCS#8 version 0.
  const version = new Uint8Array([0x02, 0x01, 0x00]);
  const info = sequence(version, algId, keyOctets);
  return info.buffer as ArrayBuffer;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Read the `parameters` field out of a SEC1 `ECPrivateKey`.
 *
 * SEC1 is `SEQUENCE { version INTEGER, privateKey OCTET STRING,
 * parameters [0] ECParameters OPTIONAL, publicKey [1] BIT STRING OPTIONAL }`.
 * The curve is an explicit `[0]` context tag wrapping the curve OID, so this
 * scans for it and re-emits the OID as a bare OBJECT IDENTIFIER.
 */
function sec1Parameters(sec1: Uint8Array): Uint8Array {
  // Walk top-level fields after the SEQUENCE header.
  let offset = 1;
  if (sec1[offset]! & 0x80) offset += 1 + (sec1[offset]! & 0x7f);
  else offset += 1;

  while (offset < sec1.length) {
    const tag = sec1[offset]!;
    let length = sec1[offset + 1]!;
    let header = 2;
    if (length & 0x80) {
      const count = length & 0x7f;
      length = 0;
      for (let i = 0; i < count; i += 1) {
        length = (length << 8) | sec1[offset + 2 + i]!;
      }
      header = 2 + count;
    }
    // [0] EXPLICIT → the curve OID sits inside as a full OBJECT IDENTIFIER.
    if (tag === 0xa0) {
      return sec1.slice(offset + header, offset + header + length);
    }
    offset += header + length;
  }

  throw new KeyImportError(
    'The SEC1 EC key has no curve parameters. Convert it to PKCS#8 instead: ' +
      '`openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem`.'
  );
}

/**
 * Work out the Web Crypto import algorithm for a key.
 *
 * The private JWK is inspected after a probe import that ignores the curve,
 * because the curve is part of the algorithm descriptor: importing a P-384
 * key as P-256 fails, so the curve must come from the key, not a default.
 */
async function algorithmFor(
  der: ArrayBuffer,
  format: string
): Promise<{
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
  keyType: string;
  keyCurve?: string;
}> {
  // Try Ed25519 first: it takes a bare string algorithm and needs no curve.
  try {
    const key = await crypto.subtle.importKey('pkcs8', der, 'Ed25519', true, [
      'sign',
    ]);
    const jwk = await crypto.subtle.exportKey('jwk', key);
    return {
      algorithm: 'Ed25519',
      keyType: 'OKP',
      keyCurve: jwk.crv,
    };
  } catch {
    // Not Ed25519 — fall through to EC and RSA.
  }

  // EC: the curve is carried in the PKCS#8 parameters. Probing each supported
  // curve is more reliable than decoding the OID, and the list is short.
  for (const namedCurve of ['P-256', 'P-384', 'P-521'] as const) {
    try {
      const key = await crypto.subtle.importKey(
        'pkcs8',
        der,
        { name: 'ECDSA', namedCurve },
        true,
        ['sign']
      );
      return {
        algorithm: { name: 'ECDSA', namedCurve },
        keyType: 'EC',
        keyCurve: namedCurve,
      };
    } catch {
      // Try the next curve.
    }
  }

  // RSA: hash choice does not affect PKCS#8 import, only signing.
  try {
    const key = await crypto.subtle.importKey(
      'pkcs8',
      der,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['sign']
    );
    const jwk = await crypto.subtle.exportKey('jwk', key);
    if (jwk.kty === 'RSA') {
      return {
        algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        keyType: 'RSA',
      };
    }
  } catch {
    // Fall through to the error below.
  }

  throw new KeyImportError(
    `Could not determine the key algorithm${format ? ` (${format})` : ''}. ` +
      'Supported: Ed25519, ECDSA P-256/P-384/P-521, RSA.'
  );
}

/** Import a PEM private key into a signable JWK pair. */
export async function importPrivateKey(pem: string): Promise<ImportedPrivateKey> {
  const { der, format } = toPkcs8Der(pem);
  const { algorithm, keyType, keyCurve } = await algorithmFor(der, format);

  const privateKey = await crypto.subtle.importKey('pkcs8', der, algorithm, true, [
    'sign',
  ]);
  const privateJwk = await crypto.subtle.exportKey('jwk', privateKey);

  // Web Crypto's private JWK still carries the public components (`x`/`y` for
  // EC, `x` for OKP, `n`/`e` for RSA), so the public JWK is that same object
  // with the secret members removed — no second import or derive step needed.
  const publicJwk: JsonWebKey = { ...privateJwk };
  delete publicJwk.d;
  delete publicJwk.p;
  delete publicJwk.q;
  delete publicJwk.dp;
  delete publicJwk.dq;
  delete publicJwk.qi;
  delete publicJwk.oth;
  delete publicJwk.k;

  return {
    privateJwk,
    publicJwk,
    importAlgorithm: algorithm,
    format,
    keyType,
    keyCurve,
  };
}

