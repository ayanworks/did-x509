// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Bridge between a did:x509 verification method (`type: "JsonWebKey"`) and
 * Digital Bazaar's Data Integrity key suites.
 *
 * did:x509 DID documents expose the certificate's key as a plain JWK, and
 * `Ed25519VerificationKey2020.fromJsonWebKey` accepts exactly that shape
 * (`type: "JsonWebKey"` + `publicKeyJwk`) — but it only builds the *public*
 * half. The issuer also holds the matching private JWK, so the private key is
 * attached here in the suite's multibase form (ed25519-priv multicodec
 * `0x80 0x26` + base58btc).
 *
 * Kept in sync with `examples/lib/did-x509-key.ts`.
 */

import {
  Ed25519VerificationKey2020,
  type Ed25519VerificationKey2020Options,
} from '@digitalbazaar/ed25519-verification-key-2020';
import { base58btc } from 'multiformats/bases/base58';

/** Multicodec header for Ed25519 private keys (0x8026 varint). */
const MULTICODEC_ED25519_PRIV_HEADER = new Uint8Array([0x80, 0x26]);

export interface DidX509JsonWebKey {
  /** The verification method id, e.g. `${did}#0`. */
  id: string;
  /** Always `JsonWebKey` for did:x509 (also accepted by the suite). */
  type: 'JsonWebKey';
  /** The DID. */
  controller: string;
  /** The certificate's public key. */
  publicKeyJwk: JsonWebKey;
}

export interface DidX509Ed25519KeyPair
  extends Ed25519VerificationKey2020Options {
  privateKeyMultibase: string;
}

/**
 * Build an Ed25519 Data Integrity key pair from a did:x509 verification
 * method plus the issuer's matching private JWK.
 */
export async function ed25519KeyFromDidX509(
  verificationMethod: DidX509JsonWebKey,
  privateJwk: { d?: string }
): Promise<Ed25519VerificationKey2020> {
  const key = await Ed25519VerificationKey2020.fromJsonWebKey({
    id: verificationMethod.id,
    type: verificationMethod.type,
    controller: verificationMethod.controller,
    publicKeyJwk: verificationMethod.publicKeyJwk,
  });

  if (privateJwk.d) {
    // WebCrypto JWK `d` is the 32-byte Ed25519 seed; the suite's multibase
    // form encodes the canonical 64-byte secret key (seed ‖ public key), so
    // the leaf's `x` is appended after the seed.
    const seed = base64urlToBytes(privateJwk.d);
    const publicKey = base64urlToBytes(
      verificationMethod.publicKeyJwk['x'] as string
    );
    const secretKey = new Uint8Array([...seed, ...publicKey]);
    const prefixed = new Uint8Array(
      MULTICODEC_ED25519_PRIV_HEADER.length + secretKey.length
    );
    prefixed.set(MULTICODEC_ED25519_PRIV_HEADER, 0);
    prefixed.set(secretKey, MULTICODEC_ED25519_PRIV_HEADER.length);
    key.privateKeyMultibase = base58btc.encode(prefixed);
  }

  return key;
}

function base64urlToBytes(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  return new Uint8Array(Buffer.from(padded, 'base64'));
}
