// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Shared helpers for certificate-chain tests.
 */

import { X509Certificate } from '@peculiar/x509';
import * as asn1js from 'asn1js';

/**
 * Flip bits in a certificate's serial number.
 *
 * Leaves the subject (and therefore any DID predicates) untouched but changes
 * bytes the signature covers, so signature verification must fail. Used to
 * prove that verification actually runs rather than short-circuiting.
 */
export function tamperSerialNumber(cert: X509Certificate): X509Certificate {
  const root = asn1js.fromBER(cert.rawData).result;
  const tbs = (root as asn1js.Sequence).valueBlock.value[0]! as asn1js.Sequence;
  const serial = tbs.valueBlock.value.find(
    b => b instanceof asn1js.Integer
  )! as asn1js.Integer;
  const view = serial.valueBlock.valueHexView;
  view[view.length - 1] ^= 0xff;
  view[view.length - 2] ^= 0x55;
  return new X509Certificate(root.toBER());
}
