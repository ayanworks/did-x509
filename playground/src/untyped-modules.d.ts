// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Ambient declarations for dependencies that ship no types.
 *
 * The JSON-LD stack (`@digitalbazaar/*`, `jsonld-signatures`) is plain
 * JavaScript with no `types` field and no `@types` package. Deno's checker
 * treated them as `any` implicitly; TypeScript needs to be told, and doing so
 * here keeps `npm run check` focused on real errors instead of listing the
 * same five modules on every run.
 *
 * Everything else in the playground — Credo, `@peculiar/x509`, `pkijs`,
 * `@owf/*`, `@sd-jwt/*` — is typed, so no declaration appears for it.
 */

declare module '@digitalbazaar/data-integrity';
declare module '@digitalbazaar/data-integrity-context';
declare module '@digitalbazaar/credentials-context';
declare module '@digitalbazaar/security-context';
declare module '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
declare module '@digitalbazaar/vc';
declare module 'jsonld-signatures';

/**
 * `@digitalbazaar/ed25519-verification-key-2020` is untyped, but `lib/`
 * uses it in type positions as well as at runtime, so it needs more than a
 * bare `any` stub.
 */
declare module '@digitalbazaar/ed25519-verification-key-2020' {
  export interface Ed25519VerificationKey2020Options {
    id?: string;
    type?: string;
    controller?: string;
    publicKeyJwk?: JsonWebKey;
    publicKeyMultibase?: string;
  }

  export class Ed25519VerificationKey2020 {
    id?: string;
    type?: string;
    controller?: string;
    publicKeyJwk?: JsonWebKey;
    publicKeyMultibase?: string;
    privateKeyMultibase?: string;
    signer(): {
      algorithm?: string;
      sign(options: { data: Uint8Array }): Promise<Uint8Array>;
    };
    verifier(): {
      algorithm?: string;
      verify(options: { data: Uint8Array; signature: Uint8Array }): Promise<boolean>;
    };
    static fromJsonWebKey(
      options: Ed25519VerificationKey2020Options
    ): Promise<Ed25519VerificationKey2020>;
    static generate(
      options?: Ed25519VerificationKey2020Options
    ): Promise<Ed25519VerificationKey2020>;
  }

  export default Ed25519VerificationKey2020;
}
