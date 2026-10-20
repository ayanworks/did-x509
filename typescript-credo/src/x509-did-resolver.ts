// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * did:x509 method resolver for credo-ts.
 *
 * Follows the Credo `DidResolver` interface (supportedMethods / allowsCaching /
 * resolve) and delegates validation to @didx509/native (Microsoft's didx509cpp
 * resolver as a Node-API addon) when it is installed, falling back to the pure
 * TypeScript @didx509/core implementation otherwise.
 *
 * did:x509 is the one DID method where the issuer's certificate chain *is*
 * the trust anchor: resolution requires the chain to be supplied with each
 * request (the `x509chain` resolution option, a comma-separated list of
 * base64url-encoded DER certificates). Because the same DID can resolve to
 * different documents for different chains, this resolver sets
 * `allowsCaching = false`.
 */

import { DidDocument, JsonTransformer } from '@credo-ts/core';
import type {
  AgentContext,
  DidResolutionOptions,
  DidResolutionResult,
  DidResolver,
  ParsedDid,
} from '@credo-ts/core';
import { loadX509Chain, resolveDid } from '@didx509/core';
import type { DidDocument as DidDocumentJson } from '@didx509/core';

/**
 * The validation engine backing the resolver.
 *
 * - `'auto'` (default): use @didx509/native when its addon loads, otherwise
 *   fall back to @didx509/core.
 * - `'native'`: require @didx509/native (throws when it cannot be loaded).
 * - `'core'`: always use the pure-TypeScript implementation.
 */
export type Didx509Implementation = 'auto' | 'native' | 'core';

export interface X509DidResolverOptions {
  /** Which did:x509 validation engine to use. Defaults to `'auto'`. */
  implementation?: Didx509Implementation;

  /**
   * Rewrite the resolved verification method `type` from the did:x509 spec's
   * `JsonWebKey` to W3C `JsonWebKey2020`.
   *
   * The did:x509 specification (and Microsoft's reference resolver) emits
   * `type: "JsonWebKey"`. Credo's key-mapping layer only recognises
   * `JsonWebKey2020`, `Multikey`, `Ed25519VerificationKey2018` and
   * `EcdsaSecp256k1VerificationKey2019`, so a spec-exact document cannot be
   * used by Credo's own signing and verification APIs — they throw
   * `Unsupported key did from verification method type 'JsonWebKey'`.
   *
   * Off by default: resolution stays byte-for-byte identical to the reference
   * resolver unless you opt in. Enable it when you intend to feed the document
   * to `agent.dids.import(...)` and sign with the wallet key.
   *
   * @default false
   */
  jsonWebKey2020VerificationMethod?: boolean;

  /**
   * Optional hook invoked when the `x509chain` resolution option is absent.
   * Return the comma-separated base64url DER chain for the DID (e.g. from your
   * own registry or database), or `undefined` to let resolution fail.
   *
   * Credo's built-in verification helpers resolve DID documents without
   * forwarding resolution options; a chain provider keeps verification flows
   * working there.
   */
  getChain?: (
    did: string,
    agentContext: AgentContext
  ) => string | undefined | Promise<string | undefined>;
}

/**
 * The subset of @didx509/native this resolver uses. The package is an
 * optional peer — when absent, `import()` rejects and the resolver falls back
 * to @didx509/core.
 */
interface NativeResolverModule {
  resolveDidFromPem(did: string, pemChain: string): Promise<DidDocumentJson>;
  x509ChainToPem(x509chain: string): string;
}

/** Indirection keeps bundlers from statically resolving the optional peer. */
const DIDX509_NATIVE = '@didx509/native';

export class X509DidResolver implements DidResolver {
  public readonly supportedMethods = ['x509'];
  public readonly allowsCaching = false;
  public readonly allowsLocalDidRecord = false;

  private implementationPromise?: Promise<'native' | 'core'>;
  private selectedImplementation?: 'native' | 'core';
  private nativeModule?: NativeResolverModule;

  public constructor(private readonly options: X509DidResolverOptions = {}) {
    const mode = options.implementation ?? 'auto';
    if (mode !== 'auto' && mode !== 'native' && mode !== 'core') {
      throw new Error(
        `Unknown implementation '${mode}' — expected 'auto', 'native' or 'core'`
      );
    }
  }

  /** The engine in use after the first resolution (undefined before). */
  public get usedImplementation(): 'native' | 'core' | undefined {
    return this.selectedImplementation;
  }

  public async resolve(
    agentContext: AgentContext,
    did: string,
    _parsed: ParsedDid,
    didResolutionOptions: DidResolutionOptions
  ): Promise<DidResolutionResult> {
    const x509chain = await this.getX509Chain(
      did,
      agentContext,
      didResolutionOptions
    );

    if (!x509chain) {
      return {
        didResolutionMetadata: {
          error: 'invalidDidResolutionOptions',
          message: 'x509chain resolution option is required',
        },
        didDocument: null,
        didDocumentMetadata: {},
      };
    }

    // Outside the try/catch: a misconfiguration (implementation: 'native'
    // without the addon installed) must surface loudly, not as a resolution
    // error.
    const implementation = await this.selectImplementation();

    try {
      const documentJson =
        implementation === 'native'
          ? await this.resolveWithNative(did, x509chain)
          : await resolveDid(did, loadX509Chain(x509chain));

      if (this.options.jsonWebKey2020VerificationMethod) {
        this.applyJsonWebKey2020(documentJson);
      }

      return {
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
        didDocument: JsonTransformer.fromJSON(
          documentJson as unknown as Record<string, unknown>,
          DidDocument
        ),
        didDocumentMetadata: {},
      };
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error ?? 'unknown error');
      return {
        didResolutionMetadata: { error: 'notFound', message },
        didDocument: null,
        didDocumentMetadata: {},
      };
    }
  }

  /**
   * Rewrite `type: "JsonWebKey"` to `type: "JsonWebKey2020"` in place.
   *
   * Only the verification method `type` is touched; ids, controller and key
   * material are left alone, so the document still describes exactly the same
   * key — it just uses a type Credo's key-mapping layer recognises.
   */
  private applyJsonWebKey2020(document: DidDocumentJson): void {
    const methods = document.verificationMethod;
    if (Array.isArray(methods)) {
      for (const method of methods) {
        if (method && method.type === 'JsonWebKey') {
          method.type = 'JsonWebKey2020';
        }
      }
    }
  }

  private async getX509Chain(
    did: string,
    agentContext: AgentContext,
    didResolutionOptions: DidResolutionOptions
  ): Promise<string | undefined> {
    const option = didResolutionOptions['x509chain'];
    if (typeof option === 'string' && option.length > 0) return option;

    if (this.options.getChain) {
      const chain = await this.options.getChain(did, agentContext);
      return chain && chain.length > 0 ? chain : undefined;
    }
    return undefined;
  }

  private selectImplementation(): Promise<'native' | 'core'> {
    const mode = this.options.implementation ?? 'auto';

    if (mode === 'core') {
      this.selectedImplementation = 'core';
      return Promise.resolve('core');
    }

    this.implementationPromise ??= this.loadNative().then(
      () => {
        this.selectedImplementation = 'native';
        return 'native' as const;
      },
      (error) => {
        if (mode === 'native') throw error;
        // 'auto': the pure-TypeScript engine is a fully supported fallback.
        this.selectedImplementation = 'core';
        return 'core' as const;
      }
    );
    return this.implementationPromise;
  }

  private async loadNative(): Promise<NativeResolverModule> {
    try {
      // Indirection through a variable keeps bundlers from statically
      // resolving the optional @didx509/native peer (it may not be
      // installed).
      const specifier = DIDX509_NATIVE;
      const mod = (await import(/* @vite-ignore */ specifier)) as
        NativeResolverModule;

      if (
        typeof mod.resolveDidFromPem !== 'function' ||
        typeof mod.x509ChainToPem !== 'function'
      ) {
        throw new Error('module does not expose the expected API');
      }

      this.nativeModule = mod;
      return mod;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(
        `@didx509/native could not be loaded — install it alongside this package (npm install @didx509/native) or construct X509DidResolver with implementation: 'core'. Reason: ${message}`,
        { cause: error }
      );
    }
  }

  private async resolveWithNative(
    did: string,
    x509chain: string
  ): Promise<DidDocumentJson> {
    const native = this.nativeModule;
    if (!native) throw new Error('@didx509/native was not loaded');
    return native.resolveDidFromPem(did, native.x509ChainToPem(x509chain));
  }
}
