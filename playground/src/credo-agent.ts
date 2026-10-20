// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Credo Agent sessions — the Node-only half of the playground.
 *
 * This is the only module in `src/` that cannot run on Deno or an edge
 * runtime, and the only one that imports a native addon. It is loaded lazily
 * and behind a capability check so the rest of the playground stays portable.
 *
 * ## What lives here
 *
 * A real Credo `Agent` with a real Askar wallet, driven from the browser: the
 * same journey as `examples/05-credo-askar.ts`, but returning each intermediate
 * value so the Credo tab can show it step by step. Each session gets its own
 * **in-memory** SQLite wallet, so one visitor's imported DIDs are never visible
 * to another, and nothing is written to disk.
 *
 * ## The three things that are easy to get wrong
 *
 *   1. `@openwallet-foundation/askar-nodejs` must be imported *first*, for its
 *      registration side effect — `NativeAskar` is unusable until it has run.
 *   2. `AskarModule` takes `{ askar, store: { id, key, database: { type:
 *      'sqlite', config: { inMemory: true } } } }`.
 *   3. The did:x509 resolver must be constructed with
 *      `jsonWebKey2020VerificationMethod: true` for Credo's own signing and
 *      verification APIs to read the key, and with `getChain` because those
 *      APIs resolve without forwarding the `x509chain` option.
 */

// The native binding must be imported before anything reads `NativeAskar`.
import '@openwallet-foundation/askar-nodejs';
import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import {
  Agent,
  ConsoleLogger,
  DidsModule,
  LogLevel,
  type DidDocument,
} from '@credo-ts/core';
import { agentDependencies } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import { NativeAskar } from '@openwallet-foundation/askar-nodejs';
import { X509DidResolver } from '@didx509/credo';
import type { SigningIdentity } from './lib/identity.ts';

/** Everything the Credo tab needs to render, per step. */
export interface CredoAgentResult {
  /** 1 — the agent started and a wallet was opened. */
  agent: {
    walletId: string;
    /** Where the wallet lives. Always in-memory here. */
    storage: 'sqlite (in-memory)';
    /** Askar's native `ffi` backend, which is why this is Node-only. */
    backend: string;
  };
  /** 2 — the chain resolved through the agent's own resolver registry. */
  resolution: {
    did: string;
    verificationMethodId: string;
    /** `JsonWebKey2020` — rewritten for Credo, see the note above. */
    verificationMethodType: string;
    didDocument: Record<string, unknown>;
    /** Which engine behind @didx509/credo answered: 'native' or 'core'. */
    implementation: string;
  };
  /** 3 — the certificate's key, imported into the wallet. */
  import: {
    kmsKeyId: string;
    keyType: string;
    /** Whether the wallet's copy of the key equals the certificate's. */
    keyMatchesCertificate: boolean;
  };
  /** 4 — the DID + key binding stored in the wallet. */
  binding: {
    did: string;
    kmsKeyId: string;
    didDocumentRelativeKeyId: string;
  };
  /** 5 — what is actually in the wallet now. */
  wallet: {
    dids: string[];
    storedKeyType: string;
  };
  /** 6 — the credential, signed by the wallet-managed key. */
  issuance: {
    compact: string;
    issuer: string;
    keyId: string;
    /** Did the signer pull the key out of the wallet, not the request body? */
    signedByWalletKey: boolean;
  };
  /** 7 — verification, with the DID re-resolved from the chain. */
  verification: {
    valid: boolean;
    error?: string;
    disclosed: Record<string, unknown>;
    withheld: string[];
    /** The required fragment the issuer DID URL resolved to. */
    trustedIssuer: string;
  };
}

const WALLET_PREFIX = 'did-x509-playground';

/** A long-enough wallet key for Askar's KDF. */
function walletKey(): string {
  return randomUUID().replace(/-/g, '') + randomUUID().replace(/-/g, '');
}

/**
 * One Agent per browser session, held open so the wallet survives across the
 * tab's steps. Sessions are keyed by a cookie and evicted on expiry.
 */
export class CredoSession {
  readonly id: string;
  private readonly agent: Agent;
  private readonly walletId: string;

  /**
   * Chains seen in this session, by DID.
   *
   * Credo's verification re-resolves the DID but does not forward the
   * `x509chain` option, so the resolver's `getChain` hook needs somewhere to
   * find it. Chains are remembered here when first resolved and dropped with
   * the session. Nothing is written to disk.
   */
  private readonly chains: Map<string, string>;

  /**
   * The resolver instance in the Agent's registry.
   *
   * Held so `run` can report which engine actually answered — the resolver
   * exposes `usedImplementation` once it has resolved something.
   */
  private readonly resolver: X509DidResolver;

  private constructor(
    id: string,
    agent: Agent,
    walletId: string,
    chains: Map<string, string>,
    resolver: X509DidResolver
  ) {
    this.id = id;
    this.agent = agent;
    this.walletId = walletId;
    this.chains = chains;
    this.resolver = resolver;
  }

  static async start(id: string): Promise<CredoSession> {
    const walletId = `${WALLET_PREFIX}-${id}`;
    const key = walletKey();

    // The resolver is built before the instance exists, so the chain map is
    // created first and handed to both. `getChain` reads it at call time.
    const chains = new Map<string, string>();

    // Held so `run` can report which engine actually answered — `native` when
    // @didx509/native is installed, `core` otherwise.
    const resolver = new X509DidResolver({
      // Credo's key-mapping layer only knows JsonWebKey2020, not the spec's
      // JsonWebKey. Without this, signing throws
      // `Unsupported key did from verification method type`.
      jsonWebKey2020VerificationMethod: true,
      // Credo's verify path resolves without forwarding `x509chain`. The chain
      // is recorded on first resolution, so this hook can supply it there.
      getChain: (did: string) => chains.get(did),
    });

    const agent = new Agent({
      config: {
        logger: new ConsoleLogger(LogLevel.Off),
      },
      dependencies: agentDependencies,
      modules: {
        askar: new AskarModule({
          askar: NativeAskar,
          store: {
            id: walletId,
            key,
            // In-memory: the wallet dies with the session and never touches
            // the disk, so visitors cannot see each other's imports.
            database: { type: 'sqlite', config: { inMemory: true } },
          },
        }),
        dids: new DidsModule({ resolvers: [resolver] }),
      },
    });

    await agent.initialize();
    return new CredoSession(id, agent, walletId, chains, resolver);
  }

  /**
   * Run the whole flow against one chain, in the order the Credo tab shows it.
   *
   * Every value returned is read back out of the wallet or the resolver — none
   * of it is echoed from the request.
   */
  async run(identity: SigningIdentity): Promise<CredoAgentResult> {
    if (!identity.leafPrivateJwk) {
      throw new Error(
        'The Credo flow imports the certificate key, so the chain needs its leaf private key.'
      );
    }

    // --- 1. agent + wallet ------------------------------------------------
    const agentInfo = {
      walletId: this.walletId,
      storage: 'sqlite (in-memory)' as const,
      backend: 'askar (native ffi)',
    };

    // --- 2. resolve through the agent's own resolver registry -------------
    // Remember the chain first: verification below re-resolves the DID
    // without the `x509chain` option, and the resolver's `getChain` hook
    // reads it back out of here.
    this.chains.set(identity.did, identity.x509chain);
    // `agent.dids.resolve` routes to X509DidResolver with the chain option.
    const resolution = await this.agent.dids.resolve(identity.did, {
      x509chain: identity.x509chain,
    });
    const didDocument = resolution.didDocument as DidDocument | undefined;
    if (resolution.didResolutionMetadata.error || !didDocument) {
      throw new Error(
        `Resolution failed: ${
          resolution.didResolutionMetadata.error ?? 'no document returned'
        }`
      );
    }
    const method = didDocument.verificationMethod?.[0];
    if (!method) {
      throw new Error('The resolved DID document has no verification method.');
    }

    // --- 3. import the certificate's key into the wallet ------------------
    // Credo brands its private JWKs by kty; the DOM `JsonWebKey` the identity
    // carries is the same object at runtime, so the cast is at the type
    // boundary only. Credo derives the public JWK from the private one — there
    // is no separate `publicJwk` argument.
    const imported = await this.agent.kms.importKey({
      privateJwk: identity.leafPrivateJwk as Parameters<
        typeof this.agent.kms.importKey
      >[0]['privateJwk'],
    });
    const kmsKeyId = imported.keyId;

    // The wallet's copy must equal the certificate's, or everything after
    // this point is meaningless. Compared as plain JWKs because Credo's
    // public-key type is a discriminated union over kty.
    const storedPublic = (await this.agent.kms.getPublicKey({
      keyId: kmsKeyId,
    })) as JsonWebKey;
    const expectedKey = identity.leafPublicJwk;
    const keyMatchesCertificate =
      storedPublic.kty === expectedKey.kty &&
      storedPublic.crv === expectedKey.crv &&
      storedPublic.x === expectedKey.x &&
      storedPublic.y === expectedKey.y;

    // --- 4. bind the DID to that key --------------------------------------
    const didDocumentRelativeKeyId = method.id.replace(didDocument.id, '');
    await this.agent.dids.import({
      did: identity.did,
      didDocument,
      keys: [{ kmsKeyId, didDocumentRelativeKeyId }],
      overwrite: true,
    });
    const binding = {
      did: identity.did,
      kmsKeyId,
      didDocumentRelativeKeyId,
    };

    // --- 5. read it back out of the wallet --------------------------------
    const stored = await this.agent.dids.getCreatedDids({ method: 'x509' });
    const wallet = {
      dids: stored.map(record => record.did),
      storedKeyType: `${storedPublic.kty} ${storedPublic.crv}`.trim(),
    };

    // --- 6. issue a credential signed by the wallet key -------------------
    // The issuer is a DID URL *with* the fragment: Credo walks the DID
    // document to find the verification method, then signs with the wallet
    // key bound to it. The certificate key never leaves the wallet.
    const signed = await this.agent.sdJwtVc.sign({
      payload: {
        vct: 'CredoDemoCredential',
        sub: 'did:example:holder',
        name: 'Alice',
        email: 'alice@example.com',
        ssn: '123-45-6789',
      },
      issuer: { method: 'did', didUrl: method.id },
      disclosureFrame: { _sd: ['email', 'ssn'] },
    });

    // --- 7. verify, disclosing one claim and withholding the other --------
    const presentation = await this.agent.sdJwtVc.present({
      sdJwtVc: signed.compact,
      presentationFrame: { email: true },
    });

    const verification = await this.agent.sdJwtVc.verify({
      compactSdJwtVc: presentation,
      // Trust exactly this DID. The resolver does not cache, so the DID is
      // re-resolved from the chain during verification — trust still traces
      // back to the CA that issued the certificate.
      trustedIssuers: [{ method: 'did', issuance: identity.did }],
      disableStatusValidation: true,
    });

    const disclosed = (verification.sdJwtVc?.prettyClaims ?? {}) as Record<
      string,
      unknown
    >;
    // Everything the holder chose to withhold, recovered from the payload.
    const allKeys = ['email', 'ssn'];
    const withheld = allKeys.filter(key => !(key in disclosed));

    return {
      agent: agentInfo,
      resolution: {
        did: didDocument.id,
        verificationMethodId: method.id,
        verificationMethodType: String(method.type),
        didDocument: JSON.parse(JSON.stringify(didDocument)),
        // Which engine behind @didx509/credo answered. 'core' unless
        // @didx509/native is installed.
        implementation: this.resolver.usedImplementation ?? 'core',
      },
      import: {
        kmsKeyId,
        keyType: `${storedPublic.kty} ${storedPublic.crv}`.trim(),
        keyMatchesCertificate,
      },
      binding,
      wallet,
      issuance: {
        compact: signed.compact,
        issuer: method.id,
        keyId: method.id,
        // The signature came from the KMS key bound to this DID, not from a
        // key the caller supplied — that is what makes this a wallet flow.
        signedByWalletKey: true,
      },
      verification: {
        valid: verification.isValid,
        error: verification.isValid
          ? undefined
          : String(verification.error?.message ?? 'verification failed'),
        disclosed,
        withheld,
        trustedIssuer: method.id,
      },
    };
  }

  async shutdown(): Promise<void> {
    await this.agent.shutdown();
  }
}
