// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Session storage for the Credo Agent.
 *
 * One Agent per browser, keyed by an httpOnly session cookie. Wallets are
 * in-memory, so they cost real resources while they live and need collecting:
 * this keeps an idle timeout, a hard cap on concurrent agents, and a sweeper.
 *
 * The whole module is a no-op on runtimes without the native Askar addon —
 * `available()` is the gate the server uses to decide whether to advertise the
 * Credo Agent endpoints at all.
 */

import { randomUUID } from 'node:crypto';

import type { CredoAgentResult, CredoSession } from './credo-agent.ts';
import type { SigningIdentity } from './lib/identity.ts';

/** Idle timeout: an untouched session is shut down after this long. */
const IDLE_MS = 15 * 60 * 1000;

/** Hard cap on concurrent agents, so a public demo cannot exhaust the box. */
const MAX_SESSIONS = 24;

/** Cookie name carrying the session id. */
export const SESSION_COOKIE = 'didx509_credo_sid';

interface Entry {
  session: CredoSession;
  lastUsed: number;
}

const sessions = new Map<string, Entry>();

let sweeper: NodeJS.Timeout | undefined;

/**
 * Whether the native Askar backend can be loaded.
 *
 * Importing `credo-agent.ts` is what pulls in the addon, so this is a dynamic
 * import: on Deno or an edge runtime it throws and the playground simply
 * serves the portable flows instead of failing at startup.
 */
export async function available(): Promise<boolean> {
  try {
    await import('./credo-agent.ts');
    return true;
  } catch {
    return false;
  }
}

function startSweeper(): void {
  if (sweeper) return;
  sweeper = setInterval(() => {
    const now = Date.now();
    for (const [id, entry] of sessions) {
      if (now - entry.lastUsed > IDLE_MS) {
        sessions.delete(id);
        entry.session.shutdown().catch(() => {});
      }
    }
  }, 60 * 1000);
  // Do not hold the process open for the benefit of the sweeper alone.
  sweeper.unref?.();
}

/** Look up a session, or create one and report the cookie to set. */
async function acquire(
  sessionId: string | undefined
): Promise<{ entry: Entry; id: string; created: boolean }> {
  if (sessionId && sessions.has(sessionId)) {
    const entry = sessions.get(sessionId)!;
    entry.lastUsed = Date.now();
    return { entry, id: sessionId, created: false };
  }

  // Evict the least-recently-used session when at capacity.
  if (sessions.size >= MAX_SESSIONS) {
    let oldestId: string | undefined;
    let oldest = Infinity;
    for (const [id, entry] of sessions) {
      if (entry.lastUsed < oldest) {
        oldest = entry.lastUsed;
        oldestId = id;
      }
    }
    if (oldestId) {
      const victim = sessions.get(oldestId)!;
      sessions.delete(oldestId);
      victim.session.shutdown().catch(() => {});
    }
  }

  const { CredoSession: Session } = await import('./credo-agent.ts');
  const id = randomUUID();
  const session = await Session.start(id);
  const entry: Entry = { session, lastUsed: Date.now() };
  sessions.set(id, entry);
  startSweeper();
  return { entry, id, created: true };
}

/** Run the full Credo flow for this browser, starting an Agent if needed. */
export async function runCredoAgent(
  sessionId: string | undefined,
  identity: SigningIdentity
): Promise<{ result: CredoAgentResult; sessionId: string; setCookie?: string }> {
  const { entry, id, created } = await acquire(sessionId);
  const result = await entry.session.run(identity);
  return {
    result,
    sessionId: id,
    setCookie: created ? cookieHeader(id) : undefined,
  };
}

/** Shut a session down and forget it. */
export async function endSession(sessionId: string | undefined): Promise<void> {
  if (!sessionId) return;
  const entry = sessions.get(sessionId);
  if (!entry) return;
  sessions.delete(sessionId);
  await entry.session.shutdown().catch(() => {});
}

function cookieHeader(id: string): string {
  // httpOnly so page scripts cannot read it; SameSite=Lax is enough for a
  // same-origin demo and keeps the cookie off cross-site requests.
  return `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${
    IDLE_MS / 1000
  }`;
}

/** Live session count — surfaced by the health probe. */
export function sessionCount(): number {
  return sessions.size;
}

/** Shut everything down; used on process exit. */
export async function shutdownAll(): Promise<void> {
  if (sweeper) clearInterval(sweeper);
  sweeper = undefined;
  const all = [...sessions.values()];
  sessions.clear();
  await Promise.allSettled(all.map(entry => entry.session.shutdown()));
}
