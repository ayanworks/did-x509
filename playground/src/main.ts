// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Node entry point — the only host-specific file in the playground.
 *
 * `handleRequest` in `server.ts` is a `fetch`-shaped handler with no host
 * assumptions. This file adapts Node's `http` server to it, which is all the
 * binding requires: build a `Request`, call the handler, write the `Response`.
 *
 * ## Why Node and not Deno
 *
 * The Credo tab runs a real Credo `Agent` with an Askar wallet. Askar is a
 * native addon (`ffi-napi` plus a prebuilt `.node`), and native addons have no
 * build for Deno or for edge runtimes. Everything else in the playground —
 * every flow, every signing path — is portable; only this entry point and the
 * `credo-agent` / `credo-session` modules need Node.
 *
 * The handler split is unchanged, so moving back to an edge host is still a
 * matter of writing a new binder rather than touching the routes.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { handleRequest } from './server.ts';

/** Read the request body into a Buffer, without buffering more than we allow. */
const MAX_BODY_BYTES = 4 * 1024 * 1024; // 4 MiB: a chain plus a key, generous.

async function readBody(request: IncomingMessage): Promise<Buffer | undefined> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = chunk as Buffer;
    total += buffer.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error('Request body too large.');
    }
    chunks.push(buffer);
  }
  return chunks.length ? Buffer.concat(chunks) : undefined;
}

/** Adapt Node's request/response pair to the portable fetch handler. */
async function nodeToFetch(
  request: IncomingMessage,
  response: ServerResponse
): Promise<void> {
  const host = request.headers.host ?? 'localhost';
  const url = new URL(request.url ?? '/', `http://${host}`);

  try {
    const body = await readBody(request);
    const fetchRequest = new Request(url, {
      method: request.method,
      headers: request.headers as Record<string, string>,
      // Node's http layer gives us a Buffer; Request accepts Uint8Array.
      body:
        request.method === 'GET' || request.method === 'HEAD'
          ? undefined
          : new Uint8Array(body!),
    });

    const fetchResponse = await handleRequest(fetchRequest);

    // Preserve multiple Set-Cookie headers, which a plain object would collapse.
    const headers: Record<string, string | string[]> = {};
    fetchResponse.headers.forEach((value, key) => {
      if (key === 'set-cookie') return;
      headers[key] = value;
    });
    const cookies = fetchResponse.headers.getSetCookie?.() ?? [];
    if (cookies.length) headers['set-cookie'] = cookies;

    response.writeHead(fetchResponse.status, headers);
    response.end(Buffer.from(await fetchResponse.arrayBuffer()));
  } catch (error) {
    // A binding-level failure is a 500 for the client, never a crash for the
    // process: a public demo should outlive one bad request.
    const message = (error as Error).message ?? 'Internal error';
    response.writeHead(500, { 'content-type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ error: message }, null, 2));
  }
}

const port = Number(process.env.PORT ?? 8000);

const server = createServer((request, response) => {
  void nodeToFetch(request, response);
});

server.listen(port, () => {
  console.log(`did:x509 playground — http://localhost:${port}`);
  console.log('Credo tab: real Credo Agent with an in-memory Askar wallet.');
});

/** On shutdown, close open Agent wallets so the process can exit cleanly. */
async function shutdown(signal: string): Promise<void> {
  console.log(`\n${signal} — shutting down`);
  server.close();
  try {
    const { shutdownAll } = await import('./credo-session.ts');
    await shutdownAll();
  } catch {
    // The Credo Agent may never have been used; nothing to clean up.
  }
  process.exit(0);
}

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));
