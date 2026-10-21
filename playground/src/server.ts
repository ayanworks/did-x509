// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Playground HTTP handler.
 *
 * This module is deliberately host-agnostic: it exports a `fetch`-shaped
 * handler and does no I/O of its own beyond calling the flow functions. The
 * Node entry point (`main.ts`) binds it to `node:http`; a Cloudflare Worker
 * would bind the same handler to `export default { fetch }`. Keeping the
 * split here is what makes a host change a config edit rather than a rewrite.
 *
 * The Credo Agent routes are the one exception to "host-agnostic": they need
 * the native Askar addon, so they are loaded lazily and report themselves
 * unavailable when the addon cannot be imported. Everything else here — and
 * every credential flow — runs on any runtime.
 */

import { FLOWS, runAll, type FlowName, type FlowResult } from './flows.ts';
import {
  CREDO_LAST_STEP,
  type CredoStep,
} from './credo-agent.ts';
import { STUDIO_SCRIPT } from './studio-script.ts';
import {
  credentialCatalogue,
  capabilityMatrix,
  generateOptions,
  identityFromRequest,
  studioGenerate,
  studioSign,
  studioUpload,
  studioCredoResolve,
  studioVerify,
  type SubjectAttribute,
  type GenerateRequest,
  type SignRequestBody,
  type UploadRequest,
  type VerifyRequestBody,
} from './studio.ts';

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  // The playground is a public demo with no user data.
  'access-control-allow-origin': '*',
} as const;

/**
 * Cookie carrying the Credo Agent session id.
 *
 * Repeated literally rather than imported from `credo-session.ts`: importing
 * that module is what loads the native Askar addon, and this file must stay
 * loadable on hosts that cannot.
 */
const SESSION_COOKIE = 'didx509_credo_sid';

/** Wrap a payload in a JSON response. */
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: JSON_HEADERS,
  });
}

/**
 * Read one cookie out of a `Cookie:` header.
 *
 * Deliberately minimal — the playground sets exactly one cookie, and pulling in
 * a cookie parser for that would be more code than the thing it parses.
 */
function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return rest.join('=');
  }
  return undefined;
}

/**
 * Clamp a requested Credo step to the supported 1-7 range.
 *
 * An absent or unusable value means "run the whole flow", which keeps the
 * original single-call behaviour for callers that do not care about steps.
 */
function clampStep(value: unknown): CredoStep {
  if (typeof value !== 'number' || !Number.isFinite(value)) return CREDO_LAST_STEP;
  const step = Math.trunc(value);
  if (step < 1) return 1;
  if (step > CREDO_LAST_STEP) return CREDO_LAST_STEP;
  return step as CredoStep;
}

/**
 * Whether the Credo Agent can run on this host.
 *
 * Cached, because the answer cannot change within a process and the check
 * itself loads the native addon.
 */
let credoAgentSupport: Promise<boolean> | undefined;
function credoAgentAvailable(): Promise<boolean> {
  if (!credoAgentSupport) {
    credoAgentSupport = import('./credo-session.ts').then(module =>
      module.available()
    );
  }
  return credoAgentSupport;
}

/** The landing page: a self-contained HTML document (no build step). */
function landingPage(): Response {
  return new Response(HTML, {
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}

/**
 * Route a request.
 *
 * Routes:
 *   GET  /                 landing page
 *   GET  /api/flows        the list of available flows
 *   POST /api/run/:flow    run one flow and return its result
 *   POST /api/run          run every flow
 *   GET  /api/catalogue    credential templates + generator options
 *   POST /api/generate     generate a test CA/leaf chain
 *   POST /api/upload       parse an uploaded chain (+ optional key)
 *   POST /api/sign         sign a credential with a selected identity
 *   POST /api/verify       verify a credential and recover its issuer
 *   GET  /api/health       liveness probe
 */
export async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'content-type',
      },
    });
  }

  if (path === '/' && request.method === 'GET') {
    return landingPage();
  }

  if (path === '/api/health') {
    return json({ status: 'ok' });
  }

  // --- Certificate Studio ---------------------------------------------------
  // The catalogue and options are static; the four operations each take a thin
  // JSON body. Nothing is retained between requests.
  if (path === '/api/catalogue' && request.method === 'GET') {
    return json({
      credentials: credentialCatalogue(),
      options: generateOptions(),
      capabilityMatrix: capabilityMatrix(),
    });
  }

  if (path === '/api/generate' && request.method === 'POST') {
    return serialize(async () =>
      json({ identity: await studioGenerate(await body<GenerateRequest>(request)) })
    );
  }

  if (path === '/api/upload' && request.method === 'POST') {
    return serialize(async () =>
      json({ identity: await studioUpload(await body<UploadRequest>(request)) })
    );
  }

  if (path === '/api/sign' && request.method === 'POST') {
    return serialize(async () => {
      const result = await studioSign(await body<SignRequestBody>(request));
      return json(result);
    });
  }

  if (path === '/api/verify' && request.method === 'POST') {
    return serialize(async () =>
      json({ verification: await studioVerify(await body<VerifyRequestBody>(request)) })
    );
  }

  if (path === '/api/credo-resolve' && request.method === 'POST') {
    return serialize(async () =>
      json({
        resolution: await studioCredoResolve(
          await body<{
            chainPem: string;
            didSubjectAttribute?: SubjectAttribute;
            implementation?: 'core' | 'native';
          }>(request)
        ),
      })
    );
  }

  // --- Credo Agent (Node only) ---------------------------------------------
  // These routes need the native Askar addon, so they are absent on hosts that
  // cannot load it. The UI asks `/api/credo-agent/status` first and hides the
  // tab when the answer is no.
  if (path === '/api/credo-agent/status' && request.method === 'GET') {
    return json({ available: await credoAgentAvailable() });
  }

  if (path === '/api/credo-agent/run' && request.method === 'POST') {
    const payload = await body<{
      chainPem: string;
      keyPem: string;
      didSubjectAttribute?: SubjectAttribute;
      /** Run only up to this step. Omitted means the whole flow. */
      through?: number;
    }>(request);
    const sid = readCookie(request.headers.get('cookie'), SESSION_COOKIE);
    return serialize(async () => {
      // Parsed inside the guard: a bad chain or a missing key is the caller's
      // error and should come back as a readable 400, not a crash.
      const identity = await identityFromRequest(payload);
      // Clamped rather than trusted: an out-of-range step would otherwise
      // silently run nothing and return a result with no steps in it.
      const through = clampStep(payload.through);
      const { runCredoAgent } = await import('./credo-session.ts');
      const { result, setCookie } = await runCredoAgent(sid, identity, through);
      const headers = new Headers(JSON_HEADERS);
      if (setCookie) headers.append('set-cookie', setCookie);
      return new Response(JSON.stringify({ result }, null, 2), {
        status: 200,
        headers,
      });
    });
  }

  if (path === '/api/credo-agent/reset' && request.method === 'POST') {
    const sid = readCookie(request.headers.get('cookie'), SESSION_COOKIE);
    return serialize(async () => {
      const { endSession } = await import('./credo-session.ts');
      await endSession(sid);
      const headers = new Headers(JSON_HEADERS);
      headers.append(
        'set-cookie',
        `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
      );
      return new Response(JSON.stringify({ ok: true }, null, 2), {
        status: 200,
        headers,
      });
    });
  }

  if (path === '/api/flows' && request.method === 'GET') {
    return json({ flows: Object.keys(FLOWS) });
  }

  if (path === '/api/run' && request.method === 'POST') {
    return runAndSerialize(() => runAll());
  }

  const match = path.match(/^\/api\/run\/([a-z0-9-]+)$/);
  if (match && request.method === 'POST') {
    const name = match[1] as FlowName;
    const flow = FLOWS[name];
    if (!flow) {
      return json({ error: `Unknown flow: ${name}` }, 404);
    }
    return runAndSerialize(async () => [await flow()]);
  }

  return json({ error: 'Not found' }, 404);
}

/** Run flows, converting a thrown error into a 500 rather than a crash. */
async function runAndSerialize(
  run: () => Promise<FlowResult[]>
): Promise<Response> {
  try {
    return json({ results: await run() });
  } catch (error) {
    // Surface the message: the playground exists to show real behaviour,
    // including failures.
    return json({ error: (error as Error).message }, 500);
  }
}

/**
 * Run a handler, turning a thrown error into a 400 with its message.
 *
 * Errors here are overwhelmingly the caller's (a malformed chain, a key that
 * does not match, a format the key cannot sign), so the message is the useful
 * part and is passed through rather than masked.
 */
async function serialize(run: () => Promise<Response>): Promise<Response> {
  try {
    return await run();
  } catch (error) {
    return json({ error: (error as Error).message }, 400);
  }
}

/** Parse a JSON request body, with a readable error when it is malformed. */
async function body<T>(request: Request): Promise<T> {
  try {
    return (await request.json()) as T;
  } catch {
    throw new Error('The request body must be JSON.');
  }
}

// The AyanWorks mark, inlined so the page stays self-contained (no build step,
// no external asset fetch). Only the four mark paths are kept — the wordmark is
// rendered as HTML text so it stays crisp and follows the page font. The glyph
// is `fill: currentColor`, which lets the same markup sit on the dark header
// and on light surfaces without a second asset.
const LOGO_MARK = `<svg class="mark" viewBox="0 14.9 181 182.5" aria-hidden="true"><path fill="currentColor" d="M180.326 105.141C180.326 154.932 139.966 195.302 90.1644 195.302C40.3631 195.302 0.00280762 154.942 0.00280762 105.141C0.00280762 55.3393 40.3734 14.979 90.1644 14.979C139.955 14.979 180.326 55.3496 180.326 105.141Z"/><path fill="#A46704" d="M31.9354 84.6312C21.1684 94.125 12.6419 102.31 9.74865 104.85C3.01514 113.843 6.94614 116.899 8.51373 119.703C9.01395 120.587 10.222 120.68 10.8826 119.905C27.0679 101.201 62.0876 83.8848 100.907 98.9492C100.907 98.9492 69.7243 72.1686 31.9354 84.6312Z"/><path fill="#CE9200" d="M126.075 94.6267C109.6 71.3429 89.0812 53.5577 62.0727 58.1475C42.4915 61.5033 38.4288 82.8368 51.4818 96.6764C64.0616 109.923 86.7274 105.657 94.0864 91.0189C94.0864 91.0189 99.7321 107.976 116.303 106.533C126.075 105.672 130.473 102.986 126.075 94.6267Z"/><path fill="#FFD302" d="M158.474 141.646C158.374 140.008 156.086 140.286 155.321 140.897C141.224 151.392 113.413 161.233 92.8609 160.754C65.1085 160.108 47.7608 141.94 47.9086 142.058C47.9086 142.058 68.9937 165.859 102.075 165.859C135.157 165.859 158.668 146.825 158.474 141.646Z"/></svg>`;

const HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>did:x509 playground — AYANWORKS</title>
<meta name="description" content="Resolve did:x509 DIDs and sign verifiable credentials with certificate-backed identities. Built by AYANWORKS.">
<meta name="theme-color" content="#0a1628">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  /* AyanWorks brand tokens, taken from ayanworks.com. */
  :root {
    --navy-950: #0a1628;  /* page background */
    --navy-900: #1a2b45;  /* cards on dark */
    --navy-800: #274368;
    --navy-600: #315f9a;
    --navy-500: #4177b5;
    --navy-100: #dce6f3;
    --navy-50:  #f0f4fa;
    --gold-600: #b07834;
    --gold-500: #c8903f;  /* primary accent */
    --gold-400: #d0a358;
    --gold-200: #ead9b3;
    --gold-50:  #fbf8f0;
    --ink-500:  #64748b;
    --ok:       #10b981;
    --bad:      #dc4227;

    color-scheme: dark;
    --surface: var(--navy-950);
    --panel: rgba(255, 255, 255, .03);
    --line: rgba(200, 168, 78, .18);
    --line-soft: rgba(255, 255, 255, .08);
    --text: #e8eef7;
    --muted: #94a3b8;
    --accent: var(--gold-500);
    --radius: .7rem;
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body {
    margin: 0;
    font: 16px/1.6 Inter, system-ui, -apple-system, Segoe UI, sans-serif;
    color: var(--text);
    background:
      radial-gradient(ellipse 60% 50% at 85% 0%, rgba(200, 168, 78, .07), transparent 70%),
      linear-gradient(160deg, #050a14 0%, var(--navy-950) 45%, #0f1f38 100%);
    background-attachment: fixed;
    min-height: 100vh;
  }
  .wrap { margin: 0 auto; padding: 0 1.25rem 3rem; max-width: 62rem; }

  /* Header ------------------------------------------------------------- */
  header {
    display: flex; align-items: center; gap: .75rem; flex-wrap: wrap;
    padding: 1.5rem 0 1.25rem; margin-bottom: 1.75rem;
    border-bottom: 1px solid var(--line);
  }
  .brand { display: flex; align-items: center; gap: .65rem; color: #fff; }
  .mark { width: 2.1rem; height: 2.1rem; flex: none; display: block; }
  .wordmark {
    font-size: 1.16rem; font-weight: 700; letter-spacing: .16em;
    text-transform: uppercase; line-height: 1;
  }
  .divider { width: 1px; height: 1.9rem; background: var(--line); }
  .product { font-size: .95rem; color: var(--muted); letter-spacing: .01em; }
  .product b { color: var(--gold-400); font-weight: 600; }

  /* Hero --------------------------------------------------------------- */
  .badge-row {
    display: inline-flex; align-items: center; gap: .5rem;
    padding: .3rem .7rem; margin-bottom: 1.1rem;
    border: 1px solid var(--line); border-radius: 999px;
    background: rgba(200, 168, 78, .06);
    color: var(--gold-400); font-size: .72rem; font-weight: 600;
    letter-spacing: .1em; text-transform: uppercase;
  }
  .badge-row .dot {
    width: .4rem; height: .4rem; border-radius: 999px;
    background: var(--gold-400); box-shadow: 0 0 0 3px rgba(200, 168, 78, .16);
  }
  h1 { margin: 0 0 .35rem; font-size: clamp(1.7rem, 4vw, 2.35rem); font-weight: 700; letter-spacing: -.01em; line-height: 1.15; }
  h1 .accent {
    background: linear-gradient(92deg, var(--gold-400), var(--gold-500));
    -webkit-background-clip: text; background-clip: text; color: transparent;
  }
  .tagline { margin: 0 0 2rem; max-width: 46rem; color: var(--muted); }

  /* Tabs --------------------------------------------------------------- */
  .tabs { display: flex; gap: .35rem; margin: 0 0 1.5rem; border-bottom: 1px solid var(--line-soft); }
  .tab {
    appearance: none; background: none; border: 0; cursor: pointer;
    padding: .6rem .95rem; margin-bottom: -1px;
    font: inherit; font-weight: 600; font-size: .9rem;
    color: var(--muted); border-bottom: 2px solid transparent;
  }
  .tab:hover { color: var(--text); }
  .tab[aria-selected="true"] { color: var(--gold-400); border-bottom-color: var(--gold-500); }
  [hidden] { display: none !important; }

  /* Studio steps ------------------------------------------------------- */
  .step {
    border: 1px solid var(--line-soft); border-radius: var(--radius);
    background: var(--panel); padding: 1.15rem 1.25rem; margin-bottom: 1rem;
  }
  .step[data-done="true"] { border-color: var(--line); }
  .step-head { display: flex; align-items: baseline; gap: .6rem; margin-bottom: .35rem; }
  .step-num {
    flex: none; width: 1.55rem; height: 1.55rem; border-radius: 999px;
    display: grid; place-items: center; font-size: .78rem; font-weight: 700;
    background: rgba(200, 168, 78, .12); color: var(--gold-400);
    border: 1px solid var(--line);
  }
  .step[data-done="true"] .step-num { background: var(--gold-500); color: var(--navy-950); border-color: var(--gold-500); }
  .step h2 { margin: 0; font-size: 1.02rem; font-weight: 600; }
  .step p.hint { margin: 0 0 .9rem 2.15rem; color: var(--muted); font-size: .87rem; }
  .step .body { margin-left: 2.15rem; }
  .step.locked { opacity: .5; }
  .step.locked .step-num { background: transparent; }
  .step.locked .body { pointer-events: none; }

  /* Forms -------------------------------------------------------------- */
  .field { display: flex; flex-direction: column; gap: .3rem; margin-bottom: .75rem; }
  .field label { font-size: .78rem; font-weight: 600; color: var(--muted); letter-spacing: .02em; }
  input[type=text], input[type=number], select, textarea {
    width: 100%; padding: .5rem .65rem; font: inherit; font-size: .88rem;
    color: var(--text); background: rgba(10, 22, 40, .6);
    border: 1px solid var(--line-soft); border-radius: .45rem;
  }
  input:focus, select:focus, textarea:focus { outline: 2px solid var(--gold-500); outline-offset: 1px; }
  textarea { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: .76rem; resize: vertical; min-height: 6rem; }
  .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: .65rem; }
  .row { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
  button.action {
    appearance: none; cursor: pointer; font: inherit; font-size: .88rem; font-weight: 600;
    padding: .5rem .95rem; border-radius: .45rem; border: 1px solid var(--gold-500);
    background: linear-gradient(180deg, var(--gold-400), var(--gold-500)); color: var(--navy-950);
  }
  button.action:hover { filter: brightness(1.07); }
  button.action:disabled { opacity: .55; cursor: not-allowed; }
  button.ghost {
    appearance: none; cursor: pointer; font: inherit; font-size: .88rem; font-weight: 600;
    padding: .5rem .95rem; border-radius: .45rem;
    border: 1px solid var(--line-soft); background: none; color: var(--text);
  }
  button.ghost:hover { border-color: var(--gold-500); color: var(--gold-400); }
  .seg { display: inline-flex; border: 1px solid var(--line-soft); border-radius: .45rem; overflow: hidden; }
  .seg button {
    appearance: none; cursor: pointer; font: inherit; font-size: .84rem; font-weight: 600;
    padding: .42rem .8rem; background: none; border: 0; color: var(--muted);
  }
  .seg button + button { border-left: 1px solid var(--line-soft); }
  .seg button[aria-pressed="true"] { background: rgba(200, 168, 78, .14); color: var(--gold-400); }
  .seg button:disabled { opacity: .4; cursor: not-allowed; }

  /* Certificate cards -------------------------------------------------- */
  .cert {
    border: 1px solid var(--line-soft); border-radius: .5rem;
    padding: .8rem .9rem; margin-bottom: .6rem; background: rgba(10, 22, 40, .4);
  }
  .cert-head { display: flex; align-items: center; gap: .5rem; margin-bottom: .5rem; flex-wrap: wrap; }
  .role { font-size: .68rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; padding: .15rem .45rem; border-radius: .3rem; }
  .role.leaf { background: rgba(16, 185, 129, .16); color: #4ade80; }
  .role.root { background: rgba(200, 168, 78, .16); color: var(--gold-400); }
  .role.intermediate { background: rgba(65, 119, 181, .2); color: #7fb2e6; }
  .cert-head .subject { font-weight: 600; font-size: .9rem; }
  .kv { display: grid; grid-template-columns: minmax(7rem, auto) 1fr; gap: .18rem .8rem; font-size: .8rem; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; font-family: "JetBrains Mono", ui-monospace, monospace; word-break: break-all; font-size: .76rem; }
  details.more { margin-top: .55rem; }
  details.more summary { cursor: pointer; font-size: .8rem; color: var(--gold-400); }
  details.more pre { margin: .5rem 0 0; }

  .mono { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: .8rem; word-break: break-all; }
  .did-box {
    padding: .55rem .7rem; border-radius: .45rem; font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: .79rem; word-break: break-all; background: rgba(200, 168, 78, .08);
    border: 1px solid var(--line); color: var(--gold-200);
  }
  .note { font-size: .82rem; color: var(--muted); margin: .6rem 0 0; }
  .note.warn { color: #fbbf24; }
  .pill { font-size: .7rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; padding: .16rem .45rem; border-radius: .3rem; }
  .pill.ok { background: rgba(16, 185, 129, .16); color: #4ade80; }
  .pill.bad { background: rgba(220, 66, 39, .16); color: #fca5a5; }
  .claims { display: grid; grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr)); gap: .55rem; }
  .claim { display: flex; flex-direction: column; gap: .25rem; }
  .claim small { color: var(--muted); font-size: .72rem; }
  .claim .claim-row { display: flex; align-items: center; gap: .4rem; }
  .claim input[type=checkbox] { width: auto; }
  .outcome { margin-top: .8rem; padding-top: .8rem; border-top: 1px dashed var(--line-soft); }

  /* Verification verdict + checklist ----------------------------------- */
  .verdict {
    display: flex; align-items: flex-start; gap: .7rem;
    padding: .8rem .9rem; border-radius: var(--radius);
    border: 1px solid var(--line-soft); margin-bottom: .9rem;
  }
  .verdict.good { background: rgba(16, 185, 129, .1); border-color: rgba(16, 185, 129, .4); }
  .verdict.bad { background: rgba(220, 66, 39, .1); border-color: rgba(220, 66, 39, .4); }
  .verdict-mark {
    flex: none; width: 1.5rem; height: 1.5rem; border-radius: 50%;
    display: grid; place-items: center; font-weight: 700; font-size: .9rem;
  }
  .verdict.good .verdict-mark { background: var(--ok); color: #04140d; }
  .verdict.bad .verdict-mark { background: var(--bad); color: #fff; }
  .verdict b { display: block; font-size: .95rem; }
  .verdict small { display: block; color: var(--muted); font-size: .8rem; margin-top: .2rem; }

  .checks { display: grid; gap: .45rem; margin-bottom: .9rem; }
  .check {
    display: flex; align-items: flex-start; gap: .6rem;
    padding: .5rem .7rem; border-radius: .5rem;
    background: rgba(255, 255, 255, .03); border: 1px solid var(--line-soft);
  }
  .check .tick { flex: none; width: 1.1rem; font-weight: 700; text-align: center; }
  .check.ok .tick { color: #4ade80; }
  .check.bad .tick { color: #fca5a5; }
  .check.skip .tick { color: var(--muted); }
  .check.skip { opacity: .75; }
  .check b { display: block; font-size: .84rem; font-weight: 600; }
  .check small { display: block; color: var(--muted); font-size: .77rem; margin-top: .12rem; line-height: 1.4; }
  h3.sub {
    font-size: .8rem; text-transform: uppercase; letter-spacing: .07em;
    color: var(--gold-400); margin: 1.1rem 0 .5rem;
  }
  .did-box {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: .85rem; word-break: break-all;
    padding: .7rem .8rem; border-radius: .5rem;
    background: rgba(200, 168, 78, .08); border: 1px solid rgba(200, 168, 78, .3);
  }

  /* Flow grid ---------------------------------------------------------- */
  .flows { display: grid; gap: .8rem; grid-template-columns: repeat(auto-fit, minmax(14.5rem, 1fr)); margin-bottom: 1rem; }
  button {
    padding: .95rem 1.05rem;
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
    background: var(--panel);
    color: inherit; font: inherit; text-align: left; cursor: pointer;
    transition: border-color .16s, background .16s, transform .16s;
  }
  button:hover:not(:disabled) {
    border-color: var(--gold-500);
    background: rgba(200, 168, 78, .08);
    transform: translateY(-1px);
  }
  button:focus-visible { outline: 2px solid var(--gold-400); outline-offset: 2px; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  button.action:disabled, button.ghost:disabled { cursor: not-allowed; }
  button strong { display: block; margin-bottom: .2rem; font-weight: 600; }
  button span { font-size: .85rem; color: var(--muted); }
  #run-all {
    width: 100%; text-align: center; margin-bottom: 2rem;
    border-color: rgba(200, 168, 78, .45);
    background: linear-gradient(180deg, rgba(200, 168, 78, .12), rgba(200, 168, 78, .04));
    font-weight: 600;
  }
  #run-all strong { margin: 0; }

  /* Results ------------------------------------------------------------ */
  .result {
    border: 1px solid var(--line-soft); border-radius: var(--radius);
    background: var(--panel); padding: 1.1rem 1.15rem; margin-top: 1rem;
  }
  .result h3 { margin: 0 0 .3rem; font-size: 1.02rem; display: flex; align-items: center; gap: .55rem; flex-wrap: wrap; }
  .badge { display: inline-block; padding: .12rem .55rem; border-radius: 999px; font-size: .72rem; font-weight: 600; letter-spacing: .02em; }
  .ok { background: rgba(16, 185, 129, .14); color: #34d399; border: 1px solid rgba(16, 185, 129, .3); }
  .bad { background: rgba(220, 66, 39, .15); color: #f87171; border: 1px solid rgba(220, 66, 39, .35); }
  .summary { margin: .25rem 0 .75rem; font-size: .9rem; color: var(--muted); }
  .did {
    font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace;
    font-size: .76rem; word-break: break-all; color: var(--gold-200);
    background: rgba(0, 0, 0, .25); border-radius: .45rem; padding: .5rem .65rem;
  }
  pre {
    background: rgba(0, 0, 0, .35); border: 1px solid var(--line-soft);
    padding: 1rem; border-radius: .5rem; overflow: auto;
    font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace;
    font-size: .8rem; max-height: 30rem; margin: 1rem 0 0;
  }
  .error { color: #f87171; }
  .running { color: var(--muted); }

  /* Credo flow --------------------------------------------------------- */
  .credo-source {
    display: flex; align-items: center; gap: .75rem; flex-wrap: wrap;
    padding: .85rem 1rem; border: 1px solid var(--line-soft); border-radius: var(--radius);
    background: var(--panel); margin-bottom: 1.25rem;
  }
  .credo-source #credo-source-note { flex: 1 1 16rem; }
  /* A neutral pill, for states that are neither a pass nor a failure. */
  .pill.neutral { background: rgba(255, 255, 255, .06); color: var(--muted); }
  /* Pills sit in a row above the key/value detail of each Credo step. */
  .steps-ok { display: flex; flex-wrap: wrap; gap: .4rem; margin: 0 0 .8rem; }
  .steps-ok .pill + .pill { margin-left: 0; }
  /* h3.sub labels the disclosed/withheld columns of the verification step. */
  h3.sub { font-size: .86rem; margin: 0 0 .5rem; color: var(--muted); }
  /* De-emphasised text, e.g. withheld claims in the verification detail. */
  .muted { color: var(--muted); }

  /* Capability matrix -------------------------------------------------- */
  /* A collapsible reference table: out of the way until wanted, but one click
     from the key-type form it explains. */
  .matrix { margin: 0 0 1.5rem; border: 1px solid var(--line-soft); border-radius: .5rem; background: rgba(255,255,255,.02); }
  .matrix > summary { cursor: pointer; list-style: none; padding: .7rem .9rem; display: flex; flex-wrap: wrap; align-items: baseline; gap: .6rem; }
  .matrix > summary::-webkit-details-marker { display: none; }
  .matrix > summary::before { content: "▸"; color: var(--gold-400); font-size: .8rem; }
  .matrix[open] > summary::before { content: "▾"; }
  .matrix-title { font-weight: 600; font-size: .92rem; }
  .matrix-body { padding: 0 .9rem 1rem; overflow-x: auto; }
  table.caps { border-collapse: collapse; width: 100%; font-size: .82rem; }
  table.caps th, table.caps td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line-soft); vertical-align: top; }
  table.caps th { color: var(--muted); font-weight: 600; font-size: .74rem; letter-spacing: .04em; text-transform: uppercase; white-space: nowrap; }
  table.caps td.key { white-space: nowrap; }
  table.caps td.key b { font-weight: 600; }
  table.caps td.key small { display: block; color: var(--muted); font-size: .74rem; }
  /* A per-cell verdict pill, with the algorithm named when it works. */
  .cap { display: inline-block; font-size: .72rem; font-weight: 700; padding: .14rem .4rem; border-radius: .3rem; white-space: nowrap; }
  .cap.yes { background: rgba(16, 185, 129, .16); color: #4ade80; }
  .cap.no { background: rgba(220, 66, 39, .14); color: #fca5a5; }
  .cap.spec { background: rgba(255, 255, 255, .06); color: var(--muted); }
  .cap-why { display: block; color: var(--muted); font-size: .74rem; margin-top: .25rem; max-width: 24rem; }

  /* Footer ------------------------------------------------------------- */
  footer { margin-top: 3rem; padding-top: 1.25rem; border-top: 1px solid var(--line); font-size: .84rem; color: var(--muted); }
  footer p { margin: 0 0 .5rem; }
  code { font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace; font-size: .82em; background: rgba(255, 255, 255, .06); padding: .1rem .35rem; border-radius: .3rem; }
  a { color: var(--gold-400); text-decoration: none; border-bottom: 1px solid rgba(208, 163, 88, .3); }
  a:hover { color: var(--gold-200); border-bottom-color: var(--gold-200); }
  .credit { margin-top: 1rem; font-size: .78rem; opacity: .7; }
</style>
</head>
<body>
<div class="wrap">
<header>
  <span class="brand">
    ${LOGO_MARK}
    <span class="wordmark">Ayanworks</span>
  </span>
  <span class="divider" aria-hidden="true"></span>
  <span class="product"><b>did:x509</b> playground</span>
</header>

<div class="badge-row"><span class="dot" aria-hidden="true"></span> Digital Trust Infrastructure</div>
<h1>Resolve <span class="accent">did:x509</span> DIDs and sign credentials</h1>
<p class="tagline">
  Every run builds a throwaway CA and leaf certificate chain, derives the DID from
  the chain, and signs a credential with the certificate's own key — issued and
  verified end to end. The Certificate Studio keeps nothing; the Credo flow opens
  a per-browser wallet in memory that disappears with your session.
</p>

<div class="tabs" role="tablist">
  <button class="tab" role="tab" id="tab-studio" aria-controls="panel-studio" aria-selected="true">Certificate Studio</button>
  <button class="tab" role="tab" id="tab-credo" aria-controls="panel-credo" aria-selected="false">Credo flow</button>
  <button class="tab" role="tab" id="tab-flows" aria-controls="panel-flows" aria-selected="false">Smoke tests</button>
</div>

<section id="panel-studio" role="tabpanel" aria-labelledby="tab-studio">
  <p class="note" style="margin:0 0 1rem">
    Bring your own CA or generate a test one, derive its <b>did:x509</b> DID, sign a
    credential, then verify it and recover the issuer from the credential itself.
    Parsing is per-request: nothing you paste is stored.
  </p>

  <!-- capability matrix --------------------------------------------------- -->
  <details class="matrix" id="capability-matrix">
    <summary>
      <span class="matrix-title">Which key type signs which credential format</span>
      <span class="note" style="margin:0">signing algorithms, per spec and as implemented</span>
    </summary>
    <div class="matrix-body" id="capability-matrix-body">
      <p class="note" style="margin:0 0 .8rem">
        Loading…
      </p>
    </div>
  </details>

  <!-- 1 ------------------------------------------------------------------ -->
  <div class="step" id="step-1" data-done="false">
    <div class="step-head"><span class="step-num">1</span><h2>Load a certificate chain</h2></div>
    <p class="hint">Generate a throwaway test CA, or paste a real PEM chain with its leaf private key.</p>
    <div class="body">
      <div class="seg" role="group" aria-label="Identity source">
        <button id="src-generate" aria-pressed="true">Generate test CA</button>
        <button id="src-upload" aria-pressed="false">Upload real chain</button>
      </div>

      <!-- generation form -->
      <div id="form-generate" style="margin-top:1rem">
        <div class="grid-2">
          <div class="field"><label for="ca-alg">CA key algorithm</label><select id="ca-alg"></select></div>
          <div class="field"><label for="leaf-alg">Leaf key algorithm</label><select id="leaf-alg"></select></div>
          <div class="field"><label for="ca-cn">CA common name (CN)</label><input id="ca-cn" type="text" value="AyanWorks Test Root CA"></div>
          <div class="field"><label for="ca-o">CA organisation (O)</label><input id="ca-o" type="text" value="AyanWorks"></div>
          <div class="field"><label for="leaf-cn">Leaf common name (CN)</label><input id="leaf-cn" type="text" value="Acme Engineering"></div>
          <div class="field"><label for="leaf-o">Leaf organisation (O)</label><input id="leaf-o" type="text" value="Acme Corp"></div>
          <div class="field"><label for="leaf-ou">Leaf organisational unit (OU)</label><input id="leaf-ou" type="text" value="Engineering"></div>
          <div class="field"><label for="leaf-c">Leaf country (C)</label><input id="leaf-c" type="text" value="US"></div>
          <div class="field"><label for="validity">Validity (days)</label><input id="validity" type="number" value="30" min="1" max="3650"></div>
          <div class="field"><label for="did-attr">DID subject attribute</label><select id="did-attr"></select></div>
        </div>
        <div class="row"><button class="action" id="btn-generate">Generate chain</button></div>
      </div>

      <!-- upload form -->
      <div id="form-upload" hidden style="margin-top:1rem">
        <div class="field">
          <label for="up-chain">PEM certificate chain — leaf first, then its issuers</label>
          <textarea id="up-chain" placeholder="-----BEGIN CERTIFICATE-----
…leaf…
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
…issuing CA…
-----END CERTIFICATE-----"></textarea>
        </div>
        <div class="field">
          <label for="up-key">Leaf private key PEM (optional — required to sign)</label>
          <textarea id="up-key" placeholder="-----BEGIN PRIVATE KEY-----
…PKCS#8, PKCS#1 or SEC1 all work…
-----END PRIVATE KEY-----"></textarea>
        </div>
        <div class="field" style="max-width:16rem"><label for="up-attr">DID subject attribute</label><select id="up-attr"></select></div>
        <div class="row"><button class="action" id="btn-upload">Parse chain</button></div>
        <p class="note">No key? The chain is still inspected and its DID resolved — signing stays disabled.</p>
      </div>
      <div id="step-1-out"></div>
    </div>
  </div>

  <!-- 2 ------------------------------------------------------------------ -->
  <div class="step locked" id="step-2" data-done="false">
    <div class="step-head"><span class="step-num">2</span><h2>Certificate details</h2></div>
    <p class="hint">Every certificate in the chain, as parsed — subject, validity, key, extensions, fingerprints.</p>
    <div class="body" id="step-2-out"><p class="note">Load a chain first.</p></div>
  </div>

  <!-- 3 ------------------------------------------------------------------ -->
  <div class="step locked" id="step-3" data-done="false">
    <div class="step-head"><span class="step-num">3</span><h2>Derived DID</h2></div>
    <p class="hint">The did:x509 DID falls out of the chain — anchored on the CA fingerprint and the leaf's subject attribute.</p>
    <div class="body">
      <div id="step-3-out"><p class="note">Load a chain first.</p></div>
    </div>
  </div>

  <!-- 4 + 5 -------------------------------------------------------------- -->
  <div class="step locked" id="step-4" data-done="false">
    <div class="step-head"><span class="step-num">4</span><h2>Sign a credential</h2></div>
    <p class="hint">Pick a credential type and format. The leaf key signs; the chain is embedded in the credential.</p>
    <div class="body">
      <div class="grid-2">
        <div class="field"><label for="vc-template">Credential type</label><select id="vc-template"></select></div>
        <div class="field"><label for="vc-format">Format</label><select id="vc-format"></select></div>
      </div>
      <div class="field"><label>Claims</label><div class="claims" id="vc-claims"></div></div>
      <div class="row" style="margin-top:.4rem">
        <button class="action" id="btn-sign">Sign credential</button>
        <span class="note" id="vc-hint" style="margin:0"></span>
      </div>
      <div id="step-4-out"></div>
    </div>
  </div>

  <!-- 6 ------------------------------------------------------------------ -->
  <div class="step locked" id="step-5" data-done="false">
    <div class="step-head"><span class="step-num">6</span><h2>Verify &amp; recover the issuer</h2></div>
    <p class="hint">A verifier gets only the credential. It checks the issuer signature, the embedded chain, and the DID, then rebuilds the issuer identity from the chain.</p>
    <div class="body">
      <div class="row" style="margin:0 0 .6rem">
        <button class="action" id="btn-verify" disabled>Verify credential</button>
      </div>
      <div id="step-5-out"><p class="note">Sign a credential first.</p></div>
    </div>
  </div>
</section>

<section id="panel-credo" role="tabpanel" aria-labelledby="tab-credo" hidden>
  <p class="note" style="margin:0 0 1rem">
    The full Credo integration, driven from your browser through a <b>real Credo
    <code>Agent</code></b> with an <b>Askar wallet</b>. It reuses the chain you
    loaded in the Certificate Studio — switch to that tab and load one first.
  </p>

  <div id="credo-unavailable" hidden>
    <p class="note warn">
      The Credo Agent needs the native Askar backend, which is unavailable on
      this host. This playground must be started with Node
      (<code>npm start</code>) for the Credo flow. The Certificate Studio and the
      Smoke tests work everywhere.
    </p>
  </div>

  <div id="credo-ready">
    <div class="credo-source" id="credo-source">
      <span class="pill neutral" id="credo-source-pill">no chain loaded</span>
      <span class="note" id="credo-source-note" style="margin:0">
        Load a chain in the Certificate Studio tab to begin.
      </span>
    </div>

    <!-- 1 -->
    <div class="step locked" id="credo-step-1" data-done="false">
      <div class="step-head"><span class="step-num">1</span><h2>Start a Credo Agent</h2></div>
      <p class="hint">A real <code>Agent</code> with an in-memory Askar wallet, created for this browser session only.</p>
      <div class="body">
        <div class="row" style="margin:0 0 .6rem">
          <button class="action step-run" id="btn-credo-step-1" disabled>Run this step</button>
        </div>
        <div id="credo-1-out"><p class="note">Load a chain first.</p></div>
      </div>
    </div>

    <!-- 2 -->
    <div class="step locked" id="credo-step-2" data-done="false">
      <div class="step-head"><span class="step-num">2</span><h2>Resolve the DID through the Agent</h2></div>
      <p class="hint"><code>agent.dids.resolve(did, { x509chain })</code> — the chain is the trust anchor, so it travels with every call.</p>
      <div class="body">
        <div class="row" style="margin:0 0 .6rem">
          <button class="action step-run" id="btn-credo-step-2" disabled>Run this step</button>
        </div>
        <div id="credo-2-out"><p class="note">Resolve a chain first.</p></div>
      </div>
    </div>

    <!-- 3 -->
    <div class="step locked" id="credo-step-3" data-done="false">
      <div class="step-head"><span class="step-num">3</span><h2>Import the certificate key</h2></div>
      <p class="hint">The leaf certificate's private key goes into the Askar wallet; the wallet's copy is compared against the certificate.</p>
      <div class="body">
        <div class="row" style="margin:0 0 .6rem">
          <button class="action step-run" id="btn-credo-step-3" disabled>Run this step</button>
        </div>
        <div id="credo-3-out"><p class="note">Resolve a chain first.</p></div>
      </div>
    </div>

    <!-- 4 -->
    <div class="step locked" id="credo-step-4" data-done="false">
      <div class="step-head"><span class="step-num">4</span><h2>Bind the DID to the key</h2></div>
      <p class="hint"><code>agent.dids.import({ did, didDocument, keys })</code> — the DID document now names a key the wallet holds.</p>
      <div class="body">
        <div class="row" style="margin:0 0 .6rem">
          <button class="action step-run" id="btn-credo-step-4" disabled>Run this step</button>
        </div>
        <div id="credo-4-out"><p class="note">Import a key first.</p></div>
      </div>
    </div>

    <!-- 5 -->
    <div class="step locked" id="credo-step-5" data-done="false">
      <div class="step-head"><span class="step-num">5</span><h2>What is in the wallet</h2></div>
      <p class="hint">Read back from the wallet — the DID and the key type Askar is actually holding.</p>
      <div class="body">
        <div class="row" style="margin:0 0 .6rem">
          <button class="action step-run" id="btn-credo-step-5" disabled>Run this step</button>
        </div>
        <div id="credo-5-out"><p class="note">Import the DID first.</p></div>
      </div>
    </div>

    <!-- 6 -->
    <div class="step locked" id="credo-step-6" data-done="false">
      <div class="step-head"><span class="step-num">6</span><h2>Issue a credential</h2></div>
      <p class="hint">An SD-JWT VC signed by the <b>wallet-managed key</b>, with <code>iss</code> = the did:x509 DID. The certificate key never leaves the wallet.</p>
      <div class="body">
        <div class="row" style="margin:0 0 .6rem">
          <button class="action step-run" id="btn-credo-step-6" disabled>Run this step</button>
        </div>
        <div id="credo-6-out"><p class="note">Bind the DID first.</p></div>
      </div>
    </div>

    <!-- 7 -->
    <div class="step locked" id="credo-step-7" data-done="false">
      <div class="step-head"><span class="step-num">7</span><h2>Verify</h2></div>
      <p class="hint">The verifier re-resolves the DID from the chain, then checks the signature — the holder discloses one claim and withholds another.</p>
      <div class="body">
        <div class="row" style="margin:0 0 .6rem">
          <button class="action step-run" id="btn-credo-verify" disabled>Run this step</button>
        </div>
        <div id="credo-7-out"><p class="note">Issue a credential first.</p></div>
      </div>
    </div>

    <div class="row" style="margin-top:1rem">
      <button class="action" id="btn-credo-run">Run all seven steps</button>
      <button class="ghost" id="btn-credo-reset">Reset the wallet</button>
    </div>
    <div id="credo-run-out"></div>
  </div>
</section>

<section id="panel-flows" role="tabpanel" aria-labelledby="tab-flows" hidden>
  <p class="note" style="margin:0 0 1rem">
    Five self-contained smoke-test flows, each starting from a fresh throwaway chain.
    These mirror <code>npm run all</code>, so the CLI and this page exercise the same code.
  </p>
  <div class="flows" id="flows">
    <button data-flow="resolve"><strong>Resolve</strong><span>Recover a DID document from a certificate chain</span></button>
    <button data-flow="jsonld"><strong>JSON-LD VC</strong><span>Data Integrity credential (eddsa-rdfc-2022)</span></button>
    <button data-flow="sd-jwt"><strong>SD-JWT VC</strong><span>ES256 with selective disclosure</span></button>
    <button data-flow="mdoc"><strong>mDoc</strong><span>ISO/IEC 18013-5 with x5chain</span></button>
    <button data-flow="credo"><strong>Credo</strong><span>Resolve, import and verify via @didx509/credo</span></button>
  </div>
  <button id="run-all"><strong>Run all five flows</strong></button>
  <main id="output"></main>
</section>


<footer>
  <p>
    Wraps Microsoft's <a href="https://github.com/microsoft/didx509cpp">didx509cpp</a> reference resolver.
    Prefer the CLI? <code>npm run all</code> runs every flow locally.
  </p>
  <p class="credit">
    Built by <a href="https://www.ayanworks.com">AYANWORKS</a> — Digital Trust Infrastructure for Nations.
  </p>
</footer>
</div>

<script type="module">
  const output = document.getElementById('output');
  const buttons = [...document.querySelectorAll('#flows button')];
  const runAll = document.getElementById('run-all');

  const esc = s => String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]);

  function render(results) {
    output.innerHTML = results.map(r => {
      const ok = r.flow === 'jsonld' || r.flow === 'sd-jwt'
        ? r.details.verified
        : r.flow === 'credo'
          // Keyless resolution is a valid outcome, not a failure.
          ? r.details.canSign === false || r.details.verified
          : r.flow === 'mdoc'
            ? r.details.issuerAuthVerified
            : true;
      const { document, credential, didDocument, ...rest } = r.details;
      return \`
        <section class="result">
          <h3>\${esc(r.title)}
            <span class="badge \${ok ? 'ok' : 'bad'}">\${ok ? 'verified' : 'failed'}</span>
          </h3>
          <p class="summary">\${esc(r.summary)}</p>
          <div class="did">\${esc(r.did)}</div>
          <pre>\${esc(JSON.stringify(rest, null, 2))}</pre>
        </section>\`;
    }).join('');
  }

  function error(message) {
    output.innerHTML = \`<section class="result"><h3 class="error">Error</h3><pre>\${esc(message)}</pre></section>\`;
  }

  async function run(path) {
    buttons.forEach(b => b.disabled = true);
    runAll.disabled = true;
    output.innerHTML = '<section class="result running">Running…</section>';
    try {
      const res = await fetch(path, { method: 'POST' });
      const body = await res.json();
      if (!res.ok) return error(body.error ?? \`HTTP \${res.status}\`);
      render(body.results);
    } catch (e) {
      error(e.message);
    } finally {
      buttons.forEach(b => b.disabled = false);
      runAll.disabled = false;
    }
  }

  buttons.forEach(b => b.addEventListener('click', () => run(\`/api/run/\${b.dataset.flow}\`)));
  runAll.addEventListener('click', () => run('/api/run'));
</script>
<script type="module">
${STUDIO_SCRIPT}
</script>
</body>
</html>
`;
