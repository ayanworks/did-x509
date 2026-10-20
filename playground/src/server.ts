// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Playground HTTP handler.
 *
 * This module is deliberately host-agnostic: it exports a `fetch`-shaped
 * handler and does no I/O of its own beyond calling the flow functions. The
 * Deno entry point (`main.ts`) binds it to `Deno.serve`; a Cloudflare Worker
 * would bind the same handler to `export default { fetch }`. Keeping the
 * split here is what makes the April 2027 host change a config edit rather
 * than a rewrite.
 */

import { FLOWS, runAll, type FlowName, type FlowResult } from './flows.ts';

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  // The playground is a public demo with no user data.
  'access-control-allow-origin': '*',
} as const;

/** Wrap a payload in a JSON response. */
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: JSON_HEADERS,
  });
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

const HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>did:x509 playground</title>
<style>
  :root { color-scheme: light dark; --accent: #4f46e5; }
  * { box-sizing: border-box; }
  body {
    margin: 0 auto; padding: 2rem 1.25rem; max-width: 60rem;
    font: 16px/1.6 system-ui, -apple-system, Segoe UI, sans-serif;
  }
  h1 { margin: 0 0 .25rem; font-size: 1.9rem; }
  .tagline { margin: 0 0 2rem; opacity: .75; }
  .flows { display: grid; gap: .75rem; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); margin-bottom: 2rem; }
  button {
    padding: .85rem 1rem; border: 1px solid color-mix(in srgb, currentColor 25%, transparent);
    border-radius: .6rem; background: transparent; color: inherit;
    font: inherit; text-align: left; cursor: pointer; transition: border-color .15s, background .15s;
  }
  button:hover:not(:disabled) { border-color: var(--accent); background: color-mix(in srgb, var(--accent) 8%, transparent); }
  button:disabled { opacity: .5; cursor: progress; }
  button strong { display: block; margin-bottom: .15rem; }
  button span { font-size: .875rem; opacity: .7; }
  #run-all { width: 100%; text-align: center; margin-bottom: 2rem; border-color: var(--accent); }
  pre {
    background: color-mix(in srgb, currentColor 7%, transparent);
    padding: 1rem; border-radius: .6rem; overflow: auto; font-size: .82rem;
    max-height: 32rem;
  }
  .result { border-top: 1px solid color-mix(in srgb, currentColor 15%, transparent); padding-top: 1rem; margin-top: 1rem; }
  .result h3 { margin: 0 0 .25rem; font-size: 1rem; }
  .badge { display: inline-block; padding: .1rem .5rem; border-radius: 1rem; font-size: .75rem; font-weight: 600; }
  .ok { background: #16a34a22; color: #15803d; }
  .bad { background: #dc262622; color: #b91c1c; }
  .summary { margin: .25rem 0 .75rem; font-size: .9rem; opacity: .8; }
  .did { font-family: ui-monospace, Menlo, monospace; font-size: .78rem; word-break: break-all; opacity: .8; }
  .error { color: #b91c1c; }
  footer { margin-top: 2.5rem; font-size: .82rem; opacity: .65; }
  a { color: var(--accent); }
</style>
</head>
<body>
<h1>did:x509 playground</h1>
<p class="tagline">
  Resolve DIDs and sign credentials with certificate-backed identities.
  Each run generates a throwaway CA + leaf chain — nothing is stored.
</p>

<div class="flows" id="flows">
  <button data-flow="resolve"><strong>Resolve</strong><span>Recover a DID document from a certificate chain</span></button>
  <button data-flow="jsonld"><strong>JSON-LD VC</strong><span>Data Integrity credential (eddsa-rdfc-2022)</span></button>
  <button data-flow="sd-jwt"><strong>SD-JWT VC</strong><span>ES256 with selective disclosure</span></button>
  <button data-flow="mdoc"><strong>mDoc</strong><span>ISO/IEC 18013-5 with x5chain</span></button>
</div>

<button id="run-all"><strong>Run all four flows</strong></button>

<main id="output"></main>

<footer>
  Wraps Microsoft's <a href="https://github.com/microsoft/didx509cpp">didx509cpp</a> reference resolver.
  Prefer the CLI? <code>deno task all</code> runs every flow locally.
</footer>

<script type="module">
  const output = document.getElementById('output');
  const buttons = [...document.querySelectorAll('#flows button')];
  const runAll = document.getElementById('run-all');

  const esc = s => String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]);

  function render(results) {
    output.innerHTML = results.map(r => {
      const ok = r.flow === 'jsonld' || r.flow === 'sd-jwt'
        ? r.details.verified
        : r.flow === 'mdoc'
          ? r.details.issuerAuthVerified
          : true;
      const { document, credential, ...rest } = r.details;
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
    output.innerHTML = '<section class="result">Running…</section>';
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
</body>
</html>
`;
