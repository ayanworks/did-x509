// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Certificate Studio browser logic, embedded in the landing page.
 *
 * Kept in its own file and inlined at serve time so the page needs no bundler
 * and no extra request — the playground stays a single self-contained HTML
 * response, which is what makes it deployable anywhere, including an edge
 * runtime with no build step.
 *
 * ## State
 *
 * The only state is `identity`, the last parsed/generated chain, held in the
 * browser. Signing re-sends its PEM with every request because the server
 * deliberately keeps nothing between calls. That is why `keyPem` travels back
 * from the server for generated chains: the browser has nowhere else to get it.
 */

export const STUDIO_SCRIPT = String.raw`
(() => {
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

  // The last loaded identity, held client-side only.
  let identity = null;
  let catalogue = { credentials: [], options: { algorithms: [], subjectAttributes: [] }, capabilityMatrix: null };
  let signed = null;

  async function api(path, body) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    });
    const payload = await res.json();
    if (!res.ok) throw new Error(payload.error ?? 'HTTP ' + res.status);
    return payload;
  }

  // --- tabs ---------------------------------------------------------------
  const tabs = {
    studio: { button: $('tab-studio'), panel: $('panel-studio') },
    credo: { button: $('tab-credo'), panel: $('panel-credo') },
    flows: { button: $('tab-flows'), panel: $('panel-flows') },
  };
  function selectTab(which) {
    for (const [name, { button, panel }] of Object.entries(tabs)) {
      const active = name === which;
      button.setAttribute('aria-selected', String(active));
      panel.hidden = !active;
    }
    if (which === 'credo') syncCredoSource();
  }
  for (const [name, { button }] of Object.entries(tabs)) {
    button.addEventListener('click', () => selectTab(name));
  }

  // --- step helpers -------------------------------------------------------
  function setStep(n, state) {
    const el = $('step-' + n);
    el.dataset.done = state === 'done' ? 'true' : 'false';
    el.classList.toggle('locked', state === 'locked');
  }

  /** Same, for the Credo tab's steps, whose ids already carry the prefix. */
  function setCredoStep(n, state) {
    const el = $('credo-step-' + n);
    el.dataset.done = state === 'done' ? 'true' : 'false';
    el.classList.toggle('locked', state === 'locked');
  }
  function fail(target, message) {
    $(target).innerHTML = '<p class="note warn">' + esc(message) + '</p>';
  }

  // --- certificate rendering ---------------------------------------------
  function renderCertificates(certs) {
    return certs.map(c => {
      const x = c.extensions;
      const rows = [
        ['Issuer', c.issuer],
        ['Serial', c.serialNumber],
        ['Valid from', c.notBefore.slice(0, 10)],
        ['Valid to', c.notAfter.slice(0, 10) + (c.expired ? ' (expired)' : '')],
        ['Validity', c.validityDays + ' days'],
        ['Signature', c.signatureAlgorithm],
        ['Public key', c.keyType + (c.keySizeBits ? ' · ' + c.keySizeBits + ' bit' : '')],
        ['SHA-256', c.sha256],
      ];
      if (x.basicConstraints) rows.push(['Basic constraints', x.basicConstraints + (x.isCa ? '' : ' (cannot sign other certs)')]);
      if (x.keyUsage && x.keyUsage.length) rows.push(['Key usage', x.keyUsage.join(', ')]);
      if (x.extendedKeyUsage) rows.push(['Extended key usage', x.extendedKeyUsage.join(', ')]);
      if (x.subjectAltName) rows.push(['Subject alt names', x.subjectAltName.map(s => s.type + ':' + s.value).join(', ')]);

      return '<div class="cert">'
        + '<div class="cert-head"><span class="role ' + c.role + '">' + c.role + '</span>'
        + '<span class="subject">' + esc(c.subject) + '</span>'
        + (c.expired ? '<span class="pill bad">expired</span>' : '<span class="pill ok">valid</span>')
        + (c.selfSigned ? '<span class="pill ok">self-signed</span>' : '')
        + (c.extensions.isCa && !c.extensions.canSign ? '<span class="pill bad">CA-only</span>' : '')
        + '</div>'
        + '<dl class="kv">' + rows.map(([k, v]) =>
            '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>').join('') + '</dl>'
        + '<details class="more"><summary>PEM · ' + c.sizeBytes + ' bytes · SHA-384/512</summary>'
        + '<pre>' + esc(c.pem) + '</pre></details>'
        + '</div>';
    }).join('');
  }

  // --- step 1: load -------------------------------------------------------
  async function loadIdentity(payload) {
    const { identity: next } = await api(payload.endpoint, payload.body);
    identity = next;
    signed = null;

    // Steps 2 and 3 are always available once a chain is loaded; 4 needs a key.
    setStep(2, 'done');
    $('step-2-out').innerHTML = renderCertificates(next.certificates);

    $('step-3-out').innerHTML =
      '<div class="did-box">' + esc(next.did) + '</div>'
      + '<p class="note">Verification method <code>' + esc(next.verificationMethodId) + '</code>'
      + ' · subject attribute <b>' + esc(next.didSubjectAttribute) + '</b>'
      + ' · ' + next.certificates.length + ' certificate(s) in chain.</p>'
      + (next.warnings.length ? next.warnings.map(w => '<p class="note warn">' + esc(w) + '</p>').join('') : '')
      + '<details class="more"><summary>DID document (' + (next.didDocument.verificationMethod || []).length + ' verification method)</summary>'
      + '<pre>' + esc(JSON.stringify(next.didDocument, null, 2)) + '</pre></details>';
    setStep(3, 'done');

    // A new chain invalidates the Credo tab's loaded source; it re-reads
    // from here.
    resetCredo();

    // Step 4: only if a key is present.
    if (next.keyPresent) {
      setStep(4, 'open');
      $('vc-hint').textContent = 'Signing with ' + (next.keyType || 'key')
        + (next.keyFormat ? ' (' + next.keyFormat + ')' : '')
        + '. Signable formats: ' + next.signableFormats.join(', ') + '.';
    } else {
      setStep(4, 'locked');
      setStep(5, 'locked');
      $('step-4-out').innerHTML = '';
      $('step-5-out').innerHTML = '<p class="note">No private key, so no credential can be signed.</p>';
    }
    if (next.keyPresent) { setStep(5, 'locked'); $('step-5-out').innerHTML = '<p class="note">Sign a credential first.</p>'; }
    $('btn-verify').disabled = true;

    populateFormats();
  }

  // --- step 4: credential form -------------------------------------------
  function templateById(id) { return catalogue.credentials.find(c => c.id === id); }

  function populateFormats() {
    const template = templateById($('vc-template').value);
    if (!template || !identity) return;
    const ok = identity.signableFormats;
    const formats = template.formats.filter(f => ok.includes(f));
    const select = $('vc-format');
    select.innerHTML = formats.map(f => '<option value="' + f + '">' + f + '</option>').join('');
    if (formats.length === 0) {
      select.innerHTML = '<option value="">— none —</option>';
      $('btn-sign').disabled = true;
      // Say *why*, and distinguish the two possible reasons. "The spec does not
      // allow this key type" and "our COSE library cannot carry this key" are
      // different problems with different fixes, so the hint names which one.
      const keyType = identity.keyType || (identity.leafPublicJwk && identity.leafPublicJwk.kty) || '?';
      const offered = template.formats
        .map(f => capabilityNote(keyType, f))
        .filter(Boolean);
      $('vc-hint').innerHTML = 'This identity\u2019s key (' + esc(keyType)
        + ') cannot sign any format offered for this credential.'
        + (offered.length ? ' ' + esc(offered[0]) : '');
      return;
    }
    $('btn-sign').disabled = false;
    populateClaims();
  }

  /**
   * The reason a key type cannot sign a format, if the matrix has one.
   *
   * Reads the same data the capability table renders, so the inline hint and
   * the reference table always agree.
   */
  function capabilityNote(keyType, format) {
    const matrix = catalogue.capabilityMatrix;
    if (!matrix) return '';
    const row = matrix.rows.find(r => r.genAlgorithm === keyType);
    if (!row) return '';
    const cell = row.cells.find(c => c.format === format);
    return cell && cell.why ? cell.why : '';
  }

  /** Render the capability matrix: which key type signs which format. */
  function renderCapabilityMatrix() {
    const matrix = catalogue.capabilityMatrix;
    const host = $('capability-matrix-body');
    if (!host || !matrix) return;
    const head = '<tr><th>Key type</th>'
      + matrix.formats.map(f => '<th>' + esc(f.id) + '</th>').join('')
      + '</tr>';
    const rows = matrix.rows.map(row =>
      '<tr><td class="key"><b>' + esc(row.label) + '</b><small>' + esc(row.description) + '</small></td>'
      + row.cells.map(cell =>
          '<td><span class="cap ' + (cell.verdict === 'yes' ? 'yes' : cell.verdict === 'spec' ? 'spec' : 'no') + '">'
          + esc(cell.label) + '</span>'
          + (cell.why ? '<span class="cap-why">' + esc(cell.why) + '</span>' : '')
          + '</td>').join('')
      + '</tr>').join('');
    const notes = matrix.formats.map(f =>
      '<p class="note" style="margin:.4rem 0 0"><b>' + esc(f.id)
      + '</b> — allowed by spec: <code>' + esc(f.spec) + '</code>. ' + esc(f.note) + '</p>').join('');
    host.innerHTML = '<table class="caps">' + head + rows + '</table>' + notes;
  }

  function populateClaims() {
    const template = templateById($('vc-template').value);
    if (!template) return;
    const offersWithhold = $('vc-format').value === 'sd-jwt';
    $('vc-claims').innerHTML = template.claimFields.map(f =>
      '<div class="claim"><small>' + esc(f.label) + '</small>'
      + '<div class="claim-row"><input type="text" data-claim="' + esc(f.key) + '" value="' + esc(f.value) + '">'
      + (offersWithhold && f.disclosable
          ? '<label title="Withhold from the presentation"><input type="checkbox" data-withhold="' + esc(f.key) + '"> hide</label>'
          : '')
      + '</div></div>').join('');
  }

  function readClaims() {
    const claims = {};
    document.querySelectorAll('#vc-claims [data-claim]').forEach(el => { claims[el.dataset.claim] = el.value; });
    const withheld = [...document.querySelectorAll('#vc-claims [data-withhold]:checked')].map(el => el.dataset.withhold);
    return { claims, withheld };
  }

  // --- step 5: sign + verify ---------------------------------------------
  async function sign() {
    if (!identity) return;
    const { claims, withheld } = readClaims();
    $('btn-sign').disabled = true;
    $('step-4-out').innerHTML = '<p class="note">Signing…</p>';
    try {
      const result = await api('/api/sign', {
        chainPem: identity.pemChain,
        keyPem: identity.keyPem ?? identity.uploadedKeyPem,
        didSubjectAttribute: identity.didSubjectAttribute,
        format: $('vc-format').value,
        templateId: $('vc-template').value,
        claims,
        withheld,
      });
      signed = result.signed;
      const payload = typeof signed.payload === 'string' ? signed.payload : JSON.stringify(signed.payload, null, 2);

      $('step-4-out').innerHTML =
        '<div class="outcome"><p class="note">Signed with <b>' + esc(signed.format)
        + '</b>; the chain (' + signed.x5c.length + ' certificates) is embedded in the credential.</p>'
        + '<div class="field"><label>Signed payload</label><textarea readonly rows="10">' + esc(payload) + '</textarea></div>'
        + '<details class="more"><summary>Preview</summary><pre>' + esc(JSON.stringify(signed.preview, null, 2)) + '</pre></details>'
        + '</div>';
      setStep(4, 'done');

      // Step 6 is deliberately not run here: verifying is the verifier's own
      // action, and they should see the checks happen on demand rather than
      // as a side effect of signing.
      setStep(5, 'open');
      $('step-5-out').innerHTML =
        '<p class="note">Credential ready. Run the verifier to check it.</p>';
      $('btn-verify').disabled = false;
    } catch (e) {
      fail('step-4-out', e.message);
    } finally {
      $('btn-sign').disabled = false;
    }
  }

  async function verify(payload, format) {
    setStep(5, 'open');
    $('btn-verify').disabled = true;
    $('step-5-out').innerHTML = '<p class="note">Verifying signature, chain and DID…</p>';
    try {
      const { verification } = await api('/api/verify', { format, payload });
      const i = verification.issuer;

      // The verdict first: everything below it is detail.
      let html = '<div class="verdict ' + (verification.signatureValid ? 'good' : 'bad') + '">'
        + '<span class="verdict-mark">' + (verification.signatureValid ? '✓' : '✕') + '</span>'
        + '<div><b>' + (verification.signatureValid
            ? 'Credential verified'
            : 'Verification failed') + '</b>'
        + '<small>' + esc(verification.error
            ?? (verification.signatureValid
              ? 'The signature is valid and the issuer identity was recovered from the embedded chain.'
              : 'The credential did not pass verification. See the checks below.')) + '</small></div>'
        + '</div>';

      // The checks that produced the verdict.
      const checks = verification.checks || [];
      if (checks.length) {
        html += '<div class="checks">' + checks.map(c =>
          '<div class="check ' + (c.passed ? 'ok' : c.skipped ? 'skip' : 'bad') + '">'
          + '<span class="tick">' + (c.passed ? '✓' : c.skipped ? '–' : '✕') + '</span>'
          + '<div><b>' + esc(c.label) + '</b><small>' + esc(c.detail) + '</small></div>'
          + '</div>').join('') + '</div>';
      }

      // Only surface the recovered issuer when the checks support it. Showing
      // "here is your issuer" next to a failed verdict would invite reading
      // the details as trustworthy when nothing vouches for them.
      if (i && verification.signatureValid) {
        html += '<h3 class="sub">Issuer recovered from the credential</h3>'
          + '<p class="note">Claimed issuer <code class="mono">' + esc(i.claimedDid) + '</code></p>'
          + (i.subjectAttribute ? '<p class="note">Recovered subject <b>' + esc(i.subjectAttribute) + '</b> = ' + esc(i.subjectValue) + '</p>' : '')
          + '<details class="more" open><summary>Issuer certificates (' + i.certificates.length + ', from ' + esc(i.source) + ')</summary>'
          + renderCertificates(i.certificates) + '</details>'
          + i.warnings.map(w => '<p class="note warn">' + esc(w) + '</p>').join('');
      } else if (i) {
        html += '<p class="note warn">Issuer details withheld: the credential did not verify, so the recovered chain is not trustworthy.</p>';
      }

      html += '<details class="more"><summary>Raw verification result</summary><pre>'
        + esc(JSON.stringify(verification, (k, v) => k === 'pem' ? undefined : v, 2)) + '</pre></details>';

      $('step-5-out').innerHTML = html;
      setStep(5, 'done');
    } catch (e) {
      fail('step-5-out', e.message);
    } finally {
      $('btn-verify').disabled = false;
    }
  }

  // --- wiring -------------------------------------------------------------
  $('src-generate').addEventListener('click', () => {
    $('src-generate').setAttribute('aria-pressed', 'true');
    $('src-upload').setAttribute('aria-pressed', 'false');
    $('form-generate').hidden = false; $('form-upload').hidden = true;
  });
  $('src-upload').addEventListener('click', () => {
    $('src-generate').setAttribute('aria-pressed', 'false');
    $('src-upload').setAttribute('aria-pressed', 'true');
    $('form-generate').hidden = true; $('form-upload').hidden = false;
  });

  $('btn-generate').addEventListener('click', async () => {
    $('btn-generate').disabled = true;
    $('step-1-out').innerHTML = '<p class="note">Generating…</p>';
    try {
      await loadIdentity({
        endpoint: '/api/generate',
        body: {
          caSubject: { C: 'US', O: $('ca-o').value, CN: $('ca-cn').value },
          leafSubject: { C: $('leaf-c').value, O: $('leaf-o').value, OU: $('leaf-ou').value, CN: $('leaf-cn').value },
          caAlgorithm: $('ca-alg').value,
          leafAlgorithm: $('leaf-alg').value,
          validityDays: Number($('validity').value) || 30,
          didSubjectAttribute: $('did-attr').value,
        },
      });
      $('step-1-out').innerHTML = '<p class="note">Generated a throwaway CA and leaf. Nothing was stored.</p>';
      setStep(1, 'done');
    } catch (e) {
      fail('step-1-out', e.message);
    } finally {
      $('btn-generate').disabled = false;
    }
  });

  $('btn-upload').addEventListener('click', async () => {
    $('btn-upload').disabled = true;
    $('step-1-out').innerHTML = '<p class="note">Parsing…</p>';
    try {
      await loadIdentity({
        endpoint: '/api/upload',
        body: {
          chainPem: $('up-chain').value,
          keyPem: $('up-key').value,
          didSubjectAttribute: $('up-attr').value,
        },
      });
      // An uploaded key must be re-sent on each signing request, since the
      // server retains nothing; keep it alongside the parsed identity.
      identity.uploadedKeyPem = $('up-key').value;
      $('step-1-out').innerHTML = '<p class="note">Chain parsed. The private key is kept only in this page.</p>';
      setStep(1, 'done');
    } catch (e) {
      fail('step-1-out', e.message);
    } finally {
      $('btn-upload').disabled = false;
    }
  });

  $('vc-template').addEventListener('change', populateFormats);
  $('vc-format').addEventListener('change', populateClaims);
  $('btn-sign').addEventListener('click', sign);

  // ========================================================================
  // Credo flow tab
  // ========================================================================
  //
  // Drives a real Credo Agent on the server. The chain is whatever the
  // Certificate Studio loaded: the browser holds it and re-sends it, because
  // the server keeps nothing between requests. The Agent's *wallet*, though,
  // does persist — keyed by a session cookie — which is why the steps are
  // separate and why "Reset the wallet" exists.

  let credoAvailable = null;       // null = not asked yet
  let credoResult = null;          // the last run's full result
  let credoRunning = false;

  function resetCredo() {
    credoResult = null;
    $('btn-credo-verify').disabled = true;
    // Each step keeps its own "what to do first" line, so the panel reads as a
    // sequence rather than seven identical placeholders.
    const pending = {
      1: 'Load a chain first.',
      2: 'Run step 1 first.',
      3: 'Resolve the DID first.',
      4: 'Import the key first.',
      5: 'Bind the DID first.',
      6: 'Check the wallet first.',
      7: 'Issue a credential first.',
    };
    for (let n = 1; n <= 7; n++) {
      setCredoStep(n, 'locked');
      const out = $('credo-' + n + '-out');
      if (out) out.innerHTML = '<p class="note">' + pending[n] + '</p>';
    }
    $('credo-run-out').innerHTML = '';
    $('btn-credo-run').disabled = !identity;
    syncCredoSource();
  }

  /** Reflect whether the Studio has a chain the Credo tab can use. */
  function syncCredoSource() {
    const pill = $('credo-source-pill');
    const note = $('credo-source-note');
    if (!identity) {
      pill.className = 'pill neutral';
      pill.textContent = 'no chain loaded';
      note.textContent = 'Load a chain in the Certificate Studio tab to begin.';
      return;
    }
    pill.className = 'pill ok';
    pill.textContent = 'chain loaded';
    const canSign = Boolean(identity.keyPresent);
    note.innerHTML = '<code>' + esc(identity.did) + '</code>'
      + (canSign
          ? ' — with its leaf private key, so all seven steps can run.'
          : ' — <b>no private key</b>, so the key import and signing steps cannot run. '
            + 'Upload the key, or use <b>Generate test CA</b> in the Studio.');
    $('btn-credo-run').disabled = !canSign || credoRunning;
  }

  function credoIdentityPayload() {
    return {
      chainPem: identity.pemChain,
      keyPem: identity.keyPem ?? identity.uploadedKeyPem ?? '',
      didSubjectAttribute: identity.didSubjectAttribute,
    };
  }

  async function credoStatus() {
    if (credoAvailable !== null) return credoAvailable;
    try {
      const res = await fetch('/api/credo-agent/status');
      const body = await res.json();
      credoAvailable = Boolean(body.available);
    } catch {
      credoAvailable = false;
    }
    $('credo-unavailable').hidden = credoAvailable;
    $('credo-ready').hidden = !credoAvailable;
    if (credoAvailable) resetCredo();
    return credoAvailable;
  }

  /** Render one step's body from the run result. */
  function renderCredoSteps(result) {
    const kv = rows => '<dl class="kv">' + rows.map(([k, v]) =>
      '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>').join('') + '</dl>';

    // 1 — agent
    $('credo-1-out').innerHTML =
      '<div class="row steps-ok"><span class="pill ok">agent initialized</span>'
      + '<span class="pill ok">' + esc(result.agent.storage) + '</span></div>'
      + kv([
          ['Wallet id', result.agent.walletId],
          ['Storage', result.agent.storage],
          ['Backend', result.agent.backend],
        ])
      + '<p class="note">The wallet is per-browser and in-memory — it disappears when this session ends.</p>';
    setCredoStep(1, 'done');

    // 2 — resolution
    const doc = result.resolution.didDocument || {};
    $('credo-2-out').innerHTML =
      '<div class="row steps-ok"><span class="pill ok">resolved via Agent</span>'
      + '<span class="pill ok">' + esc(result.resolution.verificationMethodType) + '</span>'
      + '<span class="pill ok">engine: ' + esc(result.resolution.implementation) + '</span>'
      + '<span class="pill ok">no caching</span></div>'
      + kv([
          ['DID', result.resolution.did],
          ['Verification method', result.resolution.verificationMethodId],
          ['Method type', result.resolution.verificationMethodType],
        ])
      + '<details class="more"><summary>Resolved DID document</summary><pre>'
      + esc(JSON.stringify(doc, null, 2)) + '</pre></details>';
    setCredoStep(2, 'done');

    // 3 — key import
    const matches = result.import.keyMatchesCertificate;
    $('credo-3-out').innerHTML =
      '<div class="row steps-ok">'
      + '<span class="pill ' + (matches ? 'ok' : 'bad') + '">'
      + (matches ? 'wallet key matches the certificate' : 'key mismatch') + '</span></div>'
      + kv([
          ['KMS key id', result.import.kmsKeyId],
          ['Key type', result.import.keyType],
        ])
      + '<p class="note">The wallet now holds the certificate\u2019s private key. '
      + 'It was compared against the certificate\u2019s public key to confirm they are the same key.</p>';
    setCredoStep(3, 'done');

    // 4 — binding
    $('credo-4-out').innerHTML =
      '<div class="row steps-ok"><span class="pill ok">DID + key binding stored</span></div>'
      + kv([
          ['DID', result.binding.did],
          ['Document-relative key id', result.binding.didDocumentRelativeKeyId],
          ['KMS key id', result.binding.kmsKeyId],
        ])
      + '<p class="note">This is the exact pair <code>agent.dids.import</code> writes: '
      + 'the DID document, plus which wallet key backs its verification method.</p>';
    setCredoStep(4, 'done');

    // 5 — wallet contents
    $('credo-5-out').innerHTML =
      '<div class="row steps-ok"><span class="pill ok">' + result.wallet.dids.length
      + ' did:x509 ' + (result.wallet.dids.length === 1 ? 'DID' : 'DIDs') + ' in the wallet</span>'
      + '<span class="pill ok">' + esc(result.wallet.storedKeyType) + '</span></div>'
      + '<dl class="kv">' + result.wallet.dids.map(d =>
          '<dt>DID</dt><dd>' + esc(d) + '</dd>').join('') + '</dl>';
    setCredoStep(5, 'done');

    // 6 — issuance
    $('credo-6-out').innerHTML =
      '<div class="row steps-ok"><span class="pill ok">signed by the wallet key</span>'
      + '<span class="pill ok">chain embedded</span></div>'
      + kv([
          ['iss', result.issuance.issuer],
          ['Key used', result.issuance.keyId],
        ])
      + '<div class="field"><label>Signed SD-JWT VC</label><textarea readonly rows="6">'
      + esc(result.issuance.compact) + '</textarea></div>'
      + '<p class="note">No key material was sent from the browser — the Agent signed with the '
      + 'key bound to the DID inside the wallet.</p>';
    setCredoStep(6, 'done');

    // 7 — verification, on demand
    $('credo-7-out').innerHTML =
      '<p class="note">Credential ready. Run the verifier to check it against the re-resolved DID.</p>';
    setCredoStep(7, 'open');
    $('btn-credo-verify').disabled = false;
    $('btn-credo-verify').dataset.ready = 'true';
  }

  async function runCredoFlow() {
    if (!identity) { fail('credo-run-out', 'Load a chain in the Certificate Studio tab first.'); return; }
    if (!identity.keyPresent) {
      fail('credo-run-out', 'This chain has no private key, so the Credo flow cannot import it.');
      return;
    }
    if (!(await credoStatus())) return;

    credoRunning = true;
    $('btn-credo-run').disabled = true;
    $('credo-run-out').innerHTML = '<p class="note">Starting a Credo Agent and running all seven steps…</p>';
    try {
      const { result } = await api('/api/credo-agent/run', credoIdentityPayload());
      credoResult = result;
      renderCredoSteps(result);
      $('credo-run-out').innerHTML = '';
    } catch (e) {
      fail('credo-run-out', 'Credo flow failed: ' + e.message);
    } finally {
      credoRunning = false;
      $('btn-credo-run').disabled = false;
    }
  }

  function renderCredoVerification(result) {
    const v = result.verification;
    let html = '<div class="verdict ' + (v.valid ? 'good' : 'bad') + '">'
      + '<span class="verdict-mark">' + (v.valid ? '✓' : '✕') + '</span>'
      + '<div><b>' + (v.valid ? 'Credential verified' : 'Verification failed') + '</b>'
      + '<small>' + esc(v.error
          ?? (v.valid
            ? 'The signature is valid: the wallet key signed it and the DID re-resolved from the chain.'
            : 'The credential did not pass verification.')) + '</small></div></div>';

    const all = Object.entries(v.disclosed ?? {}).sort(([a], [b]) => a.localeCompare(b));
    html += '<div class="grid-2" style="margin-top:1rem">'
      + '<div><h3 class="sub" style="margin-top:0">Disclosed</h3>'
      + '<dl class="kv">' + all.map(([k, val]) =>
          '<dt>' + esc(k) + '</dt><dd>' + esc(String(val)) + '</dd>').join('') + '</dl></div>'
      + '<div><h3 class="sub" style="margin-top:0">Withheld</h3>'
      + (v.withheld.length
          ? '<dl class="kv">' + v.withheld.map(k =>
              '<dt>' + esc(k) + '</dt><dd class="muted">not disclosed</dd>').join('') + '</dl>'
          : '<p class="note">Nothing was withheld.</p>')
      + '</div></div>'
      + '<p class="note">The verifier trusts <code>' + esc(v.trustedIssuer)
      + '</code> and re-resolved it from the certificate chain — the trust anchor is the CA, not this page.</p>'
      + '<details class="more"><summary>Full verification result</summary><pre>'
      + esc(JSON.stringify(v, null, 2)) + '</pre></details>';

    $('credo-7-out').innerHTML = html;
    setCredoStep(7, 'done');
  }

  $('btn-credo-run').addEventListener('click', runCredoFlow);

  $('btn-credo-verify').addEventListener('click', async () => {
    if (!credoResult) { fail('credo-7-out', 'Run the flow first.'); return; }
    setCredoStep(7, 'open');
    $('btn-credo-verify').disabled = true;
    $('credo-7-out').innerHTML = '<p class="note">Re-resolving the DID and verifying…</p>';
    try {
      renderCredoVerification(credoResult);
    } catch (e) {
      fail('credo-7-out', e.message);
    } finally {
      $('btn-credo-verify').disabled = false;
    }
  });

  $('btn-credo-reset').addEventListener('click', async () => {
    $('btn-credo-reset').disabled = true;
    try {
      await api('/api/credo-agent/reset', {});
      resetCredo();
      $('credo-run-out').innerHTML = '<p class="note">Wallet reset. The Agent will be recreated on the next run.</p>';
    } catch (e) {
      fail('credo-run-out', e.message);
    } finally {
      $('btn-credo-reset').disabled = false;
    }
  });

  // Step 6 is an explicit action: the verifier decides when to check.
  $('btn-verify').addEventListener('click', () => {
    if (!signed) {
      fail('step-5-out', 'Sign a credential first.');
      return;
    }
    verify(signed.payload, signed.format);
  });

  // --- bootstrap ----------------------------------------------------------
  (async () => {
    try {
      const res = await fetch('/api/catalogue');
      catalogue = await res.json();
      const opt = catalogue.options;
      const algOptions = opt.algorithms.map(a => '<option>' + a + '</option>').join('');
      $('ca-alg').innerHTML = algOptions;
      $('ca-alg').value = 'P-256';
      $('leaf-alg').innerHTML = algOptions;
      $('leaf-alg').value = 'P-256';
      const attrOptions = opt.subjectAttributes.map(a => '<option>' + a + '</option>').join('');
      $('did-attr').innerHTML = attrOptions;
      $('up-attr').innerHTML = attrOptions;
      $('vc-template').innerHTML = catalogue.credentials.map(c =>
        '<option value="' + c.id + '">' + esc(c.label) + '</option>').join('');

      renderCapabilityMatrix();

      // Ask the server whether the Credo Agent can run here, so the tab shows
      // either the flow or an explanation rather than failing on click.
      $('credo-ready').hidden = true;
      $('credo-unavailable').hidden = true;
      await credoStatus();
    } catch (e) {
      fail('step-1-out', 'Could not load the catalogue: ' + e.message);
    }
  })();
})();
`;
