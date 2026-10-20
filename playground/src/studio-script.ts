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
  let catalogue = { credentials: [], options: { algorithms: [], subjectAttributes: [] } };
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
  const tabStudio = $('tab-studio'), tabFlows = $('tab-flows');
  const panelStudio = $('panel-studio'), panelFlows = $('panel-flows');
  function selectTab(which) {
    const studio = which === 'studio';
    tabStudio.setAttribute('aria-selected', String(studio));
    tabFlows.setAttribute('aria-selected', String(!studio));
    panelStudio.hidden = !studio;
    panelFlows.hidden = studio;
  }
  tabStudio.addEventListener('click', () => selectTab('studio'));
  tabFlows.addEventListener('click', () => selectTab('flows'));

  // --- step helpers -------------------------------------------------------
  function setStep(n, state) {
    const el = $('step-' + n);
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
      // Say *why*: the key type, not the credential, is the blocker.
      $('vc-hint').innerHTML = 'This identity\u2019s key (' + esc(identity.keyType || '?')
        + ') cannot sign any format offered for this credential.';
      return;
    }
    $('btn-sign').disabled = false;
    populateClaims();
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
    } catch (e) {
      fail('step-1-out', 'Could not load the catalogue: ' + e.message);
    }
  })();
})();
`;
