// Minimal glue for the SeqLN device-signer web page. Loads the wallet SDK
// (which loads the wasm module from ./pkg via the browser fetch path), wires the
// form, and renders status + a live sign-request log. Everything below the SDK
// is transport-agnostic; this file is the only DOM-specific code.

import { SeqlnSigner } from '../sdk/seqln-signer-sdk.js';

const $ = (id) => document.getElementById(id);
const log = $('log');
let signer = null;

function bytesToHex(b) { let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; }

function setStatus(state, detail) {
  const el = $('status');
  el.className = 'pill s-' + state;
  el.textContent = detail ? `${state} — ${detail}` : state;
}
function addStatusLine(text) {
  const l = document.createElement('div');
  l.className = 'line';
  l.innerHTML = `<span class="seq">·</span><span class="status">${text}</span>`;
  log.appendChild(l); log.scrollTop = log.scrollHeight;
}
function addReqLine(r) {
  const l = document.createElement('div');
  l.className = 'line';
  const outcome = r.rejected ? `<span class="rej">REJECTED (policy)</span>` : `<span class="ok">${r.replyBytes}B reply</span>`;
  l.innerHTML = `<span class="seq">#${r.seq}</span><span class="name">${r.name}</span>${outcome}`;
  log.appendChild(l); log.scrollTop = log.scrollHeight;
  $('served').textContent = `${r.seq} requests`;
}

// Live-derive and show the device pubkey (what the host pins) as the priv is edited.
async function refreshDevicePub() {
  const priv = $('devPriv').value.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(priv)) { $('devPub').textContent = '—'; return; }
  try { $('devPub').textContent = await SeqlnSigner.devicePubkey(priv); }
  catch { $('devPub').textContent = 'invalid key'; }
}
$('devPriv').addEventListener('input', refreshDevicePub);
$('gen').addEventListener('click', () => {
  const b = new Uint8Array(32); crypto.getRandomValues(b);
  $('devPriv').value = bytesToHex(b); refreshDevicePub();
});

$('connect').addEventListener('click', async () => {
  const mnemonic = $('mnemonic').value.trim();
  const wsUrl = $('wsUrl').value.trim();
  const hostStaticPubkey = $('hostPub').value.trim();
  const deviceStaticPrivkey = $('devPriv').value.trim();
  if (!mnemonic || !hostStaticPubkey || !/^[0-9a-fA-F]{64}$/.test(deviceStaticPrivkey)) {
    addStatusLine('need a mnemonic, host pubkey, and a 32-byte device privkey'); return;
  }
  $('connect').disabled = true; log.innerHTML = ''; $('nodeId').textContent = '—';
  try {
    signer = await SeqlnSigner.fromMnemonic(mnemonic);       // wasm signer, keys on device
    signer.setPolicy($('policy').value);
    signer.onStatus = (st) => {
      setStatus(st.state, st.state === 'node_id' ? null : st.detail);
      if (st.state === 'node_id') { $('nodeId').textContent = st.nodeId; addStatusLine(`node id derived: ${st.nodeId}`); }
      else addStatusLine(`[${st.state}] ${st.detail || ''}`);
      if (st.state === 'closed' || st.state === 'error') { $('connect').disabled = false; $('disconnect').disabled = true; }
    };
    signer.onRequest = addReqLine;
    await signer.connect({ wsUrl, hostStaticPubkey, deviceStaticPrivkey });
    $('disconnect').disabled = false;
  } catch (e) {
    setStatus('error', e.message); addStatusLine('connect failed: ' + e.message);
    $('connect').disabled = false;
  }
});

$('disconnect').addEventListener('click', () => {
  signer?.disconnect();
  $('disconnect').disabled = true; $('connect').disabled = false;
});
