// SeqLN Tier-2 device signer over a real WebSocket, driven by the wallet SDK.
//
// This is the FULL browser-shaped device path minus only the DOM: it uses the
// exact `SeqlnSigner` SDK a browser wallet calls, over Node 22's built-in global
// `WebSocket` client, through the WS<->TCP relay, to a hosted proxy in
// SEQLN_SIGNER_LISTEN (Noise_XK responder) mode. A browser swaps this file for a
// few DOM handlers; the SDK, the wasm signer, the Noise handshake, the frame
// codec, and the served hsmd protocol are byte-for-byte identical.
//
// Usage:
//   node ws_device.mjs <wsUrl> <mnemonic-file> <host_pub_hex> <device_priv_hex>
//                      [--enforce] [--hsm-secret]
//
// `<mnemonic-file>` is a text BIP-39 mnemonic (default) or, with --hsm-secret,
// the raw on-disk hsm_secret bytes. It logs the Noise result, the node id the
// wasm signer derives over the link, and a per-type tally of served requests,
// then serves until the hosted node closes the link.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { SeqlnSigner } from '../sdk/seqln-signer-sdk.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const WASM = readFileSync(join(HERE, '..', 'web', 'pkg', 'seqln_signer_wasm_bg.wasm'));

const [wsUrl, secretPath, hostPubHex, devicePrivHex, ...rest] = process.argv.slice(2);
if (!wsUrl || !secretPath || !hostPubHex || !devicePrivHex) {
  console.error('usage: node ws_device.mjs <wsUrl> <mnemonic-file> <host_pub_hex> <device_priv_hex> [--enforce] [--hsm-secret]');
  process.exit(2);
}
const enforce = rest.includes('--enforce');
const useHsmSecret = rest.includes('--hsm-secret');

// TEST-ONLY: SEQLN_DEV_REJECT_ONCE="56,23" makes the device reject each listed
// hsmd wire type ONCE (zero-length sentinel), to exercise the proxy's B6 fail-soft.
const rejectOnce = (process.env.SEQLN_DEV_REJECT_ONCE || '')
  .split(',').map((s) => s.trim()).filter(Boolean).map(Number);
const sopts = { wasm: WASM, rejectOnce: rejectOnce.length ? rejectOnce : undefined };

const signer = useHsmSecret
  ? await SeqlnSigner.fromHsmSecret(new Uint8Array(readFileSync(secretPath)), sopts)
  : await SeqlnSigner.fromMnemonic(readFileSync(secretPath, 'utf8'), sopts);
if (enforce) signer.setPolicy('enforce');

signer.onStatus = (st) => {
  if (st.state === 'node_id') console.error(`device: served INIT -> node id ${st.nodeId}`);
  else console.error(`device: [${st.state}] ${st.detail || ''}`);
};
let firstFew = 0;
signer.onRequest = (r) => {
  if (firstFew++ < 12 || r.rejected)
    console.error(`device:   #${r.seq} ${r.name} -> ${r.rejected ? 'REJECTED (policy)' : r.replyBytes + 'B reply'}`);
};

const devicePub = await SeqlnSigner.devicePubkey(devicePrivHex, { wasm: WASM });
console.error(`device: transport pubkey ${devicePub}  (host must pin this)`);
console.error(`device: connecting ${wsUrl} (Noise_XK initiator, policy=${enforce ? 'enforce' : 'permissive'})`);

try {
  await signer.connect({ wsUrl, hostStaticPubkey: hostPubHex, deviceStaticPrivkey: devicePrivHex });
} catch (e) {
  console.error('device: connect failed:', e.message);
  process.exit(1);
}

// Print the node id as soon as the hosted node boots (first INIT), then keep
// serving. The parent harness reads this line to compare against getinfo.
try {
  const id = await signer.whenNodeId(25000);
  console.log(`NODE_ID ${id}`);
} catch (e) {
  console.error('device:', e.message);
}

// Serve until the link ends; periodically dump the tally.
function dumpTally() {
  const counts = [...signer.servedCounts().entries()].sort((a, b) => a[0] - b[0]);
  const total = counts.reduce((s, [, n]) => s + n, 0);
  console.error(`device: served ${total} hsmd requests: ` +
    counts.map(([t, n]) => `${t}:${n}`).join(' '));
}
const iv = setInterval(() => { if (signer.state() === 'closed' || signer.state() === 'error') { clearInterval(iv); dumpTally(); process.exit(0); } }, 500);
process.on('SIGTERM', () => { dumpTally(); process.exit(0); });
process.on('SIGINT', () => { dumpTally(); process.exit(0); });
