// Browser-shaped device signer over the network (SeqLN Tier-2 role flip).
//
// This is the BROWSER topology: the device signer (this process, driving the
// wasm module) is the Noise_XK INITIATOR and connects OUT over TCP to a hosted
// `hsmd-proxy` running in SEQLN_SIGNER_LISTEN responder mode. After mutual
// authentication it serves the signer-split frame protocol from wasm, so the
// hosted lightningd derives its node id and runs entirely off this remote,
// keyless-on-the-host signer. A browser build swaps this TCP socket for a
// WebSocket; nothing else changes.
//
// Usage:
//   node device_link.mjs <host:port> <hsm_secret> <host_pub_hex> <device_priv_hex>
//                        [--enforce]
//
// It logs the handshake result, the node id the wasm signer hands back in the
// INIT reply, and a tally of served hsmd message types, then serves until the
// hosted node closes the link.

import { readFileSync } from 'node:fs';
import net from 'node:net';
import { webcrypto } from 'node:crypto';
import { Signer, NoiseSession, devicePubkey } from '../pkg/seqln_signer_wasm.js';

const [addr, secretPath, hostPubHex, devicePrivHex, ...rest] = process.argv.slice(2);
if (!addr || !secretPath || !hostPubHex || !devicePrivHex) {
  console.error('usage: node device_link.mjs <host:port> <hsm_secret> <host_pub_hex> <device_priv_hex> [--enforce]');
  process.exit(2);
}
const enforce = rest.includes('--enforce');
const [host, port] = addr.split(':');
const hostPub = Buffer.from(hostPubHex, 'hex');
const devicePriv = Buffer.from(devicePrivHex, 'hex');
const secret = readFileSync(secretPath);

function rand32() {
  const b = new Uint8Array(32);
  webcrypto.getRandomValues(b);
  return Buffer.from(b);
}

// Parse the compressed node_id out of an INIT_REPLY_V4 body:
//   type(2) hsm_version(4) num_caps(2) caps(4*num) node_id(33) ...
function nodeIdFromInitReply(framed) {
  const body = framed.subarray(4); // strip u32 frame length
  if (body.readUInt16BE(0) !== 114) return null; // 114 = WIRE_HSMD_INIT_REPLY_V4
  const numCaps = body.readUInt16BE(6);
  const off = 2 + 4 + 2 + 4 * numCaps;
  return body.subarray(off, off + 33).toString('hex');
}

const signer = new Signer(secret);
if (enforce) signer.setEnforce(true);

// Bound after a successful connect.
let sock = null;
let inbuf = Buffer.alloc(0);
let waiter = null;
let closed = false;

async function readExact(n) {
  while (inbuf.length < n) {
    if (closed) throw new Error('link closed');
    await new Promise((res) => { waiter = res; });
  }
  const out = inbuf.subarray(0, n);
  inbuf = inbuf.subarray(n);
  return out;
}

// Retry with a FRESH socket each attempt (a failed connect destroys its own
// socket), only attaching the streaming handlers once connected.
async function connectRetry(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const s = new net.Socket();
    try {
      await new Promise((res, rej) => {
        s.once('error', rej);
        s.connect(Number(port), host, () => { s.removeListener('error', rej); res(); });
      });
      s.setNoDelay(true);
      s.on('data', (d) => { inbuf = Buffer.concat([inbuf, d]); if (waiter) { const w = waiter; waiter = null; w(); } });
      s.on('close', () => { closed = true; if (waiter) { const w = waiter; waiter = null; w(); } });
      s.on('error', () => {});
      sock = s;
      return;
    } catch (e) {
      s.destroy();
      if (Date.now() > deadline) throw e;
      await new Promise((r) => setTimeout(r, 200));
    }
  }
}

async function main() {
  const devicePub = Buffer.from(devicePubkey(devicePriv)).toString('hex');
  console.error(`device: pubkey ${devicePub}`);
  console.error(`device: connecting to hosted proxy ${host}:${port} (Noise_XK initiator)`);
  await connectRetry(30000);

  // --- Noise_XK handshake as INITIATOR ---
  const sess = NoiseSession.newInitiator(hostPub, devicePriv, rand32());
  sock.write(Buffer.from(sess.writeActOne()));
  const act2 = await readExact(50);
  const act3 = sess.readActTwo(act2);          // throws if the host key is wrong
  sock.write(Buffer.from(act3));
  console.error('device: Noise_XK handshake OK (host authenticated, act3 sent) — serving');

  // --- serve the signer-split frame protocol over the encrypted stream ---
  let plain = Buffer.alloc(0);          // decrypted-but-unparsed plaintext
  const served = new Map();
  let announcedNodeId = false;

  async function refillPlain() {
    const hdr = await readExact(18);
    const bodyLen = sess.decryptHeader(hdr);
    const body = await readExact(bodyLen + 16);
    plain = Buffer.concat([plain, Buffer.from(sess.decryptBody(body))]);
  }

  for (;;) {
    // Reassemble one whole request frame: u32-LE len || payload.
    while (plain.length < 4) { await refillPlain(); }
    const flen = plain.readUInt32LE(0);
    while (plain.length < 4 + flen) { await refillPlain(); }
    const frame = Buffer.from(plain.subarray(0, 4 + flen));
    plain = plain.subarray(4 + flen);

    // hsmd type of the request (for the tally).
    const isMain = frame[4];
    const hoff = 4 + 1 + (isMain ? 0 : 33) + 8 + 8;
    const reqType = frame.length >= hoff + 2 ? frame.readUInt16BE(hoff) : -1;
    served.set(reqType, (served.get(reqType) || 0) + 1);

    const reply = Buffer.from(signer.processFrame(frame));
    if (!announcedNodeId) {
      const id = nodeIdFromInitReply(reply);
      if (id) { console.error(`device: served INIT -> node id ${id}`); announcedNodeId = true; }
    }
    sock.write(Buffer.from(sess.encrypt(reply)));

    if (closed) break;
  }
}

main().catch((e) => {
  console.error('device: link ended:', e.message);
  const total = 'see tally above';
  process.exit(0);
});

// Periodic tally so a long-running link shows progress.
process.on('SIGTERM', () => process.exit(0));
