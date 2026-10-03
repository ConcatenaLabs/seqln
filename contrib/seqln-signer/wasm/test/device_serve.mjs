// The WASM device signer as a drop-in for `seqln-signer --connect`.
//
// It runs the browser build (the `wasm-pack --target nodejs` package in
// ../pkg) the way the native binary runs the same library, so a test harness
// can serve a hosted node from either and expect the same behaviour:
//
//   node device_serve.mjs --connect <host:port>
//
// From the working directory: `hsm_secret` (mnemonic format), the channel
// store `seqln-signer-channels` (or the path in SEQLN_SIGNER_STORE), loaded at
// start and rewritten before any reply to a request that changed it, and the
// log `seqln-signer.log`. From the environment, as the native binary reads
// them: SEQLN_SIGNER_PRIVKEY and SEQLN_HOST_PEER_PUBKEY (the Noise_XK keys),
// SEQLN_SIGNER_POLICY (`permissive` turns enforcement off),
// SEQLN_SIGNER_PAY_LIMIT, SEQLN_SIGNER_PAY_LIMITS, SEQLN_SIGNER_PAY_PERIOD and
// SEQLN_SIGNER_TRACE. Each refusal is logged as the native binary logs it,
// `seqln-signer: POLICY REJECT: <reason>`. The process serves one link and
// exits when it closes; the caller restarts it, as a browser reconnects.

import { readFileSync, writeFileSync, renameSync, appendFileSync, existsSync, openSync, fsyncSync, closeSync } from 'node:fs';
import net from 'node:net';
import { webcrypto } from 'node:crypto';
import { Signer, NoiseSession } from '../pkg/seqln_signer_wasm.js';

function arg(name) {
  const i = process.argv.indexOf(name);
  if (i >= 0) return process.argv[i + 1];
  const eq = process.argv.find((a) => a.startsWith(name + '='));
  return eq ? eq.slice(name.length + 1) : undefined;
}

const addr = arg('--connect') || process.env.SEQLN_SIGNER_CONNECT;
if (!addr) {
  console.error('usage: node device_serve.mjs --connect <host:port>');
  process.exit(2);
}
const [host, port] = addr.split(':');
const STORE = process.env.SEQLN_SIGNER_STORE || 'seqln-signer-channels';
const LOG = 'seqln-signer.log';
const trace = !!process.env.SEQLN_SIGNER_TRACE;

function log(line) {
  try { appendFileSync(LOG, line + '\n'); } catch {}
}
function say(line) {
  log(line);
  console.error(line);
}
function fatal(msg) {
  say(`seqln-signer: ${msg}`);
  process.exit(2);
}
function need(name) {
  const v = process.env[name];
  if (!v) fatal(`set ${name}`);
  return Buffer.from(v.trim(), 'hex');
}

const signer = new Signer(readFileSync('hsm_secret'));
signer.setEnforce(process.env.SEQLN_SIGNER_POLICY !== 'permissive');

// Payment limits, as `Limits::from_env` reads them.
function atoms(v) {
  const s = String(v).trim();
  if (/^none$/i.test(s)) return undefined;
  if (!/^[0-9]+$/.test(s)) fatal(`bad payment limit: limit ${JSON.stringify(s)} is neither a number of atoms nor \`none\``);
  return Number(s);
}
if (process.env.SEQLN_SIGNER_PAY_LIMIT !== undefined) {
  signer.setPaymentLimit(undefined, atoms(process.env.SEQLN_SIGNER_PAY_LIMIT));
}
for (const item of (process.env.SEQLN_SIGNER_PAY_LIMITS || '').split(',').filter((x) => x.trim())) {
  const [a, n] = item.split('=');
  if (n === undefined) fatal(`bad payment limit: SEQLN_SIGNER_PAY_LIMITS item ${JSON.stringify(item)} is not <asset>=<atoms>`);
  signer.setPaymentLimit(a.trim(), atoms(n));
}
if (process.env.SEQLN_SIGNER_PAY_PERIOD !== undefined) {
  signer.setPaymentPeriod(Number(process.env.SEQLN_SIGNER_PAY_PERIOD));
}

// The channel store: restored at start; a bad blob is logged and left out.
if (existsSync(STORE)) {
  try {
    const n = signer.importChannels(readFileSync(STORE));
    log(`seqln-signer: restored ${n} channel(s) from ${STORE}`);
    for (const c of JSON.parse(signer.predatingChannels())) {
      say(`seqln-signer: channel ${c.dbid} of peer ${c.peerId} (funding ${c.fundingTxid}:${c.fundingOutnum}, ${c.fundingSats}) predates validation: no commitment step is signed for it; its peer closes it`);
    }
  } catch (e) {
    say(`seqln-signer: channel store ${STORE} NOT restored: ${e.message || e}`);
  }
}
signer.takeChannelsDirty();

function saveStore(blob) {
  const tmp = STORE + '.tmp';
  writeFileSync(tmp, blob);
  const fd = openSync(tmp, 'r');
  fsyncSync(fd);
  closeSync(fd);
  renameSync(tmp, STORE);
}

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

async function connect() {
  const s = new net.Socket();
  await new Promise((res, rej) => {
    s.once('error', rej);
    s.connect(Number(port), host, () => { s.removeListener('error', rej); res(); });
  });
  s.setNoDelay(true);
  s.on('data', (d) => { inbuf = Buffer.concat([inbuf, d]); if (waiter) { const w = waiter; waiter = null; w(); } });
  s.on('close', () => { closed = true; if (waiter) { const w = waiter; waiter = null; w(); } });
  s.on('error', () => {});
  sock = s;
}

async function main() {
  const hostPub = need('SEQLN_HOST_PEER_PUBKEY');
  const devicePriv = need('SEQLN_SIGNER_PRIVKEY');
  try {
    await connect();
  } catch (e) {
    process.exit(1);
  }
  const eph = new Uint8Array(32);
  webcrypto.getRandomValues(eph);
  const sess = NoiseSession.newInitiator(hostPub, devicePriv, eph);
  sock.write(Buffer.from(sess.writeActOne()));
  sock.write(Buffer.from(sess.readActTwo(await readExact(50))));
  log(`seqln-signer: connected to ${addr} (wasm, Noise_XK initiator)`);

  let plain = Buffer.alloc(0);
  const refill = async () => {
    const hdr = await readExact(18);
    const len = sess.decryptHeader(hdr);
    plain = Buffer.concat([plain, Buffer.from(sess.decryptBody(await readExact(len + 16)))]);
  };
  for (;;) {
    while (plain.length < 4) await refill();
    const flen = plain.readUInt32LE(0);
    while (plain.length < 4 + flen) await refill();
    const frame = Buffer.from(plain.subarray(0, 4 + flen));
    plain = plain.subarray(4 + flen);

    if (trace) {
      const isMain = frame[4];
      const off = 4 + 1 + (isMain ? 0 : 33);
      const dbid = frame.readBigUInt64LE(off);
      const t = frame.length >= off + 16 + 2 ? frame.readUInt16BE(off + 16) : null;
      log(`seqln-signer: TRACE req type=${t === null ? 'None' : `Some(${t})`} is_main=${isMain ? 'true' : 'false'} dbid=${dbid} msglen=${flen - (off + 16 - 4)}`);
    }
    let reply;
    try {
      reply = Buffer.from(signer.processFrame(frame));
    } catch (e) {
      fatal(`FATAL: ${e.message || e}`);
    }
    const why = signer.lastReject;
    if (why && why !== 'unimplemented or malformed request') say(`seqln-signer: POLICY REJECT: ${why}`);
    if (signer.takeChannelsDirty()) {
      try {
        saveStore(Buffer.from(signer.exportChannels()));
      } catch (e) {
        say(`seqln-signer: REFUSED: channel store ${STORE} not written: ${e.message || e}`);
        process.exit(1);
      }
    }
    sock.write(Buffer.from(sess.encrypt(reply)));
    if (closed) break;
  }
}

main().catch((e) => {
  log(`seqln-signer: link ended: ${e.message || e}`);
  process.exit(0);
});
process.on('SIGTERM', () => process.exit(0));
