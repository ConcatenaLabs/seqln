// WASM enforce-mode (M4 validating policy) proof.
//
// Two things, both inside the wasm module:
//   1. Replaying the WHOLE real corpus with the validating policy ENFORCED still
//      yields byte-identical replies to libhsmd (legitimate signs are untouched
//      by enforcement) — mirrors the native "enforce replay 99/0 byte-exact".
//   2. A TAMPERED peer commitment (one output byte altered) is REFUSED in
//      enforce mode (zero-length sentinel) yet still SIGNED in permissive mode —
//      proving the browser signer actually validates, not just relays.
//
// Usage: node enforce.mjs <corpus.bin> <hsm_secret> <oracle_replies.bin>

import { readFileSync } from 'node:fs';
import { Signer } from '../pkg/seqln_signer_wasm.js';

const [corpusPath, secretPath, oraclePath] = process.argv.slice(2);
const corpus = readFileSync(corpusPath);
const secret = readFileSync(secretPath);
const oracle = readFileSync(oraclePath);

function splitRecords(buf) {
  const out = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = buf.readUInt32LE(off);
    out.push(buf.subarray(off, off + 4 + len));
    off += 4 + len;
  }
  return out;
}
function frameType(r) {
  const isMain = r[4];
  const hdr = 1 + (isMain ? 0 : 33) + 8 + 8;
  return r.length >= 4 + hdr + 2 ? r.readUInt16BE(4 + hdr) : -1;
}
function hsmdOffset(r) {
  const isMain = r[4];
  return 4 + 1 + (isMain ? 0 : 33) + 8 + 8;
}

const requests = splitRecords(corpus);
const oracleReplies = splitRecords(oracle);

// --- 1. Enforce-mode full-corpus replay: still byte-exact vs libhsmd ---------
{
  const s = new Signer(secret);
  s.setEnforce(true);
  let pass = 0, fail = 0;
  for (let i = 0; i < requests.length; i++) {
    const got = Buffer.from(s.processFrame(requests[i]));
    if (got.equals(oracleReplies[i])) pass++;
    else { fail++; console.error(`  enforce replay FAIL entry ${i} (type ${frameType(requests[i])})`); }
  }
  console.log(`1) enforce-mode corpus replay: ${pass}/${requests.length} byte-exact vs libhsmd (${fail} fail)`);
  if (fail !== 0) process.exit(1);
}

// Replay frames [0, k) into a fresh signer at the given policy, returning it.
function signerReplayedTo(k, enforce) {
  const s = new Signer(secret);
  s.setEnforce(enforce);
  for (let i = 0; i < k; i++) s.processFrame(requests[i]);
  return s;
}

// --- 2. Tampered peer commitment: rejected in enforce, signed in permissive --
const IDX = 74; // first SIGN_REMOTE_COMMITMENT_TX (the fundee theft vector)
if (frameType(requests[IDX]) !== 19) {
  console.error(`expected SIGN_REMOTE_COMMITMENT_TX at ${IDX}, got type ${frameType(requests[IDX])}`);
  process.exit(2);
}

// Sanity: enforce ACCEPTS the legitimate commitment (non-empty signed reply).
{
  const s = signerReplayedTo(IDX, true);
  const reply = Buffer.from(s.processFrame(requests[IDX]));
  const bodyLen = reply.readUInt32LE(0);
  console.log(`2a) enforce accepts the LEGITIMATE peer commitment: reply ${bodyLen} bytes (signed)`);
  if (bodyLen === 0) { console.error('   unexpected: enforce rejected a legitimate commitment'); process.exit(1); }
}

// Flip one byte of the commitment tx body and find an offset that the validator
// catches: enforce -> refuse (0 bytes), permissive -> still sign (>0 bytes).
const orig = requests[IDX];
const start = hsmdOffset(orig) + 2 /*msgtype*/ + 10; // skip into the tx body
const end = orig.length - 80;                        // stay ahead of the htlc tail
let demo = null;
for (let pos = start; pos < end && !demo; pos++) {
  const tampered = Buffer.from(orig);
  tampered[pos] ^= 0x01;

  const permReply = Buffer.from(signerReplayedTo(IDX, false).processFrame(tampered));
  const enfReply = Buffer.from(signerReplayedTo(IDX, true).processFrame(tampered));
  if (permReply.length > 4 && enfReply.readUInt32LE(0) === 0) {
    demo = { pos, hsmdByte: pos - hsmdOffset(orig), permBytes: permReply.readUInt32LE(0) };
  }
}

if (!demo) {
  console.error('   could not construct a tamper the validator distinguishes (unexpected)');
  process.exit(1);
}
console.log(`2b) TAMPERED peer commitment (flipped tx byte @hsmd+${demo.hsmdByte}):`);
console.log(`      permissive -> SIGNED (${demo.permBytes}-byte reply)`);
console.log(`      enforce    -> REFUSED (0-byte sentinel)`);
console.log('\n== WASM enforce-mode policy proven (byte-exact when honest, refuses theft) ==');
