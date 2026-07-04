// WASM byte-exact conformance harness (SeqLN Tier-2 device signer).
//
// Loads the wasm module (built by `wasm-pack build --target nodejs`), feeds it
// the SAME real-channel request corpus that the native harness replays, and
// byte-compares every reply against libhsmd's own replies (dumped by the native
// `conformance` binary with SEQLN_DUMP_REPLIES).
//
// SUCCESS => the browser-shaped wasm signer produces byte-identical derivations
// and signatures to native libhsmd, entry for entry.
//
// Usage: node conformance.mjs <corpus.bin> <hsm_secret> <oracle_replies.bin>

import { readFileSync } from 'node:fs';
import { Signer } from '../pkg/seqln_signer_wasm.js';

const [corpusPath, secretPath, oraclePath] = process.argv.slice(2);
if (!corpusPath || !secretPath || !oraclePath) {
  console.error('usage: node conformance.mjs <corpus.bin> <hsm_secret> <oracle_replies.bin>');
  process.exit(2);
}

const corpus = readFileSync(corpusPath);
const secret = readFileSync(secretPath);
const oracle = readFileSync(oraclePath);

// Split a byte stream of length-prefixed records (u32-LE len || len bytes) into
// an array of whole records (INCLUDING the 4-byte length prefix), which is
// exactly the on-the-wire framing of both a request frame and a framed reply.
function splitRecords(buf) {
  const out = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = buf.readUInt32LE(off);
    const end = off + 4 + len;
    if (end > buf.length) throw new Error(`truncated record at ${off}`);
    out.push(buf.subarray(off, end));
    off = end;
  }
  return out;
}

// hsmd message type = the first u16 (big-endian) of the reply body (after the
// 4-byte frame length), for a per-type tally. 0 = zero-length sentinel.
function hsmdType(record) {
  const len = record.readUInt32LE(0);
  if (len < 2) return 0;
  return record.readUInt16BE(4);
}

const requests = splitRecords(corpus);
const oracleReplies = splitRecords(oracle);
if (requests.length !== oracleReplies.length) {
  console.error(`corpus has ${requests.length} requests but oracle dump has ${oracleReplies.length} replies`);
  process.exit(2);
}

const signer = new Signer(secret);

let passed = 0, failed = 0;
const perType = new Map();
for (let i = 0; i < requests.length; i++) {
  const reqType = (() => {
    const r = requests[i];
    const len = r.readUInt32LE(0);
    const isMain = r[4];
    const hdr = 1 + (isMain ? 0 : 33) + 8 + 8;
    return r.length >= 4 + hdr + 2 ? r.readUInt16BE(4 + hdr) : -1;
  })();

  let got;
  try {
    got = Buffer.from(signer.processFrame(requests[i]));
  } catch (e) {
    console.error(`  FAIL entry ${i} (req type ${reqType}): wasm threw: ${e}`);
    failed++;
    continue;
  }
  const want = oracleReplies[i];
  const ok = got.equals(want);
  const t = hsmdType(want);
  const rec = perType.get(t) || { pass: 0, fail: 0 };
  if (ok) { passed++; rec.pass++; }
  else {
    failed++; rec.fail++;
    console.error(`  FAIL entry ${i} (req type ${reqType})`);
    console.error(`        oracle: ${want.toString('hex')}`);
    console.error(`        wasm  : ${got.toString('hex')}`);
  }
  perType.set(t, rec);
}

console.log('\n== SeqLN device-signer WASM byte-exact conformance ==\n');
console.log(`  corpus: ${requests.length} real-channel request frames`);
console.log('  per reply hsmd message type (type: pass/fail):');
for (const [t, r] of [...perType.entries()].sort((a, b) => a[0] - b[0])) {
  console.log(`    ${String(t).padStart(4)}: ${r.pass} pass, ${r.fail} fail`);
}
console.log(`\n== ${passed} passed, ${failed} failed ==`);
process.exit(failed === 0 ? 0 : 1);
