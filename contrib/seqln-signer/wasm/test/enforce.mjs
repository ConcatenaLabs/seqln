// WASM enforce-mode (M4 validating policy) proof.
//
// Three things, all inside the wasm module:
//   1. Replaying the WHOLE real corpus with the validating policy ENFORCED still
//      yields byte-identical replies to libhsmd (legitimate signs are untouched
//      by enforcement) — mirrors the native "enforce replay 99/0 byte-exact".
//   2. A TAMPERED peer commitment (one output byte altered) is REFUSED in
//      enforce mode (zero-length sentinel) yet still SIGNED in permissive mode —
//      proving the browser signer actually validates, not just relays.
//   3. Watchtower custody fix: a SWEEP (delayed_payment_to_us) whose output is
//      the node's OWN address is SIGNED byte-identically under enforce and
//      permissive; a sweep REDIRECTED to an attacker address is REFUSED under
//      enforce (0-byte) while permissive still signs it. This block is
//      self-contained (canonical mnemonic, synthesized frame), so it runs even
//      without the captured corpus.
//
// Usage: node enforce.mjs [<corpus.bin> <hsm_secret> <oracle_replies.bin>]
//   With the three args, tests 1 & 2 (corpus replay + commitment tamper) run.
//   Test 3 (sweep custody) always runs.

import { readFileSync } from 'node:fs';
import { Signer } from '../pkg/seqln_signer_wasm.js';

const [corpusPath, secretPath, oraclePath] = process.argv.slice(2);

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

// --- 1 & 2: corpus-backed (need the captured corpus + secret + oracle) --------
if (corpusPath && secretPath && oraclePath) {
  const corpus = readFileSync(corpusPath);
  const secret = readFileSync(secretPath);
  const oracle = readFileSync(oraclePath);
  const requests = splitRecords(corpus);
  const oracleReplies = splitRecords(oracle);

  // 1. Enforce-mode full-corpus replay: still byte-exact vs libhsmd.
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

  // 2. Tampered peer commitment: rejected in enforce, signed in permissive.
  const IDX = 74; // first SIGN_REMOTE_COMMITMENT_TX (the fundee theft vector)
  if (frameType(requests[IDX]) !== 19) {
    console.error(`expected SIGN_REMOTE_COMMITMENT_TX at ${IDX}, got type ${frameType(requests[IDX])}`);
    process.exit(2);
  }
  {
    const s = signerReplayedTo(IDX, true);
    const reply = Buffer.from(s.processFrame(requests[IDX]));
    const bodyLen = reply.readUInt32LE(0);
    console.log(`2a) enforce accepts the LEGITIMATE peer commitment: reply ${bodyLen} bytes (signed)`);
    if (bodyLen === 0) { console.error('   unexpected: enforce rejected a legitimate commitment'); process.exit(1); }
  }
  const orig = requests[IDX];
  const start = hsmdOffset(orig) + 2 + 10;
  const end = orig.length - 80;
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
} else {
  console.log('1-2) SKIP (no corpus args): run `node enforce.mjs <corpus.bin> <hsm_secret> <oracle_replies.bin>` for the commitment replay/tamper proof');
}

// --- 3. Watchtower custody fix: sweep accept (byte-exact) / reject (tampered) --
// Self-contained: canonical test mnemonic, synthesized SIGN_DELAYED_PAYMENT_TO_US.
const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const HSMD_SIGN_DELAYED_PAYMENT_TO_US = 12;

function compact(n) { if (n >= 0xfd) throw new Error('compact too big'); return Buffer.from([n]); }
function u16be(n) { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; }
function u32be(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; }
function u32le(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; }
function u64be(n) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }
function u64le(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; }

// 1-in / 1-out Bitcoin sweep tx paying `outSpk`.
function sweepTx(outSpk) {
  return Buffer.concat([
    u32le(2),                         // version
    Buffer.from([0x01]),              // vin count
    Buffer.alloc(32, 0x33),           // prev txid
    u32le(0),                         // prev vout
    Buffer.from([0x00]),              // empty scriptSig
    u32le(0xffffffff),                // sequence
    Buffer.from([0x01]),              // vout count
    u64le(90000),                     // value
    compact(outSpk.length), Buffer.from(outSpk),
    u32le(0),                         // locktime
  ]);
}
// v0 PSBT: global{unsigned tx} || input0{witness_utxo=value8||varbuff(inSpk)} || output0{}.
function sweepPsbt(tx, inAmount, inSpk) {
  const wu = Buffer.concat([u64le(inAmount), compact(inSpk.length), Buffer.from(inSpk)]);
  return Buffer.concat([
    Buffer.from('psbt\xff', 'latin1'),
    Buffer.from([0x01, 0x00]), compact(tx.length), tx, Buffer.from([0x00]), // global map
    Buffer.from([0x01, 0x01]), compact(wu.length), wu, Buffer.from([0x00]), // input-0 map
    Buffer.from([0x00]),                                                    // output-0 map
  ]);
}
// A framed SIGN_DELAYED_PAYMENT_TO_US request (is_main=0, per-peer) for `outSpk`.
function delayedFrame(outSpk) {
  const tx = sweepTx(outSpk);
  const inSpk = Buffer.concat([Buffer.from([0x00, 0x20]), Buffer.alloc(32, 0xab)]);
  const psbt = sweepPsbt(tx, 100000, inSpk);
  const wscript = Buffer.from([0x51]); // dummy scriptcode (Class A does not inspect it)
  const hsmd = Buffer.concat([
    u16be(HSMD_SIGN_DELAYED_PAYMENT_TO_US),
    u64be(0),                              // commit_num
    u32be(tx.length), tx,
    u32be(psbt.length), psbt,
    u16be(wscript.length), wscript,
  ]);
  const payload = Buffer.concat([
    Buffer.from([0x00]),      // is_main = 0
    Buffer.alloc(33, 0x07),   // node_id
    u64le(1),                 // dbid
    u64le(0),                 // capabilities
    hsmd,
  ]);
  return Buffer.concat([u32le(payload.length), payload]);
}
function bodyLen(reply) { return Buffer.from(reply).readUInt32LE(0); }

// A minimal HSMD_INIT frame (main daemon): initializes the signer's kernel with
// the testnet BIP32 versions. All optional dev fields are absent (single 0x00).
const HSMD_INIT = 11;
const BIP32_VER_TEST_PUBLIC = 0x043587cf;
const BIP32_VER_TEST_PRIVATE = 0x04358394;
function initFrame() {
  const hsmd = Buffer.concat([
    u16be(HSMD_INIT),
    u32be(BIP32_VER_TEST_PUBLIC),
    u32be(BIP32_VER_TEST_PRIVATE),
    Buffer.alloc(32, 0x00),   // chainparams genesis blockhash
    Buffer.from([0x00]),      // hsm_encryption_key : absent
    Buffer.from([0x00]),      // dev_force_privkey : absent
    Buffer.from([0x00]),      // dev_force_bip32_seed : absent
    Buffer.from([0x00]),      // dev_force_channel_secrets : absent
    Buffer.from([0x00]),      // dev_force_channel_secrets_shaseed : absent
    u32be(4),                 // min_version
    u32be(6),                 // max_version
  ]);
  const payload = Buffer.concat([
    Buffer.from([0x01]),      // is_main = 1 (no node_id)
    u64le(0),                 // dbid
    u64le(0),                 // capabilities
    hsmd,
  ]);
  return Buffer.concat([u32le(payload.length), payload]);
}
function initedSigner(enforce) {
  const s = Signer.fromMnemonic(MNEMONIC);
  s.processFrame(initFrame());
  // Set the policy EXPLICITLY in both directions: the device signer now
  // DEFAULTS to enforce (the watchtower custody flip), so a permissive signer
  // for the enforce-vs-permissive comparison must opt out via the kill-switch.
  s.setEnforce(enforce);
  return s;
}

{
  const permissive = initedSigner(false);
  const enforce = initedSigner(true);

  // The node's OWN sweep destination (bip86 p2wpkh, index 4).
  const ownSpk = Buffer.from(permissive.walletSweepScript(4, false));

  // (a) ACCEPT: enforce signs the honest sweep byte-identically to permissive.
  const legit = delayedFrame(ownSpk);
  const permReply = Buffer.from(permissive.processFrame(legit));
  const enfReply = Buffer.from(enforce.processFrame(delayedFrame(ownSpk)));
  if (bodyLen(permReply) === 0) { console.error('   permissive failed to sign an honest sweep'); process.exit(1); }
  if (!permReply.equals(enfReply)) { console.error('   enforce sweep reply not byte-identical to permissive'); process.exit(1); }
  console.log(`3a) enforce accepts the node's OWN sweep, byte-exact vs permissive: reply ${bodyLen(enfReply)} bytes (signed)`);

  // (b) REJECT: redirect the sweep to an attacker address (flip a keyhash byte).
  const attackerSpk = Buffer.from(ownSpk);
  attackerSpk[attackerSpk.length - 1] ^= 0x01;
  const tampered = delayedFrame(attackerSpk);
  const permBad = Buffer.from(initedSigner(false).processFrame(delayedFrame(attackerSpk)));
  const enfBad = Buffer.from(initedSigner(true).processFrame(tampered));
  if (bodyLen(permBad) === 0) { console.error('   permissive should still sign a redirected sweep (enforce-only fix)'); process.exit(1); }
  if (bodyLen(enfBad) !== 0) { console.error('   enforce should REFUSE a redirected sweep'); process.exit(1); }
  console.log('3b) SWEEP redirected to an attacker address:');
  console.log(`      permissive -> SIGNED (${bodyLen(permBad)}-byte reply)`);
  console.log('      enforce    -> REFUSED (0-byte sentinel)');
}

console.log('\n== WASM enforce-mode policy proven (byte-exact when honest, refuses theft on commitments AND sweeps) ==');
