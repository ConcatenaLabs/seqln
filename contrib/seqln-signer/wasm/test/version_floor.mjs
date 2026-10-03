// The WASM device refuses an INIT whose highest version is below 6, as the
// first INIT and as any later one, and never returns an old per-commitment
// secret with a point. Below version 6, GET_PER_COMMITMENT_POINT(n) would also
// return the secret of commitment n - 2: a host that re-initialised the device
// at version 4 could read the secret of a commitment the device has not revoked.
//
// Usage: node test/version_floor.mjs   (after `wasm-pack build --target nodejs --out-dir pkg`)

import { Signer } from '../pkg/seqln_signer_wasm.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const be = (n, w) => { const b = Buffer.alloc(w); if (w === 2) b.writeUInt16BE(n); else if (w === 4) b.writeUInt32BE(n); else b.writeBigUInt64BE(BigInt(n)); return b; };
const le = (n, w) => { const b = Buffer.alloc(w); if (w === 4) b.writeUInt32LE(n); else b.writeBigUInt64LE(BigInt(n)); return b; };
const PEER = Buffer.alloc(33, 2), DBID = 1;
function frame(msg, isMain) {
  const hdr = isMain ? Buffer.concat([Buffer.from([1]), le(0, 8), le(0, 8)])
                     : Buffer.concat([Buffer.from([0]), PEER, le(DBID, 8), le(0, 8)]);
  const payload = Buffer.concat([hdr, msg]);
  return new Uint8Array(Buffer.concat([le(payload.length, 4), payload]));
}
const init = (min, max) => Buffer.concat([be(11, 2), be(0x043587cf, 4), be(0x04358394, 4), Buffer.alloc(32), Buffer.alloc(5), be(min, 4), be(max, 4)]);
const gpcp = (n) => Buffer.concat([be(18, 2), be(n, 8)]);
function reply(s, msg, isMain) { return Buffer.from(s.processFrame(frame(msg, isMain))).subarray(4); }
function pointReply(s, n) {
  const r = reply(s, gpcp(n), false);
  if (r.readUInt16BE(0) !== 118) throw new Error('type ' + r.readUInt16BE(0));
  return { point: r.subarray(2, 35).toString('hex'), old: r[35] === 1 ? r.subarray(36, 68).toString('hex') : null, len: r.length };
}
function initFails(s, min, max) {
  try { reply(s, init(min, max), true); } catch (e) { return String(e.message || e); }
  return null;
}

let failed = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${what}`); if (!ok) failed++; };

// A fresh device: every range below 6 is refused, and it stays uninitialised.
for (const [min, max] of [[4, 4], [4, 5], [5, 5]]) {
  const s = Signer.fromMnemonic(MNEMONIC);
  s.setEnforce(true);
  const e = initFails(s, min, max);
  console.log(`first INIT ${min}..${max}: ${e}`);
  check(e && e.includes(`version ${min}-${max} not valid: we need 6-6`), `first INIT ${min}..${max} refused`);
  let err = null;
  try { reply(s, gpcp(3), false); } catch (x) { err = String(x.message || x); }
  check(err && err.includes('not initialized'), `no request served after the refused INIT ${min}..${max}`);
}

// What lightningd offers, 5..6, gives version 6.
const s = Signer.fromMnemonic(MNEMONIC);
s.setEnforce(true);
const r = reply(s, init(5, 6), true);
check(r.readUInt16BE(0) === 114 && r.readUInt32BE(2) === 6, 'INIT 5..6 answered at version 6');
const before = [];
for (let n = 0; n < 8; n++) before.push(pointReply(s, n));
check(before.every((p) => p.old === null && p.len === 36), 'GET_PER_COMMITMENT_POINT(0..7) at version 6: no secret');

// A later INIT at a lower version: refused, and nothing changes.
for (const [min, max] of [[4, 4], [5, 5], [4, 5]]) {
  const e = initFails(s, min, max);
  console.log(`second INIT ${min}..${max}: ${e}`);
  check(e && e.includes(`version ${min}-${max} not valid`), `second INIT ${min}..${max} refused`);
  for (let n = 0; n < 8; n++) {
    const p = pointReply(s, n);
    check(p.old === null && p.point === before[n].point, `after INIT ${min}..${max}: point ${n} unchanged, no secret`);
  }
}

if (failed) { console.log(`${failed} FAILED`); process.exit(1); }
console.log('ALL PASS');
