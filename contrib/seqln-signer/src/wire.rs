//! CLN hsmd wire codec (big-endian) for the pure-derivation message subset.
//!
//! Field order and encoding follow `hsmd/hsmd_wire.csv` and the generated
//! `hsmd/hsmd_wiregen.c`; the TLV/bigsize rules follow CLN's `towire_tlv`.
//! All multi-byte integers in the hsmd wire are BIG-endian (`towire_u16` etc.
//! call `cpu_to_be*`). This is distinct from the little-endian outer signer
//! frame in `frame.rs`.

/// hsmd wire message type numbers we handle (from `hsmd_wire.csv`).
pub mod msg {
    pub const HSMD_ECDH_REQ: u16 = 1;
    pub const HSMD_CANNOUNCEMENT_SIG_REQ: u16 = 2;
    pub const HSMD_CUPDATE_SIG_REQ: u16 = 3;
    pub const HSMD_SIGN_ANY_CANNOUNCEMENT_REQ: u16 = 4;
    pub const HSMD_SIGN_COMMITMENT_TX: u16 = 5;
    pub const HSMD_NODE_ANNOUNCEMENT_SIG_REQ: u16 = 6;
    pub const HSMD_SIGN_WITHDRAWAL: u16 = 7;
    pub const HSMD_SIGN_INVOICE: u16 = 8;
    pub const HSMD_GET_CHANNEL_BASEPOINTS: u16 = 10;
    pub const HSMD_INIT: u16 = 11;
    pub const HSMD_SIGN_DELAYED_PAYMENT_TO_US: u16 = 12;
    pub const HSMD_SIGN_REMOTE_HTLC_TO_US: u16 = 13;
    pub const HSMD_SIGN_PENALTY_TO_US: u16 = 14;
    pub const HSMD_GET_PER_COMMITMENT_POINT: u16 = 18;
    pub const HSMD_SIGN_REMOTE_COMMITMENT_TX: u16 = 19;
    pub const HSMD_SIGN_REMOTE_HTLC_TX: u16 = 20;
    pub const HSMD_SIGN_MUTUAL_CLOSE_TX: u16 = 21;
    pub const HSMD_GET_OUTPUT_SCRIPTPUBKEY: u16 = 24;
    pub const HSMD_DERIVE_SECRET: u16 = 27;
    pub const HSMD_CHECK_PUBKEY: u16 = 28;
    pub const HSMD_NEW_CHANNEL: u16 = 30;
    pub const HSMD_SETUP_CHANNEL: u16 = 31;
    pub const HSMD_CHECK_OUTPOINT: u16 = 32;
    pub const HSMD_FORGET_CHANNEL: u16 = 34;
    pub const HSMD_VALIDATE_COMMITMENT_TX: u16 = 35;
    pub const HSMD_VALIDATE_REVOCATION: u16 = 36;
    pub const HSMD_LOCK_OUTPOINT: u16 = 37;
    pub const HSMD_PREAPPROVE_INVOICE: u16 = 38;
    pub const HSMD_PREAPPROVE_KEYSEND: u16 = 39;
    pub const HSMD_REVOKE_COMMITMENT_TX: u16 = 40;
    pub const HSMD_PREAPPROVE_INVOICE_CHECK: u16 = 51;
    pub const HSMD_PREAPPROVE_KEYSEND_CHECK: u16 = 52;
    pub const HSMD_CHECK_BIP86_PUBKEY: u16 = 56;
    pub const HSMD_SIGN_ANY_DELAYED_PAYMENT_TO_US: u16 = 142;
    pub const HSMD_SIGN_ANY_REMOTE_HTLC_TO_US: u16 = 143;
    pub const HSMD_SIGN_ANY_PENALTY_TO_US: u16 = 144;
    pub const HSMD_SIGN_ANY_LOCAL_HTLC_TX: u16 = 146;

    pub const HSMD_ECDH_RESP: u16 = 100;
    pub const HSMD_CANNOUNCEMENT_SIG_REPLY: u16 = 102;
    pub const HSMD_CUPDATE_SIG_REPLY: u16 = 103;
    pub const HSMD_SIGN_ANY_CANNOUNCEMENT_REPLY: u16 = 104;
    pub const HSMD_SIGN_COMMITMENT_TX_REPLY: u16 = 105;
    pub const HSMD_NODE_ANNOUNCEMENT_SIG_REPLY: u16 = 106;
    pub const HSMD_SIGN_WITHDRAWAL_REPLY: u16 = 107;
    pub const HSMD_SIGN_INVOICE_REPLY: u16 = 108;
    pub const HSMD_GET_CHANNEL_BASEPOINTS_REPLY: u16 = 110;
    pub const HSMD_SIGN_TX_REPLY: u16 = 112;
    pub const HSMD_INIT_REPLY_V4: u16 = 114;
    pub const HSMD_GET_PER_COMMITMENT_POINT_REPLY: u16 = 118;
    pub const HSMD_GET_OUTPUT_SCRIPTPUBKEY_REPLY: u16 = 124;
    pub const HSMD_DERIVE_SECRET_REPLY: u16 = 127;
    pub const HSMD_CHECK_PUBKEY_REPLY: u16 = 128;
    pub const HSMD_NEW_CHANNEL_REPLY: u16 = 130;
    pub const HSMD_SETUP_CHANNEL_REPLY: u16 = 131;
    pub const HSMD_CHECK_OUTPOINT_REPLY: u16 = 132;
    pub const HSMD_VALIDATE_COMMITMENT_TX_REPLY: u16 = 135;
    pub const HSMD_VALIDATE_REVOCATION_REPLY: u16 = 136;
    pub const HSMD_FORGET_CHANNEL_REPLY: u16 = 134;
    pub const HSMD_LOCK_OUTPOINT_REPLY: u16 = 137;
    pub const HSMD_PREAPPROVE_INVOICE_REPLY: u16 = 138;
    pub const HSMD_PREAPPROVE_KEYSEND_REPLY: u16 = 139;
    pub const HSMD_REVOKE_COMMITMENT_TX_REPLY: u16 = 140;
    pub const HSMD_PREAPPROVE_INVOICE_CHECK_REPLY: u16 = 151;
    pub const HSMD_PREAPPROVE_KEYSEND_CHECK_REPLY: u16 = 152;
    pub const HSMD_CHECK_BIP86_PUBKEY_REPLY: u16 = 156;
}

/// Append-only big-endian wire builder.
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new(msgtype: u16) -> Self {
        let mut w = Writer { buf: Vec::new() };
        w.u16(msgtype);
        w
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    pub fn bool(&mut self, v: bool) {
        self.buf.push(v as u8);
    }
    /// CLN `bigsize` (BOLT-1) integer, used inside TLV records.
    pub fn bigsize(&mut self, v: u64) {
        if v < 0xfd {
            self.u8(v as u8);
        } else if v < 0x1_0000 {
            self.u8(0xfd);
            self.u16(v as u16);
        } else if v < 0x1_0000_0000 {
            self.u8(0xfd + 1); // 0xfe
            self.u32(v as u32);
        } else {
            self.u8(0xfd + 2); // 0xff
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }
    /// One TLV record: bigsize(type) || bigsize(len) || value.
    pub fn tlv_record(&mut self, typ: u64, value: &[u8]) {
        self.bigsize(typ);
        self.bigsize(value.len() as u64);
        self.bytes(value);
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Sequential big-endian reader over an hsmd message body.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn arr33(&mut self) -> Option<[u8; 33]> {
        self.take(33).map(|s| s.try_into().unwrap())
    }
    pub fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32).map(|s| s.try_into().unwrap())
    }
    /// Big-endian u64 (`towire_u64` / `fromwire_u64`).
    pub fn u64(&mut self) -> Option<u64> {
        let hi = self.u32()? as u64;
        let lo = self.u32()? as u64;
        Some((hi << 32) | lo)
    }
    pub fn bool(&mut self) -> Option<bool> {
        self.u8().map(|b| b != 0)
    }
    /// Take `n` raw bytes as an owned Vec.
    pub fn take_bytes(&mut self, n: usize) -> Option<Vec<u8>> {
        self.take(n).map(|s| s.to_vec())
    }
    /// Take `n` raw bytes as a borrowed slice.
    pub fn take_slice(&mut self, n: usize) -> Option<&'a [u8]> {
        self.take(n)
    }
    /// A `u16`-length-prefixed byte string (`wscript_len,u16` + `wscript`).
    pub fn u16_prefixed(&mut self) -> Option<Vec<u8>> {
        let n = self.u16()? as usize;
        self.take_bytes(n)
    }
    pub fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.data[self.pos..];
        self.pos = self.data.len();
        s
    }
    /// Read an `?field`: 1 presence byte, then the value only if present.
    /// Returns Some(true) if we skipped a present value of `value_len`.
    fn optional(&mut self, value_len: usize) -> Option<bool> {
        let present = self.u8()? != 0;
        if present {
            self.skip(value_len)?;
        }
        Some(present)
    }
}

/// Peek the message type (first 2 big-endian bytes), like `fromwire_peektype`.
pub fn peektype(msg: &[u8]) -> Option<u16> {
    if msg.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([msg[0], msg[1]]))
}

/// The bits of `hsmd_init` the kernel needs: the BIP32 version words and the
/// negotiated version range. Mirrors the parse in `signerd_init`.
pub struct InitFields {
    pub bip32_pubkey_version: u32,
    pub bip32_privkey_version: u32,
    pub min_version: u32,
    pub max_version: u32,
}

/// Parse an `hsmd_init` request far enough to extract `InitFields`.
///
/// Layout (`hsmd_wire.csv` + `fromwire_hsmd_init`): type, bip32_key_version(8),
/// chainparams(32 genesis), five `?`-optional dev fields, min(u32), max(u32),
/// tlvs. We only need the version words and the min/max, but we must correctly
/// skip the optionals to reach them.
pub fn parse_init(msg: &[u8]) -> Option<InitFields> {
    let mut r = Reader::new(msg);
    if r.u16()? != msg::HSMD_INIT {
        return None;
    }
    let bip32_pubkey_version = r.u32()?;
    let bip32_privkey_version = r.u32()?;
    r.skip(32)?; // chainparams genesis blockhash
    r.optional(32)?; // hsm_encryption_key : ?secret
    r.optional(32)?; // dev_force_privkey : ?privkey
    r.optional(32)?; // dev_force_bip32_seed : ?secret
    r.optional(160)?; // dev_force_channel_secrets : ?secrets (funding + 4 secrets)
    r.optional(32)?; // dev_force_channel_secrets_shaseed : ?sha256
    let min_version = r.u32()?;
    let max_version = r.u32()?;
    Some(InitFields {
        bip32_pubkey_version,
        bip32_privkey_version,
        min_version,
        max_version,
    })
}

/// Parse `hsmd_get_channel_basepoints`: node_id(33) || dbid(u64).
pub fn parse_get_channel_basepoints(msg: &[u8]) -> Option<([u8; 33], u64)> {
    let mut r = Reader::new(msg);
    if r.u16()? != msg::HSMD_GET_CHANNEL_BASEPOINTS {
        return None;
    }
    let id = r.arr33()?;
    let dbid = read_u64(&mut r)?;
    Some((id, dbid))
}

/// Parse `hsmd_get_per_commitment_point`: n(u64).
pub fn parse_get_per_commitment_point(msg: &[u8]) -> Option<u64> {
    let mut r = Reader::new(msg);
    if r.u16()? != msg::HSMD_GET_PER_COMMITMENT_POINT {
        return None;
    }
    read_u64(&mut r)
}

/// Parse `hsmd_ecdh_req`: point(33).
pub fn parse_ecdh_req(msg: &[u8]) -> Option<[u8; 33]> {
    let mut r = Reader::new(msg);
    if r.u16()? != msg::HSMD_ECDH_REQ {
        return None;
    }
    r.arr33()
}

/// Parse `hsmd_derive_secret`: len(u16) || info[len].
pub fn parse_derive_secret(msg: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(msg);
    if r.u16()? != msg::HSMD_DERIVE_SECRET {
        return None;
    }
    let len = r.u16()? as usize;
    let info = r.rest();
    if info.len() < len {
        return None;
    }
    Some(info[..len].to_vec())
}

/// Parse `hsmd_check_pubkey` / `hsmd_check_bip86_pubkey`: index(u32) || pubkey(33).
pub fn parse_check_pubkey(msg: &[u8], expect_type: u16) -> Option<(u32, [u8; 33])> {
    let mut r = Reader::new(msg);
    if r.u16()? != expect_type {
        return None;
    }
    let index = r.u32()?;
    let pubkey = r.arr33()?;
    Some((index, pubkey))
}

fn read_u64(r: &mut Reader) -> Option<u64> {
    let hi = r.u32()? as u64;
    let lo = r.u32()? as u64;
    Some((hi << 32) | lo)
}

// =====================================================================
// M2b: the `bitcoin_tx` wire object = u32(len) || linearized-elements-tx ||
// wally_psbt.  We parse the linearized Elements tx far enough for the BIP-143
// sighash, and pull the input amount from the PSBT's witness_utxo.
// =====================================================================

use crate::kernel::{ElementsTx, Network, TxInput, TxOutput};

/// `WALLY_TX_ISSUANCE_FLAG` / `WALLY_TX_PEGIN_FLAG` set in an input's index.
const WALLY_TX_ISSUANCE_FLAG: u32 = 0x8000_0000;
const WALLY_TX_PEGIN_FLAG: u32 = 0x4000_0000;

/// A parsed `bitcoin_tx` wire object.
pub struct BitcoinTx {
    pub tx: ElementsTx,
    pub psbt: Vec<u8>,
}

/// Bitcoin/Elements compact-size varint over a byte slice with a cursor.
fn read_compact(d: &[u8], p: &mut usize) -> Option<u64> {
    let first = *d.get(*p)?;
    *p += 1;
    match first {
        0xfd => {
            let v = u16::from_le_bytes(d.get(*p..*p + 2)?.try_into().ok()?) as u64;
            *p += 2;
            Some(v)
        }
        0xfe => {
            let v = u32::from_le_bytes(d.get(*p..*p + 4)?.try_into().ok()?) as u64;
            *p += 4;
            Some(v)
        }
        0xff => {
            let v = u64::from_le_bytes(d.get(*p..*p + 8)?.try_into().ok()?);
            *p += 8;
            Some(v)
        }
        x => Some(x as u64),
    }
}

/// A confidential asset/value/nonce commitment field: `get_commitment_len`
/// (`external/libwally-core/src/script.c`). `is_value` selects the 9-byte
/// explicit-value length; others use 33. Returns the raw field bytes.
fn commit_field<'a>(d: &'a [u8], p: &mut usize, is_value: bool) -> Option<&'a [u8]> {
    let first = *d.get(*p)?;
    let len = match first {
        0x00 => 1,                                 // null
        0x01 => if is_value { 9 } else { 33 },     // explicit
        _ => 33,                                   // confidential (0x02/03/08/09/0a/0b)
    };
    let s = d.get(*p..*p + len)?;
    *p += len;
    Some(s)
}

/// Parse a linearized Elements transaction far enough for the sighash
/// (through locktime; witnesses that follow are ignored). Mirrors
/// `tx_from_bytes` (`external/libwally-core/src/transaction.c`).
pub fn parse_elements_tx(d: &[u8]) -> Option<ElementsTx> {
    let version = u32::from_le_bytes(d.get(0..4)?.try_into().ok()?);
    let mut p = 4usize;
    // Elements: a single witness-flag byte after version.
    let _flag = *d.get(p)?;
    p += 1;

    let nin = read_compact(d, &mut p)? as usize;
    let mut inputs = Vec::with_capacity(nin);
    for _ in 0..nin {
        let txhash: [u8; 32] = d.get(p..p + 32)?.try_into().ok()?;
        p += 32;
        let index = u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?);
        p += 4;
        let slen = read_compact(d, &mut p)? as usize; // scriptSig
        p += slen;
        let sequence = u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?);
        p += 4;
        let is_issuance = (index & WALLY_TX_ISSUANCE_FLAG) != 0;
        let is_pegin = (index & WALLY_TX_PEGIN_FLAG) != 0;
        if is_issuance {
            // nonce(32) || entropy(32) || issuance_amount(value) || inflation_keys(value)
            // || Sequentia asset-denomination byte(1).
            p += 32 + 32;
            commit_field(d, &mut p, true)?;
            commit_field(d, &mut p, true)?;
            p += 1;
        }
        let _ = is_pegin;
        inputs.push(TxInput {
            txhash,
            index,
            sequence,
            is_issuance,
        });
    }

    let nout = read_compact(d, &mut p)? as usize;
    let mut outputs = Vec::with_capacity(nout);
    for _ in 0..nout {
        let asset = commit_field(d, &mut p, false)?.to_vec();
        let value = commit_field(d, &mut p, true)?.to_vec();
        let nonce = commit_field(d, &mut p, false)?.to_vec();
        let slen = read_compact(d, &mut p)? as usize;
        let script = d.get(p..p + slen)?.to_vec();
        p += slen;
        outputs.push(TxOutput {
            asset,
            value,
            nonce,
            script,
        });
    }

    let locktime = u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?);
    Some(ElementsTx {
        version,
        inputs,
        outputs,
        locktime,
        network: Network::Elements,
    })
}

/// Parse a linearized Bitcoin (non-Elements) transaction far enough for the
/// BIP-143 sighash. Mirrors `tx_from_bytes` (`external/libwally-core`) for the
/// `is_elements == false` path.
///
/// Bitcoin serialization (from `wally_tx_to_bytes`, non-Elements):
/// `version(4 LE) || [marker(0x00) flag(0x01) IF witnessed] || nin || inputs ||
/// nout || outputs || [witnesses IF witnessed] || locktime(4 LE)`. Note the
/// witness marker/flag are TWO bytes (vs Elements' single flag byte) and, when
/// present, the witness stacks sit BETWEEN the outputs and the locktime (Elements
/// puts them after the locktime). CLN's `linearize_wtx` only emits the flag when
/// `uses_witness(wtx)`, so the unsigned commitment/HTLC txs handed to the signer
/// have none; we still detect + skip witnesses so a witnessed tx locates its
/// locktime correctly. Inputs: `txhash(32) || index(4 LE) || scriptSig(varbuff)
/// || sequence(4 LE)` (no issuance/pegin on Bitcoin). Outputs:
/// `value(8 LE) || script(varbuff)`.
pub fn parse_bitcoin_tx(d: &[u8]) -> Option<ElementsTx> {
    let version = u32::from_le_bytes(d.get(0..4)?.try_into().ok()?);
    let mut p = 4usize;
    // BIP-144 marker/flag: only present when the tx carries witnesses. A real tx
    // has >=1 input, so a 0x00 here can only be the marker (never a 0-input count).
    let witnessed = *d.get(p)? == 0x00;
    if witnessed {
        // marker(0x00) already peeked; require flag(0x01) after it.
        if *d.get(p + 1)? != 0x01 {
            return None;
        }
        p += 2;
    }

    let nin = read_compact(d, &mut p)? as usize;
    let mut inputs = Vec::with_capacity(nin);
    for _ in 0..nin {
        let txhash: [u8; 32] = d.get(p..p + 32)?.try_into().ok()?;
        p += 32;
        let index = u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?);
        p += 4;
        let slen = read_compact(d, &mut p)? as usize; // scriptSig
        p += slen;
        let sequence = u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?);
        p += 4;
        inputs.push(TxInput {
            txhash,
            index,
            sequence,
            is_issuance: false,
        });
    }

    let nout = read_compact(d, &mut p)? as usize;
    let mut outputs = Vec::with_capacity(nout);
    for _ in 0..nout {
        let value = d.get(p..p + 8)?.to_vec(); // 8-byte LE satoshi, verbatim
        p += 8;
        let slen = read_compact(d, &mut p)? as usize;
        let script = d.get(p..p + slen)?.to_vec();
        p += slen;
        outputs.push(TxOutput {
            asset: Vec::new(),
            value,
            nonce: Vec::new(),
            script,
        });
    }

    // Skip the witness stacks (present only when `witnessed`), which sit before
    // the locktime, so we land on the locktime. Each input: num_items(varint)
    // then that many varbuff items.
    if witnessed {
        for _ in 0..nin {
            let items = read_compact(d, &mut p)? as usize;
            for _ in 0..items {
                let wlen = read_compact(d, &mut p)? as usize;
                p += wlen;
            }
        }
    }

    let locktime = u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?);
    Some(ElementsTx {
        version,
        inputs,
        outputs,
        locktime,
        network: Network::Bitcoin,
    })
}

/// Read a `bitcoin_tx` wire object from the reader (`fromwire_bitcoin_tx`).
///
/// The linearized tx comes first, then the PSBT. We read both raw, decide the
/// network (see [`detect_network`]) — which needs the PSBT's witness_utxo shape —
/// and only THEN parse the linearized tx with the right codec, since the two
/// serializations diverge (Elements' flag byte + confidential outputs vs
/// Bitcoin's plain 8-byte-value outputs).
pub fn read_bitcoin_tx(r: &mut Reader) -> Option<BitcoinTx> {
    let len = r.u32()? as usize; // big-endian tx byte length
    let lin = r.take_slice(len)?;
    let plen = r.u32()? as usize; // big-endian psbt byte length
    let psbt = r.take_bytes(plen)?;
    let network = detect_network(&psbt);
    let tx = match network {
        Network::Bitcoin => parse_bitcoin_tx(lin)?,
        Network::Elements => parse_elements_tx(lin)?,
    };
    Some(BitcoinTx { tx, psbt })
}

/// Decide whether a `bitcoin_tx` wire object is a Bitcoin or an Elements tx.
///
/// FORMAT SELECTION (documented mechanism). One `seqln-signer` process serves
/// one hosted node, but the SAME binary serves both an Elements asset node and a
/// Bitcoin BTC node (different instances/ports), so the network must be resolved
/// per request without changing the Elements path. Resolution order:
///
///   1. `SEQLN_SIGNER_NETWORK` env (`bitcoin`/`btc` or `elements`/`liquid`) — an
///      explicit, per-instance override. This is what the box's BTC device
///      signer sets (`=bitcoin`); the asset signer leaves it unset. Authoritative
///      when present, so a deployment never depends on the sniff below.
///   2. Structural sniff of the input-0 witness_utxo: an Elements output starts
///      with a 33-byte asset commitment (first byte 0x01/0x0a/0x0b) and consumes
///      the whole value buffer as `asset||value||nonce||varbuff(script)`; a
///      Bitcoin TxOut consumes it as `value(8 LE)||varbuff(script)`. If exactly
///      one interpretation consumes the buffer, that wins.
///   3. Default `Elements` — byte-identical to the pre-Bitcoin behaviour, so an
///      unrecognised/absent witness_utxo never disturbs the Elements path.
pub fn detect_network(psbt: &[u8]) -> Network {
    if let Ok(v) = std::env::var("SEQLN_SIGNER_NETWORK") {
        match v.trim().to_ascii_lowercase().as_str() {
            "bitcoin" | "btc" => return Network::Bitcoin,
            "elements" | "liquid" => return Network::Elements,
            _ => {}
        }
    }
    if let Some(val) = psbt_witness_utxo_raw(psbt, 0) {
        let btc = witness_utxo_is_bitcoin(val);
        let ele = witness_utxo_is_elements(val);
        match (btc, ele) {
            (true, false) => return Network::Bitcoin,
            (false, true) => return Network::Elements,
            _ => {} // ambiguous or unrecognised -> fall through to the default
        }
    }
    Network::Elements
}

/// Does `val` parse EXACTLY as a Bitcoin TxOut (`value(8 LE) || varbuff(script)`)?
fn witness_utxo_is_bitcoin(val: &[u8]) -> bool {
    if val.len() < 9 {
        return false;
    }
    let mut p = 8usize;
    let Some(slen) = read_compact(val, &mut p) else {
        return false;
    };
    p + (slen as usize) == val.len()
}

/// Does `val` parse EXACTLY as an Elements output
/// (`asset(commit) || value(commit) || nonce(commit) || varbuff(script)`)?
fn witness_utxo_is_elements(val: &[u8]) -> bool {
    let mut p = 0usize;
    if commit_field(val, &mut p, false).is_none() {
        return false;
    }
    if commit_field(val, &mut p, true).is_none() {
        return false;
    }
    if commit_field(val, &mut p, false).is_none() {
        return false;
    }
    let Some(slen) = read_compact(val, &mut p) else {
        return false;
    };
    p + (slen as usize) == val.len()
}

/// Extract the 9-byte confidential value (`0x01 || uint64_be`) of the
/// witness_utxo for `input_index`, i.e. `psbt_input_get_amount` re-encoded by
/// `wally_tx_confidential_value_from_satoshi`. Returns None if the value is not
/// an explicit (unblinded) amount, which never happens on transparent channels.
pub fn psbt_input_value9(psbt: &[u8], input_index: usize) -> Option<[u8; 9]> {
    if psbt.len() < 5 {
        return None;
    }
    let mut p = 5usize; // skip magic "psbt\xff"
    skip_psbt_map(psbt, &mut p)?; // global map
    for i in 0..=input_index {
        if i == input_index {
            return find_witness_utxo_value(psbt, &mut p);
        }
        skip_psbt_map(psbt, &mut p)?;
    }
    None
}

/// Extract the input `input_index` Bitcoin witness_utxo amount as a raw 8-byte
/// little-endian value (the input to [`crate::kernel::bitcoin_sighash_sw_v0`]).
/// The witness_utxo value for a Bitcoin channel is a plain `TxOut`
/// (`value(8 LE) || varbuff(script)`), so the amount is its first 8 bytes,
/// re-emitted verbatim (`hash_le64`). Returns None if there is no witness_utxo.
pub fn psbt_input_value_sats_le(psbt: &[u8], input_index: usize) -> Option<[u8; 8]> {
    let val = psbt_witness_utxo_raw(psbt, input_index)?;
    let bytes = val.get(0..8)?;
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    Some(out)
}

/// Return the raw `PSBT_IN_WITNESS_UTXO` (key `0x01`) value bytes for
/// `input_index`, WITHOUT decoding — used by the Bitcoin amount decode and by
/// [`detect_network`]. Mirrors the map navigation in [`psbt_input_value9`].
fn psbt_witness_utxo_raw(psbt: &[u8], input_index: usize) -> Option<&[u8]> {
    if psbt.len() < 5 {
        return None;
    }
    let mut p = 5usize; // skip magic "psbt\xff" / "pset\xff"
    skip_psbt_map(psbt, &mut p)?; // global map
    for i in 0..=input_index {
        if i == input_index {
            return find_witness_utxo_raw(psbt, &mut p);
        }
        skip_psbt_map(psbt, &mut p)?;
    }
    None
}

/// Within one input map, return the raw value bytes of `PSBT_IN_WITNESS_UTXO`
/// (key `0x01`), or None if absent.
fn find_witness_utxo_raw<'a>(d: &'a [u8], p: &mut usize) -> Option<&'a [u8]> {
    let mut result = None;
    loop {
        let keylen = read_compact(d, p)? as usize;
        if keylen == 0 {
            break;
        }
        let key = d.get(*p..*p + keylen)?;
        *p += keylen;
        let vallen = read_compact(d, p)? as usize;
        let val = d.get(*p..*p + vallen)?;
        *p += vallen;
        if keylen == 1 && key[0] == 0x01 {
            result = Some(val);
        }
    }
    result
}

/// Skip one PSBT key-value map (terminated by a zero-length key).
fn skip_psbt_map(d: &[u8], p: &mut usize) -> Option<()> {
    loop {
        let keylen = read_compact(d, p)? as usize;
        if keylen == 0 {
            return Some(());
        }
        *p += keylen;
        let vallen = read_compact(d, p)? as usize;
        *p += vallen;
    }
}

/// Within one input map, find `PSBT_IN_WITNESS_UTXO` (key `0x01`) and decode the
/// explicit value from the serialized Elements output it holds.
fn find_witness_utxo_value(d: &[u8], p: &mut usize) -> Option<[u8; 9]> {
    let mut result = None;
    loop {
        let keylen = read_compact(d, p)? as usize;
        if keylen == 0 {
            break;
        }
        let key = d.get(*p..*p + keylen)?;
        *p += keylen;
        let vallen = read_compact(d, p)? as usize;
        let val = d.get(*p..*p + vallen)?;
        *p += vallen;

        if keylen == 1 && key[0] == 0x01 {
            // Elements output: asset || value || nonce || varbuff(script).
            let mut vp = 0usize;
            commit_field(val, &mut vp, false)?; // asset
            let value = commit_field(val, &mut vp, true)?; // value
            if value.len() == 9 && value[0] == 0x01 {
                let mut out = [0u8; 9];
                out.copy_from_slice(value);
                result = Some(out);
            }
        }
    }
    result
}

// =====================================================================
// SIGN_WITHDRAWAL (msg 7): num_inputs(u16) || inputs(hsm_utxo)* || wally_psbt.
// The signer funds its OWN wallet inputs of the withdrawal/funding tx. Unlike
// the commitment messages there is NO separate linearized `bitcoin_tx`; the tx
// being signed is the PSBT's global unsigned tx (v0), so we parse that for the
// BIP-143 sighash and add a PSBT_IN_PARTIAL_SIG per input we control.
// =====================================================================

/// A parsed `hsm_utxo` (`fromwire_hsm_utxo`, `hsmd/hsm_utxo.c`). We keep the
/// fields needed to locate + sign a wallet input; `close_info` (a
/// their-unilateral-close to-us output being swept) is decoded to keep the byte
/// layout exact but is not part of the funding-open path.
pub struct HsmUtxo {
    /// Outpoint txid, raw 32 bytes (internal order, matches the tx's txhash).
    pub txid: [u8; 32],
    pub vout: u32,
    /// `amount_sat` of the UTXO (the segwit-v0 sighash `value`).
    pub amount: u64,
    /// The wallet key index (m/86'/0'/0'/0/index on a mnemonic node, else m/0/0/index).
    pub keyindex: u32,
    pub script_pubkey: Vec<u8>,
    /// True for a their-unilateral-close to-us input (needs channel-key derivation,
    /// not the HD wallet path); never present in a channel-funding withdrawal.
    pub is_unilateral_close: bool,
}

/// Read one `hsm_utxo` subtype (see `fromwire_hsm_utxo`):
/// outpoint(txid32 || vout u32) || amount_sat(u64) || keyindex(u32) ||
/// bool(legacy is_p2sh) || u16-prefixed scriptPubkey || bool is_unilateral_close
/// [ || channel_id(u64) || node_id(33) || ?commitment_point(33) ||
/// bool option_anchors || csv(u32) ] || bool(legacy is_in_coinbase).
pub fn read_hsm_utxo(r: &mut Reader) -> Option<HsmUtxo> {
    let txid = r.arr32()?;
    let vout = r.u32()?;
    let amount = r.u64()?;
    let keyindex = r.u32()?;
    let _is_p2sh_legacy = r.bool()?; // always emitted false; type comes from scriptPubkey
    let script_pubkey = r.u16_prefixed()?;
    let is_unilateral_close = r.bool()?;
    if is_unilateral_close {
        r.u64()?; // channel_id
        r.arr33()?; // peer node_id
        if r.bool()? {
            r.arr33()?; // commitment_point (?)
        }
        r.bool()?; // option_anchors
        r.u32()?; // csv
    }
    let _is_in_coinbase = r.bool()?;
    Some(HsmUtxo {
        txid,
        vout,
        amount,
        keyindex,
        script_pubkey,
        is_unilateral_close,
    })
}

/// Parse a `hsmd_sign_withdrawal` request into (utxos, raw psbt bytes).
pub fn parse_sign_withdrawal(m: &[u8]) -> Option<(Vec<HsmUtxo>, Vec<u8>)> {
    let mut r = Reader::new(m);
    if r.u16()? != msg::HSMD_SIGN_WITHDRAWAL {
        return None;
    }
    let num_inputs = r.u16()? as usize;
    let mut utxos = Vec::with_capacity(num_inputs);
    for _ in 0..num_inputs {
        utxos.push(read_hsm_utxo(&mut r)?);
    }
    // wally_psbt: u32 byte length + bytes (`fromwire_wally_psbt`).
    let plen = r.u32()? as usize;
    let psbt = r.take_bytes(plen)?;
    Some((utxos, psbt))
}

/// Return the raw value of the v0 `PSBT_GLOBAL_UNSIGNED_TX` (global map key 0x00)
/// = the linearized unsigned tx. Present on the Bitcoin path (lightningd
/// downgrades to v0 for non-Elements before sending); absent on a v2 PSET.
pub fn psbt_global_unsigned_tx(psbt: &[u8]) -> Option<&[u8]> {
    if psbt.len() < 5 {
        return None;
    }
    let mut p = 5usize; // skip magic "psbt\xff"
    loop {
        let keylen = read_compact(psbt, &mut p)? as usize;
        if keylen == 0 {
            return None; // end of global map, no unsigned tx (v2)
        }
        let key = psbt.get(p..p + keylen)?;
        p += keylen;
        let vallen = read_compact(psbt, &mut p)? as usize;
        let val = psbt.get(p..p + vallen)?;
        p += vallen;
        if keylen == 1 && key[0] == 0x00 {
            return Some(val);
        }
    }
}

/// Byte offset of the 0x00 terminator of input map `idx` (0-based), i.e. the
/// splice point at which to insert a new record into that input's key-value map.
/// Mirrors the map navigation of [`psbt_witness_utxo_raw`].
pub fn psbt_input_map_terminator(psbt: &[u8], idx: usize) -> Option<usize> {
    if psbt.len() < 5 {
        return None;
    }
    let mut p = 5usize; // skip magic
    skip_psbt_map(psbt, &mut p)?; // global map
    for i in 0..=idx {
        loop {
            let term = p; // offset of this record's keylen byte
            let keylen = read_compact(psbt, &mut p)? as usize;
            if keylen == 0 {
                if i == idx {
                    return Some(term);
                }
                break; // advance to the next input map
            }
            p += keylen;
            let vallen = read_compact(psbt, &mut p)? as usize;
            p += vallen;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Build a minimal single-input PSBT whose input-0 witness_utxo (key 0x01)
    /// holds `wu`, enough for the navigation in `psbt_witness_utxo_raw`:
    /// magic(5) || empty global map (0x00) || input-0 map { 0x01: wu } || 0x00.
    fn psbt_with_wu(wu: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(b"psbt\xff");
        p.push(0x00); // global map terminator (empty)
        p.push(0x01); // keylen
        p.push(0x01); // key = PSBT_IN_WITNESS_UTXO
        assert!(wu.len() < 0xfd);
        p.push(wu.len() as u8); // vallen (compact, small)
        p.extend_from_slice(wu);
        p.push(0x00); // input-0 map terminator
        p
    }

    /// A Bitcoin TxOut witness_utxo: value(8 LE) || varbuff(P2WSH script).
    fn btc_wu(sats: u64) -> Vec<u8> {
        let mut v = sats.to_le_bytes().to_vec();
        let script = unhex("00200101010101010101010101010101010101010101010101010101010101010101");
        v.push(script.len() as u8); // 0x22
        v.extend_from_slice(&script);
        v
    }

    /// An Elements output witness_utxo: asset(0x01||32) || value(0x01||u64_be) ||
    /// nonce(0x00) || varbuff(P2WSH script).
    fn elements_wu(sats: u64) -> Vec<u8> {
        let mut v = vec![0x01u8];
        v.extend_from_slice(&[0u8; 32]); // asset id
        v.push(0x01);
        v.extend_from_slice(&sats.to_be_bytes()); // value (0x01 || u64_be)
        v.push(0x00); // null nonce
        let script = unhex("00200101010101010101010101010101010101010101010101010101010101010101");
        v.push(script.len() as u8);
        v.extend_from_slice(&script);
        v
    }

    #[test]
    fn sniff_bitcoin_witness_utxo() {
        let wu = btc_wu(60_000);
        assert!(witness_utxo_is_bitcoin(&wu));
        assert!(!witness_utxo_is_elements(&wu));
        let psbt = psbt_with_wu(&wu);
        assert_eq!(psbt_input_value_sats_le(&psbt, 0), Some(60_000u64.to_le_bytes()));
    }

    #[test]
    fn sniff_elements_witness_utxo() {
        let wu = elements_wu(60_000);
        assert!(witness_utxo_is_elements(&wu));
        assert!(!witness_utxo_is_bitcoin(&wu));
        let psbt = psbt_with_wu(&wu);
        // The Elements 9-byte decode still works and holds the same amount.
        let v9 = psbt_input_value9(&psbt, 0).unwrap();
        assert_eq!(v9[0], 0x01);
        assert_eq!(u64::from_be_bytes(v9[1..9].try_into().unwrap()), 60_000);
    }

    /// The REAL `WIRE_HSMD_SIGN_REMOTE_COMMITMENT_TX` that the box's BTC hosted
    /// node sent (and the old, Elements-only signer rejected with "Bad
    /// sign_tx_reply"): a testnet4 anchor commitment, funding 60000 sat. Confirms
    /// the wire object decodes as Bitcoin end-to-end (tx + PSBT witness_utxo) with
    /// the right amount, so the sighash path is fed correct bytes. Public testnet
    /// tx data — no secret. hsmd_msg = type(0013) || u32(txlen) || tx || u32(psbtlen) || psbt.
    #[test]
    fn real_btc_sign_remote_commitment_request() {
        let msg = unhex(
            "0013000000890200000001b48df211ed41d16672b6f7eb863dc8f5b741abbfa9a8b826f3d22b5d88f26857\
             0000000000d662d180024a01000000000000220020d0dcdb317af356f0a66f1575887639d1b9e4406ffa63\
             d963468b284767462fa768e30000000000002200208aab7752ea60afd4060572793021d496f8ccab2a3d32\
             9e27e945b4342716255f1ceef720000001b870736274ff0100890200000001b48df211ed41d16672b6f7eb\
             863dc8f5b741abbfa9a8b826f3d22b5d88f268570000000000d662d180024a010000000000002200 20d0dc\
             db317af356f0a66f1575887639d1b9e4406ffa63d963468b284767462fa768e300000000000022002 08aab\
             7752ea60afd4060572793021d496f8ccab2a3d329e27e945b4342716255f1ceef7200001012b60ea0000000\
             000002200204e0cd2d0be1d96450ac86deca0cec865d64af25c378e40a9b97dea712de0b54e01054752210\
             34a8f59e0d673e1c655442244a80e5eafe7cde78397095c53c722e815232961a92103c5e01a4141bc87b5a1\
             5e2852f4c6235deb5fab673fe2f7eb13c1e07104416fb252ae2206034a8f59e0d673e1c655442244a80e5ea\
             fe7cde78397095c53c722e815232961a90800aedc6100000000220603c5e01a4141bc87b5a15e2852f4c623\
             5deb5fab673fe2f7eb13c1e07104416fb2088fee292800000000000101282103c5e01a4141bc87b5a15e285\
             2f4c6235deb5fab673fe2f7eb13c1e07104416fb2ac736460b268000101252103e0e01f17a1c26ac15fc5fd\
             0e17e6601a694aea98f13952a08b6ca21491cefadfad51b200034a8f59e0d673e1c655442244a80e5eafe7c\
             de78397095c53c722e815232961a9032bfe69d9b28c8c9e9f93538c76da23999b96c7f2f4ff8939c449832d\
             40ad3ef3010000000000000000000000000000"
                .replace(' ', "")
                .as_str(),
        );
        let mut r = Reader::new(&msg);
        assert_eq!(r.u16().unwrap(), msg::HSMD_SIGN_REMOTE_COMMITMENT_TX);
        let bt = read_bitcoin_tx(&mut r).expect("decode bitcoin_tx");
        assert_eq!(bt.tx.network, Network::Bitcoin);
        assert_eq!(bt.tx.version, 2);
        assert_eq!(bt.tx.inputs.len(), 1);
        assert_eq!(bt.tx.outputs.len(), 2);
        // Anchor (330 sat) + to_local (58216 sat).
        assert_eq!(u64::from_le_bytes(bt.tx.outputs[0].value[..].try_into().unwrap()), 330);
        assert_eq!(u64::from_le_bytes(bt.tx.outputs[1].value[..].try_into().unwrap()), 58216);
        // The funding witness_utxo amount decodes to 60000 sat.
        let v8 = psbt_input_value_sats_le(&bt.psbt, 0).expect("witness_utxo amount");
        assert_eq!(u64::from_le_bytes(v8), 60_000);
        // And the remote_funding pubkey trails the wire object (33 bytes).
        assert!(r.arr33().is_some());
    }

    /// The REAL `WIRE_HSMD_SIGN_WITHDRAWAL` the box's BTC hosted node sent for its
    /// channel-funding tx (and the old signer rejected with "Error parsing 7"):
    /// one P2WPKH wallet input (80000 sat, bip86 keyindex 1) funding a 60000-sat
    /// channel with p2tr change. Public testnet data — no secret. Proves the
    /// request + v0-PSBT decode and the partial-sig splice work on the real bytes.
    const REAL_WITHDRAWAL: &str = "0007000142cd59f23fe5fc46dae740eadf21b8436ada95b2f1eee888ecb805abb82d70c40000000000000000000138800000000100001600148dacd6af53b24ede66b06ab6e018a0451933d52c0000000001e570736274ff010089020000000142cd59f23fe5fc46dae740eadf21b8436ada95b2f1eee888ecb805abb82d70c40000000000fdffffff0260ea000000000000220020a10d8e03d2cb7fa7acbb942b07a37475766c59846eeb0ac436cb4cb7c36297228f4b0000000000002251206929e08209d2fcac61aada3f7c20f566f18bcf589749cc43f58b4bb45fb320bf0b2f0200000100c30200000003df95ea936d7194002e5ba394b546d616755c38699af5e4b2b3ea110f054c49f40000000000fdffffff994e1ab706c206afb7812e023fede7c47b1e84a8f6ad910592ac7c3ef9b8be6e0100000000fdffffff92ac0f2c6ec867179576e381d8d4068101c8cc7e9c5d2592882973f7f29ca5db0000000000fdffffff0280380100000000001600148dacd6af53b24ede66b06ab6e018a0451933d52c9ac60000000000001600147460dcbcf5d2997d166bb4bbf77a6a4c83cd49a3002f020001011f80380100000000001600148dacd6af53b24ede66b06ab6e018a0451933d52c0cfc096c696768746e696e67020200010cfc096c696768746e696e670108fccef1173bb126c40000210776cfb07e3d50463fcd1af2b6cea85a8ab07f6e7910ce771d96f6d7e3de15b3690900f6ca4640030000000cfc096c696768746e696e67010869ddcf9667cf9c7400";

    #[test]
    fn real_sign_withdrawal_parses_and_splices() {
        let msg = unhex(REAL_WITHDRAWAL);
        let (utxos, psbt) = parse_sign_withdrawal(&msg).expect("parse withdrawal");
        assert_eq!(utxos.len(), 1);
        let u = &utxos[0];
        assert_eq!(u.amount, 80_000);
        assert_eq!(u.vout, 0);
        assert_eq!(u.keyindex, 1);
        assert!(!u.is_unilateral_close);
        // Native P2WPKH scriptPubkey (OP_0 push20 <keyhash>).
        assert_eq!(u.script_pubkey.len(), 22);
        assert_eq!(&u.script_pubkey[..2], &[0x00, 0x14]);
        // The outpoint txid is the funding UTXO in internal (LE) byte order.
        assert_eq!(&u.txid[..4], &unhex("42cd59f2")[..]);

        // Reads as a v0 PSBT with a global unsigned tx.
        assert_eq!(&psbt[..5], b"psbt\xff");
        let lin = psbt_global_unsigned_tx(&psbt).expect("global unsigned tx");
        let tx = parse_bitcoin_tx(lin).expect("parse unsigned tx");
        assert_eq!(tx.network, Network::Bitcoin);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.inputs[0].txhash, u.txid);
        // Funding output 60000 sat + p2tr change 19343 sat.
        assert_eq!(u64::from_le_bytes(tx.outputs[0].value[..].try_into().unwrap()), 60_000);
        assert_eq!(u64::from_le_bytes(tx.outputs[1].value[..].try_into().unwrap()), 19_343);
        // The witness_utxo amount for input 0 decodes to 80000 sat.
        assert_eq!(psbt_input_value_sats_le(&psbt, 0), Some(80_000u64.to_le_bytes()));

        // Splice a dummy partial_sig into input 0's map; the PSBT must still
        // navigate (witness_utxo still readable, terminator shifted correctly).
        let term = psbt_input_map_terminator(&psbt, 0).expect("input-0 terminator");
        let mut rec = vec![34u8, 0x02];
        rec.extend_from_slice(&[3u8; 33]); // dummy 33-byte "pubkey"
        rec.push(2); // vallen
        rec.extend_from_slice(&[0x30, 0x01]); // dummy value
        let mut spliced = psbt[..term].to_vec();
        spliced.extend_from_slice(&rec);
        spliced.extend_from_slice(&psbt[term..]);
        assert_eq!(spliced.len(), psbt.len() + rec.len());
        assert_eq!(psbt_input_value_sats_le(&spliced, 0), Some(80_000u64.to_le_bytes()));
    }

    #[test]
    fn detect_network_env_and_sniff() {
        // With no env set, the sniff decides per witness_utxo shape.
        // (Guard: only assert the env-free path if the box hasn't exported it.)
        if std::env::var("SEQLN_SIGNER_NETWORK").is_err() {
            assert_eq!(detect_network(&psbt_with_wu(&btc_wu(50_000))), Network::Bitcoin);
            assert_eq!(detect_network(&psbt_with_wu(&elements_wu(50_000))), Network::Elements);
            // An unrecognised / absent witness_utxo defaults to Elements (the
            // pre-Bitcoin behaviour), never disturbing the Elements path.
            assert_eq!(detect_network(b"psbt\xff\x00\x00"), Network::Elements);
        }
    }
}
