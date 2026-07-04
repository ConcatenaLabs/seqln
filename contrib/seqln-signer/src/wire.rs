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

use crate::kernel::{ElementsTx, TxInput, TxOutput};

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
    })
}

/// Read a `bitcoin_tx` wire object from the reader (`fromwire_bitcoin_tx`).
pub fn read_bitcoin_tx(r: &mut Reader) -> Option<BitcoinTx> {
    let len = r.u32()? as usize; // big-endian tx byte length
    let lin = r.take_slice(len)?;
    let tx = parse_elements_tx(lin)?;
    let plen = r.u32()? as usize; // big-endian psbt byte length
    let psbt = r.take_bytes(plen)?;
    Some(BitcoinTx { tx, psbt })
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
