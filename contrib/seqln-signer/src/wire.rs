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
    pub const HSMD_GET_CHANNEL_BASEPOINTS: u16 = 10;
    pub const HSMD_INIT: u16 = 11;
    pub const HSMD_GET_PER_COMMITMENT_POINT: u16 = 18;
    pub const HSMD_DERIVE_SECRET: u16 = 27;
    pub const HSMD_CHECK_PUBKEY: u16 = 28;
    pub const HSMD_NEW_CHANNEL: u16 = 30;
    pub const HSMD_SETUP_CHANNEL: u16 = 31;
    pub const HSMD_CHECK_OUTPOINT: u16 = 32;
    pub const HSMD_FORGET_CHANNEL: u16 = 34;
    pub const HSMD_LOCK_OUTPOINT: u16 = 37;
    pub const HSMD_CHECK_BIP86_PUBKEY: u16 = 56;

    pub const HSMD_ECDH_RESP: u16 = 100;
    pub const HSMD_GET_CHANNEL_BASEPOINTS_REPLY: u16 = 110;
    pub const HSMD_INIT_REPLY_V4: u16 = 114;
    pub const HSMD_GET_PER_COMMITMENT_POINT_REPLY: u16 = 118;
    pub const HSMD_DERIVE_SECRET_REPLY: u16 = 127;
    pub const HSMD_CHECK_PUBKEY_REPLY: u16 = 128;
    pub const HSMD_NEW_CHANNEL_REPLY: u16 = 130;
    pub const HSMD_SETUP_CHANNEL_REPLY: u16 = 131;
    pub const HSMD_CHECK_OUTPOINT_REPLY: u16 = 132;
    pub const HSMD_FORGET_CHANNEL_REPLY: u16 = 134;
    pub const HSMD_LOCK_OUTPOINT_REPLY: u16 = 137;
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
