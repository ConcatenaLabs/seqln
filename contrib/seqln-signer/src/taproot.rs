//! The taproot-covenant channel type (`option_seq_taproot_covenant`): the
//! leaves and two-leaf trees of its commitment outputs, built as
//! `common/tcov_scripts.c` builds them, and the Elements taproot signature
//! hash that signs their spends (`bitcoin/tapscript.c`, which calls
//! libwally's `bip341_signature_hash` with Elements on).
//!
//! Elements chains, Sequentia among them, change BIP341/342 in three places:
//! the leaf version is 0xc4, every tag ends in "/elements", and the signature
//! hash commits to the chain's genesis hash and to each input's asset, its
//! issuance and each output's proofs.

use bitcoin::hashes::{ripemd160, sha256, Hash, HashEngine};
use secp256k1::{All, Keypair, Message, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::kernel::ElementsTx;

/// Tapscript's leaf version on Elements chains (0xc0 on Bitcoin).
pub const LEAF_VERSION: u8 = 0xc4;

/// BIP341's default sighash type: SIGHASH_ALL with a 64-byte signature.
pub const SIGHASH_DEFAULT: u8 = 0x00;

/// `WALLY_TX_ISSUANCE_FLAG` and `WALLY_TX_PEGIN_FLAG`: the top bits of a
/// serialized Elements prevout index.
const INDEX_FLAGS: u32 = 0xc000_0000;

fn tagged_engine(tag: &str) -> sha256::HashEngine {
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(t.as_byte_array());
    e.input(t.as_byte_array());
    e
}

/// `tagged_hash(tag, data)` = SHA256(SHA256(tag) || SHA256(tag) || data).
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut e = tagged_engine(tag);
    e.input(data);
    sha256::Hash::from_engine(e).to_byte_array()
}

fn sha(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

/// SHA256 of `data`: a payment hash from its preimage.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha(data)
}

fn compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

fn ser_string(out: &mut Vec<u8>, b: &[u8]) {
    compact_size(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// tagged_hash("TapLeaf/elements", 0xc4 || compact_size(len) || script)
pub fn leaf_hash(script: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(script.len() + 4);
    m.push(LEAF_VERSION);
    ser_string(&mut m, script);
    tagged_hash("TapLeaf/elements", &m)
}

/// tagged_hash("TapBranch/elements", min(a, b) || max(a, b))
pub fn branch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(lo);
    m[32..].copy_from_slice(hi);
    tagged_hash("TapBranch/elements", &m)
}

/// A taproot output whose script tree holds exactly two leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree2 {
    pub leaves: [Vec<u8>; 2],
    pub leaf_hashes: [[u8; 32]; 2],
    pub merkle_root: [u8; 32],
    /// The x-only internal key.
    pub internal: [u8; 32],
    /// The tweaked output key: the witness v1 program.
    pub program: [u8; 32],
    /// Whether the output key's y is odd (the control block's parity bit).
    pub odd: bool,
}

impl Tree2 {
    /// The tree with `internal_key` (compressed) and the two leaves. `None`
    /// if the key is not a point or the tweak lands on infinity.
    pub fn new(
        secp: &Secp256k1<All>,
        internal_key: &[u8; 33],
        leaf0: Vec<u8>,
        leaf1: Vec<u8>,
    ) -> Option<Tree2> {
        let leaf_hashes = [leaf_hash(&leaf0), leaf_hash(&leaf1)];
        let merkle_root = branch_hash(&leaf_hashes[0], &leaf_hashes[1]);
        let internal: [u8; 32] = internal_key[1..].try_into().ok()?;
        let xonly = XOnlyPublicKey::from_slice(&internal).ok()?;
        let tweak = taptweak(&internal, &merkle_root)?;
        let (out, parity) = xonly.add_tweak(secp, &tweak).ok()?;
        Some(Tree2 {
            leaves: [leaf0, leaf1],
            leaf_hashes,
            merkle_root,
            internal,
            program: out.serialize(),
            odd: parity == secp256k1::Parity::Odd,
        })
    }

    /// OP_1 <program>
    pub fn script_pubkey(&self) -> Vec<u8> {
        p2tr(&self.program)
    }

    /// The control block that spends leaf `leaf` (0 or 1).
    pub fn control_block(&self, leaf: usize) -> Vec<u8> {
        let mut cb = Vec::with_capacity(65);
        cb.push(LEAF_VERSION | self.odd as u8);
        cb.extend_from_slice(&self.internal);
        cb.extend_from_slice(&self.leaf_hashes[1 - leaf]);
        cb
    }
}

/// OP_1 <32-byte program>
pub fn p2tr(program: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.push(0x51);
    s.push(32);
    s.extend_from_slice(program);
    s
}

/// tagged_hash("TapTweak/elements", internal_x || merkle_root), as a scalar.
fn taptweak(internal: &[u8; 32], merkle_root: &[u8; 32]) -> Option<Scalar> {
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(internal);
    m[32..].copy_from_slice(merkle_root);
    Scalar::from_be_bytes(tagged_hash("TapTweak/elements", &m)).ok()
}

// ---------------------------------------------------------------------------
// Leaves (`common/tcov_scripts.c`).
// ---------------------------------------------------------------------------

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_VERIFY: u8 = 0x69;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_OVER: u8 = 0x78;
const OP_ROT: u8 = 0x7b;
const OP_SIZE: u8 = 0x82;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
const OP_INSPECTINPUTASSET: u8 = 0xc8;
const OP_INSPECTINPUTVALUE: u8 = 0xc9;
const OP_PUSHCURRENTINPUTINDEX: u8 = 0xcd;
const OP_INSPECTOUTPUTASSET: u8 = 0xce;
const OP_INSPECTOUTPUTVALUE: u8 = 0xcf;
const OP_INSPECTOUTPUTSCRIPTPUBKEY: u8 = 0xd1;
const OP_GREATERTHANOREQUAL64: u8 = 0xdf;
const OP_ECMULSCALARVERIFY: u8 = 0xe3;

/// secp256k1's generator, compressed.
const GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
    0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
    0xf8, 0x17, 0x98,
];

/// A direct push (`script_push_bytes`): every operand here is under 76 bytes.
fn push(s: &mut Vec<u8>, b: &[u8]) {
    debug_assert!(b.len() < 76);
    s.push(b.len() as u8);
    s.extend_from_slice(b);
}

/// A positive script number, minimally encoded.
fn push_num(s: &mut Vec<u8>, mut num: u32) {
    if num == 0 {
        s.push(OP_0);
        return;
    }
    if num <= 16 {
        s.push(OP_1 + num as u8 - 1);
        return;
    }
    let mut buf = Vec::with_capacity(5);
    while num != 0 {
        buf.push((num & 0xff) as u8);
        num >>= 8;
    }
    if buf[buf.len() - 1] & 0x80 != 0 {
        buf.push(0);
    }
    push(s, &buf);
}

fn xonly(key: &[u8; 33]) -> &[u8] {
    &key[1..]
}

/// COV(A, X, D): the output at this input's index carries explicit asset A,
/// an explicit value of at least X and pays the witness v1 program D.
fn add_cov(s: &mut Vec<u8>, asset_id: &[u8; 32], x: u64, d_program: &[u8; 32]) {
    s.extend_from_slice(&[OP_PUSHCURRENTINPUTINDEX, OP_DUP, OP_DUP, OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY]);
    push(s, asset_id);
    s.extend_from_slice(&[OP_EQUALVERIFY, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY]);
    push(s, &x.to_le_bytes());
    s.extend_from_slice(&[OP_GREATERTHANOREQUAL64, OP_VERIFY, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1, OP_EQUALVERIFY]);
    push(s, d_program);
    s.push(OP_EQUAL);
}

/// KEEP(S): the output at this input's index carries this input's explicit
/// asset, at least its explicit value, and pays the segwit script `dest_spk`.
fn add_keep(s: &mut Vec<u8>, dest_spk: &[u8]) -> Option<()> {
    let len = dest_spk.len();
    let version = *dest_spk.first()?;
    if len < 4 || dest_spk[1] as usize != len - 2 || !(version == OP_0 || (OP_1..=OP_16).contains(&version)) {
        return None;
    }
    s.extend_from_slice(&[
        OP_PUSHCURRENTINPUTINDEX, OP_DUP, OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY,
        OP_OVER, OP_INSPECTINPUTASSET, OP_1, OP_EQUALVERIFY, OP_EQUALVERIFY,
        OP_DUP, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY,
        OP_OVER, OP_INSPECTINPUTVALUE, OP_1, OP_EQUALVERIFY,
        OP_GREATERTHANOREQUAL64, OP_VERIFY, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    ]);
    s.push(version);
    s.push(OP_EQUALVERIFY);
    push(s, &dest_spk[2..]);
    s.push(OP_EQUAL);
    Some(())
}

/// DELAY: <delayed_key> OP_CHECKSIGVERIFY <to_self_delay> OP_CSV
pub fn leaf_delay(delayed_key: &[u8; 33], to_self_delay: u16) -> Vec<u8> {
    let mut s = Vec::with_capacity(40);
    push(&mut s, xonly(delayed_key));
    s.push(OP_CHECKSIGVERIFY);
    push_num(&mut s, to_self_delay as u32);
    s.push(OP_CHECKSEQUENCEVERIFY);
    s
}

/// REVOKE: <per_commitment_point> <G> OP_ROT OP_ECMULSCALARVERIFY KEEP(S)
pub fn leaf_revoke(per_commitment_point: &[u8; 33], dest_spk: &[u8]) -> Option<Vec<u8>> {
    let mut s = Vec::with_capacity(120);
    push(&mut s, per_commitment_point);
    push(&mut s, &GENERATOR);
    s.push(OP_ROT);
    s.push(OP_ECMULSCALARVERIFY);
    add_keep(&mut s, dest_spk)?;
    Some(s)
}

/// An offered HTLC's TIMEOUT: <self_htlc_key> OP_CHECKSIGVERIFY <cltv>
/// OP_CLTV OP_DROP COV(A, X, D)
pub fn leaf_offered_timeout(
    self_htlc_key: &[u8; 33],
    cltv_expiry: u32,
    asset_id: &[u8; 32],
    x: u64,
    d_program: &[u8; 32],
) -> Vec<u8> {
    let mut s = Vec::with_capacity(132);
    push(&mut s, xonly(self_htlc_key));
    s.push(OP_CHECKSIGVERIFY);
    push_num(&mut s, cltv_expiry);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(OP_DROP);
    add_cov(&mut s, asset_id, x, d_program);
    s
}

fn add_hashlock(s: &mut Vec<u8>, payment_ripemd: &[u8; 20]) {
    s.push(OP_SIZE);
    push_num(s, 32);
    s.push(OP_EQUALVERIFY);
    s.push(OP_HASH160);
    push(s, payment_ripemd);
    s.push(OP_EQUALVERIFY);
}

/// An offered HTLC's SUCCESS: the hash lock, then <other_htlc_key> OP_CHECKSIG
pub fn leaf_offered_success(payment_ripemd: &[u8; 20], other_htlc_key: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(64);
    add_hashlock(&mut s, payment_ripemd);
    push(&mut s, xonly(other_htlc_key));
    s.push(OP_CHECKSIG);
    s
}

/// A received HTLC's SUCCESS: the hash lock, then <self_htlc_key>
/// OP_CHECKSIGVERIFY COV(A, X, D)
pub fn leaf_received_success(
    payment_ripemd: &[u8; 20],
    self_htlc_key: &[u8; 33],
    asset_id: &[u8; 32],
    x: u64,
    d_program: &[u8; 32],
) -> Vec<u8> {
    let mut s = Vec::with_capacity(156);
    add_hashlock(&mut s, payment_ripemd);
    push(&mut s, xonly(self_htlc_key));
    s.push(OP_CHECKSIGVERIFY);
    add_cov(&mut s, asset_id, x, d_program);
    s
}

/// A received HTLC's TIMEOUT: <other_htlc_key> OP_CHECKSIGVERIFY <cltv> OP_CLTV
pub fn leaf_received_timeout(other_htlc_key: &[u8; 33], cltv_expiry: u32) -> Vec<u8> {
    let mut s = Vec::with_capacity(40);
    push(&mut s, xonly(other_htlc_key));
    s.push(OP_CHECKSIGVERIFY);
    push_num(&mut s, cltv_expiry);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s
}

/// The keys of one commitment, held by "self" (counterparty "other"), as
/// `derive_keyset` gives them under `option_static_remotekey`.
pub struct TcovKeys {
    pub revocation: [u8; 33],
    pub self_delayed: [u8; 33],
    pub self_htlc: [u8; 33],
    pub other_htlc: [u8; 33],
    /// Other's payment basepoint: the key of S, the script KEEP pays.
    pub other_payment: [u8; 33],
}

/// P2WPKH of `key`: S, other's static payment script.
pub fn p2wpkh(key: &[u8; 33]) -> Vec<u8> {
    let h = bitcoin::hashes::hash160::Hash::hash(key).to_byte_array();
    let mut s = Vec::with_capacity(22);
    s.push(0x00);
    s.push(20);
    s.extend_from_slice(&h);
    s
}

/// RIPEMD160 of a payment hash: what the hash locks compare HASH160 of the
/// preimage with.
pub fn payment_ripemd(payment_hash: &[u8; 32]) -> [u8; 20] {
    ripemd160::Hash::hash(payment_hash).to_byte_array()
}

/// to_local, and D: leaf 0 DELAY, leaf 1 REVOKE.
pub fn to_local_tree(
    secp: &Secp256k1<All>,
    k: &TcovKeys,
    per_commitment_point: &[u8; 33],
    to_self_delay: u16,
) -> Option<Tree2> {
    Tree2::new(
        secp,
        &k.revocation,
        leaf_delay(&k.self_delayed, to_self_delay),
        leaf_revoke(per_commitment_point, &p2wpkh(&k.other_payment))?,
    )
}

/// An HTLC the commitment's holder offered: leaf 0 TIMEOUT, leaf 1 SUCCESS.
#[allow(clippy::too_many_arguments)]
pub fn offered_tree(
    secp: &Secp256k1<All>,
    k: &TcovKeys,
    per_commitment_point: &[u8; 33],
    to_self_delay: u16,
    asset_id: &[u8; 32],
    payment_hash: &[u8; 32],
    cltv_expiry: u32,
    x: u64,
) -> Option<Tree2> {
    let d = to_local_tree(secp, k, per_commitment_point, to_self_delay)?;
    Tree2::new(
        secp,
        &k.revocation,
        leaf_offered_timeout(&k.self_htlc, cltv_expiry, asset_id, x, &d.program),
        leaf_offered_success(&payment_ripemd(payment_hash), &k.other_htlc),
    )
}

/// An HTLC the commitment's holder received: leaf 0 SUCCESS, leaf 1 TIMEOUT.
#[allow(clippy::too_many_arguments)]
pub fn received_tree(
    secp: &Secp256k1<All>,
    k: &TcovKeys,
    per_commitment_point: &[u8; 33],
    to_self_delay: u16,
    asset_id: &[u8; 32],
    payment_hash: &[u8; 32],
    cltv_expiry: u32,
    x: u64,
) -> Option<Tree2> {
    let d = to_local_tree(secp, k, per_commitment_point, to_self_delay)?;
    Tree2::new(
        secp,
        &k.revocation,
        leaf_received_success(&payment_ripemd(payment_hash), &k.self_htlc, asset_id, x, &d.program),
        leaf_received_timeout(&k.other_htlc, cltv_expiry),
    )
}

// ---------------------------------------------------------------------------
// The provider-signed credit (`common/credit_scripts.c`).
// ---------------------------------------------------------------------------

const OP_2DUP: u8 = 0x6e;
const OP_SWAP: u8 = 0x7c;
const OP_CAT: u8 = 0x7e;
const OP_1ADD: u8 = 0x8b;
const OP_SHA256: u8 = 0xa8;
const OP_CHECKSIGFROMSTACKVERIFY: u8 = 0xc2;
const OP_INSPECTINPUTSCRIPTPUBKEY: u8 = 0xca;
const OP_SUB64: u8 = 0xd8;
const OP_GREATERTHAN64: u8 = 0xde;

/// BIP341's NUMS point H, with even y: the internal key of the provider's
/// output on the holder's commitment, which nobody can spend by key.
pub const NUMS: [u8; 33] = [
    0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
    0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce,
    0x80, 0x3a, 0xc0,
];

/// Dtag = tagged_hash("SeqLN/credit", channel_id): binds a note to its
/// channel (BOLT 2's channel id, from the funding outpoint).
pub fn credit_tag(channel_id: &[u8; 32]) -> [u8; 32] {
    tagged_hash("SeqLN/credit", channel_id)
}

/// BOLT 2's channel id: the funding txid (as lightningd holds it) with the
/// output index XORed into its last two bytes.
pub fn channel_id(funding_txid: &[u8; 32], funding_txout: u16) -> [u8; 32] {
    let mut id = *funding_txid;
    id[30] ^= (funding_txout >> 8) as u8;
    id[31] ^= funding_txout as u8;
    id
}

/// Pc, the credit key: the provider's funding key plus
/// tagged_hash("SeqLN/credit-key", funding key) * G.  It signs nothing but
/// notes.
pub fn credit_key(secp: &Secp256k1<All>, provider_funding: &[u8; 33]) -> Option<[u8; 33]> {
    let pk = secp256k1::PublicKey::from_slice(provider_funding).ok()?;
    let t = Scalar::from_be_bytes(tagged_hash("SeqLN/credit-key", provider_funding)).ok()?;
    Some(pk.add_exp_tweak(secp, &t).ok()?.serialize())
}

/// What a note signs: Dtag || c (8 bytes, little-endian) || payment hash.
pub fn credit_note_msg(dtag: &[u8; 32], credit: u64, payment_hash: &[u8; 32]) -> [u8; 72] {
    let mut m = [0u8; 72];
    m[..32].copy_from_slice(dtag);
    m[32..40].copy_from_slice(&credit.to_le_bytes());
    m[40..].copy_from_slice(payment_hash);
    m
}

/// Whether `sig` is the credit key's BIP340 signature of the note (`credit`,
/// `payment_hash`) on the channel `dtag`: the 72-byte message itself, as
/// OP_CHECKSIGFROMSTACKVERIFY checks it, not a hash of it.
pub fn credit_note_check(
    secp: &Secp256k1<All>,
    dtag: &[u8; 32],
    credit_key: &[u8; 33],
    credit: u64,
    payment_hash: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    use secp256k1::ffi::CPtr;
    let Ok(xonly) = XOnlyPublicKey::from_slice(&credit_key[1..]) else {
        return false;
    };
    let msg = credit_note_msg(dtag, credit, payment_hash);
    // SAFETY: every pointer is to a live buffer of the length passed, and the
    // context is the caller's, which verifies.
    unsafe {
        secp256k1::ffi::secp256k1_schnorrsig_verify(
            secp.ctx().as_ptr(),
            sig.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            xonly.as_c_ptr(),
        ) == 1
    }
}

/// CLAIM: pays the holder's v0 program `holder_spk` (P2WPKH) what a note
/// signed by `credit_key` on the channel `dtag` still owes it out of an
/// output worth `b` in its commitment; the rest stays under the same script.
pub fn leaf_claim(dtag: &[u8; 32], credit_key: &[u8; 33], b: u64, holder_spk: &[u8]) -> Option<Vec<u8>> {
    if holder_spk.len() != 22 || holder_spk[0] != OP_0 || holder_spk[1] != 20 {
        return None;
    }
    let mut s = Vec::with_capacity(172);
    s.extend_from_slice(&[OP_SIZE, 0x01, 32, OP_EQUALVERIFY, OP_SHA256, OP_OVER]);
    push(&mut s, dtag);
    s.extend_from_slice(&[OP_SWAP, OP_CAT, OP_SWAP, OP_CAT, OP_ROT, OP_SWAP]);
    push(&mut s, xonly(credit_key));
    s.push(OP_CHECKSIGFROMSTACKVERIFY);
    push(&mut s, &b.to_le_bytes());
    s.extend_from_slice(&[
        OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE, OP_1, OP_EQUALVERIFY, OP_SUB64, OP_VERIFY,
        OP_2DUP, OP_GREATERTHAN64, OP_VERIFY,
        OP_OVER, OP_SWAP, OP_SUB64, OP_VERIFY,
        OP_PUSHCURRENTINPUTINDEX, OP_1ADD, OP_DUP, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY,
        OP_ROT, OP_EQUALVERIFY,
        OP_DUP, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_0, OP_EQUALVERIFY,
    ]);
    push(&mut s, &holder_spk[2..]);
    s.extend_from_slice(&[
        OP_EQUALVERIFY, OP_INSPECTOUTPUTASSET, OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET,
        OP_ROT, OP_EQUALVERIFY, OP_EQUALVERIFY,
    ]);
    push(&mut s, &b.to_le_bytes());
    s.extend_from_slice(&[
        OP_SWAP, OP_SUB64, OP_VERIFY,
        OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, OP_EQUALVERIFY,
        OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY,
        OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTSCRIPTPUBKEY,
        OP_ROT, OP_EQUALVERIFY, OP_EQUALVERIFY,
        OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTASSET,
        OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET,
        OP_ROT, OP_EQUALVERIFY, OP_EQUAL,
    ]);
    Some(s)
}

/// What a channel's credit leaves are built from.
pub struct CreditParams {
    pub dtag: [u8; 32],
    pub credit_key: [u8; 33],
    /// U: the holder's static payment script, P2WPKH of its payment
    /// basepoint.
    pub holder_spk: Vec<u8>,
}

impl CreditParams {
    /// For the channel funded at (`funding_txid`, `funding_txout`), whose
    /// provider's funding key is `provider_funding` and whose holder's
    /// payment basepoint is `holder_payment`.
    pub fn new(
        secp: &Secp256k1<All>,
        funding_txid: &[u8; 32],
        funding_txout: u16,
        provider_funding: &[u8; 33],
        holder_payment: &[u8; 33],
    ) -> Option<CreditParams> {
        Some(CreditParams {
            dtag: credit_tag(&channel_id(funding_txid, funding_txout)),
            credit_key: credit_key(secp, provider_funding)?,
            holder_spk: p2wpkh(holder_payment),
        })
    }
}

/// The scriptPubKey of the provider's to_local on its own commitment,
/// worth `value`: internal key the revocation key, CLAIM at depth one,
/// DELAY and REVOKE at depth two.
pub fn credit_to_local_spk(
    secp: &Secp256k1<All>,
    k: &TcovKeys,
    per_commitment_point: &[u8; 33],
    to_self_delay: u16,
    cp: &CreditParams,
    value: u64,
) -> Option<Vec<u8>> {
    let two = to_local_tree(secp, k, per_commitment_point, to_self_delay)?;
    let claim = leaf_hash(&leaf_claim(&cp.dtag, &cp.credit_key, value, &cp.holder_spk)?);
    let root = branch_hash(&claim, &two.merkle_root);
    tweaked_spk(secp, &k.revocation, &root)
}

/// The scriptPubKey of the provider's output on the holder's commitment,
/// worth `value`: no key path (NUMS), CLAIM, and PROVIDER, the provider's
/// own spend after `delay` blocks.
pub fn credit_to_remote_spk(
    secp: &Secp256k1<All>,
    provider_payment: &[u8; 33],
    delay: u16,
    cp: &CreditParams,
    value: u64,
) -> Option<Vec<u8>> {
    let t = Tree2::new(
        secp,
        &NUMS,
        leaf_claim(&cp.dtag, &cp.credit_key, value, &cp.holder_spk)?,
        leaf_delay(provider_payment, delay),
    )?;
    Some(t.script_pubkey())
}

fn tweaked_spk(secp: &Secp256k1<All>, internal_key: &[u8; 33], root: &[u8; 32]) -> Option<Vec<u8>> {
    let internal: [u8; 32] = internal_key[1..].try_into().ok()?;
    let xonly = XOnlyPublicKey::from_slice(&internal).ok()?;
    let tweak = taptweak(&internal, root)?;
    let (out, _) = xonly.add_tweak(secp, &tweak).ok()?;
    Some(p2tr(&out.serialize()))
}

// ---------------------------------------------------------------------------
// The Elements taproot signature hash.
// ---------------------------------------------------------------------------

/// An input's previous output, its fields as serialized: the asset and value
/// commitments (33 and 9 bytes when explicit) and the scriptPubKey.
pub struct Prevout {
    pub asset: Vec<u8>,
    pub value: Vec<u8>,
    pub script: Vec<u8>,
}

fn ser_output(out: &mut Vec<u8>, o: &crate::kernel::TxOutput) {
    out.extend_from_slice(&o.asset);
    out.extend_from_slice(&o.value);
    out.extend_from_slice(&o.nonce);
    ser_string(out, &o.script);
}

/// The signature hash of input `index` of `tx` on the Elements chain whose
/// genesis hash is `genesis` (internal byte order): the script path of
/// `leaf`, or the key path when `leaf` is `None`; BIP342's key_version 0 and
/// no OP_CODESEPARATOR. A port of `TaprootSignatureHash` in the Sequentia
/// node's test framework, which libwally's `bip341_signature_hash` matches.
///
/// Every output's proofs and every input's issuance proofs are taken as
/// empty: the caller checks that the transaction has none (an unblinded
/// transaction with no issuance). `None` for an issuance or peg-in input, a
/// count of prevouts other than the inputs', an index out of range, or a
/// sighash type BIP341 does not define.
pub fn elements_sighash(
    tx: &ElementsTx,
    prevouts: &[Prevout],
    index: usize,
    leaf: Option<&[u8]>,
    hash_type: u8,
    genesis: &[u8; 32],
) -> Option<[u8; 32]> {
    if prevouts.len() != tx.inputs.len() || index >= tx.inputs.len() {
        return None;
    }
    if !matches!(hash_type, 0x00..=0x03 | 0x81..=0x83) {
        return None;
    }
    if tx.inputs.iter().any(|i| i.is_issuance || i.index & INDEX_FLAGS != 0) {
        return None;
    }
    let out_type = if hash_type == SIGHASH_DEFAULT { 0x01 } else { hash_type & 0x03 };
    let acp = hash_type & 0x80 != 0;
    let empty_proofs = [0x00u8, 0x00];

    let mut m = Vec::with_capacity(400);
    m.extend_from_slice(genesis);
    m.extend_from_slice(genesis);
    m.push(hash_type);
    m.extend_from_slice(&tx.version.to_le_bytes());
    m.extend_from_slice(&tx.locktime.to_le_bytes());
    if !acp {
        // sha_outpoint_flags: neither issuance nor peg-in on any input.
        m.extend_from_slice(&sha(&vec![0u8; tx.inputs.len()]));
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(&i.txhash);
            b.extend_from_slice(&i.index.to_le_bytes());
        }
        m.extend_from_slice(&sha(&b));
        let mut b = Vec::new();
        for p in prevouts {
            b.extend_from_slice(&p.asset);
            b.extend_from_slice(&p.value);
        }
        m.extend_from_slice(&sha(&b));
        let mut b = Vec::new();
        for p in prevouts {
            ser_string(&mut b, &p.script);
        }
        m.extend_from_slice(&sha(&b));
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(&i.sequence.to_le_bytes());
        }
        m.extend_from_slice(&sha(&b));
        // sha_issuances: a null issuance is the byte 0x00.
        m.extend_from_slice(&sha(&vec![0u8; tx.inputs.len()]));
        // sha_issuance_rangeproofs: two empty proofs per input.
        m.extend_from_slice(&sha(&empty_proofs.repeat(tx.inputs.len())));
    }
    if out_type == 0x01 {
        let mut b = Vec::new();
        for o in &tx.outputs {
            ser_output(&mut b, o);
        }
        m.extend_from_slice(&sha(&b));
        // sha_output_witnesses: an empty surjection proof and range proof.
        m.extend_from_slice(&sha(&empty_proofs.repeat(tx.outputs.len())));
    }
    let spend_type: u8 = if leaf.is_some() { 2 } else { 0 };
    m.push(spend_type);
    if acp {
        let i = &tx.inputs[index];
        let p = &prevouts[index];
        m.push(0x00); // outpoint flags
        m.extend_from_slice(&i.txhash);
        m.extend_from_slice(&i.index.to_le_bytes());
        m.extend_from_slice(&p.asset);
        m.extend_from_slice(&p.value);
        ser_string(&mut m, &p.script);
        m.extend_from_slice(&i.sequence.to_le_bytes());
        m.push(0x00); // null issuance
    } else {
        m.extend_from_slice(&(index as u32).to_le_bytes());
    }
    if out_type == 0x03 {
        match tx.outputs.get(index) {
            Some(o) => {
                let mut b = Vec::new();
                ser_output(&mut b, o);
                m.extend_from_slice(&sha(&b));
                m.extend_from_slice(&sha(&empty_proofs));
            }
            None => return None,
        }
    }
    if let Some(leaf) = leaf {
        m.extend_from_slice(&leaf_hash(leaf));
        m.push(0x00); // key_version
        m.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // no OP_CODESEPARATOR
    }
    Some(tagged_hash("TapSighash/elements", &m))
}

/// BIP340 signature of `sighash` by `sk`, with no auxiliary randomness (as
/// `tap_sign` makes it: the same request always gets the same signature).
pub fn sign(secp: &Secp256k1<All>, sighash: &[u8; 32], sk: &SecretKey) -> [u8; 64] {
    let kp = Keypair::from_secret_key(secp, sk);
    let msg = Message::from_digest(*sighash);
    secp.sign_schnorr_no_aux_rand(&msg, &kp).serialize()
}

/// The key path: `internal_sk` tweaked for `merkle_root` (negated first when
/// its point's y is odd, as BIP341's x-only internal key requires), then
/// signed. Also returns the tweaked output key's x, for a check against the
/// output being spent.
pub fn sign_keypath(
    secp: &Secp256k1<All>,
    sighash: &[u8; 32],
    internal_sk: &SecretKey,
    merkle_root: &[u8; 32],
) -> Option<([u8; 64], [u8; 32])> {
    let kp = Keypair::from_secret_key(secp, internal_sk);
    let (internal, _) = kp.x_only_public_key();
    let tweak = taptweak(&internal.serialize(), merkle_root)?;
    let tweaked = kp.add_xonly_tweak(secp, &tweak).ok()?;
    let msg = Message::from_digest(*sighash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked);
    Some((sig.serialize(), tweaked.x_only_public_key().0.serialize()))
}

#[cfg(test)]
mod tests {
    //! Against `common/test/tcov_vectors.h`, which the Sequentia node's test
    //! framework made (and `common/test/run-tcov_scripts.c` checks the C
    //! builders against).
    use super::*;
    use secp256k1::PublicKey;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn a32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }
    fn a33(s: &str) -> [u8; 33] {
        h(s).try_into().unwrap()
    }

    /// One `static const char NAME[] = "hex";` or `#define NAME n` of the
    /// vectors file.
    fn v(name: &str) -> String {
        let src = include_str!("../../../common/test/tcov_vectors.h");
        for line in src.lines() {
            if let Some(rest) = line.strip_prefix(&format!("static const char {name}[] = \"")) {
                return rest.trim_end_matches("\";").to_string();
            }
            if let Some(rest) = line.strip_prefix(&format!("#define {name} ")) {
                return rest.trim().to_string();
            }
        }
        panic!("no vector {name}");
    }
    fn n(name: &str) -> u64 {
        v(name).parse().unwrap()
    }

    fn keys() -> TcovKeys {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&a32(&v("V_OTHER_PAYMENT_SECRET"))).unwrap();
        TcovKeys {
            revocation: a33(&v("V_REVOCATION_KEY")),
            self_delayed: a33(&v("V_SELF_DELAYED_KEY")),
            self_htlc: a33(&v("V_SELF_HTLC_KEY")),
            other_htlc: a33(&v("V_OTHER_HTLC_KEY")),
            other_payment: PublicKey::from_secret_key(&secp, &sk).serialize(),
        }
    }

    #[test]
    fn leaves_and_trees_match_the_vectors() {
        let secp = Secp256k1::new();
        let k = keys();
        let pcp = a33(&v("V_PER_COMMITMENT_POINT"));
        let delay = n("V_DELAY") as u16;
        let asset: [u8; 32] = h(&v("V_ASSET_TAG"))[1..].try_into().unwrap();
        let ph = a32(&v("V_PAYMENT_HASH"));
        let (cltv, x) = (n("V_CLTV") as u32, n("V_X"));

        assert_eq!(p2wpkh(&k.other_payment), h(&v("V_REVOKE_DEST")));
        let tl = to_local_tree(&secp, &k, &pcp, delay).unwrap();
        assert_eq!(tl.leaves[0], h(&v("V_TO_LOCAL_DELAY_LEAF")));
        assert_eq!(tl.leaves[1], h(&v("V_TO_LOCAL_REVOKE_LEAF")));
        assert_eq!(tl.merkle_root.to_vec(), h(&v("V_TO_LOCAL_ROOT")));
        assert_eq!(tl.script_pubkey(), h(&v("V_TO_LOCAL_SPK")));
        assert_eq!(tl.control_block(0), h(&v("V_TO_LOCAL_CB_DELAY")));
        assert_eq!(tl.control_block(1), h(&v("V_TO_LOCAL_CB_REVOKE")));

        let off = offered_tree(&secp, &k, &pcp, delay, &asset, &ph, cltv, x).unwrap();
        assert_eq!(off.leaves[0], h(&v("V_OFFERED_TIMEOUT_LEAF")));
        assert_eq!(off.leaves[1], h(&v("V_OFFERED_SUCCESS_LEAF")));
        assert_eq!(off.merkle_root.to_vec(), h(&v("V_OFFERED_ROOT")));
        assert_eq!(off.script_pubkey(), h(&v("V_OFFERED_SPK")));
        assert_eq!(off.control_block(0), h(&v("V_OFFERED_CB_TIMEOUT")));

        let rcv = received_tree(&secp, &k, &pcp, delay, &asset, &ph, cltv, x).unwrap();
        assert_eq!(rcv.leaves[0], h(&v("V_RECEIVED_SUCCESS_LEAF")));
        assert_eq!(rcv.leaves[1], h(&v("V_RECEIVED_TIMEOUT_LEAF")));
        assert_eq!(rcv.script_pubkey(), h(&v("V_RECEIVED_SPK")));
        assert_eq!(rcv.control_block(0), h(&v("V_RECEIVED_CB_SUCCESS")));
    }

    /// The claim transaction of the vectors: input 0 the offered HTLC, input
    /// 1 a fee coin in another asset.
    fn claim() -> (ElementsTx, Vec<Prevout>) {
        let raw = h(&v("V_CLAIM_TX"));
        let tx = crate::wire::parse_elements_tx(&raw).unwrap();
        let x = n("V_X");
        let explicit = |v: u64| {
            let mut b = vec![0x01];
            b.extend_from_slice(&v.to_be_bytes());
            b
        };
        let prevouts = vec![
            Prevout { asset: h(&v("V_ASSET_TAG")), value: explicit(x), script: h(&v("V_OFFERED_SPK")) },
            Prevout {
                asset: h(&v("V_FEE_ASSET_TAG")),
                value: explicit(n("V_FEE_IN")),
                script: h(&v("V_FEE_SPK")),
            },
        ];
        (tx, prevouts)
    }

    #[test]
    fn sighash_and_signatures_match_the_vectors() {
        let secp = Secp256k1::new();
        let (tx, prevouts) = claim();
        let genesis = a32(&v("V_GENESIS"));
        let leaf = h(&v("V_OFFERED_TIMEOUT_LEAF"));

        let sh = elements_sighash(&tx, &prevouts, 0, Some(&leaf), SIGHASH_DEFAULT, &genesis).unwrap();
        assert_eq!(sh.to_vec(), h(&v("V_SIGHASH_SCRIPT")));
        let sh_key = elements_sighash(&tx, &prevouts, 0, None, SIGHASH_DEFAULT, &genesis).unwrap();
        assert_eq!(sh_key.to_vec(), h(&v("V_SIGHASH_KEY")));
        let sh_acp = elements_sighash(&tx, &prevouts, 0, None, 0x83, &genesis).unwrap();
        assert_eq!(sh_acp.to_vec(), h(&v("V_SIGHASH_KEY_SINGLE_ACP")));

        // The HTLC key: simple_priv(self_htlc_secret, pcp), BOLT 3.
        let pcp = a33(&v("V_PER_COMMITMENT_POINT"));
        let base = SecretKey::from_slice(&a32(&v("V_SELF_HTLC_SECRET"))).unwrap();
        let base_pub = PublicKey::from_secret_key(&secp, &base).serialize();
        let mut pre = pcp.to_vec();
        pre.extend_from_slice(&base_pub);
        let t = Scalar::from_be_bytes(sha(&pre)).unwrap();
        let htlc_sk = base.add_tweak(&t).unwrap();
        assert_eq!(PublicKey::from_secret_key(&secp, &htlc_sk).serialize(), a33(&v("V_SELF_HTLC_KEY")));
        assert_eq!(sign(&secp, &sh, &htlc_sk).to_vec(), h(&v("V_SIG_SCRIPT")));

        // The revocation key, BOLT 3: rb * SHA256(RB || P) + pc * SHA256(P || RB).
        let rb = SecretKey::from_slice(&a32(&v("V_OTHER_REVOCATION_SECRET"))).unwrap();
        let pc = SecretKey::from_slice(&a32(&v("V_PER_COMMITMENT_SECRET"))).unwrap();
        let rb_pub = PublicKey::from_secret_key(&secp, &rb).serialize();
        let mut a = rb_pub.to_vec();
        a.extend_from_slice(&pcp);
        let mut b = pcp.to_vec();
        b.extend_from_slice(&rb_pub);
        let ra = rb.mul_tweak(&Scalar::from_be_bytes(sha(&a)).unwrap()).unwrap();
        let pb = pc.mul_tweak(&Scalar::from_be_bytes(sha(&b)).unwrap()).unwrap();
        let rev_sk = ra.add_tweak(&Scalar::from(pb)).unwrap();
        assert_eq!(PublicKey::from_secret_key(&secp, &rev_sk).serialize(), a33(&v("V_REVOCATION_KEY")));
        let root = a32(&v("V_OFFERED_ROOT"));
        let (sig, out_x) = sign_keypath(&secp, &sh_key, &rev_sk, &root).unwrap();
        assert_eq!(sig.to_vec(), h(&v("V_SIG_KEY")));
        assert_eq!(p2tr(&out_x), h(&v("V_OFFERED_SPK")));
    }

    /// One vector of `common/test/credit_vectors.h`.
    fn cv(name: &str) -> String {
        let src = include_str!("../../../common/test/credit_vectors.h");
        for line in src.lines() {
            if let Some(rest) = line.strip_prefix(&format!("static const char {name}[] = \"")) {
                return rest.trim_end_matches("\";").to_string();
            }
            if let Some(rest) = line.strip_prefix(&format!("#define {name} ")) {
                return rest.trim().to_string();
            }
        }
        panic!("no vector {name}");
    }

    #[test]
    fn credit_scripts_match_the_vectors() {
        let secp = Secp256k1::new();
        let k = keys();
        let pcp = a33(&v("V_PER_COMMITMENT_POINT"));
        let pub_of = |name: &str| {
            let sk = SecretKey::from_slice(&a32(&cv(name))).unwrap();
            PublicKey::from_secret_key(&secp, &sk).serialize()
        };
        let provider_funding = pub_of("CV_PROVIDER_FUNDING_SECRET");
        let provider_payment = pub_of("CV_PROVIDER_PAYMENT_SECRET");
        let cid = a32(&cv("CV_CHANNEL_ID"));
        let v0: u64 = cv("CV_V0").parse().unwrap();
        let delay: u16 = cv("CV_DELAY").parse().unwrap();
        let window: u16 = cv("CV_WINDOW").parse().unwrap();

        let cp = CreditParams {
            dtag: credit_tag(&cid),
            credit_key: credit_key(&secp, &provider_funding).unwrap(),
            holder_spk: p2wpkh(&k.other_payment),
        };
        assert_eq!(cp.dtag.to_vec(), h(&cv("CV_DTAG")));
        assert_eq!(cp.credit_key.to_vec(), h(&cv("CV_CREDIT_KEY")));
        assert_eq!(cp.holder_spk, h(&cv("CV_HOLDER_SPK")));
        let leaf = leaf_claim(&cp.dtag, &cp.credit_key, v0, &cp.holder_spk).unwrap();
        assert_eq!(leaf, h(&cv("CV_CLAIM_LEAF")));
        assert_eq!(leaf.len(), 172);
        assert_eq!(
            credit_to_local_spk(&secp, &k, &pcp, delay, &cp, v0).unwrap(),
            h(&cv("CV_TO_LOCAL_SPK"))
        );
        assert_eq!(
            credit_to_remote_spk(&secp, &provider_payment, window, &cp, v0).unwrap(),
            h(&cv("CV_TO_REMOTE_SPK"))
        );
        assert_eq!(leaf_delay(&provider_payment, window), h(&cv("CV_PROVIDER_LEAF")));
        // B is in the leaf: another value is another script.
        assert_ne!(
            credit_to_remote_spk(&secp, &provider_payment, window, &cp, v0 + 1).unwrap(),
            h(&cv("CV_TO_REMOTE_SPK"))
        );
        // A holder script that is not P2WPKH builds no leaf.
        assert!(leaf_claim(&cp.dtag, &cp.credit_key, v0, &p2tr(&[7; 32])).is_none());

        // The note: good as signed, refused for another credit, hash,
        // channel or key.
        let ph = a32(&cv("CV_NOTE_HASH"));
        let sig: [u8; 64] = h(&cv("CV_NOTE_SIG")).try_into().unwrap();
        let c: u64 = cv("CV_NOTE_C").parse().unwrap();
        assert!(credit_note_check(&secp, &cp.dtag, &cp.credit_key, c, &ph, &sig));
        assert!(!credit_note_check(&secp, &cp.dtag, &cp.credit_key, c + 1, &ph, &sig));
        assert!(!credit_note_check(&secp, &cp.dtag, &provider_funding, c, &ph, &sig));
        let mut other = ph;
        other[0] ^= 1;
        assert!(!credit_note_check(&secp, &cp.dtag, &cp.credit_key, c, &other, &sig));
        let mut tag = cp.dtag;
        tag[31] ^= 1;
        assert!(!credit_note_check(&secp, &tag, &cp.credit_key, c, &ph, &sig));
    }

    #[test]
    fn channel_id_is_bolt2s() {
        let mut txid = [0u8; 32];
        txid[30] = 0x12;
        txid[31] = 0x34;
        let id = channel_id(&txid, 0x0102);
        assert_eq!(&id[30..], &[0x13, 0x36]);
        assert_eq!(&id[..30], &[0u8; 30]);
    }

    #[test]
    fn sighash_refuses_what_it_cannot_hash() {
        let (mut tx, prevouts) = claim();
        let genesis = [0u8; 32];
        assert!(elements_sighash(&tx, &prevouts, 2, None, 0, &genesis).is_none());
        assert!(elements_sighash(&tx, &prevouts[..1], 0, None, 0, &genesis).is_none());
        assert!(elements_sighash(&tx, &prevouts, 0, None, 0x04, &genesis).is_none());
        tx.inputs[1].index |= 0x4000_0000; // a peg-in
        assert!(elements_sighash(&tx, &prevouts, 0, None, 0, &genesis).is_none());
    }
}
