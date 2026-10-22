//! The symmetric channel type (`option_seq_symmetric`): its leaves and trees,
//! built as `common/sym_scripts.c` builds them, so that this device computes
//! for itself what an update signature commits to and what a state pays.
//!
//! A unilateral close is a kickoff, which moves the funding output to KO, an
//! update into a state's output and, after the shared delay, the state's
//! settlement. The kickoff is signed once, at open, by both funding keys
//! (`SIGHASH_SINGLE|SIGHASH_ANYONECANPAY`). A state is signed by both update
//! keys over `SHA256(tag || n || P || R)`: P is the program of the state's
//! output, which commits to its settlement through the SETTLE leaf, and R is
//! that leaf's hash. The tag binds the chain and the funding outpoint.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use secp256k1::{All, Scalar, Secp256k1, XOnlyPublicKey};

use crate::taproot::{self, leaf_hash, tagged_hash, Tree2, NUMS};

/// The prefix of a channel's update tag.
pub const TAG_PREFIX: &[u8] = b"SeqLN symmetric update v1";

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_VERIFY: u8 = 0x69;
const OP_DROP: u8 = 0x75;
const OP_OVER: u8 = 0x78;
const OP_ROT: u8 = 0x7b;
const OP_SWAP: u8 = 0x7c;
const OP_TUCK: u8 = 0x7d;
const OP_CAT: u8 = 0x7e;
const OP_SIZE: u8 = 0x82;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_SHA256: u8 = 0xa8;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
const OP_CHECKSIGFROMSTACKVERIFY: u8 = 0xc2;
const OP_SHA256INITIALIZE: u8 = 0xc4;
const OP_SHA256UPDATE: u8 = 0xc5;
const OP_SHA256FINALIZE: u8 = 0xc6;
const OP_INSPECTINPUTASSET: u8 = 0xc8;
const OP_INSPECTINPUTVALUE: u8 = 0xc9;
const OP_PUSHCURRENTINPUTINDEX: u8 = 0xcd;
const OP_INSPECTOUTPUTASSET: u8 = 0xce;
const OP_INSPECTOUTPUTVALUE: u8 = 0xcf;
const OP_INSPECTOUTPUTSCRIPTPUBKEY: u8 = 0xd1;
const OP_GREATERTHAN64: u8 = 0xde;

fn push(s: &mut Vec<u8>, b: &[u8]) {
    debug_assert!(b.len() < 76);
    s.push(b.len() as u8);
    s.extend_from_slice(b);
}

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

/// The state number of commitment `index` of a side: the opener's even, the
/// accepter's odd (`sym_state_num`).
pub fn state_num(index: u64, opener: bool) -> Option<i64> {
    if index >= 1 << 61 {
        return None;
    }
    Some((index * 2 + if opener { 0 } else { 1 }) as i64)
}

/// One output of a settlement: its value in the channel asset, and script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Out {
    pub amount: u64,
    pub spk: Vec<u8>,
}

/// A channel's constants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Channel {
    pub tag: [u8; 32],
    /// The opener's and the accepter's update keys (compressed).
    pub keys: [[u8; 33]; 2],
    /// The channel asset: 0x01 || 32-byte id.
    pub asset: [u8; 33],
    pub delay: u16,
}

impl Channel {
    /// `genesis` and `funding_txid` in the chain's internal byte order.
    pub fn new(
        genesis: &[u8; 32],
        funding_txid: &[u8; 32],
        funding_vout: u32,
        opener_key: &[u8; 33],
        accepter_key: &[u8; 33],
        asset: &[u8; 33],
        delay: u16,
    ) -> Channel {
        let mut e = sha256::Hash::engine();
        e.input(TAG_PREFIX);
        e.input(genesis);
        e.input(funding_txid);
        e.input(&funding_vout.to_le_bytes());
        Channel {
            tag: sha256::Hash::from_engine(e).to_byte_array(),
            keys: [*opener_key, *accepter_key],
            asset: *asset,
            delay,
        }
    }

    /// UPD(k): spends this output into a state n > k signed by both keys,
    /// keeping its value and asset.
    pub fn leaf_upd(&self, k: i64) -> Vec<u8> {
        let mut s = Vec::with_capacity(140);
        s.push(OP_OVER);
        push(&mut s, &(k as u64).to_le_bytes());
        s.extend_from_slice(&[
            OP_GREATERTHAN64, OP_VERIFY,
            OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1, OP_EQUALVERIFY,
            OP_ROT, OP_SWAP, OP_CAT, OP_SWAP, OP_CAT,
        ]);
        push(&mut s, &self.tag);
        s.extend_from_slice(&[OP_SWAP, OP_CAT, OP_SHA256, OP_TUCK]);
        push(&mut s, &self.keys[0][1..]);
        s.push(OP_CHECKSIGFROMSTACKVERIFY);
        push(&mut s, &self.keys[1][1..]);
        s.extend_from_slice(&[
            OP_CHECKSIGFROMSTACKVERIFY,
            OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTVALUE,
            OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE,
            OP_ROT, OP_EQUALVERIFY, OP_EQUALVERIFY,
            OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTASSET,
            OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET,
            OP_ROT, OP_EQUALVERIFY, OP_EQUAL,
        ]);
        s
    }

    /// What SETTLE compares its outputs' streaming hash with: for each
    /// output, its asset id, 0x01, its value (8 bytes LE), 0x01, and the
    /// SHA256 of its witness program and version (v0: none).
    pub fn settle_digest(&self, outs: &[Out]) -> Option<[u8; 32]> {
        let mut e = sha256::Hash::engine();
        for o in outs {
            let (version, prog) = witness_program(&o.spk)?;
            e.input(&self.asset[1..]);
            e.input(&[1]);
            e.input(&o.amount.to_le_bytes());
            e.input(&[1]);
            let mut p = sha256::Hash::engine();
            p.input(prog);
            if version != 0 {
                p.input(&[version]);
            }
            e.input(sha256::Hash::from_engine(p).as_byte_array());
        }
        Some(sha256::Hash::from_engine(e).to_byte_array())
    }

    /// SETTLE: after the shared delay, outputs 0 .. m-1 are exactly `outs`.
    pub fn leaf_settle(&self, outs: &[Out]) -> Option<Vec<u8>> {
        let m = outs.len();
        if m == 0 || m > u32::MAX as usize {
            return None;
        }
        let mut s = Vec::new();
        push_num(&mut s, self.delay as u32);
        s.extend_from_slice(&[OP_CHECKSEQUENCEVERIFY, OP_DROP]);
        for i in 0..m {
            push_num(&mut s, i as u32);
            s.extend_from_slice(&[
                OP_INSPECTOUTPUTASSET,
                OP_CAT,
                if i == 0 { OP_SHA256INITIALIZE } else { OP_SHA256UPDATE },
            ]);
            push_num(&mut s, i as u32);
            s.extend_from_slice(&[OP_INSPECTOUTPUTVALUE, OP_CAT, OP_SHA256UPDATE]);
            push_num(&mut s, i as u32);
            s.extend_from_slice(&[
                OP_INSPECTOUTPUTSCRIPTPUBKEY,
                OP_CAT,
                OP_SHA256,
                if i == m - 1 { OP_SHA256FINALIZE } else { OP_SHA256UPDATE },
            ]);
        }
        push(&mut s, &self.settle_digest(outs)?);
        s.push(OP_EQUAL);
        Some(s)
    }

    /// State `n`'s output: `tr(H, {UPD(n), SETTLE(outs)})`, as (program, R).
    pub fn state(&self, secp: &Secp256k1<All>, n: i64, outs: &[Out]) -> Option<([u8; 32], [u8; 32])> {
        let settle = self.leaf_settle(outs)?;
        let rest = leaf_hash(&settle);
        let tree = Tree2::new(secp, &NUMS, self.leaf_upd(n), settle)?;
        Some((tree.program, rest))
    }

    /// KO, the kickoff's output: `tr(H, UPD(-1))`.
    pub fn kickoff_spk(&self, secp: &Secp256k1<All>) -> Option<Vec<u8>> {
        let root = leaf_hash(&self.leaf_upd(-1));
        let internal = XOnlyPublicKey::from_slice(&NUMS[1..]).ok()?;
        let mut m = [0u8; 64];
        m[..32].copy_from_slice(&NUMS[1..]);
        m[32..].copy_from_slice(&root);
        let tweak = Scalar::from_be_bytes(tagged_hash("TapTweak/elements", &m)).ok()?;
        let (out, _) = internal.add_tweak(secp, &tweak).ok()?;
        Some(taproot::p2tr(&out.serialize()))
    }

    /// The message both update keys sign for state `n` (program P, R).
    pub fn upd_msg(&self, n: i64, program: &[u8; 32], rest: &[u8; 32]) -> [u8; 32] {
        let mut e = sha256::Hash::engine();
        e.input(&self.tag);
        e.input(&(n as u64).to_le_bytes());
        e.input(program);
        e.input(rest);
        sha256::Hash::from_engine(e).to_byte_array()
    }
}

/// A segwit scriptPubKey's version and program.
fn witness_program(spk: &[u8]) -> Option<(u8, &[u8])> {
    let len = spk.len();
    if len < 4 || spk[1] as usize != len - 2 {
        return None;
    }
    let version = match spk[0] {
        OP_0 => 0,
        v @ OP_1..=0x60 => v - OP_1 + 1,
        _ => return None,
    };
    Some((version, &spk[2..]))
}

/// SUCCESS: the preimage of the payment hash and the receiver's signature.
pub fn leaf_htlc_success(payment_ripemd: &[u8; 20], receiver_key: &[u8; 33]) -> Vec<u8> {
    let mut s = vec![OP_SIZE];
    push_num(&mut s, 32);
    s.extend_from_slice(&[OP_EQUALVERIFY, OP_HASH160]);
    push(&mut s, payment_ripemd);
    s.push(OP_EQUALVERIFY);
    push(&mut s, &receiver_key[1..]);
    s.push(OP_CHECKSIG);
    s
}

/// TIMEOUT: the offerer's signature after the expiry.
pub fn leaf_htlc_timeout(offerer_key: &[u8; 33], cltv_expiry: u32) -> Vec<u8> {
    let mut s = Vec::new();
    push(&mut s, &offerer_key[1..]);
    s.push(OP_CHECKSIGVERIFY);
    push_num(&mut s, cltv_expiry);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s
}

/// An HTLC output of a settlement: `tr(H, {SUCCESS, TIMEOUT})`, the keys
/// HTLC basepoints, untweaked (there is no revocation).
pub fn htlc_tree(
    secp: &Secp256k1<All>,
    offerer_key: &[u8; 33],
    receiver_key: &[u8; 33],
    payment_hash: &[u8; 32],
    cltv_expiry: u32,
) -> Option<Tree2> {
    let ripemd = taproot::payment_ripemd(payment_hash);
    Tree2::new(
        secp,
        &NUMS,
        leaf_htlc_success(&ripemd, receiver_key),
        leaf_htlc_timeout(offerer_key, cltv_expiry),
    )
}

/// Whether `leaf` is the SUCCESS leaf whose receiver is `key` or the
/// TIMEOUT leaf whose offerer is `key`, for any payment hash and expiry:
/// the leaf is rebuilt from what it carries, so it must be exactly one.
pub fn leaf_pays_key(leaf: &[u8], key: &[u8; 33]) -> bool {
    if leaf.len() == 61 && leaf[0] == OP_SIZE && leaf[5] == 20 {
        let ripemd: [u8; 20] = leaf[6..26].try_into().unwrap();
        return leaf == leaf_htlc_success(&ripemd, key).as_slice();
    }
    if leaf.len() >= 36 && leaf[0] == 32 && leaf[33] == OP_CHECKSIGVERIFY {
        // The expiry: OP_0, OP_1 .. OP_16, or a push of up to 5 bytes.
        let cltv = match leaf[34] {
            OP_0 => Some(0u64),
            b @ OP_1..=0x60 => Some((b - OP_1 + 1) as u64),
            n @ 1..=5 if leaf.len() == 36 + n as usize => {
                Some(leaf[35..35 + n as usize].iter().rev().fold(0u64, |v, b| (v << 8) | *b as u64))
            }
            _ => None,
        };
        if let Some(cltv) = cltv.and_then(|v| u32::try_from(v).ok()) {
            return leaf == leaf_htlc_timeout(key, cltv).as_slice();
        }
    }
    false
}

/// A BIP340 signature by `key` (compressed) over `msg`.
pub fn verify(secp: &Secp256k1<All>, msg: &[u8; 32], sig: &[u8; 64], key: &[u8; 33]) -> bool {
    let (Ok(x), Ok(s)) = (XOnlyPublicKey::from_slice(&key[1..]), secp256k1::schnorr::Signature::from_slice(sig))
    else {
        return false;
    };
    secp.verify_schnorr(&s, &secp256k1::Message::from_digest(*msg), &x).is_ok()
}

/// An HTLC a state carries, as hsmd's request lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateHtlc {
    /// Whether this side offered it.
    pub ours: bool,
    pub amount_msat: u64,
    pub payment_hash: [u8; 32],
    pub cltv_expiry: u32,
}

/// What a state pays, read off a settlement whose every output this device
/// matched to the channel's scripts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Paid {
    /// This side's balance output (0: none).
    pub ours: u64,
    /// The other side's.
    pub theirs: u64,
    /// The HTLC outputs of HTLCs this side offered, which come back to it if
    /// they fail. An offered HTLC below the dust limit has no output: its
    /// value is in `ours` already.
    pub offered: u64,
}

/// Hold a settlement to the channel: every output is this side's balance
/// (P2WPKH of its payment basepoint), the other side's, or the output of
/// one HTLC of `htlcs` worth its whole atoms, each at most once, and the
/// outputs add up to the funding. An HTLC with no output was trimmed.
#[allow(clippy::too_many_arguments)]
pub fn check_settlement(
    secp: &Secp256k1<All>,
    funding_sats: u64,
    our_payment: &[u8; 33],
    their_payment: &[u8; 33],
    our_htlc: &[u8; 33],
    their_htlc: &[u8; 33],
    htlcs: &[StateHtlc],
    outs: &[Out],
) -> Result<Paid, String> {
    let ours_spk = taproot::p2wpkh(our_payment);
    let theirs_spk = taproot::p2wpkh(their_payment);
    let mut paid = Paid::default();
    let mut seen_ours = false;
    let mut seen_theirs = false;
    let mut used = vec![false; htlcs.len()];
    let mut total: u64 = 0;
    let trees: Vec<Option<Vec<u8>>> = htlcs
        .iter()
        .map(|h| {
            let (offerer, receiver) = if h.ours { (our_htlc, their_htlc) } else { (their_htlc, our_htlc) };
            htlc_tree(secp, offerer, receiver, &h.payment_hash, h.cltv_expiry).map(|t| t.script_pubkey())
        })
        .collect();
    for (i, o) in outs.iter().enumerate() {
        total = total.checked_add(o.amount).ok_or("the settlement overflows")?;
        if o.spk == ours_spk && !seen_ours {
            seen_ours = true;
            paid.ours = o.amount;
            continue;
        }
        if o.spk == theirs_spk && !seen_theirs {
            seen_theirs = true;
            paid.theirs = o.amount;
            continue;
        }
        let m = (0..htlcs.len()).find(|&h| {
            !used[h] && trees[h].as_deref() == Some(&o.spk[..]) && htlcs[h].amount_msat / 1000 == o.amount
        });
        match m {
            Some(h) => {
                used[h] = true;
                if htlcs[h].ours {
                    paid.offered = paid.offered.saturating_add(o.amount);
                }
            }
            None => {
                return Err(format!(
                    "settlement output {i} ({} atoms to {}) is neither side's balance nor an HTLC \
                     the state carries",
                    o.amount,
                    hex(&o.spk)
                ))
            }
        }
    }
    if total != funding_sats {
        return Err(format!("the settlement pays {total} atoms of a {funding_sats}-atom channel"));
    }
    Ok(paid)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    //! Against `common/test/sym_vectors.h`, whose builders were spent on a
    //! Sequentia chain (and whose negative cases were refused in blocks).
    use super::*;
    use secp256k1::{schnorr, Message, PublicKey, SecretKey};

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn a32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }
    fn key(secp: &Secp256k1<All>, byte: u8) -> [u8; 33] {
        PublicKey::from_secret_key(secp, &SecretKey::from_slice(&[byte; 32]).unwrap()).serialize()
    }

    const GENESIS: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const FUND_TXID: &str = "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283";
    const ASSET_ID: &str = "c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7";
    const PAYMENT_HASH: &str = "107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f";

    fn channel(secp: &Secp256k1<All>) -> Channel {
        let mut asset = [1u8; 33];
        asset[1..].copy_from_slice(&a32(ASSET_ID));
        Channel::new(&a32(GENESIS), &a32(FUND_TXID), 1, &key(secp, 0x11), &key(secp, 0x22), &asset, 144)
    }

    fn settlement(secp: &Secp256k1<All>) -> Vec<Out> {
        let htlc = htlc_tree(secp, &key(secp, 0x66), &key(secp, 0x55), &a32(PAYMENT_HASH), 500123).unwrap();
        vec![
            Out { amount: 50000, spk: htlc.script_pubkey() },
            Out { amount: 300000, spk: taproot::p2wpkh(&key(secp, 0x44)) },
            Out { amount: 650000, spk: taproot::p2wpkh(&key(secp, 0x33)) },
        ]
    }

    #[test]
    fn scripts_match_the_vectors() {
        let secp = Secp256k1::new();
        let c = channel(&secp);
        assert_eq!(c.tag, a32("0024c7c2c240711314eabeb83cbd701c1006bb9ae113510065b2402329239ae4"));
        assert_eq!(c.leaf_upd(-1), h("7808ffffffffffffffffde69cdd151887b7c7e7c7e200024c7c2c240711314eabeb83cbd701c1006bb9ae113510065b2402329239ae47c7ea87d204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aac220466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27c2cdcfcdc97b8888cdcecdc87b8887"));
        assert_eq!(c.leaf_upd(7), h("78080700000000000000de69cdd151887b7c7e7c7e200024c7c2c240711314eabeb83cbd701c1006bb9ae113510065b2402329239ae47c7ea87d204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aac220466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27c2cdcfcdc97b8888cdcecdc87b8887"));
        assert_eq!(c.kickoff_spk(&secp).unwrap(), h("5120c2bef8e073924747e8b816098a3719510f453865e332be2f22cd1fb1652c6ef6"));

        let ripemd = taproot::payment_ripemd(&a32(PAYMENT_HASH));
        assert_eq!(leaf_htlc_success(&ripemd, &key(&secp, 0x55)), h("82012088a9145d134d6fcd67e60ff01353700cd6aaa2bf568c7088209ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895bac"));
        assert_eq!(leaf_htlc_timeout(&key(&secp, 0x66), 500123), h("205ab4689e400a4a160cf01cd44730845a54768df8547dcdf073d964f109f18c30ad039ba107b1"));
        let outs = settlement(&secp);
        assert_eq!(outs[0].spk, h("5120b4db5e24c0cb73234d06aa15ba45a5e88db8236f012d5230c73f2b15015b90ad"));
        assert_eq!(outs[1].spk, h("0014cc1b07838e387deacd0e5232e1e8b49f4c29e484"));
        assert_eq!(outs[2].spk, h("00143bc28d6d92d9073fb5e3adf481795eaf446bceed"));

        assert_eq!(c.settle_digest(&outs).unwrap(), a32("1373c90544bf1aaea227d6fe0ba96a23eb0c43d14fbd35bd265826594e69fc77"));
        assert_eq!(c.leaf_settle(&outs).unwrap(), h("029000b27500ce7ec400cf7ec500d17ea8c551ce7ec551cf7ec551d17ea8c552ce7ec552cf7ec552d17ea8c6201373c90544bf1aaea227d6fe0ba96a23eb0c43d14fbd35bd265826594e69fc7787"));
        let (program, rest) = c.state(&secp, 7, &outs).unwrap();
        assert_eq!(taproot::p2tr(&program), h("5120264883291595573d1ea55e0da49ec3b7d8adbe329e336f8f4cbb02c72823bf79"));
        assert_eq!(rest, a32("4eebbcb0fe3fc8e65ef651d59cdb9e470d1bf12ca3b7be44ba784478c1185b33"));
        let msg = c.upd_msg(7, &program, &rest);
        assert_eq!(msg, a32("7689d1a60feb6ef2d0e0ff13e4bcc66982c2dd588175629194091a4349cca86a"));

        // The vectors' signatures verify over the message this device builds.
        let m = Message::from_digest(msg);
        for (k, sig) in [
            (0x11, "c214c5e7f238f2d537d61c243aafb8dd5ca9a2e2cc5c9dc3c429aa70f0701699066fa77f1362c492ed02789bfc9272e6b88b21fbf35d51dfc1d0b3accbbf1a31"),
            (0x22, "ec8477f1305776aca1336b5b366a4224ebb6d3b82a542a8fae412ffa5a43762efd423cfdbb771eb3fcb2bd7740c30fe876e26e57fd61872cf10de1d97b2ced59"),
        ] {
            let x = XOnlyPublicKey::from_slice(&key(&secp, k)[1..]).unwrap();
            let s = schnorr::Signature::from_slice(&h(sig)).unwrap();
            secp.verify_schnorr(&s, &m, &x).unwrap();
        }
    }

    #[test]
    fn settlement_is_held_to_the_channel() {
        let secp = Secp256k1::new();
        // This device is the opener (0x33 pays it), the HTLC is the
        // accepter's.
        let htlcs = [StateHtlc { ours: false, amount_msat: 50_000_000, payment_hash: a32(PAYMENT_HASH), cltv_expiry: 500123 }];
        let (op, ap, oh, ah) = (key(&secp, 0x33), key(&secp, 0x44), key(&secp, 0x55), key(&secp, 0x66));
        let outs = settlement(&secp);
        let paid = check_settlement(&secp, 1_000_000, &op, &ap, &oh, &ah, &htlcs, &outs).unwrap();
        assert_eq!(paid, Paid { ours: 650000, theirs: 300000, offered: 0 });
        // Seen from the accepter, the HTLC is its own.
        let mine = [StateHtlc { ours: true, ..htlcs[0] }];
        let paid = check_settlement(&secp, 1_000_000, &ap, &op, &ah, &oh, &mine, &outs).unwrap();
        assert_eq!(paid, Paid { ours: 300000, theirs: 650000, offered: 50000 });

        // Not the funding's value.
        assert!(check_settlement(&secp, 1_000_001, &op, &ap, &oh, &ah, &htlcs, &outs).is_err());
        // An output to anyone else.
        let mut bad = outs.clone();
        bad[1].spk = taproot::p2wpkh(&key(&secp, 0x77));
        assert!(check_settlement(&secp, 1_000_000, &op, &ap, &oh, &ah, &htlcs, &bad).is_err());
        // The HTLC output for a value the HTLC does not carry.
        let mut bad = outs.clone();
        bad[0].amount -= 1;
        bad[2].amount += 1;
        assert!(check_settlement(&secp, 1_000_000, &op, &ap, &oh, &ah, &htlcs, &bad).is_err());
        // The HTLC's leaves swapped between the sides: not this HTLC.
        let swapped = htlc_tree(&secp, &oh, &ah, &a32(PAYMENT_HASH), 500123).unwrap();
        let mut bad = outs.clone();
        bad[0].spk = swapped.script_pubkey();
        assert!(check_settlement(&secp, 1_000_000, &op, &ap, &oh, &ah, &htlcs, &bad).is_err());
        // Our balance twice.
        let mut bad = outs.clone();
        bad[1].spk = bad[2].spk.clone();
        assert!(check_settlement(&secp, 1_000_000, &op, &ap, &oh, &ah, &htlcs, &bad).is_err());
        // An HTLC with no output (trimmed): its value is the offerer's.
        let trimmed = vec![
            Out { amount: 300000, spk: taproot::p2wpkh(&ap) },
            Out { amount: 700000, spk: taproot::p2wpkh(&op) },
        ];
        let small = [StateHtlc { amount_msat: 500_000, ..mine[0] }];
        let paid = check_settlement(&secp, 1_000_000, &ap, &op, &ah, &oh, &small, &trimmed).unwrap();
        assert_eq!(paid, Paid { ours: 300000, theirs: 700000, offered: 0 });
    }

    #[test]
    fn htlc_leaves_name_their_key() {
        let secp = Secp256k1::new();
        let (mine, theirs) = (key(&secp, 0x55), key(&secp, 0x66));
        let ripemd = taproot::payment_ripemd(&a32(PAYMENT_HASH));
        assert!(leaf_pays_key(&leaf_htlc_success(&ripemd, &mine), &mine));
        assert!(!leaf_pays_key(&leaf_htlc_success(&ripemd, &theirs), &mine));
        for cltv in [0u32, 1, 16, 17, 127, 128, 255, 256, 500123, 0x7fff_ffff, u32::MAX] {
            assert!(leaf_pays_key(&leaf_htlc_timeout(&mine, cltv), &mine), "{cltv}");
            assert!(!leaf_pays_key(&leaf_htlc_timeout(&theirs, cltv), &mine));
        }
        // A timeout leaf whose expiry is not minimally pushed, and other
        // scripts, are not.
        let mut odd = leaf_htlc_timeout(&mine, 500123);
        let at = odd.len() - 1;
        odd[34] += 1;
        odd.insert(at, 0);
        assert!(!leaf_pays_key(&odd, &mine));
        assert!(!leaf_pays_key(&[], &mine));
        assert!(!leaf_pays_key(&channel(&secp).leaf_upd(7), &mine));
    }

    #[test]
    fn state_numbers() {
        assert_eq!(state_num(0, true), Some(0));
        assert_eq!(state_num(0, false), Some(1));
        assert_eq!(state_num(4, false), Some(9));
        assert_eq!(state_num(1 << 61, true), None);
    }
}
