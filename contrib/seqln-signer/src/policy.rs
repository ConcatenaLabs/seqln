//! The M4 validating-signer policy (I/O-free, WASM-ready).
//!
//! Today's signer (M2b) signs any well-formed commitment request — it mirrors
//! libhsmd's `validate_commitment_tx` STUB (`hsmd/libhsmd.c:1898`). That means a
//! malicious HOSTED lightningd could hand the device a commitment transaction
//! whose outputs pay the channel's funds to an ATTACKER script, and the device
//! would sign it. This module makes the device a TRUE validating signer: before
//! it signs a commitment, it reconstructs — from the channel state it tracks and
//! the per-commitment point in the request — every scriptPubKey a legitimate
//! commitment may contain, and REFUSES to sign if any output pays somewhere else
//! or if value is created.
//!
//! Everything here is pure (no sockets/files/process), reusing only the crypto
//! kernel, so it drops into the same `wasm32` device build as `kernel.rs`.
//!
//! ## What is validated (enforce mode)
//!
//! For `WIRE_HSMD_SIGN_REMOTE_COMMITMENT_TX` (the peer's commitment, the pure-LN
//! fundee's theft vector) and `WIRE_HSMD_VALIDATE_COMMITMENT_TX` (our own local
//! commitment — both carry the HTLC set), FULL output validation:
//!
//!  * the single input spends the tracked funding outpoint;
//!  * every non-fee output pays to one of the EXPECTED scripts, each rebuilt from
//!    the channel keys + the request's per-commitment point:
//!      - `to_local`  = P2WSH of the revocable-delayed script (the correct
//!                      revocation + delayed keys, correct `to_self_delay`),
//!      - `to_remote` = P2WPKH of the correct remote payment key (or the anchored
//!                      P2WSH variant),
//!      - each HTLC   = P2WSH of the offered/received HTLC script for a payment
//!                      hash the request lists,
//!      - anchors     = P2WSH of the anchor script for each funding key;
//!  * VALUE CONSERVATION: sum(output values) <= funding amount (the shortfall is
//!    the miner fee; no value may be created).
//!  * every output value is explicit (transparent-by-default channels; a blinded
//!    commitment output is rejected as anomalous).
//!
//! For `WIRE_HSMD_SIGN_COMMITMENT_TX` (our own commitment, msg 5) the request
//! carries NO HTLC data, so HTLC outputs cannot be reconstructed; see
//! [`validate_local_commitment_no_htlcs`] for the strongest correct subset there.
//!
//! The watchtower custody fix (Phase A) EXTENDED enforcement to the on-chain
//! sweep/penalty/HTLC-tx handlers: `sign_*_to_us` + penalties now range-check
//! the committed output against the node's own cached wallet scripts, and the
//! two HTLC-tx signs (`sign_remote_htlc_tx`, `sign_any_local_htlc_tx`) against
//! the reconstructed to_local P2WSH — see `dispatch.rs::check_sweep_outputs`.
//! Still deferred to a VLS-parity follow-up (signed as today, even in enforce):
//! rate-limiting and per-state velocity checks.

use crate::kernel::{ElementsTx, Kernel, Network, TxOutput};
use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};

/// Signing policy. DEFAULT is now `Enforce` (the watchtower custody guard: the
/// device refuses any commitment/sweep whose output is not the channel's own
/// reconstructed script). `Permissive` (= the pre-M4 sign-on-request behaviour)
/// is the explicit opt-out KILL-SWITCH, selected only by
/// `SEQLN_SIGNER_POLICY=permissive` (native) or the wallet passing
/// `enforce=false` (WASM), so a mis-cache can never brick signing.
///
/// The flip is safe for already-open channels: every legitimate sweep an
/// existing channel produces still signs under enforce — proven by the
/// `enforce_signs_every_existing_channel_op` corpus replay (tests/tamper.rs),
/// the reconnect path replays `SETUP_CHANNEL` per channel so the store is warm
/// before any HTLC-tx sign (hsmd/hsmd_proxy.c), and the sweep destination
/// (`bip86_pubkey(final_key_idx)`) sits far below the `SWEEP_KEY_SCAN` custody
/// range on a hosted keyless node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    Permissive,
    Enforce,
}

impl Policy {
    /// Read `SEQLN_SIGNER_POLICY` (`enforce` | `permissive`), defaulting to
    /// `Enforce`. Only the literal `permissive` opts back out (the kill-switch);
    /// anything else — unset, empty, or `enforce` — enforces. Kept out of
    /// `kernel.rs`; this is the one env touch and it is a plain string read, not
    /// device I/O.
    pub fn from_env() -> Policy {
        match std::env::var("SEQLN_SIGNER_POLICY").ok().as_deref() {
            Some("permissive") => Policy::Permissive,
            _ => Policy::Enforce,
        }
    }
    pub fn is_enforce(self) -> bool {
        self == Policy::Enforce
    }
}

/// BOLT commitment side. On the wire (`enum side`) LOCAL = 0, REMOTE = 1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Local = 0,
    Remote = 1,
}

/// One HTLC from a commitment request (`hsm_htlc` subtype).
pub struct Htlc {
    /// `htlc_owner`: LOCAL(0) or REMOTE(1) — decides offered vs received.
    pub side: u8,
    pub amount_msat: u64,
    pub payment_hash: [u8; 32],
    pub cltv_expiry: u32,
}

/// Per-channel state, keyed by (peer node_id, dbid), built from
/// `WIRE_HSMD_SETUP_CHANNEL`. Everything needed to derive the expected
/// commitment outputs; OUR own basepoints are re-derived from the kernel on
/// demand (they are a pure function of the seed + node_id + dbid).
#[derive(Clone)]
pub struct ChannelState {
    pub funding_sats: u64,
    pub funding_txid: [u8; 32],
    pub funding_txout: u16,
    /// `our_config.to_self_delay` — the delay WE impose on THEM (used by the
    /// remote commitment's to_local).
    pub local_to_self_delay: u16,
    /// `their_config.to_self_delay` — the delay THEY impose on US (used by our
    /// local commitment's to_local).
    pub remote_to_self_delay: u16,
    pub remote_revocation: [u8; 33],
    pub remote_payment: [u8; 33],
    pub remote_htlc: [u8; 33],
    pub remote_delayed: [u8; 33],
    pub remote_funding: [u8; 33],
    pub option_static_remotekey: bool,
    pub option_anchors: bool,
}

/// The in-memory store of channel states. A device tracks few channels, so a
/// flat map is ample; lookups are by (node_id, dbid).
#[derive(Default)]
pub struct ChannelStore {
    map: std::collections::HashMap<([u8; 33], u64), ChannelState>,
}

impl ChannelStore {
    pub fn new() -> Self {
        ChannelStore {
            map: std::collections::HashMap::new(),
        }
    }
    pub fn insert(&mut self, node_id: [u8; 33], dbid: u64, st: ChannelState) {
        self.map.insert((node_id, dbid), st);
    }
    pub fn get(&self, node_id: &[u8; 33], dbid: u64) -> Option<&ChannelState> {
        self.map.get(&(*node_id, dbid))
    }
    pub fn contains(&self, node_id: &[u8; 33], dbid: u64) -> bool {
        self.map.contains_key(&(*node_id, dbid))
    }
    /// Remove a channel (FORGET_CHANNEL). Returns whether anything was removed,
    /// so the caller knows to re-persist.
    pub fn remove(&mut self, node_id: &[u8; 33], dbid: u64) -> bool {
        self.map.remove(&(*node_id, dbid)).is_some()
    }
    /// Insert only if absent (blob import: live state from a real setup_channel
    /// this session always outranks a persisted snapshot). Returns whether the
    /// entry was added.
    pub fn insert_if_absent(&mut self, node_id: [u8; 33], dbid: u64, st: ChannelState) -> bool {
        use std::collections::hash_map::Entry;
        match self.map.entry((node_id, dbid)) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(st);
                true
            }
        }
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    /// Entries in key order, so the encoding (and therefore its MAC) is
    /// deterministic for a given store.
    pub fn entries_sorted(&self) -> Vec<(&([u8; 33], u64), &ChannelState)> {
        let mut v: Vec<_> = self.map.iter().collect();
        v.sort_by(|a, b| a.0.cmp(b.0));
        v
    }
}

// ---------------------------------------------------------------------------
// Channel-store persistence encoding.
//
// The store is IN-MEMORY state built from `setup_channel`, which CLN sends
// only at channel CREATION (openingd/dualopend) — never again for the life of
// the channel. A restarted signer that has lost it cannot validate, so enforce
// mode refuses every commitment sign for the channel, `channeld` dies at init,
// and the channel's funds are unspendable (even a close needs a signature).
// The host therefore persists the store across signer restarts: this is the
// canonical byte encoding. It carries NO secrets (funding outpoint + the
// PEER's public basepoints only); integrity comes from the seed-derived MAC
// the dispatcher wraps around it (a foreign or tampered blob fails import).
// ---------------------------------------------------------------------------

pub const CHSTORE_MAGIC: [u8; 4] = *b"SQCH";
pub const CHSTORE_VERSION: u8 = 1;
/// node_id(33) dbid(8) sats(8) txid(32) txout(2) local_delay(2) remote_delay(2)
/// 5 pubkeys(165) static_remotekey(1) anchors(1)
pub const CHSTORE_ENTRY_LEN: usize = 33 + 8 + 8 + 32 + 2 + 2 + 2 + 33 * 5 + 1 + 1;

/// Encode the whole store (deterministically; no MAC — the dispatcher owns
/// keying and appends it).
pub fn encode_channel_store(store: &ChannelStore) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 4 + store.len() * CHSTORE_ENTRY_LEN);
    out.extend_from_slice(&CHSTORE_MAGIC);
    out.push(CHSTORE_VERSION);
    out.extend_from_slice(&(store.len() as u32).to_le_bytes());
    for ((node_id, dbid), st) in store.entries_sorted() {
        out.extend_from_slice(node_id);
        out.extend_from_slice(&dbid.to_le_bytes());
        out.extend_from_slice(&st.funding_sats.to_le_bytes());
        out.extend_from_slice(&st.funding_txid);
        out.extend_from_slice(&st.funding_txout.to_le_bytes());
        out.extend_from_slice(&st.local_to_self_delay.to_le_bytes());
        out.extend_from_slice(&st.remote_to_self_delay.to_le_bytes());
        out.extend_from_slice(&st.remote_revocation);
        out.extend_from_slice(&st.remote_payment);
        out.extend_from_slice(&st.remote_htlc);
        out.extend_from_slice(&st.remote_delayed);
        out.extend_from_slice(&st.remote_funding);
        out.push(st.option_static_remotekey as u8);
        out.push(st.option_anchors as u8);
    }
    out
}

/// Decode a channel-store payload (the MAC must already have been verified
/// and stripped by the caller).
pub fn decode_channel_store(
    bytes: &[u8],
) -> Result<Vec<(([u8; 33], u64), ChannelState)>, String> {
    if bytes.len() < 9 || bytes[..4] != CHSTORE_MAGIC {
        return Err("not a channel-store blob (bad magic)".to_string());
    }
    if bytes[4] != CHSTORE_VERSION {
        return Err(format!("unsupported channel-store version {}", bytes[4]));
    }
    let count = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
    if bytes.len() != 9 + count * CHSTORE_ENTRY_LEN {
        return Err("channel-store blob length does not match its count".to_string());
    }
    let mut out = Vec::with_capacity(count);
    let mut o = 9;
    let arr33 = |b: &[u8]| -> [u8; 33] { b.try_into().unwrap() };
    for _ in 0..count {
        let e = &bytes[o..o + CHSTORE_ENTRY_LEN];
        let node_id = arr33(&e[0..33]);
        let dbid = u64::from_le_bytes(e[33..41].try_into().unwrap());
        let st = ChannelState {
            funding_sats: u64::from_le_bytes(e[41..49].try_into().unwrap()),
            funding_txid: e[49..81].try_into().unwrap(),
            funding_txout: u16::from_le_bytes(e[81..83].try_into().unwrap()),
            local_to_self_delay: u16::from_le_bytes(e[83..85].try_into().unwrap()),
            remote_to_self_delay: u16::from_le_bytes(e[85..87].try_into().unwrap()),
            remote_revocation: arr33(&e[87..120]),
            remote_payment: arr33(&e[120..153]),
            remote_htlc: arr33(&e[153..186]),
            remote_delayed: arr33(&e[186..219]),
            remote_funding: arr33(&e[219..252]),
            option_static_remotekey: e[252] != 0,
            option_anchors: e[253] != 0,
        };
        out.push(((node_id, dbid), st));
        o += CHSTORE_ENTRY_LEN;
    }
    Ok(out)
}

/// Decode a BOLT/BOLT channel_type feature bitfield (BOLT-1 big-endian: the
/// last byte holds bits 0..7) into the two flags the commitment scripts need.
/// `option_static_remotekey` = bit 12/13, `option_anchor_outputs` (deprecated) =
/// 20/21, `option_anchors_zero_fee_htlc_tx` = 22/23. Anchors imply static.
pub fn parse_channel_type(features: &[u8]) -> (bool, bool) {
    let bit = |n: usize| -> bool {
        if features.is_empty() {
            return false;
        }
        let byte_from_end = n / 8;
        if byte_from_end >= features.len() {
            return false;
        }
        let byte = features[features.len() - 1 - byte_from_end];
        (byte >> (n % 8)) & 1 == 1
    };
    let anchors = bit(20) || bit(21) || bit(22) || bit(23);
    let static_remotekey = bit(12) || bit(13) || anchors;
    (static_remotekey, anchors)
}

// ---------------------------------------------------------------------------
// BOLT-3 script builders (pure byte assembly, mirroring `bitcoin/script.c`).
// ---------------------------------------------------------------------------

const OP_0: u8 = 0x00;
const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_SWAP: u8 = 0x7c;
const OP_SIZE: u8 = 0x82;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_IFDUP: u8 = 0x73;
const OP_CLTV: u8 = 0xb1;
const OP_CSV: u8 = 0xb2;

/// `script_push_bytes` (`bitcoin/script.c`): a minimal push of <76 bytes.
fn push_bytes(s: &mut Vec<u8>, b: &[u8]) {
    // Every push here is a key(33) / hash(20) / small number, always < 76.
    debug_assert!(b.len() < 76);
    s.push(b.len() as u8);
    s.extend_from_slice(b);
}

/// `add_number` (`bitcoin/script.c`): OP_0 / OP_1..OP_16 / minimal LE push.
fn add_number(s: &mut Vec<u8>, num: u32) {
    if num == 0 {
        s.push(0x00);
    } else if num <= 16 {
        s.push(0x50 + num as u8);
    } else {
        let n = (num as u64).to_le_bytes();
        let len = if num <= 0x7F {
            1
        } else if num <= 0x7FFF {
            2
        } else if num <= 0x7F_FFFF {
            3
        } else if num <= 0x7FFF_FFFF {
            4
        } else {
            5
        };
        push_bytes(s, &n[..len]);
    }
}

/// P2WSH scriptPubKey: `OP_0 <32-byte SHA256(wscript)>`.
fn p2wsh(wscript: &[u8]) -> Vec<u8> {
    let h = sha256::Hash::hash(wscript);
    let mut s = Vec::with_capacity(34);
    s.push(OP_0);
    push_bytes(&mut s, &h[..]);
    s
}

/// P2WPKH scriptPubKey: `OP_0 <20-byte HASH160(pubkey)>`.
fn p2wpkh(pubkey: &[u8; 33]) -> Vec<u8> {
    let h = hash160::Hash::hash(pubkey);
    let mut s = Vec::with_capacity(22);
    s.push(OP_0);
    push_bytes(&mut s, &h[..]);
    s
}

/// `bitcoin_wscript_to_local`: the revocable, CSV-delayed to-self script.
fn wscript_to_local(to_self_delay: u16, csv: u32, revocation: &[u8; 33], delayed: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::new();
    s.push(OP_IF);
    push_bytes(&mut s, revocation);
    s.push(OP_ELSE);
    add_number(&mut s, core::cmp::max(csv, to_self_delay as u32));
    s.push(OP_CSV);
    s.push(OP_DROP);
    push_bytes(&mut s, delayed);
    s.push(OP_ENDIF);
    s.push(OP_CHECKSIG);
    s
}

/// `bitcoin_wscript_to_remote_anchored`: the anchor-channel to_remote script.
fn wscript_to_remote_anchored(remote_key: &[u8; 33], csv: u32) -> Vec<u8> {
    let mut s = Vec::new();
    push_bytes(&mut s, remote_key);
    s.push(OP_CHECKSIGVERIFY);
    add_number(&mut s, csv);
    s.push(OP_CSV);
    s
}

/// `bitcoin_wscript_anchor`: the 330-sat anchor output witness script.
fn wscript_anchor(funding_key: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::new();
    push_bytes(&mut s, funding_key);
    s.push(OP_CHECKSIG);
    s.push(OP_IFDUP);
    s.push(OP_NOTIF);
    add_number(&mut s, 16);
    s.push(OP_CSV);
    s.push(OP_ENDIF);
    s
}

fn hash160_of(b: &[u8]) -> [u8; 20] {
    hash160::Hash::hash(b).to_byte_array()
}
fn ripemd160_of(b: &[u8]) -> [u8; 20] {
    ripemd160::Hash::hash(b).to_byte_array()
}

/// `bitcoin_wscript_htlc_offer_ripemd160`: the offered-HTLC witness script.
fn wscript_htlc_offer(
    localhtlc: &[u8; 33],
    remotehtlc: &[u8; 33],
    payment_hash: &[u8; 32],
    revocation: &[u8; 33],
    anchors: bool,
) -> Vec<u8> {
    let mut s = Vec::new();
    s.push(OP_DUP);
    s.push(OP_HASH160);
    push_bytes(&mut s, &hash160_of(revocation));
    s.push(OP_EQUAL);
    s.push(OP_IF);
    s.push(OP_CHECKSIG);
    s.push(OP_ELSE);
    push_bytes(&mut s, remotehtlc);
    s.push(OP_SWAP);
    s.push(OP_SIZE);
    add_number(&mut s, 32);
    s.push(OP_EQUAL);
    s.push(OP_NOTIF);
    s.push(OP_DROP);
    add_number(&mut s, 2);
    s.push(OP_SWAP);
    push_bytes(&mut s, localhtlc);
    add_number(&mut s, 2);
    s.push(OP_CHECKMULTISIG);
    s.push(OP_ELSE);
    s.push(OP_HASH160);
    push_bytes(&mut s, &ripemd160_of(payment_hash));
    s.push(OP_EQUALVERIFY);
    s.push(OP_CHECKSIG);
    s.push(OP_ENDIF);
    if anchors {
        add_number(&mut s, 1);
        s.push(OP_CSV);
        s.push(OP_DROP);
    }
    s.push(OP_ENDIF);
    s
}

/// `bitcoin_wscript_htlc_receive_ripemd`: the received-HTLC witness script.
fn wscript_htlc_receive(
    cltv: u32,
    localhtlc: &[u8; 33],
    remotehtlc: &[u8; 33],
    payment_hash: &[u8; 32],
    revocation: &[u8; 33],
    anchors: bool,
) -> Vec<u8> {
    let mut s = Vec::new();
    s.push(OP_DUP);
    s.push(OP_HASH160);
    push_bytes(&mut s, &hash160_of(revocation));
    s.push(OP_EQUAL);
    s.push(OP_IF);
    s.push(OP_CHECKSIG);
    s.push(OP_ELSE);
    push_bytes(&mut s, remotehtlc);
    s.push(OP_SWAP);
    s.push(OP_SIZE);
    add_number(&mut s, 32);
    s.push(OP_EQUAL);
    s.push(OP_IF);
    s.push(OP_HASH160);
    push_bytes(&mut s, &ripemd160_of(payment_hash));
    s.push(OP_EQUALVERIFY);
    add_number(&mut s, 2);
    s.push(OP_SWAP);
    push_bytes(&mut s, localhtlc);
    add_number(&mut s, 2);
    s.push(OP_CHECKMULTISIG);
    s.push(OP_ELSE);
    s.push(OP_DROP);
    add_number(&mut s, cltv);
    s.push(OP_CLTV);
    s.push(OP_DROP);
    s.push(OP_CHECKSIG);
    s.push(OP_ENDIF);
    if anchors {
        add_number(&mut s, 1);
        s.push(OP_CSV);
        s.push(OP_DROP);
    }
    s.push(OP_ENDIF);
    s
}

/// Decode an Elements output's explicit value commitment (`0x01 || u64_be`).
/// Returns None for a blinded/confidential value (never on transparent
/// channels), which the caller treats as anomalous.
fn explicit_value(value: &[u8]) -> Option<u64> {
    if value.len() == 9 && value[0] == 0x01 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&value[1..9]);
        Some(u64::from_be_bytes(b))
    } else {
        None
    }
}

/// Decode an output's explicit satoshi value for either network: Elements uses
/// the 9-byte confidential value above; Bitcoin the plain 8-byte LE satoshi
/// stored verbatim in `o.value`. Keeps the value-conservation check correct for
/// a Bitcoin commitment when the validating policy is enabled (enforce mode);
/// the Elements decode is unchanged.
fn output_value(o: &TxOutput, network: Network) -> Option<u64> {
    match network {
        Network::Elements => explicit_value(&o.value),
        Network::Bitcoin => {
            let b: [u8; 8] = o.value.as_slice().try_into().ok()?;
            Some(u64::from_le_bytes(b))
        }
    }
}

/// The reconstructed commitment keyset (public keys only — a validating signer
/// needs no secrets to know what the outputs MUST look like).
struct Keyset {
    self_revocation_key: [u8; 33],
    self_delayed_key: [u8; 33],
    other_payment_key: [u8; 33],
    self_htlc_key: [u8; 33],
    other_htlc_key: [u8; 33],
    to_self_delay: u16,
    self_funding: [u8; 33],
    other_funding: [u8; 33],
}

/// Rebuild the keyset for the commitment of `side`, exactly as
/// `derive_keyset(point, self=basepoints[side], other=basepoints[!side], ...)`
/// (`common/keyset.c`) followed by `commit_tx`'s use of `config[!side].to_self_delay`.
#[allow(clippy::too_many_arguments)]
fn build_keyset(
    kernel: &Kernel,
    st: &ChannelState,
    our_bp: &[[u8; 33]; 5], // [revocation, payment, htlc, delayed, funding]
    side: Side,
    point: &[u8; 33],
    static_remotekey: bool,
) -> Result<Keyset, String> {
    // our_bp order matches kernel::channel_basepoints: rev, pay, htlc, delayed, funding.
    let (our_rev, our_pay, our_htlc, our_delayed, our_funding) =
        (&our_bp[0], &our_bp[1], &our_bp[2], &our_bp[3], &our_bp[4]);

    // (self_*, other_*) per side; `self` = basepoints[side].
    let (
        self_delayed_bp,
        self_htlc_bp,
        other_revocation_bp,
        other_payment_bp,
        other_htlc_bp,
        to_self_delay,
        self_funding,
        other_funding,
    ) = match side {
        Side::Remote => (
            &st.remote_delayed,
            &st.remote_htlc,
            our_rev,
            our_pay,
            our_htlc,
            st.local_to_self_delay, // config[LOCAL].to_self_delay
            st.remote_funding,
            *our_funding,
        ),
        Side::Local => (
            our_delayed,
            our_htlc,
            &st.remote_revocation,
            &st.remote_payment,
            &st.remote_htlc,
            st.remote_to_self_delay, // config[REMOTE].to_self_delay
            *our_funding,
            st.remote_funding,
        ),
    };

    let d = |bp: &[u8; 33]| -> Result<[u8; 33], String> {
        kernel
            .derive_simple_key_pub(bp, point)
            .map_err(|_| "derive_simple_key failed".to_string())
    };

    let self_revocation_key = kernel
        .derive_revocation_key_pub(other_revocation_bp, point)
        .map_err(|_| "derive_revocation_key failed".to_string())?;
    let self_delayed_key = d(self_delayed_bp)?;
    let other_payment_key = if static_remotekey {
        *other_payment_bp
    } else {
        d(other_payment_bp)?
    };
    let self_htlc_key = d(self_htlc_bp)?;
    let other_htlc_key = d(other_htlc_bp)?;

    Ok(Keyset {
        self_revocation_key,
        self_delayed_key,
        other_payment_key,
        self_htlc_key,
        other_htlc_key,
        to_self_delay,
        self_funding,
        other_funding,
    })
}

/// Build the whitelist of every scriptPubKey this commitment may legitimately
/// contain (a superset — trimmed outputs simply won't appear).
fn expected_scripts(ks: &Keyset, st: &ChannelState, side: Side, htlcs: &[Htlc]) -> Vec<Vec<u8>> {
    let mut set: Vec<Vec<u8>> = Vec::new();

    // to_local (revocable, delayed to `side`).
    set.push(p2wsh(&wscript_to_local(
        ks.to_self_delay,
        0,
        &ks.self_revocation_key,
        &ks.self_delayed_key,
    )));

    // to_remote (pays the OTHER side).
    if st.option_anchors {
        set.push(p2wsh(&wscript_to_remote_anchored(&ks.other_payment_key, 1)));
    } else {
        set.push(p2wpkh(&ks.other_payment_key));
    }

    // Anchors (option_anchors only).
    if st.option_anchors {
        set.push(p2wsh(&wscript_anchor(&ks.self_funding)));
        set.push(p2wsh(&wscript_anchor(&ks.other_funding)));
    }

    // HTLCs: offered when owned by `side`, otherwise received.
    let side_int = side as u8;
    for h in htlcs {
        let ws = if h.side == side_int {
            wscript_htlc_offer(
                &ks.self_htlc_key,
                &ks.other_htlc_key,
                &h.payment_hash,
                &ks.self_revocation_key,
                st.option_anchors,
            )
        } else {
            wscript_htlc_receive(
                h.cltv_expiry,
                &ks.self_htlc_key,
                &ks.other_htlc_key,
                &h.payment_hash,
                &ks.self_revocation_key,
                st.option_anchors,
            )
        };
        set.push(p2wsh(&ws));
    }
    set
}

/// FULL commitment validation (used for the peer's commitment and — since it
/// also carries the HTLC set — our own local commitment). Returns Ok(()) if the
/// tx is a legitimate commitment for the tracked channel, else Err(reason).
#[allow(clippy::too_many_arguments)]
pub fn validate_commitment(
    kernel: &Kernel,
    node_id: &[u8; 33],
    dbid: u64,
    st: &ChannelState,
    side: Side,
    point: &[u8; 33],
    htlcs: &[Htlc],
    tx: &ElementsTx,
) -> Result<(), String> {
    let static_remotekey = st.option_static_remotekey || st.option_anchors;
    let our_bp = kernel.channel_basepoints(node_id, dbid);
    let ks = build_keyset(kernel, st, &our_bp, side, point, static_remotekey)?;
    let whitelist = expected_scripts(&ks, st, side, htlcs);

    // The commitment spends exactly the funding outpoint, once.
    if tx.inputs.len() != 1 {
        return Err(format!(
            "commitment has {} inputs (expected 1 funding input)",
            tx.inputs.len()
        ));
    }
    let inp = &tx.inputs[0];
    if inp.txhash != st.funding_txid || inp.index as u16 != st.funding_txout {
        return Err("commitment input is not the tracked funding outpoint".to_string());
    }

    // Every output pays to an expected script; total value is conserved.
    let mut total: u128 = 0;
    for (i, o) in tx.outputs.iter().enumerate() {
        let v = output_value(o, tx.network)
            .ok_or_else(|| format!("output {i} has a non-explicit (blinded) value"))?;
        total += v as u128;
        if o.script.is_empty() {
            continue; // Elements explicit fee output.
        }
        if !whitelist.iter().any(|s| s.as_slice() == o.script.as_slice()) {
            return Err(format!(
                "output {i} pays to a script not derivable from the channel keys \
                 (value {v}, script {})",
                hexstr(&o.script)
            ));
        }
    }
    if total > st.funding_sats as u128 {
        return Err(format!(
            "value created: outputs sum {total} > funding {}",
            st.funding_sats
        ));
    }
    Ok(())
}

/// Strongest CORRECT subset for `WIRE_HSMD_SIGN_COMMITMENT_TX` (msg 5, OUR own
/// commitment): the request carries no HTLC list, so HTLC output scripts cannot
/// be reconstructed. We therefore enforce only what stays sound without them:
///  * one input, spending the funding outpoint;
///  * value conservation (no value created);
///  * every NON-P2WSH output must be a recognised `to_local`/`to_remote` script
///    (an attacker's P2WPKH/P2TR/OP_RETURN payout is rejected);
///  * P2WSH outputs are ACCEPTED unverified (they may be HTLCs we can't rebuild).
/// This still catches the blatant theft shapes on msg 5 while never falsely
/// rejecting a legitimate HTLC-bearing own-commitment. Msg 5 is not exercised by
/// the pure-LN fundee path (it appears only on a unilateral close), so this gap
/// is not on the hot path; full msg-5 HTLC validation is a follow-up.
pub fn validate_local_commitment_no_htlcs(
    kernel: &Kernel,
    node_id: &[u8; 33],
    dbid: u64,
    st: &ChannelState,
    point: &[u8; 33],
    tx: &ElementsTx,
) -> Result<(), String> {
    let static_remotekey = st.option_static_remotekey || st.option_anchors;
    let our_bp = kernel.channel_basepoints(node_id, dbid);
    let ks = build_keyset(kernel, st, &our_bp, Side::Local, point, static_remotekey)?;
    // Only the HTLC-free scripts (to_local / to_remote / anchors).
    let whitelist = expected_scripts(&ks, st, Side::Local, &[]);

    if tx.inputs.len() != 1 {
        return Err(format!("commitment has {} inputs", tx.inputs.len()));
    }
    let inp = &tx.inputs[0];
    if inp.txhash != st.funding_txid || inp.index as u16 != st.funding_txout {
        return Err("commitment input is not the tracked funding outpoint".to_string());
    }
    let mut total: u128 = 0;
    for (i, o) in tx.outputs.iter().enumerate() {
        let v = output_value(o, tx.network)
            .ok_or_else(|| format!("output {i} has a non-explicit value"))?;
        total += v as u128;
        if o.script.is_empty() {
            continue; // fee
        }
        let is_p2wsh = o.script.len() == 34 && o.script[0] == 0x00 && o.script[1] == 0x20;
        let known = whitelist.iter().any(|s| s.as_slice() == o.script.as_slice());
        if !known && !is_p2wsh {
            return Err(format!(
                "output {i} pays to a non-channel script (value {v}, script {})",
                hexstr(&o.script)
            ));
        }
    }
    if total > st.funding_sats as u128 {
        return Err(format!("value created: outputs {total} > funding {}", st.funding_sats));
    }
    Ok(())
}

/// The anchor output's witnessScript for a funding key (`bitcoin_wscript_anchor`).
/// Exposed for the device signer's `SIGN_ANCHORSPEND` handler, which must build
/// the anchor input's scriptCode + scriptPubKey to locate and sign it.
pub fn anchor_wscript(funding_key: &[u8; 33]) -> Vec<u8> {
    wscript_anchor(funding_key)
}

/// The P2WSH scriptPubKey for a witnessScript (`OP_0 <sha256(wscript)>`). Exposed
/// so the signer can match an anchor input's witness_utxo scriptPubKey.
pub fn p2wsh_spk(wscript: &[u8]) -> Vec<u8> {
    p2wsh(wscript)
}

/// The expected single `to_local` (revocable, CSV-delayed) P2WSH output of a
/// SECOND-STAGE HTLC transaction (htlc-timeout / htlc-success) for the tracked
/// channel `st` on `side` at per-commitment `point`. Unlike a direct wallet
/// sweep, an HTLC tx does NOT pay a wallet address: its lone output is the same
/// revocable-delayed to_local script the commitment uses, rebuilt from the
/// channel keys. Used by the device signer's custody check on the two HTLC-tx
/// handlers (`sign_remote_htlc_tx`, `sign_any_local_htlc_tx`).
pub fn expected_htlc_tx_to_local(
    kernel: &Kernel,
    node_id: &[u8; 33],
    dbid: u64,
    st: &ChannelState,
    side: Side,
    point: &[u8; 33],
) -> Result<Vec<u8>, String> {
    let static_remotekey = st.option_static_remotekey || st.option_anchors;
    let our_bp = kernel.channel_basepoints(node_id, dbid);
    let ks = build_keyset(kernel, st, &our_bp, side, point, static_remotekey)?;
    Ok(p2wsh(&wscript_to_local(
        ks.to_self_delay,
        0,
        &ks.self_revocation_key,
        &ks.self_delayed_key,
    )))
}

fn hexstr(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
