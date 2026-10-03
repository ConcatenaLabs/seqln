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
//! A validated commitment also yields what it pays this side ([`Split`]),
//! which the dispatcher records and [`validate_mutual_close`] holds a close to.
//!
//! For `WIRE_HSMD_SIGN_COMMITMENT_TX` (our own commitment, msg 5: the
//! signature that lets the host broadcast it) the request carries no HTLC
//! data, so its outputs cannot be rebuilt. The device signs instead only a
//! transaction it has already validated in full: one whose txid is among the
//! commitments of ours it validated and has not revoked
//! ([`ChannelState::validated`]). lightningd asks for nothing else: it signs
//! its `last_tx`, which is the commitment channeld last had validated.
//! lightningd also signs a completed mutual close with msg 5; a transaction
//! without a commitment's shape ([`is_commitment_shaped`]) is held to
//! [`validate_mutual_close`] instead, as `WIRE_HSMD_SIGN_MUTUAL_CLOSE_TX` is.
//! A commitment of ours is never signed once its secret has been revealed:
//! its number is read off the transaction ([`commitment_number`]) and compared
//! with the channel's `revoked_through`, which `REVOKE_COMMITMENT_TX` only
//! moves forward (`dispatch.rs`).
//!
//! The watchtower custody fix (Phase A) EXTENDED enforcement to the on-chain
//! sweep/penalty/HTLC-tx handlers: `sign_*_to_us` + penalties now range-check
//! the committed output against the node's own cached wallet scripts, and the
//! two HTLC-tx signs (`sign_remote_htlc_tx`, `sign_any_local_htlc_tx`) against
//! the reconstructed to_local P2WSH — see `dispatch.rs::check_sweep_outputs`.
//! Payment approval and the per-asset payment limits are checked on the same
//! two commitment requests, in `crate::payments`.

use crate::kernel::{ElementsTx, Kernel, Network, TxOutput};
use crate::payments::{AssetKey, Ledger, Offered, PayTrack, SideTrack};
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
#[derive(Clone, Copy, Debug)]
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
    /// Whether WE opened the channel (`setup_channel.is_outbound`): it orders
    /// the two payment basepoints in the commitment-number obscuring factor.
    /// `None` for a channel restored from a version-1 store, which did not
    /// record it.
    pub is_outbound: Option<bool>,
    /// The upfront shutdown scripts `setup_channel` named (empty: none).
    /// Recorded once and never replaced: BOLT 2 forbids changing them, and a
    /// mutual close must pay the peer's share to `remote_shutdown_script` when
    /// one was given.
    pub local_shutdown_script: Vec<u8>,
    pub remote_shutdown_script: Vec<u8>,
    /// The wallet key index `setup_channel` gave for the local upfront
    /// shutdown script (lightningd names one when the script is one of its
    /// wallet's addresses). The script counts as this wallet's in a close
    /// only when it derives from this device's keys at that index.
    pub local_shutdown_wallet_index: Option<u32>,
    /// The highest of OUR commitment numbers whose per-commitment secret this
    /// device has revealed (REVOKE_COMMITMENT_TX). Every commitment numbered
    /// at or below it is revoked: signing one would hand the peer the channel.
    pub revoked_through: Option<u64>,
    /// The highest of OUR commitment numbers this device has validated
    /// (VALIDATE_COMMITMENT_TX): revoking commitment n needs n + 1 validated,
    /// or the node would be left with no commitment it may broadcast.
    pub validated_through: Option<u64>,
    /// What the latest of OUR commitments this device validated pays this
    /// side, with that commitment's number (VALIDATE_COMMITMENT_TX).
    pub local_split: Option<(u64, Split)>,
    /// The same for the latest of the PEER's commitments it signed
    /// (SIGN_REMOTE_COMMITMENT_TX). A mutual close is held to the balance
    /// these two give this side ([`validate_mutual_close`]).
    pub remote_split: Option<(u64, Split)>,
    /// Our commitments this device validated in full and has not revoked:
    /// (commitment number, txid). SIGN_COMMITMENT_TX signs a commitment for
    /// broadcast only when its txid is one of these. A revocation drops every
    /// entry at or below the revoked number; at most [`MAX_VALIDATED`] are
    /// kept (an honest channel holds two at most: the current commitment and
    /// its replacement, between validating one and revoking the other).
    pub validated: Vec<(u64, [u8; 32])>,
    /// What the channel's commitments pay away: its asset, the latest
    /// commitment on each side, and the loss charged so far
    /// (`crate::payments`).
    pub pay: PayTrack,
}

/// How many unrevoked validated commitments a channel record keeps.
pub const MAX_VALIDATED: usize = 8;

/// What one commitment pays this side, in the channel asset's atoms, read off
/// a commitment whose every output the device has matched to the channel's
/// scripts. HTLC outputs belong to neither side yet and are not counted.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Split {
    /// This side's main output: `to_local` on our commitment, `to_remote` on
    /// the peer's. 0 when it was trimmed as dust.
    pub ours: u64,
    /// The commitment's fee: the funding amount less every output that is
    /// not the fee (on Elements, the explicit fee output).
    pub fee: u64,
    /// The anchor outputs (option_anchors), which the opener funds.
    pub anchors: u64,
}

impl Split {
    /// This side's share of the channel by this commitment: its main output,
    /// plus the fee and anchors when this side opened the channel (the opener
    /// pays both out of its share; a close returns the anchors to it and
    /// takes its own fee from it instead). With the opener unknown (a store
    /// from before it was recorded), the fee is not counted as ours.
    pub fn share(&self, is_outbound: Option<bool>) -> u64 {
        match is_outbound {
            Some(true) => self.ours.saturating_add(self.fee).saturating_add(self.anchors),
            _ => self.ours,
        }
    }
}

/// The newer of two (commitment number, split) records.
fn newer(a: Option<(u64, Split)>, b: Option<(u64, Split)>) -> Option<(u64, Split)> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y.0 > x.0 { y } else { x }),
        (x, None) => x,
        (None, y) => y,
    }
}

impl ChannelState {
    /// Fold what an earlier record of the same channel knew into a fresh one
    /// from `setup_channel`, which channeld re-sends at every start and the
    /// proxy replays after every reconnect: the revocation counters only
    /// grow, and a recorded upfront shutdown script is never replaced.
    pub fn merge_from(&mut self, old: &ChannelState) {
        self.revoked_through = max_opt(self.revoked_through, old.revoked_through);
        self.validated_through = max_opt(self.validated_through, old.validated_through);
        self.local_split = newer(self.local_split, old.local_split);
        self.remote_split = newer(self.remote_split, old.remote_split);
        for &(n, txid) in &old.validated {
            self.record_validated(n, txid);
        }
        self.drop_revoked();
        if self.pay == PayTrack::default() {
            self.pay = old.pay.clone();
        }
        if !old.local_shutdown_script.is_empty() {
            self.local_shutdown_script = old.local_shutdown_script.clone();
            self.local_shutdown_wallet_index = old.local_shutdown_wallet_index;
        }
        if !old.remote_shutdown_script.is_empty() {
            self.remote_shutdown_script = old.remote_shutdown_script.clone();
        }
        if self.is_outbound.is_none() {
            self.is_outbound = old.is_outbound;
        }
    }
}

impl ChannelState {
    /// Record a commitment of ours this device validated in full. Returns
    /// whether the record changed. A revoked number is never recorded.
    pub fn record_validated(&mut self, n: u64, txid: [u8; 32]) -> bool {
        if self.revoked_through.is_some_and(|r| n <= r)
            || self.validated.iter().any(|&(_, t)| t == txid)
        {
            return false;
        }
        self.validated.push((n, txid));
        self.validated.sort();
        while self.validated.len() > MAX_VALIDATED {
            self.validated.remove(0);
        }
        true
    }

    /// Forget the validated commitments at or below `revoked_through`: their
    /// secrets are out, and signing one would hand the peer the channel.
    pub fn drop_revoked(&mut self) {
        if let Some(r) = self.revoked_through {
            self.validated.retain(|&(n, _)| n > r);
        }
    }

    /// Whether `txid` is a commitment of ours this device validated and has
    /// not revoked.
    pub fn is_validated(&self, txid: &[u8; 32]) -> bool {
        self.validated.iter().any(|(_, t)| t == txid)
    }
}

fn max_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// The in-memory store of channel states. A device tracks few channels, so a
/// flat map is ample; lookups are by (node_id, dbid). The payment ledger
/// (approvals and charges across every channel) is kept and persisted with it.
#[derive(Default)]
pub struct ChannelStore {
    map: std::collections::HashMap<([u8; 33], u64), ChannelState>,
    pub ledger: Ledger,
}

impl ChannelStore {
    pub fn new() -> Self {
        ChannelStore {
            map: std::collections::HashMap::new(),
            ledger: Ledger::default(),
        }
    }
    /// The assets of every channel whose asset is known.
    pub fn assets(&self) -> Vec<AssetKey> {
        let mut v: Vec<AssetKey> = self.map.values().filter_map(|st| st.pay.asset).collect();
        v.sort();
        v.dedup();
        v
    }
    pub fn insert(&mut self, node_id: [u8; 33], dbid: u64, st: ChannelState) {
        self.map.insert((node_id, dbid), st);
    }
    pub fn get(&self, node_id: &[u8; 33], dbid: u64) -> Option<&ChannelState> {
        self.map.get(&(*node_id, dbid))
    }
    pub fn get_mut(&mut self, node_id: &[u8; 33], dbid: u64) -> Option<&mut ChannelState> {
        self.map.get_mut(&(*node_id, dbid))
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
/// Version 2 adds, after each entry's version-1 fields: the opener flag, both
/// revocation counters and both upfront shutdown scripts. Version 3 adds,
/// after those, the latest local and remote commitment splits. Version 4
/// adds, after those, the unrevoked validated commitments (count(1), then
/// number(8) and txid(32) each). Version 5 adds, after those, the channel's
/// payment tracking ([`PayTrack`]), and after the last entry the payment
/// ledger ([`Ledger`]). Version 6 adds, after the payment tracking, the
/// local shutdown script's wallet index (flag(1), then index(4)). Versions 1
/// to 5 still import (the fields they lack unknown).
pub const CHSTORE_VERSION: u8 = 6;
/// The fixed part of an entry, which is the whole of a version-1 entry:
/// node_id(33) dbid(8) sats(8) txid(32) txout(2) local_delay(2) remote_delay(2)
/// 5 pubkeys(165) static_remotekey(1) anchors(1)
pub const CHSTORE_ENTRY_LEN: usize = 33 + 8 + 8 + 32 + 2 + 2 + 2 + 33 * 5 + 1 + 1;

fn push_opt_bool(out: &mut Vec<u8>, v: Option<bool>) {
    out.push(match v {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    });
}

fn push_opt_u64(out: &mut Vec<u8>, v: Option<u64>) {
    match v {
        None => out.push(0),
        Some(n) => {
            out.push(1);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

fn push_script(out: &mut Vec<u8>, script: &[u8]) {
    out.extend_from_slice(&(script.len() as u16).to_le_bytes());
    out.extend_from_slice(script);
}

/// flag(1) then, when present, commit_num(8) ours(8) fee(8) anchors(8).
fn push_opt_split(out: &mut Vec<u8>, v: Option<(u64, Split)>) {
    match v {
        None => out.push(0),
        Some((n, s)) => {
            out.push(1);
            for x in [n, s.ours, s.fee, s.anchors] {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
    }
}

fn push_side(out: &mut Vec<u8>, side: &Option<SideTrack>) {
    match side {
        None => out.push(0),
        Some(t) => {
            out.push(1);
            for x in [t.n, t.value, t.lost] {
                out.extend_from_slice(&x.to_le_bytes());
            }
            out.extend_from_slice(&(t.offered.len() as u16).to_le_bytes());
            for h in &t.offered {
                out.extend_from_slice(&h.amount_msat.to_le_bytes());
                out.extend_from_slice(&h.hash);
                out.extend_from_slice(&h.cltv.to_le_bytes());
            }
        }
    }
}

/// flag(1) [asset(33)], local side, remote side, charged_lost(8).
fn push_pay(out: &mut Vec<u8>, p: &PayTrack) {
    match &p.asset {
        None => out.push(0),
        Some(a) => {
            out.push(1);
            out.extend_from_slice(&a.encode());
        }
    }
    push_side(out, &p.local);
    push_side(out, &p.remote);
    out.extend_from_slice(&p.charged_lost.to_le_bytes());
}

/// approvals: count(2) then hash(32) at(8); charges: count(2) then
/// asset(33) at(8) msat(8).
fn push_ledger(out: &mut Vec<u8>, l: &Ledger) {
    out.extend_from_slice(&(l.approvals.len() as u16).to_le_bytes());
    for a in &l.approvals {
        out.extend_from_slice(&a.hash);
        out.extend_from_slice(&a.at.to_le_bytes());
    }
    out.extend_from_slice(&(l.spends.len() as u16).to_le_bytes());
    for s in &l.spends {
        out.extend_from_slice(&s.asset.encode());
        out.extend_from_slice(&s.at.to_le_bytes());
        out.extend_from_slice(&s.msat.to_le_bytes());
    }
}

/// Encode the whole store (deterministically; no MAC — the dispatcher owns
/// keying and appends it).
pub fn encode_channel_store(store: &ChannelStore) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 4 + store.len() * (CHSTORE_ENTRY_LEN + 24));
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
        push_opt_bool(&mut out, st.is_outbound);
        push_opt_u64(&mut out, st.revoked_through);
        push_opt_u64(&mut out, st.validated_through);
        push_script(&mut out, &st.local_shutdown_script);
        push_script(&mut out, &st.remote_shutdown_script);
        push_opt_split(&mut out, st.local_split);
        push_opt_split(&mut out, st.remote_split);
        out.push(st.validated.len() as u8);
        for (n, txid) in &st.validated {
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(txid);
        }
        push_pay(&mut out, &st.pay);
        match st.local_shutdown_wallet_index {
            None => out.push(0),
            Some(i) => {
                out.push(1);
                out.extend_from_slice(&i.to_le_bytes());
            }
        }
    }
    push_ledger(&mut out, &store.ledger);
    out
}

/// A cursor over a store payload; every read is bounds-checked.
struct StoreReader<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> StoreReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.o.checked_add(n).filter(|&e| e <= self.b.len())
            .ok_or_else(|| "channel-store blob is truncated".to_string())?;
        let s = &self.b[self.o..end];
        self.o = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn opt_bool(&mut self) -> Result<Option<bool>, String> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(false)),
            2 => Ok(Some(true)),
            v => Err(format!("bad opener flag {v} in channel-store blob")),
        }
    }
    fn opt_u64(&mut self) -> Result<Option<u64>, String> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))),
            v => Err(format!("bad counter flag {v} in channel-store blob")),
        }
    }
    fn script(&mut self) -> Result<Vec<u8>, String> {
        let len = u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize;
        Ok(self.take(len)?.to_vec())
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn side(&mut self) -> Result<Option<SideTrack>, String> {
        match self.u8()? {
            0 => Ok(None),
            1 => {
                let (n, value, lost) = (self.u64()?, self.u64()?, self.u64()?);
                let count = self.u16()? as usize;
                if count > crate::payments::MAX_OFFERED {
                    return Err(format!("{count} offered HTLCs in a channel-store entry"));
                }
                let mut offered = Vec::with_capacity(count);
                for _ in 0..count {
                    let amount_msat = self.u64()?;
                    let hash: [u8; 32] = self.take(32)?.try_into().unwrap();
                    let cltv = u32::from_le_bytes(self.take(4)?.try_into().unwrap());
                    offered.push(Offered { amount_msat, hash, cltv });
                }
                Ok(Some(SideTrack { n, value, offered, lost }))
            }
            v => Err(format!("bad side flag {v} in channel-store blob")),
        }
    }
    fn pay(&mut self) -> Result<PayTrack, String> {
        let asset = match self.u8()? {
            0 => None,
            1 => Some(AssetKey::decode(self.take(33)?)?),
            v => return Err(format!("bad asset flag {v} in channel-store blob")),
        };
        let local = self.side()?;
        let remote = self.side()?;
        let charged_lost = self.u64()?;
        Ok(PayTrack { asset, local, remote, charged_lost })
    }
    fn ledger(&mut self) -> Result<Ledger, String> {
        use crate::payments::{Approval, Spend, MAX_APPROVALS, MAX_SPENDS};
        let mut l = Ledger::default();
        let n = self.u16()? as usize;
        if n > MAX_APPROVALS {
            return Err(format!("{n} approvals in a channel-store blob"));
        }
        for _ in 0..n {
            let hash: [u8; 32] = self.take(32)?.try_into().unwrap();
            l.approvals.push(Approval { hash, at: self.u64()? });
        }
        let n = self.u16()? as usize;
        if n > MAX_SPENDS {
            return Err(format!("{n} charges in a channel-store blob"));
        }
        for _ in 0..n {
            let asset = AssetKey::decode(self.take(33)?)?;
            let at = self.u64()?;
            l.spends.push(Spend { asset, at, msat: self.u64()? });
        }
        Ok(l)
    }
    fn opt_split(&mut self) -> Result<Option<(u64, Split)>, String> {
        match self.u8()? {
            0 => Ok(None),
            1 => {
                let n = self.u64()?;
                let s = Split { ours: self.u64()?, fee: self.u64()?, anchors: self.u64()? };
                Ok(Some((n, s)))
            }
            v => Err(format!("bad split flag {v} in channel-store blob")),
        }
    }
}

/// A decoded channel-store payload: its entries and its payment ledger
/// (empty before version 5).
pub type DecodedStore = (Vec<(([u8; 33], u64), ChannelState)>, Ledger);

/// Decode a channel-store payload (the MAC must already have been verified
/// and stripped by the caller). Takes versions 1 to 6.
pub fn decode_channel_store(bytes: &[u8]) -> Result<DecodedStore, String> {
    if bytes.len() < 9 || bytes[..4] != CHSTORE_MAGIC {
        return Err("not a channel-store blob (bad magic)".to_string());
    }
    let version = bytes[4];
    if !(1..=6).contains(&version) {
        return Err(format!("unsupported channel-store version {version}"));
    }
    let count = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
    if version == 1 && bytes.len() != 9 + count * CHSTORE_ENTRY_LEN {
        return Err("channel-store blob length does not match its count".to_string());
    }
    let mut out = Vec::with_capacity(count.min(1024));
    let mut r = StoreReader { b: bytes, o: 9 };
    let arr33 = |b: &[u8]| -> [u8; 33] { b.try_into().unwrap() };
    for _ in 0..count {
        let e = r.take(CHSTORE_ENTRY_LEN)?;
        let node_id = arr33(&e[0..33]);
        let dbid = u64::from_le_bytes(e[33..41].try_into().unwrap());
        let mut st = ChannelState {
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
            is_outbound: None,
            local_shutdown_script: Vec::new(),
            remote_shutdown_script: Vec::new(),
            local_shutdown_wallet_index: None,
            revoked_through: None,
            validated_through: None,
            local_split: None,
            remote_split: None,
            validated: Vec::new(),
            pay: PayTrack::default(),
        };
        if version >= 2 {
            st.is_outbound = r.opt_bool()?;
            st.revoked_through = r.opt_u64()?;
            st.validated_through = r.opt_u64()?;
            st.local_shutdown_script = r.script()?;
            st.remote_shutdown_script = r.script()?;
        }
        if version >= 3 {
            st.local_split = r.opt_split()?;
            st.remote_split = r.opt_split()?;
        }
        if version >= 4 {
            let n = r.u8()? as usize;
            if n > MAX_VALIDATED {
                return Err(format!("{n} validated commitments in a channel-store entry"));
            }
            for _ in 0..n {
                let num = r.u64()?;
                let txid: [u8; 32] = r.take(32)?.try_into().unwrap();
                st.validated.push((num, txid));
            }
            st.drop_revoked();
        }
        if version >= 5 {
            st.pay = r.pay()?;
        }
        if version >= 6 {
            st.local_shutdown_wallet_index = match r.u8()? {
                0 => None,
                1 => Some(u32::from_le_bytes(r.take(4)?.try_into().unwrap())),
                v => return Err(format!("bad wallet-index flag {v} in channel-store blob")),
            };
        }
        out.push(((node_id, dbid), st));
    }
    let ledger = if version >= 5 { r.ledger()? } else { Ledger::default() };
    if r.o != bytes.len() {
        return Err("channel-store blob has trailing bytes".to_string());
    }
    Ok((out, ledger))
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
/// also carries the HTLC set — our own local commitment). Returns what the
/// commitment pays this side if the tx is a legitimate commitment for the
/// tracked channel, else Err(reason).
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
) -> Result<Split, String> {
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

    // This side's main output: to_local on our commitment, to_remote (the
    // OTHER side's payment script) on the peer's. expected_scripts puts
    // to_local first, to_remote second, then the two anchors.
    let ours_script = match side {
        Side::Local => &whitelist[0],
        Side::Remote => &whitelist[1],
    };
    let anchor_scripts: &[Vec<u8>] = if st.option_anchors { &whitelist[2..4] } else { &[] };

    // Every output pays to an expected script; total value is conserved.
    let mut total: u128 = 0;
    let mut not_fee: u128 = 0;
    let mut split = Split::default();
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
        not_fee += v as u128;
        if o.script == *ours_script {
            split.ours = split.ours.saturating_add(v);
        } else if anchor_scripts.iter().any(|s| *s == o.script) {
            split.anchors = split.anchors.saturating_add(v);
        }
    }
    if total > st.funding_sats as u128 {
        return Err(format!(
            "value created: outputs sum {total} > funding {}",
            st.funding_sats
        ));
    }
    split.fee = (st.funding_sats as u128 - not_fee) as u64;
    Ok(split)
}

/// Whether a transaction spending the funding output has the shape BOLT 3
/// gives a commitment: locktime's upper byte 0x20 and the single input's
/// sequence's upper byte 0x80, the two halves of the obscured commitment
/// number. A mutual close (locktime 0, final sequence) does not.
pub fn is_commitment_shaped(tx: &ElementsTx) -> bool {
    tx.inputs.len() == 1 && tx.locktime >> 24 == 0x20 && tx.inputs[0].sequence >> 24 == 0x80
}

/// The commitment number a commitment-shaped transaction carries (BOLT 3:
/// the lower 48 bits of SHA256(opener payment_basepoint || accepter
/// payment_basepoint), XORed into sequence and locktime). Read off the
/// transaction itself, so a host cannot pass an old commitment under the
/// current number. `None` if the transaction is not commitment-shaped or the
/// channel's opener is not known.
pub fn commitment_number(
    kernel: &Kernel,
    node_id: &[u8; 33],
    dbid: u64,
    st: &ChannelState,
    tx: &ElementsTx,
) -> Option<u64> {
    if !is_commitment_shaped(tx) {
        return None;
    }
    let ours = kernel.channel_basepoints(node_id, dbid)[1];
    let (opener, accepter) = if st.is_outbound? {
        (ours, st.remote_payment)
    } else {
        (st.remote_payment, ours)
    };
    let mut pre = Vec::with_capacity(66);
    pre.extend_from_slice(&opener);
    pre.extend_from_slice(&accepter);
    let h = sha256::Hash::hash(&pre).to_byte_array();
    let mut obscurer = 0u64;
    for b in &h[26..32] {
        obscurer = (obscurer << 8) | *b as u64;
    }
    let obscured = ((tx.inputs[0].sequence as u64 & 0x00ff_ffff) << 24)
        | (tx.locktime as u64 & 0x00ff_ffff);
    Some(obscured ^ obscurer)
}

/// The dust limit Core Lightning gives its own side of every channel
/// (`chainparams->dust_limit`, 546 on every network it knows): an honest close
/// leaves this side's output out only when it is worth less than that.
pub const CLOSE_DUST_TOLERANCE: u64 = 546;

/// The ceiling on a close fee the device lets the opener's balance pay, as a
/// multiple of the latest validated commitment's fee plus anchors. A close is
/// a smaller transaction than a commitment, so at the commitment's own
/// feerate it costs less than the commitment's fee; four times leaves room
/// for a feerate that rose since the last `update_fee`.
pub const CLOSE_FEE_CEILING_FACTOR: u64 = 4;

/// Mutual-close validation (enforce mode), for SIGN_MUTUAL_CLOSE_TX and for
/// a close-shaped transaction under SIGN_COMMITMENT_TX: lightningd signs the
/// closing transaction it rebroadcasts (`drop_to_chain`, cooperative) with the
/// same message it uses for its own commitment.
///
///  * the single input spends the tracked funding outpoint;
///  * every value is explicit and the outputs do not exceed the funding;
///  * besides the fee, at most two outputs: at most one paying this device's
///    wallet (one of its own wallet scripts, `own`, or `own_close`: the local
///    upfront shutdown script, when it derives from this device's keys), our
///    share; and at most one paying the peer: its recorded upfront shutdown
///    script when `setup_channel` named one, else any one script;
///  * the split: see [`check_close_balance`].
///
/// The local upfront shutdown script alone does not make an output ours:
/// `setup_channel` comes from the host, so a script the device cannot derive
/// could be the host's.
pub fn validate_mutual_close(
    st: &ChannelState,
    own: &std::collections::HashSet<Vec<u8>>,
    own_close: Option<&[u8]>,
    tx: &ElementsTx,
) -> Result<(), String> {
    if tx.inputs.len() != 1 {
        return Err(format!("close has {} inputs", tx.inputs.len()));
    }
    let inp = &tx.inputs[0];
    if inp.txhash != st.funding_txid || inp.index as u16 != st.funding_txout {
        return Err("close input is not the tracked funding outpoint".to_string());
    }
    let (mut total, mut ours, mut theirs) = (0u128, 0usize, 0usize);
    let (mut ours_value, mut theirs_value) = (0u64, 0u64);
    for (i, o) in tx.outputs.iter().enumerate() {
        let v = output_value(o, tx.network)
            .ok_or_else(|| format!("output {i} has a non-explicit value"))?;
        total += v as u128;
        if o.script.is_empty() {
            continue; // fee
        }
        if own.contains(&o.script) || own_close == Some(o.script.as_slice()) {
            ours += 1;
            ours_value = v;
        } else if st.remote_shutdown_script.is_empty()
            || o.script == st.remote_shutdown_script
        {
            theirs += 1;
            theirs_value = v;
        } else {
            return Err(format!(
                "output {i} pays neither this wallet nor the peer's recorded \
                 shutdown script (value {v}, script {})",
                hexstr(&o.script)
            ));
        }
    }
    if ours > 1 || theirs > 1 {
        return Err(format!("close has {ours} outputs to us and {theirs} to the peer"));
    }
    if total > st.funding_sats as u128 {
        return Err(format!("value created: outputs {total} > funding {}", st.funding_sats));
    }
    let fee = st.funding_sats - ours_value - theirs_value;
    check_close_balance(st, (ours == 1).then_some(ours_value), theirs_value, fee)
}

/// Hold a close to this side's balance: the larger of the shares
/// ([`Split::share`]) that the latest of our commitments the device validated
/// and the latest of the peer's it signed give us. A close is negotiated only
/// once neither commitment carries an HTLC (BOLT 2), when the two agree, so a
/// stale record cannot lower the figure an honest close is held to.
///
///  * When this side opened the channel it pays the close fee from its share,
///    up to [`CLOSE_FEE_CEILING_FACTOR`] times the commitment's fee and
///    anchors; the fundee pays none of it. With the opener unknown the fee
///    is deducted (the permissive reading).
///  * The output to this wallet must be at least that share less the fee;
///    it may be absent only when what is due is under
///    [`CLOSE_DUST_TOLERANCE`].
///  * The peer's output may not exceed the funding less our share: dust
///    trimmed from us goes to the fee, never to the peer.
///  * With no balance known yet (a store from before balances were
///    recorded, or a channel armed from the node), a close that pays this
///    wallet nothing is refused.
pub fn check_close_balance(
    st: &ChannelState,
    ours_out: Option<u64>,
    theirs_out: u64,
    close_fee: u64,
) -> Result<(), String> {
    let mut known: Option<(u64, u64)> = None; // (share, fee ceiling)
    for (_, sp) in [st.local_split, st.remote_split].into_iter().flatten() {
        let share = sp.share(st.is_outbound);
        let ceiling = CLOSE_FEE_CEILING_FACTOR.saturating_mul(sp.fee.saturating_add(sp.anchors));
        known = Some(match known {
            None => (share, ceiling),
            Some((s, c)) => (s.max(share), c.max(ceiling)),
        });
    }
    let (share, ceiling) = match known {
        Some(k) => k,
        None if ours_out.is_some() => return Ok(()),
        None => {
            return Err("the close pays this wallet nothing and no balance is known \
                        for the channel yet"
                .to_string())
        }
    };
    let fee_share = if st.is_outbound == Some(false) { 0 } else { close_fee.min(ceiling) };
    let due = share.saturating_sub(fee_share);
    match ours_out {
        Some(v) if v < due => {
            return Err(format!(
                "the close pays this wallet {v}, below its balance {share} less \
                 {fee_share} of close fee"
            ))
        }
        None if due > CLOSE_DUST_TOLERANCE => {
            return Err(format!(
                "the close pays this wallet nothing, but its balance is {share} \
                 ({due} after {fee_share} of close fee)"
            ))
        }
        _ => {}
    }
    let theirs_max = st.funding_sats.saturating_sub(share);
    if theirs_out > theirs_max {
        return Err(format!(
            "the close pays the peer {theirs_out}, above its share {theirs_max}"
        ));
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

/// The script of `htlc`'s output on the commitment of `side` at per-commitment
/// `point`, for harnesses that build commitments carrying HTLCs.
pub fn htlc_output_script(
    kernel: &Kernel,
    node_id: &[u8; 33],
    dbid: u64,
    st: &ChannelState,
    side: Side,
    point: &[u8; 33],
    htlc: &Htlc,
) -> Result<Vec<u8>, String> {
    let static_remotekey = st.option_static_remotekey || st.option_anchors;
    let our_bp = kernel.channel_basepoints(node_id, dbid);
    let ks = build_keyset(kernel, st, &our_bp, side, point, static_remotekey)?;
    Ok(expected_scripts(&ks, st, side, std::slice::from_ref(htlc)).pop().expect("one HTLC"))
}

fn hexstr(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
