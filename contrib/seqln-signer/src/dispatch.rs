//! Dispatch of one framed request to a reply, for the pure-derivation subset.
//!
//! This mirrors `signerd_handle` + `hsmd_handle_client_message` for the M2a
//! subset only. Messages outside the subset return the zero-length error
//! sentinel (so non-conformance is obvious). Cases where the reference libhsmd
//! calls `hsmd_status_failed` (fatal) are surfaced as `Outcome::Fatal`, so the
//! binary can exit and close the transport exactly like the oracle does.

use crate::frame::Request;
use crate::hsm_secret::HsmSecret;
use crate::kernel::{self, Kernel};
use crate::policy::{self, ChannelState, ChannelStore, Htlc, Policy, Side};
use crate::wire::{self, msg, BitcoinTx, Writer};
use bitcoin::secp256k1::SecretKey;

/// Our supported hsmd wire version range, matching `signerd_init`.
const OUR_MIN_VERSION: u32 = 4;
const OUR_MAX_VERSION: u32 = 6;

/// `enum sighash_type` (`bitcoin/signature.h`).
const SIGHASH_ALL: u32 = 0x01;
/// `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`, used for anchor-channel HTLC sigs.
const SIGHASH_SINGLE_ACP: u32 = 0x03 | 0x80;
/// Wire size of a `hsm_htlc` subtype: side(u8) + amount(u64) + hash(32) + cltv(u32).
const HSM_HTLC_LEN: usize = 1 + 8 + 32 + 4;

/// How many of the node's OWN wallet key indices [0, N) we derive into the sweep
/// custody set. The signer never learns `final_key_idx` (it is not in the
/// setup_channel wire), so the enforce-mode output-ownership check on sweep/
/// penalty handlers is a bounded range-check over indices [0, N). N is generous
/// so an honest sweep is never falsely refused; the set is derived once (OnceCell)
/// because deriving ~N*3 keys per signature would be prohibitive.
const SWEEP_KEY_SCAN: u32 = 5000;

/// The capabilities array from `hsmd_init()`, in the exact order libhsmd emits
/// it, followed by the two preapprove-check caps (`dev_no_preapprove_check` is
/// false in a normal, non-dev node).
const CAPABILITIES: [u32; 13] = [
    28,  // WIRE_HSMD_CHECK_PUBKEY
    56,  // WIRE_HSMD_CHECK_BIP86_PUBKEY
    142, // WIRE_HSMD_SIGN_ANY_DELAYED_PAYMENT_TO_US
    147, // WIRE_HSMD_SIGN_ANCHORSPEND
    149, // WIRE_HSMD_SIGN_HTLC_TX_MINGLE
    29,  // WIRE_HSMD_SIGN_SPLICE_TX
    32,  // WIRE_HSMD_CHECK_OUTPOINT
    34,  // WIRE_HSMD_FORGET_CHANNEL
    40,  // WIRE_HSMD_REVOKE_COMMITMENT_TX
    41,  // WIRE_HSMD_SIGN_BOLT12_2
    45,  // WIRE_HSMD_BIP137_SIGN_MESSAGE
    51,  // WIRE_HSMD_PREAPPROVE_INVOICE_CHECK
    52,  // WIRE_HSMD_PREAPPROVE_KEYSEND_CHECK
];

pub enum Outcome {
    Reply(Vec<u8>),
    /// Zero-length error sentinel (unimplemented / malformed request).
    Sentinel,
    /// The M4 validating policy REFUSED to sign (enforce mode). On the wire this
    /// is the same zero-length sentinel as `Sentinel`; the reason is logged so a
    /// theft attempt is visible. This is the security payoff of the signer split.
    Reject(String),
    /// The reference libhsmd would `hsmd_status_failed` here; exit and close.
    Fatal(String),
}

pub struct Signer {
    secret: HsmSecret,
    kernel: Option<Kernel>,
    hsm_version: u32,
    /// M4: per-channel state (from setup_channel), for validating signing.
    store: ChannelStore,
    /// M4: enforce | permissive (default ENFORCE = watchtower custody guard;
    /// permissive is the explicit kill-switch, see `Policy::from_env`).
    policy: Policy,
    /// Watchtower custody fix: the cached set of the node's OWN wallet sweep
    /// scriptPubKeys (p2wpkh + p2tr over key indices [0, SWEEP_KEY_SCAN)), used
    /// by the enforce-mode output-ownership check on the sweep/penalty handlers.
    /// Derived lazily on first use (a pure function of the seed).
    own_sweep_scripts: std::cell::OnceCell<std::collections::HashSet<Vec<u8>>>,
    /// The channel store changed (setup/forget/arm) since the host last asked
    /// (`take_channels_dirty`) — the host's cue to re-persist `export_channels`.
    store_dirty: bool,
    /// The (peer node_id, dbid) of the most recent "no tracked channel"
    /// refusal, for the host's one-time re-arm recovery (`take_last_untracked`).
    /// A Cell because the validation paths that detect it take &self.
    last_untracked: std::cell::Cell<Option<([u8; 33], u64)>>,
}

impl Signer {
    /// Construct a signer, reading the policy from `SEQLN_SIGNER_POLICY`
    /// (default ENFORCE; `SEQLN_SIGNER_POLICY=permissive` is the kill-switch).
    pub fn new(secret: HsmSecret) -> Self {
        Self::with_policy(secret, Policy::from_env())
    }

    /// Construct a signer with an explicit policy (used by the tamper test to
    /// force enforce without touching the environment).
    pub fn with_policy(secret: HsmSecret, policy: Policy) -> Self {
        Signer {
            secret,
            kernel: None,
            hsm_version: 0,
            store: ChannelStore::new(),
            policy,
            own_sweep_scripts: std::cell::OnceCell::new(),
            store_dirty: false,
            last_untracked: std::cell::Cell::new(None),
        }
    }

    /// Switch the signing policy at runtime. The browser build has no env, so
    /// the WASM binding calls this to select enforce vs permissive.
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    pub fn handle(&mut self, req: &Request) -> Outcome {
        let t = match wire::peektype(&req.hsmd_msg) {
            Some(t) => t,
            None => return Outcome::Sentinel,
        };

        if t == msg::HSMD_INIT {
            return self.handle_init(&req.hsmd_msg);
        }

        if self.kernel.is_none() {
            // libhsmd: `hsmd was not initialized correctly` -> status_failed.
            return Outcome::Fatal(format!(
                "not initialized, expected INIT ({}), got {}",
                msg::HSMD_INIT,
                t
            ));
        }

        match t {
            msg::HSMD_GET_CHANNEL_BASEPOINTS => self.handle_get_channel_basepoints(&req.hsmd_msg),
            msg::HSMD_GET_PER_COMMITMENT_POINT => {
                self.handle_get_per_commitment_point(req)
            }
            msg::HSMD_ECDH_REQ => self.handle_ecdh(&req.hsmd_msg),
            msg::HSMD_DERIVE_SECRET => self.handle_derive_secret(&req.hsmd_msg),
            msg::HSMD_CHECK_PUBKEY => self.handle_check_pubkey(&req.hsmd_msg),
            msg::HSMD_CHECK_BIP86_PUBKEY => self.handle_check_bip86_pubkey(&req.hsmd_msg),

            // ---- M2b: transaction-signing subset (§4 pure-LN hosted channel) ----
            // M4: commitment signs are the theft vector, so in enforce mode the
            // policy validates every output before signing.
            msg::HSMD_SIGN_COMMITMENT_TX => self.sign_commitment_tx_checked(req),
            msg::HSMD_SIGN_REMOTE_COMMITMENT_TX => self.sign_remote_commitment_tx_checked(req),
            // SIGN_WITHDRAWAL (7): the node signs its OWN wallet inputs of a
            // withdrawal / channel-funding tx (the funder role). Not a theft
            // vector for the fundee split, so no policy gate.
            msg::HSMD_SIGN_WITHDRAWAL => opt(self.h_sign_withdrawal(&req.hsmd_msg)),
            // SIGN_ANCHORSPEND (147): CPFP-bump a commitment by spending its
            // anchor output (funding-key partial sig) plus the node's own wallet
            // fee inputs. Advertised in CAPABILITIES but previously unhandled.
            msg::HSMD_SIGN_ANCHORSPEND => opt(self.h_sign_anchorspend(&req.hsmd_msg)),
            msg::HSMD_SIGN_MUTUAL_CLOSE_TX => opt(self.h_sign_mutual_close_tx(req)),
            msg::HSMD_SIGN_REMOTE_HTLC_TX => opt(self.h_sign_remote_htlc_tx(req)),
            msg::HSMD_SIGN_ANY_LOCAL_HTLC_TX => opt(self.h_sign_any_local_htlc_tx(&req.hsmd_msg)),
            msg::HSMD_SIGN_REMOTE_HTLC_TO_US => opt(self.h_sign_remote_htlc_to_us(req)),
            msg::HSMD_SIGN_ANY_REMOTE_HTLC_TO_US => {
                opt(self.h_sign_any_remote_htlc_to_us(&req.hsmd_msg))
            }
            msg::HSMD_SIGN_DELAYED_PAYMENT_TO_US => opt(self.h_sign_delayed_payment_to_us(req)),
            msg::HSMD_SIGN_ANY_DELAYED_PAYMENT_TO_US => {
                opt(self.h_sign_any_delayed_payment_to_us(&req.hsmd_msg))
            }
            msg::HSMD_SIGN_PENALTY_TO_US => opt(self.h_sign_penalty_to_us(req)),
            msg::HSMD_SIGN_ANY_PENALTY_TO_US => opt(self.h_sign_any_penalty_to_us(&req.hsmd_msg)),
            msg::HSMD_VALIDATE_COMMITMENT_TX => self.validate_commitment_tx_checked(req),
            msg::HSMD_REVOKE_COMMITMENT_TX => opt(self.h_revoke_commitment_tx(req)),
            msg::HSMD_VALIDATE_REVOCATION => {
                Outcome::Reply(empty_reply(msg::HSMD_VALIDATE_REVOCATION_REPLY))
            }
            msg::HSMD_GET_OUTPUT_SCRIPTPUBKEY => {
                opt(self.h_get_output_scriptpubkey(&req.hsmd_msg))
            }
            msg::HSMD_SIGN_INVOICE => opt(self.h_sign_invoice(&req.hsmd_msg)),
            msg::HSMD_PREAPPROVE_INVOICE | msg::HSMD_PREAPPROVE_INVOICE_CHECK => {
                Outcome::Reply(approve_reply(msg::HSMD_PREAPPROVE_INVOICE_REPLY))
            }
            msg::HSMD_PREAPPROVE_KEYSEND | msg::HSMD_PREAPPROVE_KEYSEND_CHECK => {
                Outcome::Reply(approve_reply(msg::HSMD_PREAPPROVE_KEYSEND_REPLY))
            }

            // Gossip signatures. §4 marks these skippable, but a live node still
            // requests them (private-channel channel_update, channel_announce),
            // so a device signer must serve them to keep the node running.
            msg::HSMD_CANNOUNCEMENT_SIG_REQ => opt(self.h_cannouncement_sig(req)),
            msg::HSMD_SIGN_ANY_CANNOUNCEMENT_REQ => opt(self.h_any_cannouncement_sig(&req.hsmd_msg)),
            msg::HSMD_NODE_ANNOUNCEMENT_SIG_REQ => opt(self.h_node_announcement_sig(&req.hsmd_msg)),
            msg::HSMD_CUPDATE_SIG_REQ => opt(self.h_cupdate_sig(&req.hsmd_msg)),

            // Trivial bookkeeping stubs: constant replies (see the `handle_*`
            // stubs in libhsmd.c). We deliberately do not deep-parse; a
            // well-formed request yields the identical constant reply.
            msg::HSMD_NEW_CHANNEL => Outcome::Reply(empty_reply(msg::HSMD_NEW_CHANNEL_REPLY)),
            msg::HSMD_SETUP_CHANNEL => {
                // M4: record the channel's parameters for later validation, then
                // return the identical constant reply (bytes unchanged).
                self.record_setup_channel(req);
                Outcome::Reply(empty_reply(msg::HSMD_SETUP_CHANNEL_REPLY))
            }
            msg::HSMD_FORGET_CHANNEL => {
                // Drop the channel from the store (and so from the next
                // persisted blob) — a forgotten channel must not linger.
                self.forget_channel(req);
                Outcome::Reply(empty_reply(msg::HSMD_FORGET_CHANNEL_REPLY))
            }
            msg::HSMD_LOCK_OUTPOINT => Outcome::Reply(empty_reply(msg::HSMD_LOCK_OUTPOINT_REPLY)),
            msg::HSMD_CHECK_OUTPOINT => {
                // handle_check_outpoint always approves: is_buried = true.
                let mut w = Writer::new(msg::HSMD_CHECK_OUTPOINT_REPLY);
                w.bool(true);
                Outcome::Reply(w.into_vec())
            }

            // Everything else is out of the M2a subset.
            _ => Outcome::Sentinel,
        }
    }

    fn kernel(&self) -> &Kernel {
        self.kernel.as_ref().expect("initialized")
    }

    fn handle_init(&mut self, m: &[u8]) -> Outcome {
        let f = match wire::parse_init(m) {
            Some(f) => f,
            None => return Outcome::Sentinel,
        };
        if OUR_MIN_VERSION > f.max_version || OUR_MAX_VERSION < f.min_version {
            return Outcome::Fatal(format!(
                "version {}-{} not valid: we need {}-{}",
                f.min_version, f.max_version, OUR_MIN_VERSION, OUR_MAX_VERSION
            ));
        }
        let hsm_version = OUR_MAX_VERSION.min(f.max_version);
        let kernel = Kernel::new(
            self.secret.seed.to_vec(),
            f.bip32_pubkey_version,
            f.bip32_privkey_version,
        );

        let mut w = Writer::new(msg::HSMD_INIT_REPLY_V4);
        w.u32(hsm_version);
        w.u16(CAPABILITIES.len() as u16);
        for c in CAPABILITIES {
            w.u32(c);
        }
        w.bytes(&kernel.node_id());
        w.bytes(&kernel.bip32_ext_key_public());
        w.bytes(&kernel.bolt12_pubkey());
        // TLV stream (ascending type order): hsm_secret_type(1), bip86_base(2).
        w.tlv_record(1, &[self.secret.secret_type]);
        w.tlv_record(2, &kernel.bip86_base_ext_key_public());

        self.kernel = Some(kernel);
        self.hsm_version = hsm_version;
        Outcome::Reply(w.into_vec())
    }

    fn handle_get_channel_basepoints(&self, m: &[u8]) -> Outcome {
        let (peer_id, dbid) = match wire::parse_get_channel_basepoints(m) {
            Some(v) => v,
            None => return Outcome::Sentinel,
        };
        let bp = self.kernel().channel_basepoints(&peer_id, dbid);
        let mut w = Writer::new(msg::HSMD_GET_CHANNEL_BASEPOINTS_REPLY);
        // towire_basepoints: revocation, payment, htlc, delayed_payment.
        for p in &bp[..4] {
            w.bytes(p);
        }
        // then funding_pubkey.
        w.bytes(&bp[4]);
        Outcome::Reply(w.into_vec())
    }

    fn handle_get_per_commitment_point(&self, req: &Request) -> Outcome {
        let n = match wire::parse_get_per_commitment_point(&req.hsmd_msg) {
            Some(n) => n,
            None => return Outcome::Sentinel,
        };
        // Uses the frame's client context (c->id, c->dbid), not the message.
        let (point, old) =
            self.kernel()
                .per_commitment_point(&req.node_id, req.dbid, n, self.hsm_version);
        let mut w = Writer::new(msg::HSMD_GET_PER_COMMITMENT_POINT_REPLY);
        w.bytes(&point);
        match old {
            Some(secret) => {
                w.bool(true);
                w.bytes(&secret);
            }
            None => w.bool(false),
        }
        Outcome::Reply(w.into_vec())
    }

    fn handle_ecdh(&self, m: &[u8]) -> Outcome {
        let point = match wire::parse_ecdh_req(m) {
            Some(p) => p,
            None => return Outcome::Sentinel,
        };
        match self.kernel().ecdh(&point) {
            Ok(ss) => {
                let mut w = Writer::new(msg::HSMD_ECDH_RESP);
                w.bytes(&ss);
                Outcome::Reply(w.into_vec())
            }
            Err(()) => Outcome::Sentinel,
        }
    }

    fn handle_derive_secret(&self, m: &[u8]) -> Outcome {
        let info = match wire::parse_derive_secret(m) {
            Some(i) => i,
            None => return Outcome::Sentinel,
        };
        let secret = self.kernel().derive_secret(&info);
        let mut w = Writer::new(msg::HSMD_DERIVE_SECRET_REPLY);
        w.bytes(&secret);
        Outcome::Reply(w.into_vec())
    }

    fn handle_check_pubkey(&self, m: &[u8]) -> Outcome {
        let (index, their) = match wire::parse_check_pubkey(m, msg::HSMD_CHECK_PUBKEY) {
            Some(v) => v,
            None => return Outcome::Sentinel,
        };
        if index >= 0x8000_0000 {
            return Outcome::Fatal(format!("Index {index} too great"));
        }
        let ours = self.kernel().bip32_child_pubkey(index);
        if ours != their {
            return Outcome::Fatal(format!("BIP32 derivation index {index} differed"));
        }
        let mut w = Writer::new(msg::HSMD_CHECK_PUBKEY_REPLY);
        w.bool(true);
        Outcome::Reply(w.into_vec())
    }

    fn handle_check_bip86_pubkey(&self, m: &[u8]) -> Outcome {
        let (index, their) = match wire::parse_check_pubkey(m, msg::HSMD_CHECK_BIP86_PUBKEY) {
            Some(v) => v,
            None => return Outcome::Sentinel,
        };
        if index >= 0x8000_0000 {
            return Outcome::Fatal(format!("Index {index} too great"));
        }
        let ours = self.kernel().bip86_child_pubkey(index);
        if ours != their {
            return Outcome::Fatal(format!("BIP86 derivation index {index} differed"));
        }
        let mut w = Writer::new(msg::HSMD_CHECK_BIP86_PUBKEY_REPLY);
        w.bool(true);
        Outcome::Reply(w.into_vec())
    }

    // =================================================================
    // M4 validating policy: record channel state, and check commitment
    // signs against it before signing (enforce mode only).
    // =================================================================

    /// Record a channel's parameters from `setup_channel` (keyed by the frame's
    /// peer node_id + dbid), so later commitment signs can be validated.
    fn record_setup_channel(&mut self, req: &Request) {
        // Best-effort: a parse failure leaves the channel untracked, and in
        // enforce mode its commitment signs are then refused (the safe default).
        if let Some(st) = parse_setup_channel(&req.hsmd_msg) {
            self.store.insert(req.node_id, req.dbid, st);
            self.store_dirty = true;
        }
    }

    /// Drop a channel on FORGET_CHANNEL. The peer id + dbid are in the MESSAGE
    /// (this arrives on lightningd's main fd, not a per-channel client fd).
    fn forget_channel(&mut self, req: &Request) {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        let _ = r.u16();
        if let (Some(node_id), Some(dbid)) = (r.arr33(), r.u64()) {
            if self.store.remove(&node_id, dbid) {
                self.store_dirty = true;
            }
        }
    }

    /// Record + return the standard refusal for a channel the store does not
    /// know, so the host can drive a one-time re-arm (`take_last_untracked`).
    fn untracked(&self, peer_id: &[u8; 33], dbid: u64) -> String {
        self.last_untracked.set(Some((*peer_id, dbid)));
        "no tracked channel (setup_channel not seen)".to_string()
    }

    // =================================================================
    // Channel-store persistence + recovery (the host's restart contract).
    //
    // `setup_channel` is sent ONCE, at channel creation; a signer restart
    // therefore orphans every live channel — enforce mode refuses all its
    // commitment signs, channeld dies at init, and the funds are frozen
    // (closing needs a signature too). The host persists the store across
    // restarts: export after any frame that dirtied it, import on boot.
    // The blob is authenticated by an HMAC keyed from the SEED (domain-
    // separated, no key material inside), so a tampered or foreign blob
    // fails import instead of poisoning validation.
    // =================================================================

    fn chstore_mac_key(&self) -> Vec<u8> {
        kernel::hkdf_sha256(
            32,
            b"seqln-signer chstore mac v1",
            &self.secret.seed,
            b"",
        )
    }

    fn chstore_mac(&self, payload: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&self.chstore_mac_key())
            .expect("hmac accepts any key length");
        mac.update(payload);
        mac.finalize().into_bytes().into()
    }

    /// The persistable channel store: canonical payload + seed-keyed MAC.
    /// Contains no secrets (funding outpoints + PEER public basepoints only).
    pub fn export_channels(&self) -> Vec<u8> {
        let mut out = policy::encode_channel_store(&self.store);
        let mac = self.chstore_mac(&out);
        out.extend_from_slice(&mac);
        out
    }

    /// Restore a persisted channel store. Entries already tracked live (a real
    /// setup_channel this session) are NOT overwritten. Returns how many
    /// entries were added; a bad MAC or malformed blob is refused whole.
    pub fn import_channels(&mut self, bytes: &[u8]) -> Result<u32, String> {
        if bytes.len() < 32 {
            return Err("channel-store blob too short".to_string());
        }
        let (payload, mac) = bytes.split_at(bytes.len() - 32);
        // Constant-time-ness is irrelevant here (the key holder verifies its
        // own blob), but use the Mac verify anyway.
        {
            use hmac::{Hmac, Mac};
            let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&self.chstore_mac_key())
                .expect("hmac accepts any key length");
            m.update(payload);
            m.verify_slice(mac)
                .map_err(|_| "channel-store MAC mismatch (foreign or tampered blob)".to_string())?;
        }
        let entries = policy::decode_channel_store(payload)?;
        let mut added = 0u32;
        for ((node_id, dbid), st) in entries {
            if self.store.insert_if_absent(node_id, dbid, st) {
                added += 1;
            }
        }
        if added > 0 {
            self.store_dirty = true;
        }
        Ok(added)
    }

    /// One-time recovery: track a channel from parameters the host read off
    /// the NODE (listpeerchannels) after the persisted blob was lost. Trust-
    /// equivalent to `setup_channel` itself (which also comes via the node);
    /// refuses to overwrite a channel that is already tracked, so a live
    /// baseline can never be replaced through this path. `funding_txid` is in
    /// INTERNAL byte order (the caller reverses a display-order txid).
    #[allow(clippy::too_many_arguments)]
    pub fn arm_channel(
        &mut self,
        node_id: [u8; 33],
        dbid: u64,
        st: ChannelState,
    ) -> Result<bool, String> {
        if self.store.contains(&node_id, dbid) {
            return Ok(false);
        }
        self.store.insert(node_id, dbid, st);
        self.store_dirty = true;
        Ok(true)
    }

    /// Is this (peer, dbid) tracked? (Host-side reconcile/diagnostics.)
    pub fn has_channel(&self, node_id: &[u8; 33], dbid: u64) -> bool {
        self.store.contains(node_id, dbid)
    }

    /// The store changed since last asked (take-and-clear).
    pub fn take_channels_dirty(&mut self) -> bool {
        std::mem::take(&mut self.store_dirty)
    }

    /// The most recent "no tracked channel" refusal (take-and-clear), as the
    /// host's cue to fetch that channel's parameters and `arm_channel`.
    pub fn take_last_untracked(&mut self) -> Option<([u8; 33], u64)> {
        self.last_untracked.take()
    }

    /// SIGN_COMMITMENT_TX (5): OUR own commitment. Validate (no-HTLC subset)
    /// then sign. Reply bytes are unchanged from M2b on accept.
    fn sign_commitment_tx_checked(&mut self, req: &Request) -> Outcome {
        if self.policy.is_enforce() {
            if let Err(reason) = self.check_own_commitment(&req.hsmd_msg) {
                return Outcome::Reject(format!("SIGN_COMMITMENT_TX refused: {reason}"));
            }
        }
        opt(self.h_sign_commitment_tx(&req.hsmd_msg))
    }

    /// SIGN_REMOTE_COMMITMENT_TX (19): the PEER's commitment (the pure-LN
    /// fundee's theft vector). Full validation, then sign.
    fn sign_remote_commitment_tx_checked(&mut self, req: &Request) -> Outcome {
        if self.policy.is_enforce() {
            if let Err(reason) = self.check_remote_commitment(req) {
                return Outcome::Reject(format!("SIGN_REMOTE_COMMITMENT_TX refused: {reason}"));
            }
        }
        opt(self.h_sign_remote_commitment_tx(req))
    }

    /// VALIDATE_COMMITMENT_TX (35): OUR own local commitment (carries the HTLC
    /// set). Full validation, then return the usual next-per-commitment reply.
    fn validate_commitment_tx_checked(&mut self, req: &Request) -> Outcome {
        if self.policy.is_enforce() {
            if let Err(reason) = self.check_local_commitment(req) {
                return Outcome::Reject(format!("VALIDATE_COMMITMENT_TX refused: {reason}"));
            }
        }
        opt(self.h_validate_commitment_tx(req))
    }

    /// Full validation of a peer commitment (`side = REMOTE`).
    fn check_remote_commitment(&self, req: &Request) -> Result<(), String> {
        let st = self
            .store
            .get(&req.node_id, req.dbid)
            .ok_or_else(|| self.untracked(&req.node_id, req.dbid))?;
        let (bt, remote_funding, remote_per_commit, htlcs) =
            parse_remote_commitment(&req.hsmd_msg)
                .ok_or_else(|| "malformed request".to_string())?;
        if remote_funding != st.remote_funding {
            return Err("remote_funding_key differs from setup_channel".to_string());
        }
        policy::validate_commitment(
            self.kernel(),
            &req.node_id,
            req.dbid,
            st,
            Side::Remote,
            &remote_per_commit,
            &htlcs,
            &bt.tx,
        )
    }

    /// Full validation of our local commitment (`side = LOCAL`); the point is
    /// OUR per-commitment point at `commit_num`, derived from our shaseed.
    fn check_local_commitment(&self, req: &Request) -> Result<(), String> {
        let st = self
            .store
            .get(&req.node_id, req.dbid)
            .ok_or_else(|| self.untracked(&req.node_id, req.dbid))?;
        let (bt, htlcs, commit_num) =
            parse_local_commitment(&req.hsmd_msg).ok_or_else(|| "malformed request".to_string())?;
        let s = self.kernel().channel_secrets(&req.node_id, req.dbid);
        let point = self.kernel().per_commit_point_at(&s.shaseed, commit_num);
        policy::validate_commitment(
            self.kernel(),
            &req.node_id,
            req.dbid,
            st,
            Side::Local,
            &point,
            &htlcs,
            &bt.tx,
        )
    }

    /// No-HTLC-subset validation of our own commitment (msg 5, which carries no
    /// HTLC list); peer_id + dbid come from the MESSAGE.
    fn check_own_commitment(&self, m: &[u8]) -> Result<(), String> {
        let (peer_id, dbid, bt, commit_num) =
            parse_own_commitment(m).ok_or_else(|| "malformed request".to_string())?;
        let st = self
            .store
            .get(&peer_id, dbid)
            .ok_or_else(|| self.untracked(&peer_id, dbid))?;
        let s = self.kernel().channel_secrets(&peer_id, dbid);
        let point = self.kernel().per_commit_point_at(&s.shaseed, commit_num);
        policy::validate_local_commitment_no_htlcs(self.kernel(), &peer_id, dbid, st, &point, &bt.tx)
    }

    // =================================================================
    // M2b transaction-signing handlers. Each returns Some(reply_bytes) or
    // None (-> zero-length sentinel, matching a malformed/unsupported input;
    // real captured requests are always well-formed and produce a reply).
    // =================================================================

    // =================================================================
    // Watchtower custody fix (enforce mode): every sweep/penalty/HTLC sign
    // must pay only the node's OWN outputs, so a compromised host cannot get
    // a self-paying sweep signed. Model on check_own/remote/local_commitment.
    // =================================================================

    /// The cached set of the node's OWN wallet sweep scriptPubKeys: for each key
    /// index in [0, SWEEP_KEY_SCAN) the p2wpkh(bip86 pubkey) [Elements sweep
    /// dest], the bip86 p2tr output [Bitcoin sweep dest], and — defensively —
    /// p2wpkh(legacy m/0/0/idx pubkey). Derived once, then reused.
    fn own_sweep_script_set(&self) -> &std::collections::HashSet<Vec<u8>> {
        self.own_sweep_scripts.get_or_init(|| {
            let k = self.kernel();
            let mut s =
                std::collections::HashSet::with_capacity(SWEEP_KEY_SCAN as usize * 3);
            for i in 0..SWEEP_KEY_SCAN {
                s.insert(k.p2wpkh_scriptpubkey(&k.bip86_child_pubkey(i)));
                s.insert(k.bip86_p2tr_scriptpubkey(i));
                s.insert(k.p2wpkh_scriptpubkey(&k.bip32_child_pubkey(i)));
            }
            s
        })
    }

    /// The node's OWN wallet sweep scriptPubKey for `index` (p2tr when `taproot`,
    /// else p2wpkh of the bip86 key). Used by the WASM binding to let a browser
    /// harness synthesize a legit/tampered sweep for the enforce proof.
    pub fn wallet_sweep_script(&self, index: u32, taproot: bool) -> Vec<u8> {
        if taproot {
            self.kernel().bip86_p2tr_scriptpubkey(index)
        } else {
            self.kernel()
                .p2wpkh_scriptpubkey(&self.kernel().bip86_child_pubkey(index))
        }
    }

    /// Enforce-mode custody check for a sweep/penalty/HTLC transaction: every
    /// output that this signature commits to must pay a script in `allowed`.
    /// Sighash-aware — under SIGHASH_SINGLE only the output at `sign_index` is
    /// committed (the tower appends its own fee inputs/outputs elsewhere); under
    /// SIGHASH_ALL every non-fee output is committed. The Elements explicit fee
    /// output (empty scriptPubKey) is skipped, exactly as `policy.rs` does.
    fn check_sweep_outputs(
        &self,
        bt: &BitcoinTx,
        sign_index: usize,
        sighash: u32,
        allowed: &std::collections::HashSet<Vec<u8>>,
    ) -> Result<(), String> {
        let base = sighash & 0x1f; // WALLY_SIGHASH_MASK
        let outs = &bt.tx.outputs;
        if base == 0x03 {
            // SIGHASH_SINGLE: only outputs[sign_index] is committed.
            let o = outs
                .get(sign_index)
                .ok_or_else(|| format!("no output at sign index {sign_index}"))?;
            if o.script.is_empty() {
                return Err("committed output is an (empty-script) fee output".to_string());
            }
            if !allowed.contains(&o.script) {
                return Err(format!(
                    "sweep output {sign_index} pays a non-owned script {}",
                    hexbytes(&o.script)
                ));
            }
        } else {
            // SIGHASH_ALL: every non-fee output is committed and must be ours.
            for (i, o) in outs.iter().enumerate() {
                if o.script.is_empty() {
                    continue; // Elements explicit fee output.
                }
                if !allowed.contains(&o.script) {
                    return Err(format!(
                        "sweep output {i} pays a non-owned script {}",
                        hexbytes(&o.script)
                    ));
                }
            }
        }
        Ok(())
    }

    /// The enforce gate for a DIRECT-TO-WALLET sweep (Class A: delayed/penalty/
    /// htlc-to-us). Returns Err if enforce is on and a committed output is not the
    /// node's own. `label` names the handler for the log line.
    fn enforce_wallet_sweep(
        &self,
        label: &str,
        bt: &BitcoinTx,
        sign_index: usize,
        sighash: u32,
    ) -> Result<(), ()> {
        if !self.policy.is_enforce() {
            return Ok(());
        }
        match self.check_sweep_outputs(bt, sign_index, sighash, self.own_sweep_script_set()) {
            Ok(()) => Ok(()),
            Err(reason) => {
                eprintln!("{label} refused (enforce): {reason}");
                Err(())
            }
        }
    }

    /// The enforce gate for a SECOND-STAGE HTLC transaction (Class B:
    /// sign_remote_htlc_tx / sign_any_local_htlc_tx). Its lone output is the
    /// revocable-delayed to_local P2WSH rebuilt from the tracked channel, NOT a
    /// wallet address, so the wallet range does not apply. Rejects if the channel
    /// is untracked or the committed output is not that script.
    fn enforce_htlc_tx_output(
        &self,
        label: &str,
        node_id: &[u8; 33],
        dbid: u64,
        side: crate::policy::Side,
        point: &[u8; 33],
        bt: &BitcoinTx,
        sign_index: usize,
        sighash: u32,
    ) -> Result<(), ()> {
        if !self.policy.is_enforce() {
            return Ok(());
        }
        let expected = match self.store.get(node_id, dbid) {
            Some(st) => {
                crate::policy::expected_htlc_tx_to_local(self.kernel(), node_id, dbid, st, side, point)
            }
            None => Err(self.untracked(node_id, dbid)),
        };
        let spk = match expected {
            Ok(spk) => spk,
            Err(reason) => {
                eprintln!("{label} refused (enforce): {reason}");
                return Err(());
            }
        };
        let mut set = std::collections::HashSet::with_capacity(1);
        set.insert(spk);
        match self.check_sweep_outputs(bt, sign_index, sighash, &set) {
            Ok(()) => Ok(()),
            Err(reason) => {
                eprintln!("{label} refused (enforce): {reason}");
                Err(())
            }
        }
    }

    /// The shared final step: the BIP-143 segwit-v0 sighash over `scriptcode`
    /// with the input `sign_index` amount (from the PSBT witness_utxo), low-R
    /// sign, and frame the `bitcoin_signature` reply (compact 64 || sighash byte).
    ///
    /// The sighash preimage format is chosen from the tx's network (mirroring the
    /// C `is_elements(chainparams)` branch in `bitcoin_tx_hash_for_sig`): Elements
    /// uses the 9-byte confidential value + `elements_sighash_sw_v0`; Bitcoin uses
    /// the plain 8-byte LE value + `bitcoin_sighash_sw_v0`. The ECDSA low-R
    /// signing below is byte-identical either way — only the hashed bytes differ.
    fn sig_reply(
        &self,
        bt: &BitcoinTx,
        sign_index: usize,
        scriptcode: &[u8],
        privkey: &SecretKey,
        sighash: u32,
        reply_type: u16,
    ) -> Option<Vec<u8>> {
        let hash = match bt.tx.network {
            kernel::Network::Elements => {
                let value9 = wire::psbt_input_value9(&bt.psbt, sign_index)?;
                kernel::elements_sighash_sw_v0(&bt.tx, sign_index, scriptcode, &value9, sighash)
            }
            kernel::Network::Bitcoin => {
                let value8 = wire::psbt_input_value_sats_le(&bt.psbt, sign_index)?;
                kernel::bitcoin_sighash_sw_v0(&bt.tx, sign_index, scriptcode, &value8, sighash)
            }
        };
        let compact = self.kernel().sign_hash_low_r(&hash, privkey);
        let mut w = Writer::new(reply_type);
        w.bytes(&compact);
        w.u8(sighash as u8);
        Some(w.into_vec())
    }

    /// SIGN_COMMITMENT_TX (5): sign OUR commitment with the 2-of-2 funding key.
    /// peer_id + dbid come from the MESSAGE.
    fn h_sign_commitment_tx(&self, m: &[u8]) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(m);
        r.u16()?;
        let peer_id = r.arr33()?;
        let dbid = r.u64()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let remote_funding = r.arr33()?;
        let s = self.kernel().channel_secrets(&peer_id, dbid);
        let local_funding = self.kernel().pubkey_of(&s.funding);
        let wscript = self.kernel().funding_wscript(&local_funding, &remote_funding);
        self.sig_reply(&bt, 0, &wscript, &s.funding, SIGHASH_ALL, msg::HSMD_SIGN_COMMITMENT_TX_REPLY)
    }

    /// SIGN_REMOTE_COMMITMENT_TX (19): sign the peer's commitment. seed from FRAME.
    fn h_sign_remote_commitment_tx(&self, req: &Request) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        r.u16()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let remote_funding = r.arr33()?;
        let s = self.kernel().channel_secrets(&req.node_id, req.dbid);
        let local_funding = self.kernel().pubkey_of(&s.funding);
        let wscript = self.kernel().funding_wscript(&local_funding, &remote_funding);
        self.sig_reply(&bt, 0, &wscript, &s.funding, SIGHASH_ALL, msg::HSMD_SIGN_TX_REPLY)
    }

    /// SIGN_MUTUAL_CLOSE_TX (21): 2-of-2 funding sig. seed from FRAME.
    fn h_sign_mutual_close_tx(&self, req: &Request) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        r.u16()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let remote_funding = r.arr33()?;
        let s = self.kernel().channel_secrets(&req.node_id, req.dbid);
        let local_funding = self.kernel().pubkey_of(&s.funding);
        let wscript = self.kernel().funding_wscript(&local_funding, &remote_funding);
        self.sig_reply(&bt, 0, &wscript, &s.funding, SIGHASH_ALL, msg::HSMD_SIGN_TX_REPLY)
    }

    /// SIGN_REMOTE_HTLC_TX (20): sign a peer HTLC tx with the per-commitment
    /// htlc key. seed from FRAME.
    fn h_sign_remote_htlc_tx(&self, req: &Request) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        r.u16()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let wscript = r.u16_prefixed()?;
        let remote_per_commit = r.arr33()?;
        let anchor = r.bool()?;
        let s = self.kernel().channel_secrets(&req.node_id, req.dbid);
        let htlc_privkey = self.kernel().derive_simple_privkey(&s.htlc, &remote_per_commit);
        let sighash = if anchor { SIGHASH_SINGLE_ACP } else { SIGHASH_ALL };
        // Custody (enforce): the HTLC-tx output must be the to_local P2WSH for
        // the tracked channel on the REMOTE side, not a host-chosen script.
        self.enforce_htlc_tx_output(
            "SIGN_REMOTE_HTLC_TX",
            &req.node_id,
            req.dbid,
            Side::Remote,
            &remote_per_commit,
            &bt,
            0,
            sighash,
        )
        .ok()?;
        self.sig_reply(&bt, 0, &wscript, &htlc_privkey, sighash, msg::HSMD_SIGN_TX_REPLY)
    }

    /// SIGN_ANY_LOCAL_HTLC_TX (146): sign our HTLC tx. peer_id/dbid from MESSAGE.
    fn h_sign_any_local_htlc_tx(&self, m: &[u8]) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(m);
        r.u16()?;
        let commit_num = r.u64()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let wscript = r.u16_prefixed()?;
        let anchor = r.bool()?;
        let input_num = r.u32()? as usize;
        let peer_id = r.arr33()?;
        let dbid = r.u64()?;
        let s = self.kernel().channel_secrets(&peer_id, dbid);
        let point = self.kernel().per_commit_point_at(&s.shaseed, commit_num);
        let htlc_privkey = self.kernel().derive_simple_privkey(&s.htlc, &point);
        let sighash = if anchor { SIGHASH_SINGLE_ACP } else { SIGHASH_ALL };
        // Custody (enforce): the HTLC-tx output must be the to_local P2WSH for
        // the tracked channel on OUR (LOCAL) side.
        self.enforce_htlc_tx_output(
            "SIGN_ANY_LOCAL_HTLC_TX",
            &peer_id,
            dbid,
            Side::Local,
            &point,
            &bt,
            input_num,
            sighash,
        )
        .ok()?;
        self.sig_reply(&bt, input_num, &wscript, &htlc_privkey, sighash, msg::HSMD_SIGN_TX_REPLY)
    }

    /// SIGN_REMOTE_HTLC_TO_US (13): claim a peer-HTLC output. seed from FRAME.
    fn h_sign_remote_htlc_to_us(&self, req: &Request) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        r.u16()?;
        let remote_per_commit = r.arr33()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let wscript = r.u16_prefixed()?;
        let anchor = r.bool()?;
        let s = self.kernel().channel_secrets(&req.node_id, req.dbid);
        let privkey = self.kernel().derive_simple_privkey(&s.htlc, &remote_per_commit);
        let sighash = if anchor { SIGHASH_SINGLE_ACP } else { SIGHASH_ALL };
        self.enforce_wallet_sweep("SIGN_REMOTE_HTLC_TO_US", &bt, 0, sighash).ok()?;
        self.sig_reply(&bt, 0, &wscript, &privkey, sighash, msg::HSMD_SIGN_TX_REPLY)
    }

    /// SIGN_ANY_REMOTE_HTLC_TO_US (143): peer_id/dbid from MESSAGE.
    fn h_sign_any_remote_htlc_to_us(&self, m: &[u8]) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(m);
        r.u16()?;
        let remote_per_commit = r.arr33()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let wscript = r.u16_prefixed()?;
        let anchor = r.bool()?;
        let _input = r.u32()?;
        let peer_id = r.arr33()?;
        let dbid = r.u64()?;
        let s = self.kernel().channel_secrets(&peer_id, dbid);
        let privkey = self.kernel().derive_simple_privkey(&s.htlc, &remote_per_commit);
        let sighash = if anchor { SIGHASH_SINGLE_ACP } else { SIGHASH_ALL };
        self.enforce_wallet_sweep("SIGN_ANY_REMOTE_HTLC_TO_US", &bt, 0, sighash).ok()?;
        self.sig_reply(&bt, 0, &wscript, &privkey, sighash, msg::HSMD_SIGN_TX_REPLY)
    }

    /// SIGN_DELAYED_PAYMENT_TO_US (12): our delayed to-self output. seed FRAME.
    fn h_sign_delayed_payment_to_us(&self, req: &Request) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        r.u16()?;
        let commit_num = r.u64()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let wscript = r.u16_prefixed()?;
        let s = self.kernel().channel_secrets(&req.node_id, req.dbid);
        let point = self.kernel().per_commit_point_at(&s.shaseed, commit_num);
        let privkey = self.kernel().derive_simple_privkey(&s.delayed, &point);
        // SINGLE|ACP (watchtower): pins the user's recovery output 0 while
        // speculad appends its own fee inputs at index >= 1 and RBFs autonomously.
        self.enforce_wallet_sweep("SIGN_DELAYED_PAYMENT_TO_US", &bt, 0, SIGHASH_SINGLE_ACP).ok()?;
        self.sig_reply(&bt, 0, &wscript, &privkey, SIGHASH_SINGLE_ACP, msg::HSMD_SIGN_TX_REPLY)
    }

    /// SIGN_ANY_DELAYED_PAYMENT_TO_US (142): peer_id/dbid from MESSAGE.
    fn h_sign_any_delayed_payment_to_us(&self, m: &[u8]) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(m);
        r.u16()?;
        let commit_num = r.u64()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let wscript = r.u16_prefixed()?;
        let _input = r.u32()?;
        let peer_id = r.arr33()?;
        let dbid = r.u64()?;
        let s = self.kernel().channel_secrets(&peer_id, dbid);
        let point = self.kernel().per_commit_point_at(&s.shaseed, commit_num);
        let privkey = self.kernel().derive_simple_privkey(&s.delayed, &point);
        // SINGLE|ACP (watchtower), see SIGN_DELAYED_PAYMENT_TO_US.
        self.enforce_wallet_sweep("SIGN_ANY_DELAYED_PAYMENT_TO_US", &bt, 0, SIGHASH_SINGLE_ACP).ok()?;
        self.sig_reply(&bt, 0, &wscript, &privkey, SIGHASH_SINGLE_ACP, msg::HSMD_SIGN_TX_REPLY)
    }

    /// SIGN_PENALTY_TO_US (14): spend a revoked peer output. seed from FRAME.
    fn h_sign_penalty_to_us(&self, req: &Request) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        r.u16()?;
        let rev_secret = r.arr32()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let wscript = r.u16_prefixed()?;
        self.penalty_sig(&req.node_id, req.dbid, &rev_secret, &bt, &wscript)
    }

    /// SIGN_ANY_PENALTY_TO_US (144): peer_id/dbid from MESSAGE.
    fn h_sign_any_penalty_to_us(&self, m: &[u8]) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(m);
        r.u16()?;
        let rev_secret = r.arr32()?;
        let bt = wire::read_bitcoin_tx(&mut r)?;
        let wscript = r.u16_prefixed()?;
        let _input = r.u32()?;
        let peer_id = r.arr33()?;
        let dbid = r.u64()?;
        self.penalty_sig(&peer_id, dbid, &rev_secret, &bt, &wscript)
    }

    fn penalty_sig(
        &self,
        peer_id: &[u8; 33],
        dbid: u64,
        rev_secret: &[u8; 32],
        bt: &BitcoinTx,
        wscript: &[u8],
    ) -> Option<Vec<u8>> {
        let rev_sk = SecretKey::from_slice(rev_secret).ok()?;
        let point = self.kernel().point_from_secret(rev_secret).ok()?;
        let s = self.kernel().channel_secrets(peer_id, dbid);
        let privkey = self
            .kernel()
            .derive_revocation_privkey(&s.revocation, &rev_sk, &point);
        // SINGLE|ACP (watchtower): pins the recovery output 0 while speculad
        // appends its own fee inputs and RBFs the justice tx autonomously.
        self.enforce_wallet_sweep("SIGN_PENALTY_TO_US", bt, 0, SIGHASH_SINGLE_ACP).ok()?;
        self.sig_reply(bt, 0, wscript, &privkey, SIGHASH_SINGLE_ACP, msg::HSMD_SIGN_TX_REPLY)
    }

    /// SIGN_WITHDRAWAL (7): sign the node's OWN wallet inputs of a withdrawal /
    /// channel-funding PSBT and return the PSBT with a `PSBT_IN_PARTIAL_SIG` per
    /// signed input, mirroring `handle_sign_withdrawal_tx` -> `sign_our_inputs`
    /// (`hsmd/libhsmd.c`). lightningd `combine_psbt`s the reply back into its own
    /// PSBT and finalizes/broadcasts it, so ANY valid signature suffices (unlike
    /// the byte-exact commitment path); we keep every other PSBT byte untouched so
    /// the outpoints line up and the combine merges cleanly.
    ///
    /// The wallet key is the SAME one `hsm_key_for_utxo` would pick: a mnemonic
    /// (BIP86) node signs even its P2WPKH wallet inputs with the m/86'/0'/0'/0/idx
    /// key (whose HASH160 is the address), a legacy node with m/0/0/idx. We
    /// resolve which by reproducing the input's scriptPubkey from the candidate
    /// key, which also covers native-P2WPKH and P2SH-P2WPKH transparently.
    fn h_sign_withdrawal(&self, m: &[u8]) -> Option<Vec<u8>> {
        let (utxos, psbt) = wire::parse_sign_withdrawal(m)?;
        let out = self.sign_wallet_inputs_into_psbt(&utxos, psbt)?;
        let mut w = Writer::new(msg::HSMD_SIGN_WITHDRAWAL_REPLY);
        w.u32(out.len() as u32);
        w.bytes(&out);
        Some(w.into_vec())
    }

    /// Sign every HD-wallet input listed in `utxos` of `psbt`, splicing a
    /// PSBT_IN_PARTIAL_SIG (or PSBT_IN_TAP_KEY_SIG for a taproot input) per input,
    /// and return the mutated PSBT bytes. Shared by SIGN_WITHDRAWAL and
    /// SIGN_ANCHORSPEND (which additionally signs the anchor input with the
    /// funding key). Byte-identical to the previous inline withdrawal loop.
    fn sign_wallet_inputs_into_psbt(
        &self,
        utxos: &[wire::HsmUtxo],
        psbt: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let network = wire::detect_network(&psbt);
        // The tx being signed comes from the PSBT. On the Bitcoin path lightningd
        // downgrades to a v0 PSBT first, so the whole unsigned tx sits in the
        // global `PSBT_GLOBAL_UNSIGNED_TX` field. An Elements asset PSET is only
        // ever v2 and has NO such field, so we rebuild the unsigned tx from its
        // per-input/per-output maps (see `wire::reconstruct_elements_tx_from_pset`);
        // the reconstructed tx yields the exact sighash libhsmd's libwally signs.
        // `tx_bytes` (the linearized tx) is only consumed by the Bitcoin taproot
        // key-path branch below; Elements funding inputs are segwit-v0, so it
        // stays empty there.
        let (tx, tx_bytes) = match network {
            kernel::Network::Bitcoin => {
                let lin = wire::psbt_global_unsigned_tx(&psbt)?;
                (wire::parse_bitcoin_tx(lin)?, lin.to_vec())
            }
            kernel::Network::Elements => {
                (wire::reconstruct_elements_tx_from_pset(&psbt)?, Vec::new())
            }
        };

        let mut out = psbt;
        // Every input's (amount, scriptPubkey) from the PSBT witness_utxos, in tx
        // order — the BIP-341 taproot sighash commits to all of them. Computed once
        // from the untouched PSBT (our splices only APPEND records, never disturb a
        // witness_utxo, so this stays valid across iterations). Empty if any input
        // lacks a Bitcoin witness_utxo (then the taproot path simply skips).
        let all_prevouts: Vec<(u64, Vec<u8>)> = (0..tx.inputs.len())
            .map(|i| wire::psbt_input_btc_prevout(&out, i))
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        for utxo in utxos {
            // The HD wallet path only; a their-close sweep needs channel keys and
            // is never part of a channel-funding withdrawal.
            if utxo.is_unilateral_close {
                continue;
            }
            // Match the utxo to its PSBT/tx input by outpoint (`wally_psbt_input_spends`).
            let Some(j) = tx
                .inputs
                .iter()
                .position(|i| i.txhash == utxo.txid && i.index == utxo.vout)
            else {
                continue;
            };
            // Taproot (BIP-86 KEY PATH) wallet input `OP_1 <32-byte x-only>`: the
            // real form a modern mnemonic node's funds sit on. Schnorr-sign the
            // BIP-341 key-spend sighash and splice a PSBT_IN_TAP_KEY_SIG record;
            // libwally's finalizer builds the P2TR witness from it. (Bitcoin only.)
            if network == kernel::Network::Bitcoin && is_p2tr(&utxo.script_pubkey) {
                if all_prevouts.len() != tx.inputs.len() {
                    continue; // missing a witness_utxo: can't build the taproot sighash
                }
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&utxo.script_pubkey[2..34]);
                let internal_sk = self.kernel().bip86_child_privkey(utxo.keyindex);
                let Some(sig) = self.kernel().taproot_keyspend_sign(
                    &tx_bytes,
                    j,
                    &all_prevouts,
                    &internal_sk,
                    &xonly,
                ) else {
                    continue;
                };
                let rec = tap_key_sig_record(&sig);
                let term = wire::psbt_input_map_terminator(&out, j)?;
                let mut next = Vec::with_capacity(out.len() + rec.len());
                next.extend_from_slice(&out[..term]);
                next.extend_from_slice(&rec);
                next.extend_from_slice(&out[term..]);
                out = next;
                continue;
            }
            // Resolve the signing key + its pubkey by reproducing the scriptPubkey.
            let Some((sk, pubkey, keyhash)) =
                self.wallet_key_for_spk(utxo.keyindex, &utxo.script_pubkey)
            else {
                continue;
            };
            // BIP-143 scriptCode for a P2WPKH / P2SH-P2WPKH input = the P2PKH template.
            let scriptcode = p2pkh_scriptcode(&keyhash);
            let hash = match network {
                kernel::Network::Bitcoin => {
                    let v8 = utxo.amount.to_le_bytes();
                    kernel::bitcoin_sighash_sw_v0(&tx, j, &scriptcode, &v8, SIGHASH_ALL)
                }
                kernel::Network::Elements => {
                    // Explicit 9-byte confidential value: 0x01 || uint64_be(amount).
                    let mut v9 = [0u8; 9];
                    v9[0] = 0x01;
                    v9[1..].copy_from_slice(&utxo.amount.to_be_bytes());
                    kernel::elements_sighash_sw_v0(&tx, j, &scriptcode, &v9, SIGHASH_ALL)
                }
            };
            // Low-R ECDSA, self-checked against the derived pubkey, DER-encoded.
            // The withdrawal path signs through libwally's `wally_psbt_sign`, so we
            // match ITS grind (NULL first nonce) — not `bitcoin/signature.c`'s
            // `sign_hash` (32-zero first nonce) used for commitments — to reproduce
            // the reference libhsmd partial-sig bytes exactly.
            let der = self.kernel().sign_low_r_der_libwally_checked(&hash, &sk, &pubkey)?;
            // Splice a PSBT_IN_PARTIAL_SIG record (key 0x02||pubkey, value DER||sighash)
            // into input j's map. Re-navigate each time: earlier inserts shift offsets.
            let rec = partial_sig_record(&pubkey, &der, SIGHASH_ALL as u8);
            let term = wire::psbt_input_map_terminator(&out, j)?;
            let mut next = Vec::with_capacity(out.len() + rec.len());
            next.extend_from_slice(&out[..term]);
            next.extend_from_slice(&rec);
            next.extend_from_slice(&out[term..]);
            out = next;
        }

        Some(out)
    }

    /// SIGN_ANCHORSPEND (147): CPFP a commitment by spending its anchor output.
    /// Mirrors libhsmd `handle_sign_anchorspend`: sign the node's own wallet fee
    /// inputs (like a withdrawal), THEN sign the anchor input with the channel
    /// FUNDING key. The anchor input is the one whose witness_utxo pays
    /// `p2wsh(wscript_anchor(local_funding_pubkey))`. Reply (148) = the mutated
    /// wally_psbt (u32 len || bytes). Any valid partial sig suffices (lightningd
    /// finalizes the PSBT), so this is not on the byte-exact commitment path.
    fn h_sign_anchorspend(&self, m: &[u8]) -> Option<Vec<u8>> {
        let (peer_id, dbid, utxos, psbt) = wire::parse_sign_anchorspend(m)?;
        // (a) sign the appended wallet fee inputs, exactly as a withdrawal.
        let out = self.sign_wallet_inputs_into_psbt(&utxos, psbt)?;
        // (b) sign the anchor input with the funding key.
        let out = self.sign_anchor_input(&peer_id, dbid, out)?;
        let mut w = Writer::new(msg::HSMD_SIGN_ANCHORSPEND_REPLY);
        w.u32(out.len() as u32);
        w.bytes(&out);
        Some(w.into_vec())
    }

    /// Splice a funding-key PSBT_IN_PARTIAL_SIG over the anchor input of `psbt`.
    /// Returns the mutated PSBT, or None if the anchor input can't be located /
    /// the sighash can't be built.
    fn sign_anchor_input(&self, peer_id: &[u8; 33], dbid: u64, psbt: Vec<u8>) -> Option<Vec<u8>> {
        let network = wire::detect_network(&psbt);
        // Rebuild the unsigned tx the same way the withdrawal path does.
        let tx = match network {
            kernel::Network::Bitcoin => {
                wire::parse_bitcoin_tx(wire::psbt_global_unsigned_tx(&psbt)?)?
            }
            kernel::Network::Elements => wire::reconstruct_elements_tx_from_pset(&psbt)?,
        };
        let s = self.kernel().channel_secrets(peer_id, dbid);
        let funding_pub = self.kernel().pubkey_of(&s.funding);
        let wscript = crate::policy::anchor_wscript(&funding_pub);
        let anchor_spk = crate::policy::p2wsh_spk(&wscript);
        // Locate the anchor input: its witness_utxo scriptPubKey is the anchor P2WSH.
        let j = (0..tx.inputs.len())
            .find(|&i| wire::psbt_input_witness_spk(&psbt, i, network).as_deref() == Some(&anchor_spk))?;
        // BIP-143 sighash over the anchor witnessScript, SIGHASH_ALL (libwally
        // grind), self-checked, then splice PSBT_IN_PARTIAL_SIG into input j.
        let hash = match network {
            kernel::Network::Bitcoin => {
                let v8 = wire::psbt_input_value_sats_le(&psbt, j)?;
                kernel::bitcoin_sighash_sw_v0(&tx, j, &wscript, &v8, SIGHASH_ALL)
            }
            kernel::Network::Elements => {
                let v9 = wire::psbt_input_value9(&psbt, j)?;
                kernel::elements_sighash_sw_v0(&tx, j, &wscript, &v9, SIGHASH_ALL)
            }
        };
        let der = self
            .kernel()
            .sign_low_r_der_libwally_checked(&hash, &s.funding, &funding_pub)?;
        let rec = partial_sig_record(&funding_pub, &der, SIGHASH_ALL as u8);
        let term = wire::psbt_input_map_terminator(&psbt, j)?;
        let mut next = Vec::with_capacity(psbt.len() + rec.len());
        next.extend_from_slice(&psbt[..term]);
        next.extend_from_slice(&rec);
        next.extend_from_slice(&psbt[term..]);
        Some(next)
    }

    /// Find the wallet privkey (+ its pubkey + HASH160) that produces `spk`,
    /// trying BIP86 (m/86'/0'/0'/0/idx) then legacy (m/0/0/idx) and matching
    /// against native-P2WPKH (`0014<h160>`) and P2SH-P2WPKH (`a914<H160>87`).
    fn wallet_key_for_spk(
        &self,
        keyindex: u32,
        spk: &[u8],
    ) -> Option<(SecretKey, [u8; 33], [u8; 20])> {
        for use_bip86 in [true, false] {
            let sk = if use_bip86 {
                self.kernel().bip86_child_privkey(keyindex)
            } else {
                self.kernel().bitcoin_wallet_privkey(keyindex)
            };
            let pubkey = self.kernel().pubkey_of(&sk);
            let keyhash = kernel::hash160(&pubkey);
            if spk_matches_keyhash(spk, &keyhash) {
                return Some((sk, pubkey, keyhash));
            }
        }
        None
    }

    /// VALIDATE_COMMITMENT_TX (35): return the next per-commitment point (the
    /// old_secret is never returned in this stub). seed from FRAME.
    fn h_validate_commitment_tx(&self, req: &Request) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        r.u16()?;
        let _bt = wire::read_bitcoin_tx(&mut r)?;
        let num_htlcs = r.u16()? as usize;
        r.skip(num_htlcs * HSM_HTLC_LEN)?;
        let commit_num = r.u64()?;
        let s = self.kernel().channel_secrets(&req.node_id, req.dbid);
        let point = self.kernel().per_commit_point_at(&s.shaseed, commit_num + 1);
        let mut w = Writer::new(msg::HSMD_VALIDATE_COMMITMENT_TX_REPLY);
        w.bool(false); // old_commitment_secret: ?secret absent
        w.bytes(&point);
        Some(w.into_vec())
    }

    /// REVOKE_COMMITMENT_TX (40): reveal commit_num's secret + next+2 point.
    fn h_revoke_commitment_tx(&self, req: &Request) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        r.u16()?;
        let commit_num = r.u64()?;
        let s = self.kernel().channel_secrets(&req.node_id, req.dbid);
        let old_secret = self.kernel().per_commit_secret_at(&s.shaseed, commit_num);
        let point = self.kernel().per_commit_point_at(&s.shaseed, commit_num + 2);
        let mut w = Writer::new(msg::HSMD_REVOKE_COMMITMENT_TX_REPLY);
        w.bytes(&old_secret); // secret (non-optional)
        w.bytes(&point);
        Some(w.into_vec())
    }

    /// GET_OUTPUT_SCRIPTPUBKEY (24): the p2wpkh for a their-unilateral-close
    /// to-us output. peer_id + channel_id from MESSAGE.
    fn h_get_output_scriptpubkey(&self, m: &[u8]) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(m);
        r.u16()?;
        let channel_id = r.u64()?;
        let peer_id = r.arr33()?;
        let present = r.bool()?;
        let commitment_point = if present { Some(r.arr33()?) } else { None };
        let s = self.kernel().channel_secrets(&peer_id, channel_id);
        let privkey = match commitment_point {
            None => s.payment,
            Some(cp) => self.kernel().derive_simple_privkey(&s.payment, &cp),
        };
        let pubkey = self.kernel().pubkey_of(&privkey);
        let script = self.kernel().p2wpkh_scriptpubkey(&pubkey);
        let mut w = Writer::new(msg::HSMD_GET_OUTPUT_SCRIPTPUBKEY_REPLY);
        w.u16(script.len() as u16);
        w.bytes(&script);
        Some(w.into_vec())
    }

    /// SIGN_INVOICE (8): recoverable node-key signature over hash_u5(hrp,u5bytes).
    fn h_sign_invoice(&self, m: &[u8]) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(m);
        r.u16()?;
        let u5 = r.u16_prefixed()?;
        let hrp = r.u16_prefixed()?;
        let hash = kernel::hash_u5(&hrp, &u5);
        let rsig = self.kernel().node_sign_recoverable(&hash);
        let mut w = Writer::new(msg::HSMD_SIGN_INVOICE_REPLY);
        w.bytes(&rsig);
        Some(w.into_vec())
    }

    // ---- Gossip signatures (BOLT-7): double-SHA256 then low-R ECDSA. ----

    /// The channel_announcement double-signature (node key + funding key), over
    /// `sha256d(ca[258..])` (`handle_sign_cannouncement`). Reply: node_sig(64) ||
    /// bitcoin_sig(64).
    fn cannouncement_reply(
        &self,
        ca: &[u8],
        peer_id: &[u8; 33],
        dbid: u64,
        reply_type: u16,
    ) -> Option<Vec<u8>> {
        const OFFSET: usize = 2 + 256;
        if ca.len() < OFFSET {
            return None;
        }
        let hash = kernel::double_sha256(&ca[OFFSET..]);
        let node_sig = self.kernel().sign_hash_low_r(&hash, &self.kernel().node_privkey());
        let funding = self.kernel().channel_secrets(peer_id, dbid).funding;
        let bitcoin_sig = self.kernel().sign_hash_low_r(&hash, &funding);
        let mut w = Writer::new(reply_type);
        w.bytes(&node_sig);
        w.bytes(&bitcoin_sig);
        Some(w.into_vec())
    }

    /// CANNOUNCEMENT_SIG_REQ (2): peer_id/dbid from FRAME.
    fn h_cannouncement_sig(&self, req: &Request) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        r.u16()?;
        let ca = r.u16_prefixed()?;
        self.cannouncement_reply(&ca, &req.node_id, req.dbid, msg::HSMD_CANNOUNCEMENT_SIG_REPLY)
    }

    /// SIGN_ANY_CANNOUNCEMENT_REQ (4): peer_id/dbid from MESSAGE.
    fn h_any_cannouncement_sig(&self, m: &[u8]) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(m);
        r.u16()?;
        let ca = r.u16_prefixed()?;
        let peer_id = r.arr33()?;
        let dbid = r.u64()?;
        self.cannouncement_reply(&ca, &peer_id, dbid, msg::HSMD_SIGN_ANY_CANNOUNCEMENT_REPLY)
    }

    /// NODE_ANNOUNCEMENT_SIG_REQ (6): node-key sig over sha256d(ann[66..]).
    fn h_node_announcement_sig(&self, m: &[u8]) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(m);
        r.u16()?;
        let ann = r.u16_prefixed()?;
        if ann.len() < 66 {
            return None;
        }
        let hash = kernel::double_sha256(&ann[66..]);
        let sig = self.kernel().sign_hash_low_r(&hash, &self.kernel().node_privkey());
        let mut w = Writer::new(msg::HSMD_NODE_ANNOUNCEMENT_SIG_REPLY);
        w.bytes(&sig);
        Some(w.into_vec())
    }

    /// CUPDATE_SIG_REQ (3): node-key sig over sha256d(cu[66..]); reply is the
    /// channel_update with bytes [2..66] replaced by the fresh signature.
    fn h_cupdate_sig(&self, m: &[u8]) -> Option<Vec<u8>> {
        let mut r = wire::Reader::new(m);
        r.u16()?;
        let cu = r.u16_prefixed()?;
        if cu.len() < 66 {
            return None;
        }
        let hash = kernel::double_sha256(&cu[66..]);
        let sig = self.kernel().sign_hash_low_r(&hash, &self.kernel().node_privkey());
        let mut out = cu.clone();
        out[2..66].copy_from_slice(&sig);
        let mut w = Writer::new(msg::HSMD_CUPDATE_SIG_REPLY);
        w.u16(out.len() as u16);
        w.bytes(&out);
        Some(w.into_vec())
    }
}

fn opt(o: Option<Vec<u8>>) -> Outcome {
    match o {
        Some(b) => Outcome::Reply(b),
        None => Outcome::Sentinel,
    }
}

/// Lowercase hex, for enforce-mode rejection log lines.
fn hexbytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// The BIP-143 scriptCode for a P2WPKH / P2SH-P2WPKH input: the P2PKH template
/// `OP_DUP OP_HASH160 <20-byte keyhash> OP_EQUALVERIFY OP_CHECKSIG` (25 bytes, no
/// length prefix — the sighash's varbuff adds it).
fn p2pkh_scriptcode(keyhash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76); // OP_DUP
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20
    s.extend_from_slice(keyhash);
    s.push(0x88); // OP_EQUALVERIFY
    s.push(0xac); // OP_CHECKSIG
    s
}

/// Does `spk` pay to `keyhash` as native P2WPKH (`0014<h160>`) or wrapped
/// P2SH-P2WPKH (`a914 HASH160(0014<h160>) 87`)?
fn spk_matches_keyhash(spk: &[u8], keyhash: &[u8; 20]) -> bool {
    // Native P2WPKH: OP_0 push20 <keyhash>.
    if spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14 && &spk[2..22] == keyhash {
        return true;
    }
    // P2SH-P2WPKH: OP_HASH160 push20 HASH160(redeemscript) OP_EQUAL,
    // redeemscript = OP_0 push20 <keyhash>.
    if spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87 {
        let mut redeem = Vec::with_capacity(22);
        redeem.push(0x00);
        redeem.push(0x14);
        redeem.extend_from_slice(keyhash);
        return spk[2..22] == kernel::hash160(&redeem);
    }
    false
}

/// One `PSBT_IN_PARTIAL_SIG` key-value record: keylen || 0x02 || pubkey(33) ||
/// vallen || DER-sig || sighash-byte. keylen (34) and vallen (< 0x4d) are always
/// single-byte compact sizes.
fn partial_sig_record(pubkey: &[u8; 33], der: &[u8], sighash: u8) -> Vec<u8> {
    let mut rec = Vec::with_capacity(1 + 34 + 1 + der.len() + 1);
    rec.push(34); // keylen = 1 (type) + 33 (pubkey)
    rec.push(0x02); // PSBT_IN_PARTIAL_SIG
    rec.extend_from_slice(pubkey);
    rec.push((der.len() + 1) as u8); // vallen = DER + sighash byte
    rec.extend_from_slice(der);
    rec.push(sighash);
    rec
}

/// True for a native witness-v1 taproot scriptPubkey `OP_1 <32-byte program>`
/// (`5120` || 32 bytes) — a BIP-86 key-path output.
fn is_p2tr(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20
}

/// One keyless `PSBT_IN_TAP_KEY_SIG` record: keylen(1) || 0x13 || vallen(0x40) ||
/// 64-byte BIP-340 Schnorr signature (SIGHASH_DEFAULT, so no trailing hash byte).
/// libwally's `finalize_p2tr` reads this field to build the taproot key-spend
/// witness `[sig]`.
fn tap_key_sig_record(sig: &[u8; 64]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(1 + 1 + 1 + 64);
    rec.push(0x01); // keylen = 1 (type only, no keydata)
    rec.push(0x13); // PSBT_IN_TAP_KEY_SIG
    rec.push(0x40); // vallen = 64
    rec.extend_from_slice(sig);
    rec
}

// ---- M4 request parsers (for the validating policy) ----

/// Parse `hsmd_setup_channel` into a [`ChannelState`]. Layout from
/// `hsmd/hsmd_wire.csv` (`basepoints` = revocation, payment, htlc, delayed;
/// `channel_type` = u16 len + feature bytes).
fn parse_setup_channel(m: &[u8]) -> Option<ChannelState> {
    let mut r = wire::Reader::new(m);
    if r.u16()? != msg::HSMD_SETUP_CHANNEL {
        return None;
    }
    let _is_outbound = r.bool()?;
    let funding_sats = r.u64()?; // amount_sat
    let _push_msat = r.u64()?; // amount_msat
    let funding_txid = r.arr32()?;
    let funding_txout = r.u16()?;
    let local_to_self_delay = r.u16()?;
    let lsl = r.u16()? as usize;
    r.skip(lsl)?; // local_shutdown_script
    if r.bool()? {
        r.u32()?; // local_shutdown_wallet_index (?u32)
    }
    let remote_revocation = r.arr33()?;
    let remote_payment = r.arr33()?;
    let remote_htlc = r.arr33()?;
    let remote_delayed = r.arr33()?;
    let remote_funding = r.arr33()?;
    let remote_to_self_delay = r.u16()?;
    let rsl = r.u16()? as usize;
    r.skip(rsl)?; // remote_shutdown_script
    let ctlen = r.u16()? as usize;
    let features = r.take_bytes(ctlen)?;
    let (option_static_remotekey, option_anchors) = policy::parse_channel_type(&features);
    Some(ChannelState {
        funding_sats,
        funding_txid,
        funding_txout,
        local_to_self_delay,
        remote_to_self_delay,
        remote_revocation,
        remote_payment,
        remote_htlc,
        remote_delayed,
        remote_funding,
        option_static_remotekey,
        option_anchors,
    })
}

/// Read `n` `hsm_htlc` subtypes: side(u8) || amount(u64) || hash(32) || cltv(u32).
fn read_htlcs(r: &mut wire::Reader, n: usize) -> Option<Vec<Htlc>> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let side = r.u8()?;
        let amount_msat = r.u64()?;
        let payment_hash = r.arr32()?;
        let cltv_expiry = r.u32()?;
        v.push(Htlc {
            side,
            amount_msat,
            payment_hash,
            cltv_expiry,
        });
    }
    Some(v)
}

/// Parse `hsmd_sign_remote_commitment_tx` -> (tx, remote_funding, remote_per_commit, htlcs).
fn parse_remote_commitment(m: &[u8]) -> Option<(BitcoinTx, [u8; 33], [u8; 33], Vec<Htlc>)> {
    let mut r = wire::Reader::new(m);
    r.u16()?;
    let bt = wire::read_bitcoin_tx(&mut r)?;
    let remote_funding = r.arr33()?;
    let remote_per_commit = r.arr33()?;
    let _static_remotekey = r.bool()?;
    let _commit_num = r.u64()?;
    let num_htlcs = r.u16()? as usize;
    let htlcs = read_htlcs(&mut r, num_htlcs)?;
    Some((bt, remote_funding, remote_per_commit, htlcs))
}

/// Parse `hsmd_validate_commitment_tx` -> (tx, htlcs, commit_num).
fn parse_local_commitment(m: &[u8]) -> Option<(BitcoinTx, Vec<Htlc>, u64)> {
    let mut r = wire::Reader::new(m);
    r.u16()?;
    let bt = wire::read_bitcoin_tx(&mut r)?;
    let num_htlcs = r.u16()? as usize;
    let htlcs = read_htlcs(&mut r, num_htlcs)?;
    let commit_num = r.u64()?;
    Some((bt, htlcs, commit_num))
}

/// Parse `hsmd_sign_commitment_tx` -> (peer_id, dbid, tx, commit_num).
fn parse_own_commitment(m: &[u8]) -> Option<([u8; 33], u64, BitcoinTx, u64)> {
    let mut r = wire::Reader::new(m);
    r.u16()?;
    let peer_id = r.arr33()?;
    let dbid = r.u64()?;
    let bt = wire::read_bitcoin_tx(&mut r)?;
    let _remote_funding = r.arr33()?;
    let commit_num = r.u64()?;
    Some((peer_id, dbid, bt, commit_num))
}

fn approve_reply(reply_type: u16) -> Vec<u8> {
    let mut w = Writer::new(reply_type);
    w.bool(true);
    w.into_vec()
}

fn empty_reply(msgtype: u16) -> Vec<u8> {
    Writer::new(msgtype).into_vec()
}

#[cfg(test)]
mod withdrawal_tests {
    use super::*;
    use crate::hsm_secret::HsmSecret;
    use crate::kernel::{Kernel, BIP32_VER_TEST_PRIVATE, BIP32_VER_TEST_PUBLIC};

    fn compact(n: usize) -> Vec<u8> {
        assert!(n < 0xfd, "test lengths stay single-byte compact");
        vec![n as u8]
    }

    /// Build a minimal unsigned Bitcoin tx: 1 input (outpoint `txid:0`), 1 output.
    fn unsigned_tx(txid: &[u8; 32], out_value: u64) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&2u32.to_le_bytes()); // version
        t.push(0x01); // vin count
        t.extend_from_slice(txid);
        t.extend_from_slice(&0u32.to_le_bytes()); // vout
        t.push(0x00); // empty scriptSig
        t.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        t.push(0x01); // vout count
        t.extend_from_slice(&out_value.to_le_bytes());
        let out_spk = [0x00u8, 0x14].iter().copied().chain([9u8; 20]).collect::<Vec<u8>>();
        t.extend_from_slice(&compact(out_spk.len()));
        t.extend_from_slice(&out_spk);
        t.extend_from_slice(&0u32.to_le_bytes()); // locktime
        t
    }

    /// Assemble a v0 PSBT: magic || global{0x00: tx} || input0{0x01: witness_utxo} || output0{}.
    fn v0_psbt(tx: &[u8], input_amount: u64, input_spk: &[u8]) -> Vec<u8> {
        let mut wu = input_amount.to_le_bytes().to_vec(); // TxOut value(8 LE)
        wu.extend_from_slice(&compact(input_spk.len()));
        wu.extend_from_slice(input_spk);

        let mut p = Vec::new();
        p.extend_from_slice(b"psbt\xff");
        // global map: PSBT_GLOBAL_UNSIGNED_TX
        p.extend_from_slice(&[0x01, 0x00]); // keylen 1, key 0x00
        p.extend_from_slice(&compact(tx.len()));
        p.extend_from_slice(tx);
        p.push(0x00); // global terminator
        // input-0 map: PSBT_IN_WITNESS_UTXO
        p.extend_from_slice(&[0x01, 0x01]); // keylen 1, key 0x01
        p.extend_from_slice(&compact(wu.len()));
        p.extend_from_slice(&wu);
        p.push(0x00); // input-0 terminator
        // output-0 map: empty
        p.push(0x00);
        p
    }

    /// One PSET key-value record: keylen(compact) || key || vallen(compact) || val.
    fn pset_rec(key: &[u8], val: &[u8]) -> Vec<u8> {
        let mut r = compact(key.len());
        r.extend_from_slice(key);
        r.extend_from_slice(&compact(val.len()));
        r.extend_from_slice(val);
        r
    }

    /// The 7-byte PSET proprietary key for a single-byte field type: `fc 04 "pset" t`.
    fn pset_key(t: u8) -> Vec<u8> {
        vec![0xfc, 0x04, 0x70, 0x73, 0x65, 0x74, t]
    }

    /// An Elements explicit witness_utxo (the UTXO being spent):
    /// asset(0x01||32) || value(0x01||u64_be) || null nonce(0x00) || varbuff(spk).
    fn elements_wu(asset_id: &[u8; 32], sats: u64, spk: &[u8]) -> Vec<u8> {
        let mut v = vec![0x01u8];
        v.extend_from_slice(asset_id);
        v.push(0x01);
        v.extend_from_slice(&sats.to_be_bytes());
        v.push(0x00);
        v.extend_from_slice(&compact(spk.len()));
        v.extend_from_slice(spk);
        v
    }

    /// The reconstruction fix, end-to-end: a Sequentia ASSET funding withdrawal
    /// arrives as a v2 PSET (NO global unsigned tx). The signer must rebuild the
    /// unsigned Elements tx from the input/output maps, compute the Elements
    /// BIP-143 sighash over it, and splice a valid PSBT_IN_PARTIAL_SIG. This
    /// asserts: (a) the tx reconstructed from the PSET has the exact inputs,
    /// outputs, asset ids, amounts and empty-script fee output we encoded; and
    /// (b) the spliced signature is over THAT reconstructed tx's sighash, using
    /// libwally's low-R grind (so it reproduces these exact bytes). The full
    /// libhsmd byte-exactness — the reconstructed-tx sighash AND the partial-sig
    /// bytes are IDENTICAL to the reference `lightning_signerd` (libwally
    /// `wally_psbt_sign`) for a real Elements v2 PSET withdrawal — is proven
    /// out-of-process by the `SEQLN_WITHDRAWAL_VECTOR` mode of the conformance
    /// harness fed by the `emit_elements_vector` binary.
    #[test]
    fn signs_own_elements_asset_funding_input() {
        // This test builds an Elements PSET; if the box env forces the Bitcoin
        // sighash format the reconstruction would be wrong, so skip there.
        if matches!(
            std::env::var("SEQLN_SIGNER_NETWORK").ok().as_deref(),
            Some("bitcoin") | Some("btc")
        ) {
            eprintln!("SKIP: SEQLN_SIGNER_NETWORK forces Bitcoin");
            return;
        }

        let seed = crate::kernel::bip39_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        );
        let kernel = Kernel::new(seed.to_vec(), BIP32_VER_TEST_PUBLIC, BIP32_VER_TEST_PRIVATE);

        // The node's own P2WPKH wallet input (bip86 key) it funds the channel from.
        let keyindex = 4u32;
        let pubkey = kernel.bip86_child_pubkey(keyindex);
        let keyhash = kernel::hash160(&pubkey);
        let in_spk: Vec<u8> = [0x00u8, 0x14].iter().copied().chain(keyhash).collect();

        // A Sequentia asset id + a distinct fee (policy) asset id (tSEQ).
        let asset_id: [u8; 32] = {
            let mut a = [0u8; 32];
            a.copy_from_slice(&crate::kernel::hash160(b"GOLD").to_vec().repeat(2)[..32]);
            a
        };
        let fee_asset: [u8; 32] = [0x77u8; 32];

        let txid = [0x33u8; 32];
        let in_amount = 500_000u64;
        let seq = 0xffff_fffdu32; // RBF-enabled, like a real funding input

        // ---- build the v2 PSET (magic "pset\xff") ----
        let mut p = Vec::new();
        p.extend_from_slice(b"pset\xff");
        // global: TX_VERSION(2), FALLBACK_LOCKTIME(0), INPUT_COUNT(1), OUTPUT_COUNT(3)
        p.extend_from_slice(&pset_rec(&[0x02], &2u32.to_le_bytes()));
        p.extend_from_slice(&pset_rec(&[0x03], &0u32.to_le_bytes()));
        p.extend_from_slice(&pset_rec(&[0x04], &[0x01])); // varint(1) inside varbuff
        p.extend_from_slice(&pset_rec(&[0x05], &[0x03])); // varint(3)
        p.push(0x00); // global terminator

        // input 0: witness_utxo(asset), previous_txid, output_index, sequence.
        let wu = elements_wu(&asset_id, in_amount, &in_spk);
        p.extend_from_slice(&pset_rec(&[0x01], &wu)); // PSBT_IN_WITNESS_UTXO
        p.extend_from_slice(&pset_rec(&[0x0e], &txid)); // PSBT_IN_PREVIOUS_TXID
        p.extend_from_slice(&pset_rec(&[0x0f], &0u32.to_le_bytes())); // OUTPUT_INDEX
        p.extend_from_slice(&pset_rec(&[0x10], &seq.to_le_bytes())); // SEQUENCE
        p.push(0x00); // input-0 terminator

        // output 0: the channel funding output (P2WSH), asset = GOLD, 300000.
        let fund_spk: Vec<u8> = [0x00u8, 0x20].iter().copied().chain([0xabu8; 32]).collect();
        p.extend_from_slice(&pset_rec(&pset_key(0x02), &asset_id)); // PSET_OUT_ASSET
        p.extend_from_slice(&pset_rec(&[0x03], &300_000u64.to_le_bytes())); // PSBT_OUT_AMOUNT
        p.extend_from_slice(&pset_rec(&[0x04], &fund_spk)); // PSBT_OUT_SCRIPT
        p.push(0x00);

        // output 1: change back to a P2WPKH of ours, asset = GOLD, 199000.
        let change_spk: Vec<u8> = [0x00u8, 0x14].iter().copied().chain([0xcdu8; 20]).collect();
        p.extend_from_slice(&pset_rec(&pset_key(0x02), &asset_id));
        p.extend_from_slice(&pset_rec(&[0x03], &199_000u64.to_le_bytes()));
        p.extend_from_slice(&pset_rec(&[0x04], &change_spk));
        p.push(0x00);

        // output 2: the FEE output — explicit fee asset, empty script.
        p.extend_from_slice(&pset_rec(&pset_key(0x02), &fee_asset));
        p.extend_from_slice(&pset_rec(&[0x03], &1_000u64.to_le_bytes()));
        p.extend_from_slice(&pset_rec(&[0x04], &[])); // empty scriptPubkey
        p.push(0x00);
        let psbt = p;

        // Sanity: detect_network must resolve Elements from the witness_utxo shape.
        assert_eq!(wire::detect_network(&psbt), kernel::Network::Elements);

        // The reconstruction must yield exactly what we encoded.
        let tx = wire::reconstruct_elements_tx_from_pset(&psbt).expect("reconstruct pset tx");
        assert_eq!(tx.network, kernel::Network::Elements);
        assert_eq!(tx.version, 2);
        assert_eq!(tx.locktime, 0);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].txhash, txid);
        assert_eq!(tx.inputs[0].index, 0);
        assert_eq!(tx.inputs[0].sequence, seq);
        assert_eq!(tx.outputs.len(), 3);
        // Funding output: explicit GOLD asset, explicit 300000, P2WSH script.
        assert_eq!(tx.outputs[0].asset[0], 0x01);
        assert_eq!(&tx.outputs[0].asset[1..], &asset_id);
        assert_eq!(tx.outputs[0].value[0], 0x01);
        assert_eq!(u64::from_be_bytes(tx.outputs[0].value[1..9].try_into().unwrap()), 300_000);
        assert_eq!(tx.outputs[0].nonce, vec![0x00]);
        assert_eq!(tx.outputs[0].script, fund_spk);
        // Fee output: explicit fee asset, empty script.
        assert_eq!(&tx.outputs[2].asset[1..], &fee_asset);
        assert_eq!(u64::from_be_bytes(tx.outputs[2].value[1..9].try_into().unwrap()), 1_000);
        assert!(tx.outputs[2].script.is_empty());

        // ---- drive the handler ----
        let mut w = Writer::new(msg::HSMD_SIGN_WITHDRAWAL);
        w.u16(1); // num_inputs
        w.bytes(&txid);
        w.u32(0); // vout
        w.u64(in_amount);
        w.u32(keyindex);
        w.bool(false); // legacy is_p2sh
        w.u16(in_spk.len() as u16);
        w.bytes(&in_spk);
        w.bool(false); // is_unilateral_close
        w.bool(false); // legacy is_in_coinbase
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        let req_msg = w.into_vec();

        let secret = HsmSecret { seed, secret_type: 2, mnemonic: String::new() };
        let mut signer = Signer::new(secret);
        signer.kernel = Some(kernel);
        signer.hsm_version = 6;

        let reply = signer.h_sign_withdrawal(&req_msg).expect("elements withdrawal reply");
        assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), msg::HSMD_SIGN_WITHDRAWAL_REPLY);
        let rlen = u32::from_be_bytes([reply[2], reply[3], reply[4], reply[5]]) as usize;
        let rpsbt = &reply[6..6 + rlen];
        assert!(rpsbt.len() > psbt.len(), "partial_sig not added");

        // Locate the partial_sig record (key 0x22, 0x02, <pubkey33>; val DER||0x01).
        let mut key = vec![34u8, 0x02];
        key.extend_from_slice(&pubkey);
        let pos = rpsbt
            .windows(key.len())
            .position(|win| win == key.as_slice())
            .expect("partial_sig record for our wallet pubkey present");
        let vp = pos + key.len();
        let vallen = rpsbt[vp] as usize;
        let value = &rpsbt[vp + 1..vp + 1 + vallen];
        let (der, sighash_byte) = value.split_at(value.len() - 1);
        assert_eq!(sighash_byte, &[SIGHASH_ALL as u8]);

        // Recompute the ELEMENTS sighash over the reconstructed tx and re-sign; the
        // handler's signature must match byte-for-byte (proves it signed the right
        // preimage over the reconstructed asset tx, not a stale/blank one).
        let scriptcode = p2pkh_scriptcode(&keyhash);
        let mut v9 = [0u8; 9];
        v9[0] = 0x01;
        v9[1..].copy_from_slice(&in_amount.to_be_bytes());
        let hash = kernel::elements_sighash_sw_v0(&tx, 0, &scriptcode, &v9, SIGHASH_ALL);
        let sk = signer.kernel().bip86_child_privkey(keyindex);
        let expected = signer
            .kernel()
            .sign_low_r_der_libwally_checked(&hash, &sk, &pubkey)
            .expect("sig self-verifies");
        assert_eq!(der, expected.as_slice(), "signature is over the wrong (or Bitcoin-format) sighash");
    }

    /// End-to-end validity self-check: a mnemonic (BIP86) node signs its own
    /// P2WPKH funding input; the returned PSBT carries a `PSBT_IN_PARTIAL_SIG`
    /// whose pubkey is the wallet key and whose signature validates against the
    /// BIP-143 sighash. Proves the funder path produces an on-chain-valid sig.
    #[test]
    fn signs_own_p2wpkh_funding_input() {
        // The Elements env override would force the wrong sighash format; skip.
        if matches!(
            std::env::var("SEQLN_SIGNER_NETWORK").ok().as_deref(),
            Some("elements") | Some("liquid")
        ) {
            eprintln!("SKIP: SEQLN_SIGNER_NETWORK forces Elements");
            return;
        }

        let seed = crate::kernel::bip39_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        );
        let kernel = Kernel::new(seed.to_vec(), BIP32_VER_TEST_PUBLIC, BIP32_VER_TEST_PRIVATE);

        // The wallet key + P2WPKH scriptPubkey the node would fund into (bip86).
        let keyindex = 7u32;
        let pubkey = kernel.bip86_child_pubkey(keyindex);
        let keyhash = kernel::hash160(&pubkey);
        let spk: Vec<u8> = [0x00u8, 0x14].iter().copied().chain(keyhash).collect();

        let txid = [0x11u8; 32];
        let amount = 80_000u64;
        let tx_bytes = unsigned_tx(&txid, 79_000);
        let psbt = v0_psbt(&tx_bytes, amount, &spk);

        // Build the SIGN_WITHDRAWAL request (hsmd wire is big-endian).
        let mut w = Writer::new(msg::HSMD_SIGN_WITHDRAWAL);
        w.u16(1); // num_inputs
        w.bytes(&txid);
        w.u32(0); // vout
        w.u64(amount);
        w.u32(keyindex);
        w.bool(false); // legacy is_p2sh
        w.u16(spk.len() as u16);
        w.bytes(&spk);
        w.bool(false); // is_unilateral_close
        w.bool(false); // legacy is_in_coinbase
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        let req_msg = w.into_vec();

        // Drive the handler with an initialized signer.
        let secret = HsmSecret { seed, secret_type: 2, mnemonic: String::new() };
        let mut signer = Signer::new(secret);
        signer.kernel = Some(kernel);
        signer.hsm_version = 6;

        let reply = signer.h_sign_withdrawal(&req_msg).expect("withdrawal reply");

        // reply = type(107) || u32(len) || psbt
        assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), msg::HSMD_SIGN_WITHDRAWAL_REPLY);
        let rlen = u32::from_be_bytes([reply[2], reply[3], reply[4], reply[5]]) as usize;
        let rpsbt = &reply[6..6 + rlen];

        // The reply must be the request PSBT plus exactly one partial_sig record.
        assert!(rpsbt.len() > psbt.len(), "partial_sig not added");

        // Locate the partial_sig: key = 0x22, 0x02, <33 pubkey>; value = DER || 0x01.
        let mut key = vec![34u8, 0x02];
        key.extend_from_slice(&pubkey);
        let pos = rpsbt
            .windows(key.len())
            .position(|win| win == key.as_slice())
            .expect("partial_sig record for our pubkey present");
        let vp = pos + key.len();
        let vallen = rpsbt[vp] as usize;
        let value = &rpsbt[vp + 1..vp + 1 + vallen];
        let (der, sighash_byte) = value.split_at(value.len() - 1);
        assert_eq!(sighash_byte, &[SIGHASH_ALL as u8]);

        // Independently recompute the sighash + sig and compare (low-R is
        // deterministic, so a correct handler reproduces these exact bytes).
        let tx = wire::parse_bitcoin_tx(&tx_bytes).unwrap();
        let scriptcode = p2pkh_scriptcode(&keyhash);
        let hash =
            kernel::bitcoin_sighash_sw_v0(&tx, 0, &scriptcode, &amount.to_le_bytes(), SIGHASH_ALL);
        let sk = signer.kernel().bip86_child_privkey(keyindex);
        let expected = signer
            .kernel()
            .sign_low_r_der_libwally_checked(&hash, &sk, &pubkey)
            .expect("sig self-verifies");
        assert_eq!(der, expected.as_slice(), "signature is over the wrong sighash");
    }

    /// The taproot fix: a mnemonic (bip86) node self-funds a channel spending its
    /// OWN native P2TR (BIP-86 key-path) wallet UTXO — the real on-chain form the
    /// hosted node's funds take. Asserts the handler splices a PSBT_IN_TAP_KEY_SIG
    /// whose 64-byte Schnorr signature VERIFIES against the tweaked output key and
    /// the BIP-341 key-spend sighash (i.e. bitcoind will accept it), and prints the
    /// reply hex for the external libwally finalizer check.
    #[test]
    fn signs_own_p2tr_funding_input() {
        use bitcoin::hashes::Hash;
        use bitcoin::key::{Keypair, TapTweak};
        use bitcoin::secp256k1::{Message, Secp256k1};
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};

        if matches!(
            std::env::var("SEQLN_SIGNER_NETWORK").ok().as_deref(),
            Some("elements") | Some("liquid")
        ) {
            eprintln!("SKIP: SEQLN_SIGNER_NETWORK forces Elements");
            return;
        }

        let seed = crate::kernel::bip39_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        );
        let kernel = Kernel::new(seed.to_vec(), BIP32_VER_TEST_PUBLIC, BIP32_VER_TEST_PRIVATE);
        let secp = Secp256k1::new();

        // The node's own P2TR wallet output = BIP-86 tweak of the internal key.
        let keyindex = 3u32;
        let internal_sk = kernel.bip86_child_privkey(keyindex);
        let tweaked = Keypair::from_secret_key(&secp, &internal_sk)
            .tap_tweak(&secp, None)
            .to_keypair();
        let (out_xonly, _) = tweaked.x_only_public_key();
        let spk: Vec<u8> = [0x51u8, 0x20].iter().copied().chain(out_xonly.serialize()).collect();

        let txid = [0x22u8; 32];
        let amount = 200_000u64;

        // Unsigned tx: spend the P2TR input into a P2WSH funding output + change.
        let mut t = Vec::new();
        t.extend_from_slice(&2u32.to_le_bytes());
        t.push(0x01);
        t.extend_from_slice(&txid);
        t.extend_from_slice(&0u32.to_le_bytes());
        t.push(0x00);
        t.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        t.push(0x02);
        t.extend_from_slice(&150_000u64.to_le_bytes());
        let fund_spk: Vec<u8> = [0x00u8, 0x20].iter().copied().chain([7u8; 32]).collect();
        t.push(fund_spk.len() as u8);
        t.extend_from_slice(&fund_spk);
        t.extend_from_slice(&49_000u64.to_le_bytes());
        t.push(spk.len() as u8);
        t.extend_from_slice(&spk); // change back to a P2TR of ours
        t.extend_from_slice(&0u32.to_le_bytes());
        let tx_bytes = t;

        // v0 PSBT: global{tx} || input0{witness_utxo=P2TR} || out0{} || out1{}.
        let mut wu = amount.to_le_bytes().to_vec();
        wu.push(spk.len() as u8);
        wu.extend_from_slice(&spk);
        let mut p = Vec::new();
        p.extend_from_slice(b"psbt\xff");
        p.extend_from_slice(&[0x01, 0x00]);
        assert!(tx_bytes.len() < 0xfd);
        p.push(tx_bytes.len() as u8);
        p.extend_from_slice(&tx_bytes);
        p.push(0x00);
        p.extend_from_slice(&[0x01, 0x01]);
        p.push(wu.len() as u8);
        p.extend_from_slice(&wu);
        p.push(0x00); // input0 terminator
        p.push(0x00); // out0
        p.push(0x00); // out1
        let psbt = p;

        let mut w = Writer::new(msg::HSMD_SIGN_WITHDRAWAL);
        w.u16(1);
        w.bytes(&txid);
        w.u32(0);
        w.u64(amount);
        w.u32(keyindex);
        w.bool(false);
        w.u16(spk.len() as u16);
        w.bytes(&spk);
        w.bool(false);
        w.bool(false);
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        let req_msg = w.into_vec();

        let secret = HsmSecret { seed, secret_type: 2, mnemonic: String::new() };
        let mut signer = Signer::new(secret);
        signer.kernel = Some(kernel);
        signer.hsm_version = 6;

        let reply = signer.h_sign_withdrawal(&req_msg).expect("withdrawal reply");
        let rlen = u32::from_be_bytes([reply[2], reply[3], reply[4], reply[5]]) as usize;
        let rpsbt = &reply[6..6 + rlen];
        assert!(rpsbt.len() > psbt.len(), "tap_key_sig not added");

        // Locate the PSBT_IN_TAP_KEY_SIG record: keylen(01) 0x13 vallen(0x40) sig(64).
        let key = [0x01u8, 0x13, 0x40];
        let pos = rpsbt
            .windows(3)
            .position(|win| win == key)
            .expect("PSBT_IN_TAP_KEY_SIG record present");
        let sig_bytes = &rpsbt[pos + 3..pos + 3 + 64];
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes).unwrap();

        // Independently recompute the BIP-341 key-spend sighash and VERIFY the sig
        // against the output key — exactly what bitcoind checks on broadcast.
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&tx_bytes).unwrap();
        let txouts = vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        }];
        let sighash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&txouts), TapSighashType::Default)
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        secp.verify_schnorr(&sig, &msg, &out_xonly)
            .expect("taproot key-spend signature must verify against the output key");
    }
}

#[cfg(test)]
mod sweep_enforce_tests {
    //! The authoritative accept/reject proof for the watchtower custody fix: in
    //! enforce mode a DIRECT-TO-WALLET sweep (delayed_payment_to_us) is SIGNED
    //! byte-identically to permissive when its output is the node's own address,
    //! and REFUSED (None) when the output is redirected to an attacker — while
    //! permissive still signs it (so the fix is enforce-only, live flow untouched).
    use super::*;
    use crate::hsm_secret::HsmSecret;
    use crate::kernel::{Kernel, BIP32_VER_TEST_PRIVATE, BIP32_VER_TEST_PUBLIC};
    use crate::policy::Policy;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn compact(n: usize) -> Vec<u8> {
        assert!(n < 0xfd);
        vec![n as u8]
    }

    /// 1-in / 1-out Bitcoin sweep tx paying `out_spk`.
    fn sweep_tx(out_spk: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&2u32.to_le_bytes());
        t.push(0x01);
        t.extend_from_slice(&[0x33u8; 32]);
        t.extend_from_slice(&0u32.to_le_bytes());
        t.push(0x00);
        t.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        t.push(0x01);
        t.extend_from_slice(&90_000u64.to_le_bytes());
        t.extend_from_slice(&compact(out_spk.len()));
        t.extend_from_slice(out_spk);
        t.extend_from_slice(&0u32.to_le_bytes());
        t
    }

    /// v0 PSBT: global{unsigned tx} || input0{witness_utxo} || output0{}.
    fn sweep_psbt(tx: &[u8], in_amount: u64, in_spk: &[u8]) -> Vec<u8> {
        let mut wu = in_amount.to_le_bytes().to_vec();
        wu.extend_from_slice(&compact(in_spk.len()));
        wu.extend_from_slice(in_spk);
        let mut p = Vec::new();
        p.extend_from_slice(b"psbt\xff");
        p.extend_from_slice(&[0x01, 0x00]);
        p.extend_from_slice(&compact(tx.len()));
        p.extend_from_slice(tx);
        p.push(0x00);
        p.extend_from_slice(&[0x01, 0x01]);
        p.extend_from_slice(&compact(wu.len()));
        p.extend_from_slice(&wu);
        p.push(0x00);
        p.push(0x00);
        p
    }

    /// A SIGN_DELAYED_PAYMENT_TO_US (12) Request whose sweep output is `out_spk`.
    fn delayed_req(out_spk: &[u8]) -> Request {
        let tx = sweep_tx(out_spk);
        let in_spk: Vec<u8> = [0x00u8, 0x20].iter().copied().chain([0xabu8; 32]).collect();
        let psbt = sweep_psbt(&tx, 100_000, &in_spk);
        let wscript = vec![0x51u8]; // dummy scriptcode; Class A does not inspect it
        let mut w = Writer::new(msg::HSMD_SIGN_DELAYED_PAYMENT_TO_US);
        w.u64(0); // commit_num
        w.u32(tx.len() as u32);
        w.bytes(&tx);
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        w.u16(wscript.len() as u16);
        w.bytes(&wscript);
        Request {
            is_main: false,
            node_id: [7u8; 33],
            dbid: 1,
            capabilities: 0,
            hsmd_msg: w.into_vec(),
        }
    }

    fn signer(policy: Policy) -> Signer {
        let seed = crate::kernel::bip39_seed(MNEMONIC, "");
        let kernel = Kernel::new(seed.to_vec(), BIP32_VER_TEST_PUBLIC, BIP32_VER_TEST_PRIVATE);
        let secret = HsmSecret { seed, secret_type: 2, mnemonic: String::new() };
        let mut s = Signer::with_policy(secret, policy);
        s.kernel = Some(kernel);
        s.hsm_version = 6;
        s
    }

    #[test]
    fn delayed_sweep_accept_byte_exact_reject_tampered() {
        if matches!(
            std::env::var("SEQLN_SIGNER_NETWORK").ok().as_deref(),
            Some("elements") | Some("liquid")
        ) {
            eprintln!("SKIP: SEQLN_SIGNER_NETWORK forces Elements");
            return;
        }

        // The node's OWN sweep destination (bip86 p2wpkh, index 4).
        let permissive = signer(Policy::Permissive);
        let own_spk = permissive.wallet_sweep_script(4, false);
        assert!(permissive.own_sweep_script_set().contains(&own_spk));

        // (1) ACCEPT: enforce signs the honest sweep byte-identically to permissive.
        let legit = delayed_req(&own_spk);
        let perm_reply = permissive
            .h_sign_delayed_payment_to_us(&legit)
            .expect("permissive signs honest sweep");
        let enforce = signer(Policy::Enforce);
        let enf_reply = enforce
            .h_sign_delayed_payment_to_us(&delayed_req(&own_spk))
            .expect("enforce signs honest sweep");
        assert_eq!(
            perm_reply, enf_reply,
            "enforcement must be transparent to an honest sweep (byte-exact)"
        );
        assert!(perm_reply.len() > 2, "a signed reply carries the sig");

        // (2) REJECT: redirect the sweep to an ATTACKER address (flip the last
        // byte of the keyhash). Enforce refuses (None); permissive still signs.
        let mut attacker_spk = own_spk.clone();
        let last = attacker_spk.len() - 1;
        attacker_spk[last] ^= 0x01;
        assert!(!permissive.own_sweep_script_set().contains(&attacker_spk));

        let tampered = delayed_req(&attacker_spk);
        assert!(
            signer(Policy::Permissive)
                .h_sign_delayed_payment_to_us(&delayed_req(&attacker_spk))
                .is_some(),
            "permissive still signs a redirected sweep (enforce-only fix)"
        );
        assert!(
            signer(Policy::Enforce)
                .h_sign_delayed_payment_to_us(&tampered)
                .is_none(),
            "enforce must REFUSE a sweep paying a non-owned output"
        );
    }
}
