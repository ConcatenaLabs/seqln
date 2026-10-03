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
use crate::payments::{self, AssetKey, Limits, Offered, Plan};
use crate::policy::{self, ChannelState, ChannelStore, Htlc, Policy, Side, Split};
use crate::wire::{self, msg, BitcoinTx, Writer};
use bitcoin::secp256k1::SecretKey;

/// The hsmd wire version this device speaks, and the only one it accepts.
/// Below version 6, GET_PER_COMMITMENT_POINT(n) also returns the secret of
/// commitment n - 2, with no revocation behind it: a host that re-initialised
/// the device at an older version could read the secret of a commitment the
/// device has not revoked and still signs for broadcast, and hand it to the
/// peer. So an INIT whose highest offered version is below 6 is refused, the
/// first one and any later one alike, and the device never returns an old
/// secret with a point: a commitment's secret leaves it only through a
/// revocation it validated (REVOKE_COMMITMENT_TX). lightningd offers 5 to 6.
const OUR_MIN_VERSION: u32 = 6;
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
    /// The channel store changed (setup, forget, arm, a validated or signed
    /// commitment, a revocation) since the host last asked
    /// (`take_channels_dirty`) — the host's cue to re-persist `export_channels`.
    store_dirty: bool,
    /// The (peer node_id, dbid) of the most recent "no tracked channel"
    /// refusal, for the host's one-time re-arm recovery (`take_last_untracked`).
    /// A Cell because the validation paths that detect it take &self.
    last_untracked: std::cell::Cell<Option<([u8; 33], u64)>>,
    /// The payment limits (`crate::payments`); configured by the host, not
    /// persisted.
    limits: Limits,
    /// The current time (Unix seconds), set by the host before each request:
    /// approvals and charges expire against it. Left at 0, nothing expires.
    now: u64,
    /// Why the device would not sign what the current request asked for,
    /// when the reply still goes out (a withdrawal returned unsigned) or the
    /// handler can only answer the sentinel. `handle` turns a sentinel with a
    /// reason into `Outcome::Reject`; the host takes the rest
    /// (`take_refusal`) to log it.
    refusal: std::cell::RefCell<Option<String>>,
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
            limits: Limits::default(),
            now: 0,
            refusal: std::cell::RefCell::new(None),
        }
    }

    /// The reason the last request was refused, when its reply was not the
    /// refusal sentinel: a withdrawal the device returned without signing it
    /// (take-and-clear). The host logs it.
    pub fn take_refusal(&mut self) -> Option<String> {
        self.refusal.borrow_mut().take()
    }

    fn refuse(&self, reason: String) {
        *self.refusal.borrow_mut() = Some(reason);
    }

    /// Set the payment limits (the native binary reads them from the
    /// environment, the WASM build from the wallet).
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Set the current time, in Unix seconds.
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    /// Switch the signing policy at runtime. The browser build has no env, so
    /// the WASM binding calls this to select enforce vs permissive.
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    pub fn handle(&mut self, req: &Request) -> Outcome {
        *self.refusal.borrow_mut() = None;
        match self.dispatch(req) {
            // A handler that refused on policy grounds left its reason.
            Outcome::Sentinel => match self.refusal.borrow_mut().take() {
                Some(reason) => Outcome::Reject(reason),
                None => Outcome::Sentinel,
            },
            other => other,
        }
    }

    fn dispatch(&mut self, req: &Request) -> Outcome {
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
            // withdrawal / channel-funding tx (the funder role). A close
            // output among them is held to the close-output rule
            // (`sign_wallet_inputs_into_psbt`).
            msg::HSMD_SIGN_WITHDRAWAL => opt(self.h_sign_withdrawal(&req.hsmd_msg)),
            // SIGN_ANCHORSPEND (147): CPFP-bump a commitment by spending its
            // anchor output (funding-key partial sig) plus the node's own wallet
            // fee inputs. Advertised in CAPABILITIES but previously unhandled.
            msg::HSMD_SIGN_ANCHORSPEND => opt(self.h_sign_anchorspend(&req.hsmd_msg)),
            msg::HSMD_SIGN_MUTUAL_CLOSE_TX => self.sign_mutual_close_tx_checked(req),
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
            msg::HSMD_REVOKE_COMMITMENT_TX => self.revoke_commitment_tx_checked(req),
            msg::HSMD_VALIDATE_REVOCATION => {
                Outcome::Reply(empty_reply(msg::HSMD_VALIDATE_REVOCATION_REPLY))
            }
            msg::HSMD_GET_OUTPUT_SCRIPTPUBKEY => {
                opt(self.h_get_output_scriptpubkey(&req.hsmd_msg))
            }
            msg::HSMD_SIGN_INVOICE => opt(self.h_sign_invoice(&req.hsmd_msg)),
            // `pay` and `keysend` ask before they offer an HTLC; the answer
            // records the payment hash as approved, within the limits.
            msg::HSMD_PREAPPROVE_INVOICE | msg::HSMD_PREAPPROVE_INVOICE_CHECK => {
                self.preapprove(req, t)
            }
            msg::HSMD_PREAPPROVE_KEYSEND | msg::HSMD_PREAPPROVE_KEYSEND_CHECK => {
                self.preapprove(req, t)
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
        // Checked before anything changes: a refused INIT, the first or a
        // later one, leaves the device as it was.
        if OUR_MIN_VERSION > f.max_version || OUR_MAX_VERSION < f.min_version {
            return Outcome::Fatal(format!(
                "version {}-{} not valid: we need {}-{} (below version 6 a commitment \
                 point carries an old commitment's secret)",
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
        let point = self.kernel().per_commitment_point(&req.node_id, req.dbid, n);
        let mut w = Writer::new(msg::HSMD_GET_PER_COMMITMENT_POINT_REPLY);
        w.bytes(&point);
        // old_commitment_secret: never present (version 6; see OUR_MIN_VERSION).
        w.bool(false);
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
        if let Some(mut st) = parse_setup_channel(&req.hsmd_msg) {
            // channeld re-sends setup_channel at every start and the proxy
            // replays it after every reconnect: keep what this device has
            // learned about the channel since (ChannelState::merge_from).
            if let Some(old) = self.store.get(&req.node_id, req.dbid) {
                st.merge_from(old);
            }
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

    /// In enforce mode, the refusal for a commitment step on a channel that
    /// predates validation (`ChannelState::predates_validation`): the device
    /// does not know the channel's state before it, and does not take the
    /// host's word for it, so it signs no commitment, ours or the peer's, no
    /// revocation and no close for it. Its peer closes it.
    fn predating(&self, peer_id: &[u8; 33], dbid: u64) -> Option<String> {
        if !self.policy.is_enforce() {
            return None;
        }
        let st = self.store.get(peer_id, dbid)?;
        st.predates_validation.then(|| {
            format!(
                "channel {} of peer {} predates validation: it came from the store of a \
                 device that validated nothing, so this device signs no commitment step for \
                 it; its peer closes it",
                dbid,
                hexbytes(&peer_id[..4])
            )
        })
    }

    /// The channels that predate validation: (peer node_id, dbid, funding
    /// txid in internal order, funding output, funding amount). The host
    /// tells the user these channels are not carried over.
    pub fn predating_channels(&self) -> Vec<([u8; 33], u64, [u8; 32], u16, u64)> {
        self.store
            .predating()
            .into_iter()
            .map(|(&(node_id, dbid), st)| (node_id, dbid, st.funding_txid, st.funding_txout, st.funding_sats))
            .collect()
    }

    // =================================================================
    // Channel-store persistence + recovery (the host's restart contract).
    //
    // `setup_channel` is sent at channel creation and again at every channeld
    // start, but the revocation counters and the recorded balance come only
    // from the commitments the device has seen: a signer that lost them can
    // no longer tell a revoked commitment from the current one. The host of
    // this library persists the store: export after any frame that dirtied
    // it (setup, forget, a validated or signed commitment, a revocation),
    // before the reply leaves, and import on boot. The native binary does so
    // itself (`src/bin/seqln-signer.rs`); the WASM build hands the blob to
    // the wallet. The blob is authenticated by an HMAC keyed from the SEED
    // (domain-separated, no key material inside), so a tampered or foreign
    // blob fails import instead of poisoning validation.
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
        let (entries, ledger, closes) = policy::decode_channel_store(payload)?;
        let mut added = 0u32;
        for ((node_id, dbid), st) in entries {
            if self.store.insert_if_absent(node_id, dbid, st) {
                added += 1;
            }
        }
        let before = self.store.ledger.clone();
        self.store.ledger.merge_from(&ledger);
        let closes_changed = self.store.merge_closes(&closes);
        if added > 0 || self.store.ledger != before || closes_changed {
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

    /// The host could not persist the store it took: keep it marked as
    /// changed, so the host refuses every reply until a save succeeds (a
    /// re-sent request that changes nothing would otherwise be answered with
    /// the record of it still unsaved).
    pub fn mark_channels_dirty(&mut self) {
        self.store_dirty = true;
    }

    /// The most recent "no tracked channel" refusal (take-and-clear), as the
    /// host's cue to fetch that channel's parameters and `arm_channel`.
    pub fn take_last_untracked(&mut self) -> Option<([u8; 33], u64)> {
        self.last_untracked.take()
    }

    /// SIGN_COMMITMENT_TX (5): OUR own commitment, or the closing transaction
    /// lightningd rebroadcasts after a mutual close (it signs that with this
    /// same message). Validate by shape, then sign. Reply bytes are unchanged
    /// from M2b on accept.
    fn sign_commitment_tx_checked(&mut self, req: &Request) -> Outcome {
        if let Some((peer, dbid, ..)) = parse_own_commitment(&req.hsmd_msg) {
            if let Some(reason) = self.predating(&peer, dbid) {
                return Outcome::Reject(format!("SIGN_COMMITMENT_TX refused: {reason}"));
            }
        }
        if self.policy.is_enforce() {
            if let Err(reason) = self.check_own_commitment(&req.hsmd_msg) {
                return Outcome::Reject(format!("SIGN_COMMITMENT_TX refused: {reason}"));
            }
        }
        let reply = self.h_sign_commitment_tx(&req.hsmd_msg);
        if reply.is_some() {
            // lightningd signs a completed mutual close with this message
            // too: what it pays this wallet is a close output.
            if let Some((_, _, bt, _, _)) = parse_own_commitment(&req.hsmd_msg) {
                if !policy::is_commitment_shaped(&bt.tx) && self.store.record_close(bt.txid) {
                    self.store_dirty = true;
                }
            }
        }
        opt(reply)
    }

    /// SIGN_MUTUAL_CLOSE_TX (21): closingd's signature on a closing proposal.
    fn sign_mutual_close_tx_checked(&mut self, req: &Request) -> Outcome {
        if let Some(reason) = self.predating(&req.node_id, req.dbid) {
            return Outcome::Reject(format!("SIGN_MUTUAL_CLOSE_TX refused: {reason}"));
        }
        if self.policy.is_enforce() {
            let check = (|| {
                let st = self
                    .store
                    .get(&req.node_id, req.dbid)
                    .ok_or_else(|| self.untracked(&req.node_id, req.dbid))?;
                let mut r = wire::Reader::new(&req.hsmd_msg);
                r.u16().ok_or("malformed request")?;
                let bt = wire::read_bitcoin_tx(&mut r).ok_or("malformed request")?;
                let own_close = self.own_close_script(st);
                policy::validate_mutual_close(st, self.own_sweep_script_set(), own_close.as_deref(), &bt.tx)
            })();
            if let Err(reason) = check {
                return Outcome::Reject(format!("SIGN_MUTUAL_CLOSE_TX refused: {reason}"));
            }
        }
        let reply = self.h_sign_mutual_close_tx(req);
        if reply.is_some() {
            // Remember the close: what it pays this wallet is a close output,
            // whose spend the device signs only to its own scripts.
            let mut r = wire::Reader::new(&req.hsmd_msg);
            if let (Some(_), Some(bt)) = (r.u16(), wire::read_bitcoin_tx(&mut r)) {
                if self.store.record_close(bt.txid) {
                    self.store_dirty = true;
                }
            }
        }
        opt(reply)
    }

    /// REVOKE_COMMITMENT_TX (40): reveal the secret of OUR commitment n. Once
    /// revealed, the peer can take everything if commitment n is ever
    /// broadcast, so in enforce mode the device reveals n only when
    ///  * it has already revealed n (channeld re-sends a revocation after a
    ///    reconnect: the call is idempotent), or
    ///  * n is the next commitment to revoke (never skipping one), and the
    ///    commitment that replaces it, n + 1, has been validated in this
    ///    device's knowledge, so the node keeps a commitment it may broadcast.
    /// A device with no record of the channel's revocations (a store from
    /// before they were recorded, or a channel armed from the node) reveals
    /// only commitment 0 until it has validated a later commitment: it does
    /// not know which commitment is current, so it never takes the host's
    /// word for it. Every reveal advances `revoked_through`, and
    /// SIGN_COMMITMENT_TX refuses any commitment at or below it.
    fn revoke_commitment_tx_checked(&mut self, req: &Request) -> Outcome {
        let mut r = wire::Reader::new(&req.hsmd_msg);
        let n = match (r.u16(), r.u64()) {
            (Some(_), Some(n)) => n,
            _ => return Outcome::Sentinel,
        };
        if let Some(reason) = self.predating(&req.node_id, req.dbid) {
            return Outcome::Reject(format!("REVOKE_COMMITMENT_TX refused: {reason}"));
        }
        if self.policy.is_enforce() {
            let refusal = match self.store.get(&req.node_id, req.dbid) {
                None => Some(self.untracked(&req.node_id, req.dbid)),
                Some(st) => match (st.revoked_through, st.validated_through) {
                    (Some(r), _) if n <= r => None,
                    (Some(r), _) if n > r.saturating_add(1) => Some(format!(
                        "commitment {n} would skip the revocation of {}", r.saturating_add(1)
                    )),
                    (_, Some(v)) if v < n.saturating_add(1) => Some(format!(
                        "commitment {} is not validated (highest {v}): revoking {n} \
                         would leave no commitment to broadcast", n.saturating_add(1)
                    )),
                    (_, Some(_)) => None,
                    (None, None) if n == 0 => None,
                    (_, None) => Some(format!(
                        "no record of this channel's commitments: revoking {n} needs \
                         commitment {} validated first", n.saturating_add(1)
                    )),
                },
            };
            if let Some(reason) = refusal {
                return Outcome::Reject(format!("REVOKE_COMMITMENT_TX refused: {reason}"));
            }
        }
        let reply = self.h_revoke_commitment_tx(req);
        if reply.is_some() {
            if let Some(st) = self.store.get_mut(&req.node_id, req.dbid) {
                if st.revoked_through.map_or(true, |r| n > r) {
                    st.revoked_through = Some(n);
                    st.drop_revoked();
                    self.store_dirty = true;
                }
            }
        }
        opt(reply)
    }

    /// SIGN_REMOTE_COMMITMENT_TX (19): the PEER's commitment (the pure-LN
    /// fundee's theft vector). Full validation, then sign, and record what it
    /// pays this side (in permissive mode too, when it validates).
    fn sign_remote_commitment_tx_checked(&mut self, req: &Request) -> Outcome {
        if let Some(reason) = self.predating(&req.node_id, req.dbid) {
            return Outcome::Reject(format!("SIGN_REMOTE_COMMITMENT_TX refused: {reason}"));
        }
        let split = self.check_remote_commitment(req);
        let plan = match (&split, parse_remote_commitment(&req.hsmd_msg)) {
            (Ok((n, sp)), Some((bt, _, _, htlcs, _))) => {
                Some(self.payment_plan(&req.node_id, req.dbid, false, *n, &bt, &htlcs, sp))
            }
            _ => None,
        };
        if self.policy.is_enforce() {
            if let Err(reason) = &split {
                return Outcome::Reject(format!("SIGN_REMOTE_COMMITMENT_TX refused: {reason}"));
            }
            if let Some(p) = &plan {
                let check = match p {
                    Ok(p) => self.check_plan(p),
                    Err(e) => Err(e.clone()),
                };
                if let Err(reason) = check {
                    return Outcome::Reject(format!("SIGN_REMOTE_COMMITMENT_TX refused: {reason}"));
                }
            }
        }
        let reply = self.h_sign_remote_commitment_tx(req);
        if let (Some(_), Ok((n, sp))) = (&reply, split) {
            if let Some(st) = self.store.get_mut(&req.node_id, req.dbid) {
                if st.remote_split.map_or(true, |(m, _)| n >= m) {
                    st.remote_split = Some((n, sp));
                    self.store_dirty = true;
                }
            }
            if let Some(Ok(p)) = plan {
                self.apply_plan(&req.node_id, req.dbid, p);
            }
        }
        opt(reply)
    }

    /// VALIDATE_COMMITMENT_TX (35): OUR own local commitment (carries the HTLC
    /// set). Full validation, then return the usual next-per-commitment reply,
    /// and record the commitment's number, its txid (the one transaction
    /// SIGN_COMMITMENT_TX may sign for it) and what it pays this side.
    fn validate_commitment_tx_checked(&mut self, req: &Request) -> Outcome {
        if let Some(reason) = self.predating(&req.node_id, req.dbid) {
            return Outcome::Reject(format!("VALIDATE_COMMITMENT_TX refused: {reason}"));
        }
        let split = self.check_local_commitment(req);
        let plan = match (&split, parse_local_commitment(&req.hsmd_msg)) {
            (Ok((n, sp)), Some((bt, htlcs, _))) => {
                Some(self.payment_plan(&req.node_id, req.dbid, true, *n, &bt, &htlcs, sp))
            }
            _ => None,
        };
        if self.policy.is_enforce() {
            if let Err(reason) = &split {
                return Outcome::Reject(format!("VALIDATE_COMMITMENT_TX refused: {reason}"));
            }
            if let Some(p) = &plan {
                let check = match p {
                    Ok(p) => self.check_plan(p),
                    Err(e) => Err(e.clone()),
                };
                if let Err(reason) = check {
                    return Outcome::Reject(format!("VALIDATE_COMMITMENT_TX refused: {reason}"));
                }
            }
        }
        let reply = self.h_validate_commitment_tx(req);
        if reply.is_some() {
            if let (Some((bt, _, n)), Some(st)) = (
                parse_local_commitment(&req.hsmd_msg),
                self.store.get_mut(&req.node_id, req.dbid),
            ) {
                if st.validated_through.map_or(true, |v| n > v) {
                    st.validated_through = Some(n);
                    self.store_dirty = true;
                }
                if let Ok((_, sp)) = split {
                    if st.local_split.map_or(true, |(m, _)| n >= m) {
                        st.local_split = Some((n, sp));
                        self.store_dirty = true;
                    }
                    if st.record_validated(n, bt.txid) {
                        self.store_dirty = true;
                    }
                }
            }
            if let Some(Ok(p)) = plan {
                self.apply_plan(&req.node_id, req.dbid, p);
            }
        }
        opt(reply)
    }

    // =================================================================
    // Payment approval and velocity limits (`crate::payments`).
    // =================================================================

    /// PREAPPROVE_INVOICE (38), PREAPPROVE_KEYSEND (39) and their
    /// check-only forms (51, 52): approve the payment hash when the stated
    /// amount, with a routing-fee allowance, fits in the smallest allowance
    /// left among the device's channel assets (the request does not say which
    /// asset will pay). A check-only request records nothing. The reply is
    /// the one libhsmd gives, with the decision in it.
    fn preapprove(&mut self, req: &Request, t: u16) -> Outcome {
        let parsed = match t {
            msg::HSMD_PREAPPROVE_INVOICE | msg::HSMD_PREAPPROVE_INVOICE_CHECK => {
                parse_preapprove_invoice(&req.hsmd_msg, t == msg::HSMD_PREAPPROVE_INVOICE_CHECK)
                    .map(|(inv, check)| (payments::decode_bolt11(&inv), check))
            }
            _ => parse_preapprove_keysend(&req.hsmd_msg, t == msg::HSMD_PREAPPROVE_KEYSEND_CHECK)
                .map(|(hash, amount, check)| (Ok((hash, Some(amount))), check)),
        };
        let reply_type = match t {
            msg::HSMD_PREAPPROVE_INVOICE | msg::HSMD_PREAPPROVE_INVOICE_CHECK => {
                msg::HSMD_PREAPPROVE_INVOICE_REPLY
            }
            _ => msg::HSMD_PREAPPROVE_KEYSEND_REPLY,
        };
        let (decoded, check_only) = match parsed {
            Some(p) => p,
            None => return Outcome::Sentinel,
        };
        let decision = decoded.and_then(|(hash, amount)| {
            if self.policy.is_enforce() {
                self.payment_fits(amount)?;
            }
            Ok(hash)
        });
        match decision {
            Ok(hash) => {
                if !check_only {
                    self.store.ledger.prune(self.now, self.limits.period_secs);
                    self.store.ledger.approve(hash, self.now);
                    self.store_dirty = true;
                }
                Outcome::Reply(approve_reply(reply_type, true))
            }
            Err(reason) => {
                eprintln!("seqln-signer: PREAPPROVE declined: {reason}");
                Outcome::Reply(approve_reply(reply_type, false))
            }
        }
    }

    /// Whether a payment of `amount_msat` (and its fee allowance) fits in
    /// what every channel asset has left this period.
    fn payment_fits(&self, amount_msat: Option<u64>) -> Result<(), String> {
        let a = match amount_msat {
            Some(a) => a,
            None => return Ok(()),
        };
        let need = a.saturating_add(payments::fee_allowance_msat(a));
        let assets = self.store.assets();
        if assets.is_empty() {
            if let Some(l) = self.limits.default_atoms.map(|x| x.saturating_mul(1000)) {
                if need > l {
                    return Err(format!(
                        "a payment of {a} msat (with {} of fee allowance) is over the limit of \
                         {l} msat per {} s",
                        need - a,
                        self.limits.period_secs
                    ));
                }
            }
            return Ok(());
        }
        for asset in assets {
            if let Some(left) = self.store.ledger.remaining_msat(&self.limits, &asset, self.now) {
                if need > left {
                    return Err(format!(
                        "a payment of {a} msat (with {} of fee allowance) does not fit in the \
                         {left} msat left this period for asset {}",
                        need - a,
                        asset.display()
                    ));
                }
            }
        }
        Ok(())
    }

    /// What a commitment this device is about to sign (the peer's) or
    /// validate (ours) means for payments.
    #[allow(clippy::too_many_arguments)]
    fn payment_plan(
        &self,
        peer: &[u8; 33],
        dbid: u64,
        local: bool,
        n: u64,
        bt: &BitcoinTx,
        htlcs: &[Htlc],
        sp: &Split,
    ) -> Result<Plan, String> {
        let st = self.store.get(peer, dbid).ok_or_else(|| self.untracked(peer, dbid))?;
        let asset = commitment_asset(&bt.tx)?;
        let offered: Vec<Offered> = htlcs
            .iter()
            .filter(|h| h.side == Side::Local as u8)
            .map(|h| Offered { amount_msat: h.amount_msat, hash: h.payment_hash, cltv: h.cltv_expiry })
            .collect();
        let offered_atoms = offered.iter().fold(0u64, |s, h| s.saturating_add(h.amount_msat / 1000));
        let value = sp.share(st.is_outbound).saturating_add(offered_atoms);
        Ok(st.pay.plan(local, n, asset, value, offered))
    }

    /// Every HTLC the commitment newly offers carries an approved payment
    /// hash, and what it pays away fits in the asset's allowance.
    fn check_plan(&self, plan: &Plan) -> Result<(), String> {
        for h in &plan.new_offered {
            if !self.store.ledger.is_approved(&h.hash, self.now, self.limits.period_secs) {
                return Err(format!(
                    "it adds an HTLC we offer ({} msat, payment hash {}) for a payment that was \
                     not approved",
                    h.amount_msat,
                    hexbytes(&h.hash)
                ));
            }
        }
        self.store.ledger.check_spend(&self.limits, &plan.asset, plan.charge_msat, self.now)
    }

    /// Record a signed or validated commitment's plan: the channel's
    /// tracking, and the charge (in enforce mode).
    fn apply_plan(&mut self, peer: &[u8; 33], dbid: u64, plan: Plan) {
        if let Some(st) = self.store.get_mut(peer, dbid) {
            if st.pay != plan.track {
                st.pay = plan.track;
                self.store_dirty = true;
            }
        }
        if self.policy.is_enforce() && plan.charge_msat > 0 {
            self.store.ledger.prune(self.now, self.limits.period_secs);
            self.store.ledger.charge(plan.asset, plan.charge_msat, self.now);
            self.store_dirty = true;
        }
    }

    /// Full validation of a peer commitment (`side = REMOTE`): its number and
    /// what it pays this side.
    fn check_remote_commitment(&self, req: &Request) -> Result<(u64, Split), String> {
        let st = self
            .store
            .get(&req.node_id, req.dbid)
            .ok_or_else(|| self.untracked(&req.node_id, req.dbid))?;
        let (bt, remote_funding, remote_per_commit, htlcs, commit_num) =
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
        .map(|sp| (commit_num, sp))
    }

    /// Full validation of our local commitment (`side = LOCAL`); the point is
    /// OUR per-commitment point at `commit_num`, derived from our shaseed.
    /// The peer's signature on it must verify against the channel's remote
    /// funding key: a commitment counts as validated, for the revocation
    /// counters and for the balance a close is held to, only when the peer
    /// has committed to it, never on the host's word alone.
    fn check_local_commitment(&self, req: &Request) -> Result<(u64, Split), String> {
        let st = self
            .store
            .get(&req.node_id, req.dbid)
            .ok_or_else(|| self.untracked(&req.node_id, req.dbid))?;
        let (bt, htlcs, commit_num) =
            parse_local_commitment(&req.hsmd_msg).ok_or_else(|| "malformed request".to_string())?;
        let (sig, sighash) = parse_local_commitment_sig(&req.hsmd_msg)
            .ok_or_else(|| "malformed request (no peer signature)".to_string())?;
        if !self.peer_funding_sig_verifies(&req.node_id, req.dbid, st, &bt, &sig, sighash) {
            return Err(format!(
                "the peer's signature on commitment {commit_num} does not verify"
            ));
        }
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
        .map(|sp| (commit_num, sp))
    }

    /// Whether `sig` is the peer's signature, by the channel's remote funding
    /// key, over input 0 of `bt` spending the 2-of-2 funding output (the
    /// sighash read from the PSBT's funding value, as for our own signature).
    fn peer_funding_sig_verifies(
        &self,
        peer_id: &[u8; 33],
        dbid: u64,
        st: &ChannelState,
        bt: &BitcoinTx,
        sig: &[u8; 64],
        sighash: u8,
    ) -> bool {
        let s = self.kernel().channel_secrets(peer_id, dbid);
        let local_funding = self.kernel().pubkey_of(&s.funding);
        let wscript = self.kernel().funding_wscript(&local_funding, &st.remote_funding);
        let hash = match bt.tx.network {
            kernel::Network::Elements => match wire::psbt_input_value9(&bt.psbt, 0) {
                Some(v) => kernel::elements_sighash_sw_v0(&bt.tx, 0, &wscript, &v, sighash as u32),
                None => return false,
            },
            kernel::Network::Bitcoin => match wire::psbt_input_value_sats_le(&bt.psbt, 0) {
                Some(v) => kernel::bitcoin_sighash_sw_v0(&bt.tx, 0, &wscript, &v, sighash as u32),
                None => return false,
            },
        };
        self.kernel().verify_hash(&hash, sig, &st.remote_funding)
    }

    /// Validation of a msg-5 request (peer_id + dbid come from the MESSAGE).
    /// This is the signature that lets the host broadcast a commitment of
    /// ours, so a commitment is signed only when it is exactly a transaction
    /// this device validated in full (VALIDATE_COMMITMENT_TX: every output
    /// rebuilt from the channel keys, the peer's signature verified) and has
    /// not revoked: its txid must be in the channel's `validated` record.
    /// lightningd asks for nothing else; msg 5 carries no HTLC list, so a
    /// commitment it did not validate could pay anything to a P2WSH.
    /// Anything else spending the funding output is held to the mutual-close
    /// policy: lightningd signs the closing transaction it rebroadcasts with
    /// this message. A refusal of either reaches lightningd, which logs it
    /// and sends nothing for that transaction.
    fn check_own_commitment(&self, m: &[u8]) -> Result<(), String> {
        let (peer_id, dbid, bt, remote_funding, commit_num) =
            parse_own_commitment(m).ok_or_else(|| "malformed request".to_string())?;
        let st = self
            .store
            .get(&peer_id, dbid)
            .ok_or_else(|| self.untracked(&peer_id, dbid))?;
        if remote_funding != st.remote_funding {
            return Err("remote_funding_key differs from setup_channel".to_string());
        }
        if !policy::is_commitment_shaped(&bt.tx) {
            let own_close = self.own_close_script(st);
            return policy::validate_mutual_close(
                st, self.own_sweep_script_set(), own_close.as_deref(), &bt.tx);
        }
        let n = policy::commitment_number(self.kernel(), &peer_id, dbid, st, &bt.tx)
            .unwrap_or(commit_num);
        if let Some(r) = st.revoked_through {
            if n <= r {
                return Err(format!(
                    "commitment {n} is revoked (secrets revealed through {r})"
                ));
            }
        }
        if !st.is_validated(&bt.txid) {
            let known: Vec<u64> = st.validated.iter().map(|&(v, _)| v).collect();
            return Err(format!(
                "commitment {n} (txid {}) is not one this device validated \
                 (unrevoked validated commitments: {known:?})",
                display_txid(&bt.txid)
            ));
        }
        Ok(())
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

    /// The channel's local upfront shutdown script, when it is this device's:
    /// one of the wallet scripts its keys give at the index `setup_channel`
    /// named for it (P2WPKH, P2SH-wrapped P2WPKH or BIP-86 P2TR, of the
    /// BIP-86 or the legacy key, the forms lightningd's wallet recognises).
    fn own_close_script(&self, st: &ChannelState) -> Option<Vec<u8>> {
        let i = st.local_shutdown_wallet_index?;
        if st.local_shutdown_script.is_empty() || i >= 0x8000_0000 {
            return None;
        }
        let k = self.kernel();
        let p2sh = |wpkh: Vec<u8>| -> Vec<u8> {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(&kernel::hash160(&wpkh));
            s.push(0x87);
            s
        };
        let bip86 = k.p2wpkh_scriptpubkey(&k.bip86_child_pubkey(i));
        let legacy = k.p2wpkh_scriptpubkey(&k.bip32_child_pubkey(i));
        let candidates = [
            p2sh(bip86.clone()),
            p2sh(legacy.clone()),
            bip86,
            legacy,
            k.bip86_p2tr_scriptpubkey(i),
        ];
        candidates
            .iter()
            .any(|c| *c == st.local_shutdown_script)
            .then(|| st.local_shutdown_script.clone())
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
    /// htlc-to-us), which spends an output of channel (`peer_id`, `dbid`)'s
    /// commitment: every output the signature commits to pays one of the
    /// node's own scripts, in the channel's asset ([`Self::sweep_loss`]).
    /// With `bounded` (the sweep of our own commitment's to_local after its
    /// delay, a close output, which nothing hurries), what the signature lets
    /// leave those scripts is also within the payment limit of that asset. A
    /// penalty or an HTLC claim races the peer: it is never refused over its
    /// fee. Returns Err, with the reason left for `handle`, when enforce is
    /// on and a check fails. `label` names the handler.
    #[allow(clippy::too_many_arguments)]
    fn enforce_wallet_sweep(
        &self,
        label: &str,
        peer_id: &[u8; 33],
        dbid: u64,
        bt: &BitcoinTx,
        sign_index: usize,
        sighash: u32,
        bounded: bool,
    ) -> Result<(), ()> {
        if !self.policy.is_enforce() {
            return Ok(());
        }
        let check = self
            .check_sweep_outputs(bt, sign_index, sighash, self.own_sweep_script_set())
            .and_then(|()| self.sweep_loss(peer_id, dbid, bt, sign_index, sighash))
            .and_then(|(asset, loss)| {
                if bounded {
                    self.within_limit(&asset, loss, "what it lets leave this device")
                } else {
                    Ok(())
                }
            });
        match check {
            Ok(()) => Ok(()),
            Err(reason) => {
                self.refuse(format!("{label} refused: {reason}"));
                Err(())
            }
        }
    }

    /// What a Class A sweep signature lets leave this device's scripts, and in
    /// which asset. The input it signs is a close output of the channel, so
    /// its asset is the channel's: the one this device recorded from the
    /// channel's commitments, whatever the request names for the input (a
    /// segwit-v0 signature does not commit to the asset of the input it
    /// spends). For a channel it never validated a commitment of, it has
    /// only the request's word: that half of the bound rests on the request.
    ///  * SIGHASH_SINGLE|ANYONECANPAY commits to this input and output
    ///    `sign_index` only: the host may add inputs and outputs, so all the
    ///    input carries beyond that output, in the channel's asset, can leave.
    ///    The output must be in that asset.
    ///  * SIGHASH_ALL commits to every output: on Sequentia what leaves is
    ///    the fee outputs, on Bitcoin the input less every output.
    fn sweep_loss(
        &self,
        peer_id: &[u8; 33],
        dbid: u64,
        bt: &BitcoinTx,
        sign_index: usize,
        sighash: u32,
    ) -> Result<(AssetKey, u64), String> {
        let single = sighash & 0x1f == 0x03;
        let outs = &bt.tx.outputs;
        match bt.tx.network {
            kernel::Network::Bitcoin => {
                let v = u64::from_le_bytes(
                    wire::psbt_input_value_sats_le(&bt.psbt, sign_index)
                        .ok_or("the request gives no amount for the input")?,
                );
                let amount = |o: &kernel::TxOutput| -> u64 {
                    o.value.get(0..8).and_then(|b| b.try_into().ok()).map_or(0, u64::from_le_bytes)
                };
                let kept = if single {
                    outs.get(sign_index).map_or(0, amount)
                } else {
                    outs.iter().fold(0u64, |t, o| t.saturating_add(amount(o)))
                };
                Ok((AssetKey::Btc, v.saturating_sub(kept)))
            }
            kernel::Network::Elements => {
                let v = wire::psbt_input_value9(&bt.psbt, sign_index)
                    .and_then(|v| explicit_amount(&v))
                    .ok_or("the input's value is not explicit")?;
                let asset = match self.store.get(peer_id, dbid).and_then(|st| st.pay.asset) {
                    Some(a) => a,
                    None => wire::psbt_input_asset(&bt.psbt, sign_index)
                        .and_then(|a| explicit_asset(&a))
                        .ok_or("the input's asset is not explicit")?,
                };
                if single {
                    let o = outs
                        .get(sign_index)
                        .ok_or_else(|| format!("no output at sign index {sign_index}"))?;
                    if explicit_asset(&o.asset) != Some(asset) {
                        return Err(format!(
                            "output {sign_index} is not in the channel's asset {}",
                            asset.display()
                        ));
                    }
                    let kept = explicit_amount(&o.value)
                        .ok_or_else(|| format!("output {sign_index} has a blinded value"))?;
                    Ok((asset, v.saturating_sub(kept)))
                } else {
                    let mut fee = 0u64;
                    for (i, o) in outs.iter().enumerate().filter(|(_, o)| o.script.is_empty()) {
                        if explicit_asset(&o.asset) != Some(asset) {
                            return Err(format!("fee output {i} is not in the channel's asset"));
                        }
                        fee = fee.saturating_add(
                            explicit_amount(&o.value)
                                .ok_or_else(|| format!("fee output {i} has a blinded value"))?,
                        );
                    }
                    Ok((asset, fee))
                }
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
                self.refuse(format!("{label} refused: {reason}"));
                return Err(());
            }
        };
        let mut set = std::collections::HashSet::with_capacity(1);
        set.insert(spk);
        match self.check_sweep_outputs(bt, sign_index, sighash, &set) {
            Ok(()) => Ok(()),
            Err(reason) => {
                self.refuse(format!("{label} refused: {reason}"));
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
        if let Some(reason) = self.predating(&req.node_id, req.dbid) {
            self.refuse(format!("SIGN_REMOTE_HTLC_TX refused: {reason}"));
            return None;
        }
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
        self.enforce_wallet_sweep("SIGN_REMOTE_HTLC_TO_US", &req.node_id, req.dbid, &bt, 0, sighash, false).ok()?;
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
        self.enforce_wallet_sweep("SIGN_ANY_REMOTE_HTLC_TO_US", &peer_id, dbid, &bt, 0, sighash, false).ok()?;
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
        self.enforce_wallet_sweep("SIGN_DELAYED_PAYMENT_TO_US", &req.node_id, req.dbid, &bt, 0, SIGHASH_SINGLE_ACP, true).ok()?;
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
        self.enforce_wallet_sweep("SIGN_ANY_DELAYED_PAYMENT_TO_US", &peer_id, dbid, &bt, 0, SIGHASH_SINGLE_ACP, true).ok()?;
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
        self.enforce_wallet_sweep("SIGN_PENALTY_TO_US", peer_id, dbid, bt, 0, SIGHASH_SINGLE_ACP, false).ok()?;
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
        let out = self.sign_wallet_inputs_into_psbt("SIGN_WITHDRAWAL", &utxos, psbt)?;
        let mut w = Writer::new(msg::HSMD_SIGN_WITHDRAWAL_REPLY);
        w.u32(out.len() as u32);
        w.bytes(&out);
        Some(w.into_vec())
    }

    /// Sign every wallet input listed in `utxos` of `psbt`, splicing a
    /// PSBT_IN_PARTIAL_SIG (or PSBT_IN_TAP_KEY_SIG for a taproot input) per input,
    /// and return the mutated PSBT bytes. Shared by SIGN_WITHDRAWAL and
    /// SIGN_ANCHORSPEND (which additionally signs the anchor input with the
    /// funding key).
    ///
    /// A close output among the inputs (what a peer's commitment paid this
    /// side, which `hsm_utxo` marks with its channel, or what a mutual close
    /// this device signed paid it) is the user's coin coming off a channel.
    /// In enforce mode the device signs a transaction spending one only when
    /// every output but the fee pays one of its own wallet scripts and the
    /// fee is within the payment limit of its asset ([`Self::check_close_spend`]).
    /// Otherwise it signs nothing and returns the PSBT as it came, so the
    /// node, which cannot finalize it, sends nothing and keeps running; the
    /// reason goes to the host (`take_refusal`).
    fn sign_wallet_inputs_into_psbt(
        &self,
        label: &str,
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
        let spends = |u: &wire::HsmUtxo| {
            tx.inputs.iter().any(|i| i.txhash == u.txid && i.index == u.vout)
        };
        if self.policy.is_enforce()
            && utxos
                .iter()
                .any(|u| spends(u) && (u.close.is_some() || self.store.is_close(&u.txid)))
        {
            if let Err(reason) = self.check_close_spend(&tx, network, utxos) {
                self.refuse(format!("{label} refused: {reason}"));
                return Some(out);
            }
        }
        for utxo in utxos {
            // Match the utxo to its PSBT/tx input by outpoint (`wally_psbt_input_spends`).
            let Some(j) = tx
                .inputs
                .iter()
                .position(|i| i.txhash == utxo.txid && i.index == utxo.vout)
            else {
                continue;
            };
            // What a peer's commitment paid this side: the channel's payment
            // key signs it (`hsm_unilateral_close_privkey`).
            if let Some(ci) = &utxo.close {
                if let Some(next) = self.sign_close_input(&tx, network, j, utxo, ci, &out) {
                    out = next;
                }
                continue;
            }
            if utxo.is_unilateral_close {
                continue;
            }
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

    /// Sign input `j`, a their-unilateral-close output (`ci`), with the
    /// channel's payment key, as `hsm_key_for_utxo` derives it: the payment
    /// basepoint secret, tweaked by the commitment point when the output
    /// carries one. The key must reproduce the output's script (P2WPKH, or the
    /// anchor channel's CSV-1 P2WSH, whose witness script is added to the
    /// input for the node's finalizer); otherwise nothing is signed.
    fn sign_close_input(
        &self,
        tx: &kernel::ElementsTx,
        network: kernel::Network,
        j: usize,
        utxo: &wire::HsmUtxo,
        ci: &wire::CloseInfo,
        psbt: &[u8],
    ) -> Option<Vec<u8>> {
        let s = self.kernel().channel_secrets(&ci.peer_id, ci.channel_id);
        let sk = match &ci.commitment_point {
            None => s.payment,
            Some(cp) => self.kernel().derive_simple_privkey(&s.payment, cp),
        };
        let pubkey = self.kernel().pubkey_of(&sk);
        let keyhash = kernel::hash160(&pubkey);
        let (spk, scriptcode, wscript) = if ci.option_anchors {
            let ws = policy::to_remote_anchored_wscript(&pubkey, ci.csv);
            (policy::p2wsh_spk(&ws), ws.clone(), Some(ws))
        } else {
            (self.kernel().p2wpkh_scriptpubkey(&pubkey), p2pkh_scriptcode(&keyhash), None)
        };
        if spk != utxo.script_pubkey {
            return None;
        }
        let hash = match network {
            kernel::Network::Bitcoin => {
                kernel::bitcoin_sighash_sw_v0(tx, j, &scriptcode, &utxo.amount.to_le_bytes(), SIGHASH_ALL)
            }
            kernel::Network::Elements => {
                let mut v9 = [0u8; 9];
                v9[0] = 0x01;
                v9[1..].copy_from_slice(&utxo.amount.to_be_bytes());
                kernel::elements_sighash_sw_v0(tx, j, &scriptcode, &v9, SIGHASH_ALL)
            }
        };
        let der = self.kernel().sign_low_r_der_libwally_checked(&hash, &sk, &pubkey)?;
        let mut rec = partial_sig_record(&pubkey, &der, SIGHASH_ALL as u8);
        if let Some(ws) = wscript {
            if !wire::psbt_input_has_key(psbt, j, &[0x05])? {
                // PSBT_IN_WITNESS_SCRIPT: the node's `psbt_finalize` builds
                // the anchor to_remote witness from it.
                rec.extend_from_slice(&compact_size(1));
                rec.push(0x05);
                rec.extend_from_slice(&compact_size(ws.len()));
                rec.extend_from_slice(&ws);
            }
        }
        let term = wire::psbt_input_map_terminator(psbt, j)?;
        let mut next = Vec::with_capacity(psbt.len() + rec.len());
        next.extend_from_slice(&psbt[..term]);
        next.extend_from_slice(&rec);
        next.extend_from_slice(&psbt[term..]);
        Some(next)
    }

    /// The close-output rule, for a transaction that spends one (enforce
    /// mode): every output but the fee pays one of this device's own wallet
    /// scripts ([`Self::own_sweep_script_set`]), unblinded, and what leaves
    /// those scripts, the fee, is at most the payment limit of its asset.
    /// On Sequentia the fee is the explicit fee output, which the signature
    /// commits to with every other output; on Bitcoin it is what the inputs
    /// this device signs carry beyond the outputs (each signature commits to
    /// its own input's amount, and inputs it does not sign only add value).
    fn check_close_spend(
        &self,
        tx: &kernel::ElementsTx,
        network: kernel::Network,
        utxos: &[wire::HsmUtxo],
    ) -> Result<(), String> {
        let own = self.own_sweep_script_set();
        let mut fees: std::collections::BTreeMap<AssetKey, u64> = Default::default();
        let mut paid: u64 = 0;
        for (i, o) in tx.outputs.iter().enumerate() {
            if network == kernel::Network::Elements && o.script.is_empty() {
                let asset = explicit_asset(&o.asset)
                    .ok_or_else(|| format!("fee output {i} has a blinded asset"))?;
                let v = explicit_amount(&o.value)
                    .ok_or_else(|| format!("fee output {i} has a blinded value"))?;
                let f = fees.entry(asset).or_insert(0);
                *f = f.saturating_add(v);
                continue;
            }
            if !own.contains(&o.script) {
                return Err(format!(
                    "output {i} pays {}, which is not one of this device's own scripts: \
                     what a channel close paid it goes only to its own addresses",
                    hexbytes(&o.script)
                ));
            }
            match network {
                kernel::Network::Elements => {
                    if explicit_asset(&o.asset).is_none()
                        || explicit_amount(&o.value).is_none()
                        || o.nonce != [0x00]
                    {
                        return Err(format!("output {i} is blinded"));
                    }
                }
                kernel::Network::Bitcoin => {
                    let v = u64::from_le_bytes(o.value.get(0..8).and_then(|b| b.try_into().ok())
                        .ok_or_else(|| format!("output {i} has no amount"))?);
                    paid = paid.saturating_add(v);
                }
            }
        }
        if network == kernel::Network::Bitcoin {
            let signed = utxos
                .iter()
                .filter(|u| tx.inputs.iter().any(|i| i.txhash == u.txid && i.index == u.vout))
                .fold(0u64, |t, u| t.saturating_add(u.amount));
            fees.insert(AssetKey::Btc, signed.saturating_sub(paid));
        }
        for (asset, fee) in fees {
            self.within_limit(&asset, fee, "its fee")?;
        }
        Ok(())
    }

    /// `what` (`amount` atoms of `asset` leaving this device's scripts) is at
    /// most the payment limit for `asset`.
    fn within_limit(&self, asset: &AssetKey, amount: u64, what: &str) -> Result<(), String> {
        match self.limits.limit_msat(asset).map(|l| l / 1000) {
            Some(limit) if amount > limit => Err(format!(
                "{what}, {amount} atoms of {}, is over this device's payment limit for that \
                 asset ({limit} atoms)",
                asset.display()
            )),
            _ => Ok(()),
        }
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
        let out = self.sign_wallet_inputs_into_psbt("SIGN_ANCHORSPEND", &utxos, psbt)?;
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

/// An explicit asset as it serializes (`0x01 || id`), as an [`AssetKey`].
fn explicit_asset(a: &[u8]) -> Option<AssetKey> {
    match a {
        [0x01, id @ ..] if id.len() == 32 => Some(AssetKey::Asset(id.try_into().ok()?)),
        _ => None,
    }
}

/// An explicit value as it serializes (`0x01 || u64 big-endian`).
fn explicit_amount(v: &[u8]) -> Option<u64> {
    match v {
        [0x01, b @ ..] if b.len() == 8 => Some(u64::from_be_bytes(b.try_into().ok()?)),
        _ => None,
    }
}

/// A Bitcoin compact size.
fn compact_size(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => {
            let mut v = vec![0xfd];
            v.extend_from_slice(&(n as u16).to_le_bytes());
            v
        }
        _ => {
            let mut v = vec![0xfe];
            v.extend_from_slice(&(n as u32).to_le_bytes());
            v
        }
    }
}

fn opt(o: Option<Vec<u8>>) -> Outcome {
    match o {
        Some(b) => Outcome::Reply(b),
        None => Outcome::Sentinel,
    }
}

/// A txid in the byte order explorers and RPCs display (reversed).
fn display_txid(txid: &[u8; 32]) -> String {
    let mut d = *txid;
    d.reverse();
    hexbytes(&d)
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
    let is_outbound = r.bool()?;
    let funding_sats = r.u64()?; // amount_sat
    let _push_msat = r.u64()?; // amount_msat
    let funding_txid = r.arr32()?;
    let funding_txout = r.u16()?;
    let local_to_self_delay = r.u16()?;
    let lsl = r.u16()? as usize;
    let local_shutdown_script = r.take_bytes(lsl)?;
    let local_shutdown_wallet_index = if r.bool()? { Some(r.u32()?) } else { None };
    let remote_revocation = r.arr33()?;
    let remote_payment = r.arr33()?;
    let remote_htlc = r.arr33()?;
    let remote_delayed = r.arr33()?;
    let remote_funding = r.arr33()?;
    let remote_to_self_delay = r.u16()?;
    let rsl = r.u16()? as usize;
    let remote_shutdown_script = r.take_bytes(rsl)?;
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
        is_outbound: Some(is_outbound),
        local_shutdown_script,
        remote_shutdown_script,
        local_shutdown_wallet_index,
        revoked_through: None,
        validated_through: None,
        local_split: None,
        remote_split: None,
        validated: Vec::new(),
        pay: Default::default(),
        predates_validation: false,
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

/// Parse `hsmd_sign_remote_commitment_tx` ->
/// (tx, remote_funding, remote_per_commit, htlcs, commit_num).
#[allow(clippy::type_complexity)]
fn parse_remote_commitment(m: &[u8]) -> Option<(BitcoinTx, [u8; 33], [u8; 33], Vec<Htlc>, u64)> {
    let mut r = wire::Reader::new(m);
    r.u16()?;
    let bt = wire::read_bitcoin_tx(&mut r)?;
    let remote_funding = r.arr33()?;
    let remote_per_commit = r.arr33()?;
    let _static_remotekey = r.bool()?;
    let commit_num = r.u64()?;
    let num_htlcs = r.u16()? as usize;
    let htlcs = read_htlcs(&mut r, num_htlcs)?;
    Some((bt, remote_funding, remote_per_commit, htlcs, commit_num))
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

/// The peer's signature a `hsmd_validate_commitment_tx` carries after its
/// commitment number and feerate: (64-byte compact signature, sighash type).
fn parse_local_commitment_sig(m: &[u8]) -> Option<([u8; 64], u8)> {
    let mut r = wire::Reader::new(m);
    r.u16()?;
    let _bt = wire::read_bitcoin_tx(&mut r)?;
    let num_htlcs = r.u16()? as usize;
    r.skip(num_htlcs * HSM_HTLC_LEN)?;
    let _commit_num = r.u64()?;
    let _feerate = r.u32()?;
    let sig: [u8; 64] = r.take_bytes(64)?.try_into().ok()?;
    let sighash = r.u8()?;
    Some((sig, sighash))
}

/// Parse `hsmd_sign_commitment_tx` ->
/// (peer_id, dbid, tx, remote_funding, commit_num).
#[allow(clippy::type_complexity)]
fn parse_own_commitment(m: &[u8]) -> Option<([u8; 33], u64, BitcoinTx, [u8; 33], u64)> {
    let mut r = wire::Reader::new(m);
    r.u16()?;
    let peer_id = r.arr33()?;
    let dbid = r.u64()?;
    let bt = wire::read_bitcoin_tx(&mut r)?;
    let remote_funding = r.arr33()?;
    let commit_num = r.u64()?;
    Some((peer_id, dbid, bt, remote_funding, commit_num))
}

fn approve_reply(reply_type: u16, approved: bool) -> Vec<u8> {
    let mut w = Writer::new(reply_type);
    w.bool(approved);
    w.into_vec()
}

/// Parse `hsmd_preapprove_invoice` (a NUL-terminated `wirestring`) or its
/// check form (then `check_only`) -> (invoice, check_only).
fn parse_preapprove_invoice(m: &[u8], with_check: bool) -> Option<(String, bool)> {
    let body = m.get(2..)?;
    let nul = body.iter().position(|&b| b == 0)?;
    let inv = std::str::from_utf8(&body[..nul]).ok()?.to_string();
    let mut r = wire::Reader::new(&body[nul + 1..]);
    let check = if with_check { r.bool()? } else { false };
    Some((inv, check))
}

/// Parse `hsmd_preapprove_keysend` (destination, payment_hash, amount_msat)
/// or its check form -> (payment_hash, amount_msat, check_only).
fn parse_preapprove_keysend(m: &[u8], with_check: bool) -> Option<([u8; 32], u64, bool)> {
    let mut r = wire::Reader::new(m);
    r.u16()?;
    let _destination = r.arr33()?;
    let hash = r.arr32()?;
    let amount = r.u64()?;
    let check = if with_check { r.bool()? } else { false };
    Some((hash, amount, check))
}

/// The asset a commitment is in: every output of a channel carries the
/// channel's asset (an explicit asset tag on Elements, the fee output too);
/// a Bitcoin commitment is in bitcoin.
fn commitment_asset(tx: &kernel::ElementsTx) -> Result<AssetKey, String> {
    match tx.network {
        kernel::Network::Bitcoin => Ok(AssetKey::Btc),
        kernel::Network::Elements => {
            let a = &tx.outputs.first().ok_or("commitment has no outputs")?.asset;
            if a.len() == 33 && a[0] == 0x01 {
                Ok(AssetKey::Asset(a[1..].try_into().unwrap()))
            } else {
                Err("commitment output has a non-explicit asset".to_string())
            }
        }
    }
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

/// Enforce mode around a channel's close and its revocations: a closing
/// transaction is checked as a close (and signed when it pays this wallet and
/// the peer), a commitment whose secret was revealed is never signed, and
/// revocation only moves forward.
#[cfg(test)]
mod close_and_revocation_tests {
    use super::*;
    use crate::hsm_secret::HsmSecret;
    use crate::kernel::{Kernel, BIP32_VER_TEST_PRIVATE, BIP32_VER_TEST_PUBLIC};
    use crate::policy::Policy;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const PEER: [u8; 33] = [0x02; 33];
    const DBID: u64 = 3;
    const FUNDING_TXID: [u8; 32] = [0x44; 32];
    const FUNDING: u64 = 1_000_000;

    fn signer(policy: Policy) -> Signer {
        let seed = crate::kernel::bip39_seed(MNEMONIC, "");
        let kernel = Kernel::new(seed.to_vec(), BIP32_VER_TEST_PUBLIC, BIP32_VER_TEST_PRIVATE);
        let secret = HsmSecret { seed, secret_type: 2, mnemonic: String::new() };
        let mut s = Signer::with_policy(secret, policy);
        s.kernel = Some(kernel);
        s.hsm_version = 6;
        s
    }

    fn point(s: &Signer, k: u8) -> [u8; 33] {
        s.kernel().pubkey_of(&SecretKey::from_slice(&[k; 32]).unwrap())
    }

    fn setup_msg(s: &Signer, outbound: bool, remote_shutdown: &[u8]) -> Vec<u8> {
        let mut w = Writer::new(msg::HSMD_SETUP_CHANNEL);
        w.bool(outbound);
        w.u64(FUNDING);
        w.u64(0); // push
        w.bytes(&FUNDING_TXID);
        w.u16(0); // funding_txout
        w.u16(144); // local_to_self_delay
        w.u16(0); // no local upfront shutdown script
        w.bool(false); // no wallet index
        for k in 1..=5u8 {
            w.bytes(&point(s, k)); // revocation, payment, htlc, delayed, funding
        }
        w.u16(144); // remote_to_self_delay
        w.u16(remote_shutdown.len() as u16);
        w.bytes(remote_shutdown);
        w.u16(2); // channel_type: option_static_remotekey (bit 12)
        w.bytes(&[0x10, 0x00]);
        w.into_vec()
    }

    fn req(msg: Vec<u8>) -> Request {
        Request { is_main: false, node_id: PEER, dbid: DBID, capabilities: 0, hsmd_msg: msg }
    }

    fn track(s: &mut Signer, outbound: bool, remote_shutdown: &[u8]) {
        let m = setup_msg(s, outbound, remote_shutdown);
        assert!(matches!(s.handle(&req(m)), Outcome::Reply(_)));
    }

    fn revoke(s: &mut Signer, n: u64) -> Outcome {
        let mut w = Writer::new(msg::HSMD_REVOKE_COMMITMENT_TX);
        w.u64(n);
        s.handle(&req(w.into_vec()))
    }

    fn st(s: &Signer) -> &ChannelState {
        s.store.get(&PEER, DBID).expect("tracked")
    }

    fn compact(n: usize) -> Vec<u8> {
        assert!(n < 0xfd);
        vec![n as u8]
    }

    /// An unsigned Elements transaction spending the funding outpoint, with
    /// explicit outputs in one asset.
    fn elements_tx(input: [u8; 32], locktime: u32, sequence: u32, outs: &[(Vec<u8>, u64)]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&2u32.to_le_bytes());
        t.push(0x00); // no witness
        t.push(0x01);
        t.extend_from_slice(&input);
        t.extend_from_slice(&0u32.to_le_bytes());
        t.push(0x00); // scriptSig
        t.extend_from_slice(&sequence.to_le_bytes());
        t.extend_from_slice(&compact(outs.len()));
        for (script, value) in outs {
            t.push(0x01);
            t.extend_from_slice(&[0x55; 32]);
            t.push(0x01);
            t.extend_from_slice(&value.to_be_bytes());
            t.push(0x00); // nonce
            t.extend_from_slice(&compact(script.len()));
            t.extend_from_slice(script);
        }
        t.extend_from_slice(&locktime.to_le_bytes());
        t
    }

    /// A PSBT whose input 0 spends the funding output: an explicit Elements
    /// witness_utxo, all the signer reads from it.
    fn funding_psbt() -> Vec<u8> {
        let mut wu = vec![0x01];
        wu.extend_from_slice(&[0x55; 32]);
        wu.push(0x01);
        wu.extend_from_slice(&FUNDING.to_be_bytes());
        wu.push(0x00);
        wu.push(34);
        wu.extend_from_slice(&[0x00, 0x20]);
        wu.extend_from_slice(&[0x66; 32]);
        let mut p = b"psbt\xff".to_vec();
        p.push(0x00); // empty global map
        p.extend_from_slice(&[0x01, 0x01]);
        p.extend_from_slice(&compact(wu.len()));
        p.extend_from_slice(&wu);
        p.push(0x00);
        p
    }

    /// SIGN_COMMITMENT_TX (msg 5) for `tx`, claiming commitment `claimed`.
    fn sign_commitment_msg(s: &Signer, tx: &[u8], claimed: u64) -> Vec<u8> {
        let psbt = funding_psbt();
        let mut w = Writer::new(msg::HSMD_SIGN_COMMITMENT_TX);
        w.bytes(&PEER);
        w.u64(DBID);
        w.u32(tx.len() as u32);
        w.bytes(tx);
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        w.bytes(&point(s, 5));
        w.u64(claimed);
        w.into_vec()
    }

    /// Our commitment number `n`, obscured into (locktime, sequence) as BOLT 3
    /// has it for this channel, opened by us.
    fn obscured(s: &Signer, n: u64) -> (u32, u32) {
        use bitcoin::hashes::{sha256, Hash};
        let ours = s.kernel().channel_basepoints(&PEER, DBID)[1];
        let mut pre = ours.to_vec();
        pre.extend_from_slice(&point(s, 2));
        let h = sha256::Hash::hash(&pre).to_byte_array();
        let mut f = 0u64;
        for b in &h[26..32] {
            f = (f << 8) | *b as u64;
        }
        let o = n ^ f;
        (0x2000_0000 | (o & 0xff_ffff) as u32, 0x8000_0000 | ((o >> 24) & 0xff_ffff) as u32)
    }

    fn close(input: [u8; 32], outs: &[(Vec<u8>, u64)]) -> Vec<u8> {
        elements_tx(input, 0, 0xffff_ffff, outs)
    }

    fn peer_script() -> Vec<u8> {
        [0x00u8, 0x14].iter().copied().chain([0x99; 20]).collect()
    }

    #[test]
    fn revocation_only_moves_forward() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        // A device with no record of the channel's commitments reveals none
        // but commitment 0, until it validates a later one.
        match revoke(&mut s, 5) {
            Outcome::Reject(r) => assert!(r.contains("no record"), "{r}"),
            _ => panic!("revoking 5 with no record must be refused"),
        }
        assert!(matches!(revoke(&mut s, 0), Outcome::Reply(_)));
        match revoke(&mut s, 1) {
            Outcome::Reject(r) => assert!(r.contains("no record"), "{r}"),
            _ => panic!("revoking 1 with nothing validated must be refused"),
        }
        s.store.get_mut(&PEER, DBID).unwrap().revoked_through = Some(5);
        s.store.get_mut(&PEER, DBID).unwrap().validated_through = Some(6);
        // Re-sending a revealed secret is harmless (channeld does, on reconnect).
        assert!(matches!(revoke(&mut s, 5), Outcome::Reply(_)));
        assert!(matches!(revoke(&mut s, 3), Outcome::Reply(_)));
        assert_eq!(st(&s).revoked_through, Some(5));
        // Skipping a commitment is refused.
        match revoke(&mut s, 7) {
            Outcome::Reject(r) => assert!(r.contains("would skip"), "{r}"),
            _ => panic!("revoking 7 after 5 must be refused"),
        }
        // The next one needs its replacement validated first.
        match revoke(&mut s, 6) {
            Outcome::Reject(r) => assert!(r.contains("not validated"), "{r}"),
            _ => panic!("revoking 6 with only 6 validated must be refused"),
        }
        s.store.get_mut(&PEER, DBID).unwrap().validated_through = Some(7);
        assert!(matches!(revoke(&mut s, 6), Outcome::Reply(_)));
        assert_eq!(st(&s).revoked_through, Some(6));
        // Permissive mode signs as asked (the kill-switch), and still counts.
        s.set_policy(Policy::Permissive);
        assert!(matches!(revoke(&mut s, 9), Outcome::Reply(_)));
        assert_eq!(st(&s).revoked_through, Some(9));
    }

    #[test]
    fn revoked_commitment_is_never_signed() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        let c = |s: &Signer, n: u64| local_commitment(s, n, 600_000, 399_000, 1_000);
        for n in 0..3 {
            assert!(matches!(validate(&mut s, n, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        }
        // The current commitment 2 signs.
        let m = sign_commitment_msg(&s, &c(&s, 2), 2);
        assert_eq!(s.check_own_commitment(&m), Ok(()));
        assert!(matches!(s.handle(&req(m)), Outcome::Reply(_)));
        // Commitments 0 and 1 are revoked.
        assert!(matches!(revoke(&mut s, 0), Outcome::Reply(_)));
        assert!(matches!(revoke(&mut s, 1), Outcome::Reply(_)));
        assert_eq!(st(&s).validated.iter().map(|v| v.0).collect::<Vec<_>>(), vec![2]);
        let m = sign_commitment_msg(&s, &c(&s, 1), 1);
        let err = s.check_own_commitment(&m).unwrap_err();
        assert!(err.contains("commitment 1 is revoked"), "{err}");
        // The number is read off the transaction: claiming the current one
        // for an old transaction changes nothing.
        let m = sign_commitment_msg(&s, &c(&s, 0), 2);
        let err = s.check_own_commitment(&m).unwrap_err();
        assert!(err.contains("commitment 0 is revoked"), "{err}");
        assert!(matches!(s.handle(&req(m.clone())), Outcome::Reject(_)));
        let m = sign_commitment_msg(&s, &c(&s, 2), 2);
        assert_eq!(s.check_own_commitment(&m), Ok(()));
    }

    #[test]
    fn closing_transaction_signs_as_a_close() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        assert!(matches!(validate(&mut s, 0, 500_000, 499_000, 1_000), Outcome::Reply(_)));
        let ours = s.wallet_sweep_script(4, false);
        let good = close(FUNDING_TXID, &[(ours.clone(), 500_000), (peer_script(), 499_000), (Vec::new(), 1_000)]);
        // As msg 5 (lightningd's rebroadcast at closing complete and at start).
        let m = sign_commitment_msg(&s, &good, 7);
        assert_eq!(s.check_own_commitment(&m), Ok(()));
        assert!(matches!(s.handle(&req(m)), Outcome::Reply(_)));
        // The same outputs in a commitment's shape are not a close: they are
        // a commitment this device never validated.
        let (lt, sq) = obscured(&s, 7);
        let shaped = elements_tx(FUNDING_TXID, lt, sq,
                                 &[(ours.clone(), 500_000), (peer_script(), 499_000), (Vec::new(), 1_000)]);
        let err = s.check_own_commitment(&sign_commitment_msg(&s, &shaped, 7)).unwrap_err();
        assert!(err.contains("commitment 7"), "{err}");
        assert!(err.contains("is not one this device validated"), "{err}");

        let refuse = |s: &Signer, tx: Vec<u8>, why: &str| {
            let err = s.check_own_commitment(&sign_commitment_msg(s, &tx, 7)).unwrap_err();
            assert!(err.contains(why), "{err}");
        };
        // Our share somewhere else, beside the peer's: two outputs not ours.
        refuse(&s, close(FUNDING_TXID, &[(peer_script(), 500_000), ([0x00u8, 0x14].iter().copied().chain([0x98; 20]).collect(), 499_000)]), "to the peer");
        // Value created.
        refuse(&s, close(FUNDING_TXID, &[(ours.clone(), 600_000), (peer_script(), 499_000)]), "value created");
        // Not the funding output.
        refuse(&s, close([0x45; 32], &[(ours.clone(), 500_000)]), "funding outpoint");

        // With the peer's upfront shutdown script recorded, the peer's share
        // must go there.
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &peer_script());
        assert!(matches!(validate(&mut s, 0, 500_000, 499_000, 1_000), Outcome::Reply(_)));
        assert_eq!(s.check_own_commitment(&sign_commitment_msg(&s, &good, 7)), Ok(()));
        refuse(&s, close(FUNDING_TXID, &[(ours.clone(), 500_000), ([0x51u8].to_vec(), 499_000)]), "recorded");
        // closingd's own request is held to the same policy.
        let mut w = Writer::new(msg::HSMD_SIGN_MUTUAL_CLOSE_TX);
        let bad = close(FUNDING_TXID, &[(ours, 500_000), ([0x51u8].to_vec(), 499_000)]);
        let psbt = funding_psbt();
        w.u32(bad.len() as u32);
        w.bytes(&bad);
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        w.bytes(&point(&s, 5));
        assert!(matches!(s.handle(&req(w.into_vec())), Outcome::Reject(_)));
    }

    #[test]
    fn setup_resend_keeps_what_the_device_learned() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &peer_script());
        s.store.get_mut(&PEER, DBID).unwrap().validated_through = Some(5);
        assert!(matches!(revoke(&mut s, 4), Outcome::Reply(_)));
        // channeld's re-send at start names no local script and may name a
        // different remote one: neither the counters nor the recorded script
        // move.
        track(&mut s, true, &[0x51]);
        assert_eq!(st(&s).revoked_through, Some(4));
        assert_eq!(st(&s).validated_through, Some(5));
        assert_eq!(st(&s).remote_shutdown_script, peer_script());
        assert_eq!(st(&s).is_outbound, Some(true));
    }

    #[test]
    fn store_v1_and_v2_still_import() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, false, &peer_script());
        for n in 0..2 {
            assert!(matches!(validate(&mut s, n, 300_000, 699_000, 1_000), Outcome::Reply(_)));
        }
        assert!(matches!(sign_remote(&mut s, 0, 699_000, 300_000, 1_000), Outcome::Reply(_)));
        assert!(matches!(revoke(&mut s, 0), Outcome::Reply(_)));
        assert!(s.store.record_close([0x99; 32]));
        assert!(!s.store.record_close([0x99; 32]));
        let v8 = policy::encode_channel_store(&s.store);
        assert_eq!(v8[4], 8);
        let (back, ledger, closes) = policy::decode_channel_store(&v8).unwrap();
        assert_eq!(closes, vec![[0x99; 32]]);
        assert_eq!(back[0].1.validated, st(&s).validated);
        assert!(!back[0].1.predates_validation);
        // The flag round-trips.
        let mut marked = ChannelStore::new();
        let mut m = st(&s).clone();
        m.predates_validation = true;
        marked.insert(PEER, DBID, m);
        let (back, _, _) = policy::decode_channel_store(&policy::encode_channel_store(&marked)).unwrap();
        assert!(back[0].1.predates_validation);
        // A version-7 payload: the same, without the entry's flag (the byte
        // before the ledger and the close record).
        let ledger_len = 2 + 40 * ledger.approvals.len() + 2 + 49 * ledger.spends.len();
        let at = v8.len() - (2 + 32) - ledger_len - 1;
        assert_eq!(v8[at], 0);
        let mut v7 = [&v8[..at], &v8[at + 1..]].concat();
        v7[4] = 7;
        let (back, l7, closes) = policy::decode_channel_store(&v7).unwrap();
        assert_eq!((l7, closes), (ledger.clone(), vec![[0x99; 32]]));
        assert!(!back[0].1.predates_validation);
        // A version-6 payload: the same, without the close record.
        let mut v6 = v7[..v7.len() - (2 + 32)].to_vec();
        v6[4] = 6;
        let (back, l6, closes) = policy::decode_channel_store(&v6).unwrap();
        assert!(closes.is_empty());
        assert_eq!(l6, ledger);
        let (_, b) = &back[0];
        // Version 6 was written by a device that validated: carried over.
        assert!(!b.predates_validation);
        assert_eq!(b.revoked_through, Some(0));
        assert_eq!(b.is_outbound, Some(false));
        assert_eq!(b.remote_shutdown_script, peer_script());
        assert_eq!(b.local_split, Some((1, Split { ours: 300_000, fee: 1_000, anchors: 0 })));
        assert_eq!(b.remote_split, Some((0, Split { ours: 300_000, fee: 1_000, anchors: 0 })));
        // Commitment 0 was revoked, so only commitment 1 stays signable.
        assert_eq!(b.validated.len(), 1);
        assert_eq!(b.validated[0].0, 1);
        assert_eq!(b.validated, st(&s).validated);
        assert_eq!(b.pay, st(&s).pay);
        assert!(b.pay.asset.is_some() && b.pay.local.is_some() && b.pay.remote.is_some());
        assert_eq!(ledger, s.store.ledger);
        assert_eq!(b.local_shutdown_wallet_index, None);
        // A version-5 payload: the same entry without the wallet index.
        let ledger_len = 2 + 40 * ledger.approvals.len() + 2 + 49 * ledger.spends.len();
        let at = v6.len() - ledger_len - 1;
        let mut v5 = [&v6[..at], &v6[at + 1..]].concat();
        v5[4] = 5;
        let (back, l5, _) = policy::decode_channel_store(&v5).unwrap();
        assert_eq!((&back[0].1.pay, &l5), (&b.pay, &ledger));
        // Older stores were written by devices that validated nothing.
        assert!(back[0].1.predates_validation);
        // A version-4 payload: the same entry without the payment tracking,
        // and no ledger.
        let side_len = |t: &Option<crate::payments::SideTrack>| {
            t.as_ref().map_or(1, |t| 1 + 24 + 2 + 44 * t.offered.len())
        };
        let pay_len = 34 + side_len(&b.pay.local) + side_len(&b.pay.remote) + 8;
        let mut v4 = v5[..v5.len() - ledger_len - pay_len].to_vec();
        v4[4] = 4;
        let (back, l4, _) = policy::decode_channel_store(&v4).unwrap();
        let (_, b) = &back[0];
        assert_eq!(b.validated.len(), 1);
        assert_eq!((b.pay.clone(), l4), Default::default());
        // A version-3 payload: the same entry without the validated record.
        let mut v3 = v4[..v4.len() - (1 + 40)].to_vec();
        v3[4] = 3;
        let (back, _, _) = policy::decode_channel_store(&v3).unwrap();
        let (_, b) = &back[0];
        assert_eq!(b.local_split, Some((1, Split { ours: 300_000, fee: 1_000, anchors: 0 })));
        assert!(b.validated.is_empty());
        // A version-2 payload: the same entry without the two splits.
        let split_len = 2 * (1 + 4 * 8);
        let mut v2 = v3[..v3.len() - split_len].to_vec();
        v2[4] = 2;
        let (back, _, _) = policy::decode_channel_store(&v2).unwrap();
        let (_, b) = &back[0];
        assert_eq!((b.revoked_through, b.is_outbound), (Some(0), Some(false)));
        assert_eq!((b.local_split, b.remote_split), (None, None));
        // A version-1 payload: the fixed part of each entry only.
        let mut v1 = v3[..9].to_vec();
        v1[4] = 1;
        v1.extend_from_slice(&v3[9..9 + policy::CHSTORE_ENTRY_LEN]);
        let (back, _, _) = policy::decode_channel_store(&v1).unwrap();
        let (_, b) = &back[0];
        assert_eq!(b.funding_sats, FUNDING);
        assert!(b.predates_validation);
        assert_eq!((b.is_outbound, b.revoked_through), (None, None));
        assert!(b.remote_shutdown_script.is_empty());
        // Truncated or padded payloads are refused, as is a version 9.
        assert!(policy::decode_channel_store(&v8[..v8.len() - 1]).is_err());
        assert!(policy::decode_channel_store(&v7[..v7.len() - 1]).is_err());
        assert!(policy::decode_channel_store(&v6[..v6.len() - 1]).is_err());
        let mut padded = v6.clone();
        padded.push(0);
        assert!(policy::decode_channel_store(&padded).is_err());
        let mut v9 = v8.clone();
        v9[4] = 9;
        assert!(policy::decode_channel_store(&v9).is_err());
    }

    // ---- Balance-held closes and store-miss revocations ----

    /// The remote funding key in `setup_msg` is `point(s, 5)`: this is the
    /// peer's secret for it, so a test can sign as the peer.
    const PEER_FUNDING_SECRET: [u8; 32] = [5; 32];

    fn our_point(s: &Signer, n: u64) -> [u8; 33] {
        let sec = s.kernel().channel_secrets(&PEER, DBID);
        s.kernel().per_commit_point_at(&sec.shaseed, n)
    }

    fn bitcoin_tx(tx: &[u8]) -> BitcoinTx {
        let psbt = funding_psbt();
        let mut w = Writer::new(0);
        w.u32(tx.len() as u32);
        w.bytes(tx);
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        wire::read_bitcoin_tx(&mut wire::Reader::new(&w.into_vec()[2..])).unwrap()
    }

    /// Our commitment n as BOLT 3 builds it for the tracked channel: to_local
    /// (our revocable delayed script at our point n), to_remote (the peer's
    /// payment basepoint: option_static_remotekey) and the explicit fee. A
    /// zero amount leaves the output out, as dust trimming does.
    fn local_commitment(s: &Signer, n: u64, to_local: u64, to_remote: u64, fee: u64) -> Vec<u8> {
        let st0 = st(s).clone();
        let local_spk = policy::expected_htlc_tx_to_local(
            s.kernel(), &PEER, DBID, &st0, Side::Local, &our_point(s, n)).unwrap();
        let remote_spk = s.kernel().p2wpkh_scriptpubkey(&point(s, 2));
        let (locktime, sequence) = obscured(s, n);
        let mut outs = Vec::new();
        if to_local > 0 {
            outs.push((local_spk, to_local));
        }
        if to_remote > 0 {
            outs.push((remote_spk, to_remote));
        }
        outs.push((Vec::new(), fee));
        elements_tx(FUNDING_TXID, locktime, sequence, &outs)
    }

    /// The peer's signature on `tx`'s funding input, by `key`.
    fn funding_sig(s: &Signer, tx: &[u8], key: &[u8; 32]) -> [u8; 64] {
        let bt = bitcoin_tx(tx);
        let sec = s.kernel().channel_secrets(&PEER, DBID);
        let ws = s.kernel().funding_wscript(&s.kernel().pubkey_of(&sec.funding), &point(s, 5));
        let v9 = wire::psbt_input_value9(&bt.psbt, 0).unwrap();
        let h = kernel::elements_sighash_sw_v0(&bt.tx, 0, &ws, &v9, SIGHASH_ALL);
        s.kernel().sign_hash_low_r(&h, &SecretKey::from_slice(key).unwrap())
    }

    fn validate_msg(tx: &[u8], n: u64, sig: &[u8; 64]) -> Vec<u8> {
        let psbt = funding_psbt();
        let mut w = Writer::new(msg::HSMD_VALIDATE_COMMITMENT_TX);
        w.u32(tx.len() as u32);
        w.bytes(tx);
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        w.u16(0); // no HTLCs
        w.u64(n);
        w.u32(7500); // feerate
        w.bytes(sig);
        w.u8(SIGHASH_ALL as u8);
        w.u16(0); // no HTLC signatures
        w.into_vec()
    }

    /// VALIDATE_COMMITMENT_TX for our commitment n, signed by the peer.
    fn validate(s: &mut Signer, n: u64, to_local: u64, to_remote: u64, fee: u64) -> Outcome {
        let tx = local_commitment(s, n, to_local, to_remote, fee);
        let sig = funding_sig(s, &tx, &PEER_FUNDING_SECRET);
        s.handle(&req(validate_msg(&tx, n, &sig)))
    }

    /// SIGN_REMOTE_COMMITMENT_TX for the peer's commitment n: its to_local
    /// at the peer's point, our to_remote (our payment basepoint).
    fn sign_remote(s: &mut Signer, n: u64, to_local: u64, to_remote: u64, fee: u64) -> Outcome {
        let pp = point(s, 9);
        let st0 = st(s).clone();
        let their_spk = policy::expected_htlc_tx_to_local(
            s.kernel(), &PEER, DBID, &st0, Side::Remote, &pp).unwrap();
        let our_spk = s.kernel().p2wpkh_scriptpubkey(&s.kernel().channel_basepoints(&PEER, DBID)[1]);
        let tx = elements_tx(FUNDING_TXID, 0x2000_0000, 0x8000_0000,
                             &[(their_spk, to_local), (our_spk, to_remote), (Vec::new(), fee)]);
        let psbt = funding_psbt();
        let mut w = Writer::new(msg::HSMD_SIGN_REMOTE_COMMITMENT_TX);
        w.u32(tx.len() as u32);
        w.bytes(&tx);
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        w.bytes(&point(s, 5)); // remote funding key
        w.bytes(&pp); // remote per-commitment point
        w.bool(true); // option_static_remotekey
        w.u64(n);
        w.u16(0); // no HTLCs
        w.u32(7500);
        s.handle(&req(w.into_vec()))
    }

    fn mutual_close_msg(s: &Signer, tx: &[u8]) -> Vec<u8> {
        let psbt = funding_psbt();
        let mut w = Writer::new(msg::HSMD_SIGN_MUTUAL_CLOSE_TX);
        w.u32(tx.len() as u32);
        w.bytes(tx);
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        w.bytes(&point(s, 5));
        w.into_vec()
    }

    fn outcome(o: &Outcome) -> &str {
        match o {
            Outcome::Reply(_) => "SIGNED",
            Outcome::Reject(r) => r.as_str(),
            Outcome::Sentinel => "sentinel",
            Outcome::Fatal(_) => "fatal",
        }
    }

    /// Ask for a close both ways it reaches the device, closingd's
    /// SIGN_MUTUAL_CLOSE_TX and lightningd's SIGN_COMMITMENT_TX: the two
    /// must agree. Ok when it is signed.
    fn sign_close(s: &mut Signer, tx: &[u8]) -> Result<(), String> {
        let by_closingd = s.handle(&req(mutual_close_msg(s, tx)));
        let by_lightningd = s.handle(&req(sign_commitment_msg(s, tx, 7)));
        let why = |o: &Outcome| outcome(o).split_once(" refused: ").map(|(_, r)| r.to_string());
        assert_eq!(why(&by_closingd), why(&by_lightningd));
        assert_eq!(outcome(&by_closingd) == "SIGNED", outcome(&by_lightningd) == "SIGNED");
        match by_closingd {
            Outcome::Reply(_) => Ok(()),
            o => Err(outcome(&o).to_string()),
        }
    }

    fn host_script() -> Vec<u8> {
        [0x00u8, 0x14].iter().copied().chain([0xAA; 20]).collect()
    }

    /// R2 F1: a "mutual close" that pays the whole channel to a script of the
    /// host's choosing and nothing (or one atom) to this device's wallet.
    #[test]
    fn r2_close_paying_us_nothing_is_refused() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]); // no upfront shutdown script (CLN default)
        let theft = close(FUNDING_TXID, &[(host_script(), FUNDING - 1_000), (Vec::new(), 1_000)]);
        // No commitment seen yet: a close with no output to us is refused.
        let err = sign_close(&mut s, &theft).unwrap_err();
        println!("R2 SIGN_MUTUAL_CLOSE_TX paying 0 to us, no balance known: {err}");
        assert!(err.contains("no balance is known"), "{err}");
        // Commitment 0 gives us 600,000 (we opened, so the 1,000 fee is ours too).
        assert!(matches!(validate(&mut s, 0, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        let err = sign_close(&mut s, &theft).unwrap_err();
        println!("R2 SIGN_MUTUAL_CLOSE_TX paying 0 to us, {} to host script: {err}", FUNDING - 1_000);
        assert!(err.contains("pays this wallet nothing, but its balance is 601000"), "{err}");
        // One atom to us, the rest to the host: refused.
        let ours = s.wallet_sweep_script(4, false);
        let theft2 = close(FUNDING_TXID, &[(ours, 1), (host_script(), FUNDING - 1_001), (Vec::new(), 1_000)]);
        let err = sign_close(&mut s, &theft2).unwrap_err();
        println!("R2 SIGN_MUTUAL_CLOSE_TX paying 1 to us: {err}");
        assert!(err.contains("pays this wallet 1, below its balance 601000"), "{err}");
    }

    /// Until a balance is known no close is signed, however much it pays
    /// this wallet: the device cannot tell an honest close from a theft's.
    /// One commitment step gives it the balance.
    #[test]
    fn close_with_no_balance_known_is_refused() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        let ours = s.wallet_sweep_script(4, false);
        let honest = close(FUNDING_TXID, &[(ours.clone(), 600_500), (peer_script(), 399_000), (Vec::new(), 500)]);
        for c in [close(FUNDING_TXID, &[(ours.clone(), 1), (peer_script(), FUNDING - 1_001), (Vec::new(), 1_000)]),
                  honest.clone()] {
            let err = sign_close(&mut s, &c).unwrap_err();
            assert!(err.contains("no balance is known for the channel yet") &&
                    err.contains("needs one of its commitments validated first"), "{err}");
        }
        assert!(matches!(validate(&mut s, 0, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        assert_eq!(sign_close(&mut s, &honest), Ok(()));
    }

    /// We opened: commitment 1 gives us to_local 600,000 and the 1,000 fee,
    /// a share of 601,000. A close may take its own fee from that share, up
    /// to four times the commitment's fee, and must give the peer no more
    /// than its 399,000.
    #[test]
    fn honest_close_within_tolerance_is_signed() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        for n in 0..2 {
            assert!(matches!(validate(&mut s, n, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        }
        assert_eq!(st(&s).local_split, Some((1, Split { ours: 600_000, fee: 1_000, anchors: 0 })));
        let ours = s.wallet_sweep_script(4, false);
        let peer = peer_script();
        let c = |o: u64, p: u64, f: u64| close(FUNDING_TXID, &[(ours.clone(), o), (peer.clone(), p), (Vec::new(), f)]);
        // The honest close: our share less a 500 fee.
        assert!(s.store.close_txids.is_empty());
        assert_eq!(sign_close(&mut s, &c(600_500, 399_000, 500)), Ok(()));
        println!("honest close paying us 600500 of a 601000 share (fee 500): SIGNED");
        // Signed (by closingd's message and by lightningd's): remembered as
        // a close, once.
        let txid = wire::parse_elements_tx_span_txid(&c(600_500, 399_000, 500));
        assert_eq!(s.store.close_txids, vec![txid]);
        // The fee at its ceiling, 4 × 1,000.
        assert_eq!(sign_close(&mut s, &c(597_000, 399_000, 4_000)), Ok(()));
        // One atom past it.
        let err = sign_close(&mut s, &c(596_999, 399_000, 4_001)).unwrap_err();
        assert!(err.contains("below its balance 601000 less 4000"), "{err}");
        // An atom short of the honest close.
        let err = sign_close(&mut s, &c(600_499, 399_001, 500)).unwrap_err();
        assert!(err.contains("below its balance"), "{err}");
        // The peer may give up some of its share.
        assert_eq!(sign_close(&mut s, &c(650_000, 349_500, 500)), Ok(()));
        // Our output trimmed: only when what is due is under the dust limit.
        let err = sign_close(&mut s, &close(FUNDING_TXID, &[(peer.clone(), 399_000), (Vec::new(), 601_000)])).unwrap_err();
        assert!(err.contains("pays this wallet nothing"), "{err}");
        // Three closes signed; the refused ones are not remembered.
        assert_eq!(s.store.close_txids.len(), 3);
    }

    /// The peer opened: it pays every fee, so a close owes us all of our
    /// to_local. A to_local trimmed from the commitment is a share of 0; a
    /// share under the dust limit may be left out of the close, but the
    /// peer gains at most that dust.
    #[test]
    fn fundee_pays_no_close_fee_and_dust_may_be_trimmed() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, false, &[]);
        assert!(matches!(validate(&mut s, 0, 300_000, 699_000, 1_000), Outcome::Reply(_)));
        let ours = s.wallet_sweep_script(4, false);
        let peer = peer_script();
        let c = |o: u64, p: u64, f: u64| close(FUNDING_TXID, &[(ours.clone(), o), (peer.clone(), p), (Vec::new(), f)]);
        assert_eq!(sign_close(&mut s, &c(300_000, 699_500, 500)), Ok(()));
        let err = sign_close(&mut s, &c(299_999, 699_501, 500)).unwrap_err();
        assert!(err.contains("pays this wallet 299999, below its balance 300000 less 0"), "{err}");

        // A share of 547, one atom over the dust limit, may not be trimmed.
        let mut s = signer(Policy::Enforce);
        track(&mut s, false, &[]);
        assert!(matches!(validate(&mut s, 0, 547, 998_453, 1_000), Outcome::Reply(_)));
        let err = sign_close(&mut s, &close(FUNDING_TXID, &[(peer.clone(), 999_000), (Vec::new(), 1_000)])).unwrap_err();
        assert!(err.contains("pays this wallet nothing, but its balance is 547"), "{err}");

        // to_local trimmed from the commitment: nothing is due to us.
        let mut s = signer(Policy::Enforce);
        track(&mut s, false, &[]);
        assert!(matches!(validate(&mut s, 0, 0, 999_000, 1_000), Outcome::Reply(_)));
        assert_eq!(sign_close(&mut s, &close(FUNDING_TXID, &[(peer.clone(), 999_500), (Vec::new(), 500)])), Ok(()));

        // We opened and to_local is trimmed: our share is the 1,000 fee.
        // After a 600 close fee, 400 is due, under the dust limit.
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        assert!(matches!(validate(&mut s, 0, 0, 999_000, 1_000), Outcome::Reply(_)));
        assert_eq!(sign_close(&mut s, &close(FUNDING_TXID, &[(peer.clone(), 999_000), (Vec::new(), 1_000)])), Ok(()));
        // The dust may go to the fee, never to the peer.
        let err = sign_close(&mut s, &close(FUNDING_TXID, &[(peer, 999_001), (Vec::new(), 999)])).unwrap_err();
        assert!(err.contains("pays the peer 999001, above its share 999000"), "{err}");
    }

    /// The peer's commitment the device signs sets the balance too, and the
    /// larger of the two latest stands.
    #[test]
    fn remote_commitment_also_sets_the_balance() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, false, &[]);
        assert!(matches!(sign_remote(&mut s, 0, 299_000, 700_000, 1_000), Outcome::Reply(_)));
        assert_eq!(st(&s).remote_split, Some((0, Split { ours: 700_000, fee: 1_000, anchors: 0 })));
        let ours = s.wallet_sweep_script(4, false);
        let peer = peer_script();
        let c = |o: u64, p: u64, f: u64| close(FUNDING_TXID, &[(ours.clone(), o), (peer.clone(), p), (Vec::new(), f)]);
        assert!(sign_close(&mut s, &c(1, 999_499, 500)).unwrap_err().contains("below its balance 700000"));
        assert_eq!(sign_close(&mut s, &c(700_000, 299_500, 500)), Ok(()));
        // A commitment of ours giving us less does not lower the figure.
        assert!(matches!(validate(&mut s, 0, 650_000, 349_000, 1_000), Outcome::Reply(_)));
        assert!(sign_close(&mut s, &c(650_000, 349_500, 500)).unwrap_err().contains("below its balance 700000"));
        // An older commitment does not replace a newer record.
        assert!(matches!(sign_remote(&mut s, 3, 0, 999_000, 1_000), Outcome::Reply(_)));
        assert!(matches!(sign_remote(&mut s, 2, 999_000, 0, 1_000), Outcome::Reply(_)));
        assert_eq!(st(&s).remote_split, Some((3, Split { ours: 999_000, fee: 1_000, anchors: 0 })));
    }

    /// A commitment counts as validated only with the peer's signature on it.
    #[test]
    fn validation_needs_the_peers_signature() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        let tx = local_commitment(&s, 1, 600_000, 399_000, 1_000);
        let mut bad = funding_sig(&s, &tx, &PEER_FUNDING_SECRET);
        bad[40] ^= 1;
        let own = funding_sig(&s, &tx, &[6; 32]);
        for sig in [bad, own] {
            match s.handle(&req(validate_msg(&tx, 1, &sig))) {
                Outcome::Reject(r) => assert!(r.contains("signature on commitment 1 does not verify"), "{r}"),
                o => panic!("validated without the peer's signature: {}", outcome(&o)),
            }
        }
        assert_eq!((st(&s).validated_through, st(&s).local_split), (None, None));
        let sig = funding_sig(&s, &tx, &PEER_FUNDING_SECRET);
        assert!(matches!(s.handle(&req(validate_msg(&tx, 1, &sig))), Outcome::Reply(_)));
        assert_eq!(st(&s).validated_through, Some(1));
    }

    /// The device reveals the secret of a commitment it has already signed
    /// for broadcast: the keyless node's preempt slot asks for exactly that
    /// signature at every commitment step, before channeld revokes the
    /// commitment it replaces. The host then holds a fully signed, revoked
    /// commitment, which the peer can take whole once it is broadcast.
    #[test]
    fn r2_reveal_after_sign_for_broadcast() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        for n in 0..3 {
            assert!(matches!(validate(&mut s, n, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        }
        assert!(matches!(revoke(&mut s, 0), Outcome::Reply(_)));
        assert!(matches!(revoke(&mut s, 1), Outcome::Reply(_)));
        // Commitment 2 is current: the device signs it for broadcast.
        let c2 = local_commitment(&s, 2, 600_000, 399_000, 1_000);
        let signed = s.handle(&req(sign_commitment_msg(&s, &c2, 2)));
        assert!(matches!(signed, Outcome::Reply(_)));
        // Commitment 3 arrives (validated), then the node asks to revoke 2.
        assert!(matches!(validate(&mut s, 3, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        let rev = revoke(&mut s, 2);
        println!("R2 REVOKE 2 after SIGN_COMMITMENT_TX 2: {}",
                 match &rev { Outcome::Reply(_) => "REVEALED", Outcome::Reject(r) => r.as_str(), _ => "other" });
        assert!(matches!(rev, Outcome::Reply(_)));
        assert_eq!(st(&s).revoked_through, Some(2));
        // From then on commitment 2 is never signed again.
        let err = s.check_own_commitment(&sign_commitment_msg(&s, &c2, 2)).unwrap_err();
        assert!(err.contains("commitment 2 is revoked"), "{err}");
    }

    /// R2 F4: a device with no revocation record must not reveal a commitment
    /// whose replacement it never validated.
    #[test]
    fn r2_fresh_record_refuses_unreplaced_commitment() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        assert_eq!(st(&s).validated_through, None);
        let rev = revoke(&mut s, 40);
        println!("R2 REVOKE 40 with no record and nothing validated: {}", outcome(&rev));
        match rev {
            Outcome::Reject(r) => assert!(r.contains("no record of this channel's commitments"), "{r}"),
            _ => panic!("revoked 40 with no record"),
        }
        assert_eq!(st(&s).revoked_through, None);
        // Once commitment 41 is validated, 40 may go.
        assert!(matches!(validate(&mut s, 41, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        assert!(matches!(revoke(&mut s, 40), Outcome::Reply(_)));
        assert_eq!(st(&s).revoked_through, Some(40));
        // A record that knows only its revocations reveals no further one.
        s.store.get_mut(&PEER, DBID).unwrap().validated_through = None;
        match revoke(&mut s, 41) {
            Outcome::Reject(r) => assert!(r.contains("no record"), "{r}"),
            _ => panic!("revoked 41 with nothing validated"),
        }
    }

    // ---- R2b H1: SIGN_COMMITMENT_TX signs only a validated commitment ----

    fn verdict(o: &Outcome) -> String {
        match o {
            Outcome::Reply(_) => "SIGNED".to_string(),
            Outcome::Reject(r) => format!("REFUSED: {r}"),
            Outcome::Sentinel => "sentinel".to_string(),
            Outcome::Fatal(_) => "fatal".to_string(),
        }
    }

    /// Our commitment n, commitment-shaped, with arbitrary outputs.
    fn shaped(s: &Signer, n: u64, outs: &[(Vec<u8>, u64)]) -> Vec<u8> {
        let (lt, sq) = obscured(s, n);
        elements_tx(FUNDING_TXID, lt, sq, outs)
    }

    fn host_p2wsh() -> Vec<u8> {
        [0x00u8, 0x20].iter().copied().chain([0xAB; 32]).collect()
    }

    /// R2b H1: with 600,000 known to be ours, "our commitment" paying 1 to
    /// to_local and the rest to a P2WSH the host chose, for the current
    /// number and for a number never validated, and the whole of our side
    /// in the host's P2WSH: each is refused, because none is a transaction
    /// the device validated. The commitment it did validate signs.
    #[test]
    fn r2b_msg5_commitment_to_host_p2wsh_signed_despite_known_balance() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        for n in 0..2 {
            assert!(matches!(validate(&mut s, n, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        }
        assert!(matches!(revoke(&mut s, 0), Outcome::Reply(_)));
        let st0 = st(&s).clone();
        let remote_spk = s.kernel().p2wpkh_scriptpubkey(&point(&s, 2));
        println!("recorded local_split {:?}, validated_through {:?}, revoked_through {:?}",
                 st0.local_split, st0.validated_through, st0.revoked_through);
        for n in [1u64, 5] {
            let local_spk = policy::expected_htlc_tx_to_local(
                s.kernel(), &PEER, DBID, &st0, Side::Local, &our_point(&s, n)).unwrap();
            let tx = shaped(&s, n, &[(local_spk, 1), (host_p2wsh(), 599_999),
                                     (remote_spk.clone(), 399_000), (Vec::new(), 1_000)]);
            let o = s.handle(&req(sign_commitment_msg(&s, &tx, n)));
            println!("R2b SIGN_COMMITMENT_TX #{n}: to_local 1, host P2WSH 599999, to_remote 399000: {}",
                     verdict(&o));
            match o {
                Outcome::Reject(r) => assert!(r.contains(&format!(
                    "commitment {n} (txid ")) && r.contains("is not one this device validated \
                     (unrevoked validated commitments: [1])"), "{r}"),
                o => panic!("signed an unvalidated commitment: {}", verdict(&o)),
            }
        }
        // No to_local at all: the whole of our side in the host's P2WSH.
        let tx = shaped(&s, 1, &[(host_p2wsh(), 600_000), (remote_spk.clone(), 399_000), (Vec::new(), 1_000)]);
        let o = s.handle(&req(sign_commitment_msg(&s, &tx, 1)));
        println!("R2b SIGN_COMMITMENT_TX #1: no to_local, host P2WSH 600000: {}", verdict(&o));
        assert!(matches!(&o, Outcome::Reject(r) if r.contains("is not one this device validated")),
                "{}", verdict(&o));
        // The same split as a mutual close is refused.
        let c = close(FUNDING_TXID, &[(host_p2wsh(), 600_000), (remote_spk, 399_000), (Vec::new(), 1_000)]);
        let o = s.handle(&req(mutual_close_msg(&s, &c)));
        println!("R2b the same value as a SIGN_MUTUAL_CLOSE_TX: {}", verdict(&o));
        assert!(matches!(o, Outcome::Reject(_)));
        // The commitment the device validated signs, under any claimed number.
        let honest = local_commitment(&s, 1, 600_000, 399_000, 1_000);
        for claimed in [1u64, 0, 9] {
            let o = s.handle(&req(sign_commitment_msg(&s, &honest, claimed)));
            println!("R2b SIGN_COMMITMENT_TX of validated #1 (claimed {claimed}): {}", verdict(&o));
            assert!(matches!(o, Outcome::Reply(_)));
        }
        // ...but not with another remote funding key: the signature would be
        // over a script that is not the funding output's.
        let mut m = sign_commitment_msg(&s, &honest, 1);
        let at = m.len() - 8 - 33;
        m[at..at + 33].copy_from_slice(&point(&s, 6));
        let o = s.handle(&req(m));
        assert!(matches!(&o, Outcome::Reject(r) if r.contains("remote_funding_key differs")), "{}", verdict(&o));
    }

    /// A device with no record of validated commitments (a store from before
    /// they were kept, or a lost store) signs none of our commitments for
    /// broadcast until it validates one; and one only ever validated as
    /// something else (the peer's commitment) does not count.
    #[test]
    fn no_validated_record_signs_no_commitment() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        let c0 = local_commitment(&s, 0, 600_000, 399_000, 1_000);
        // Signing the peer's commitment records no commitment of ours.
        assert!(matches!(sign_remote(&mut s, 0, 399_000, 600_000, 1_000), Outcome::Reply(_)));
        let o = s.handle(&req(sign_commitment_msg(&s, &c0, 0)));
        println!("SIGN_COMMITMENT_TX #0, nothing of ours validated: {}", verdict(&o));
        assert!(matches!(&o, Outcome::Reject(r) if r.contains("unrevoked validated commitments: []")),
                "{}", verdict(&o));
        // A validation refused for a bad peer signature records nothing.
        let mut bad = funding_sig(&s, &c0, &PEER_FUNDING_SECRET);
        bad[3] ^= 1;
        assert!(matches!(s.handle(&req(validate_msg(&c0, 0, &bad))), Outcome::Reject(_)));
        assert!(st(&s).validated.is_empty());
        assert!(matches!(s.handle(&req(sign_commitment_msg(&s, &c0, 0))), Outcome::Reject(_)));
        // Validated: it signs; a re-sent validation adds nothing.
        assert!(matches!(validate(&mut s, 0, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        assert!(matches!(validate(&mut s, 0, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        assert_eq!(st(&s).validated.len(), 1);
        assert!(matches!(s.handle(&req(sign_commitment_msg(&s, &c0, 0))), Outcome::Reply(_)));
        // Permissive mode (the kill-switch) signs as asked.
        s.set_policy(Policy::Permissive);
        let c5 = local_commitment(&s, 5, 1, 999_000, 999);
        assert!(matches!(s.handle(&req(sign_commitment_msg(&s, &c5, 5))), Outcome::Reply(_)));
    }

    /// The record survives the store's round trip and setup_channel's
    /// re-send, keeps only unrevoked entries, and is bounded.
    #[test]
    fn validated_record_persists_and_is_bounded() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        for n in 0..3 {
            assert!(matches!(validate(&mut s, n, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        }
        assert!(matches!(revoke(&mut s, 0), Outcome::Reply(_)));
        let blob = s.export_channels();
        let mut t = signer(Policy::Enforce);
        assert_eq!(t.import_channels(&blob), Ok(1));
        assert_eq!(st(&t).validated, st(&s).validated);
        let c2 = local_commitment(&t, 2, 600_000, 399_000, 1_000);
        assert!(matches!(t.handle(&req(sign_commitment_msg(&t, &c2, 2))), Outcome::Reply(_)));
        // channeld's setup_channel at start keeps it.
        track(&mut t, true, &[]);
        assert_eq!(st(&t).validated.iter().map(|v| v.0).collect::<Vec<_>>(), vec![1, 2]);
        // More than MAX_VALIDATED unrevoked: the oldest go.
        for n in 3..(3 + policy::MAX_VALIDATED as u64 + 2) {
            assert!(matches!(validate(&mut t, n, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        }
        assert_eq!(st(&t).validated.len(), policy::MAX_VALIDATED);
        assert_eq!(st(&t).validated[0].0, 5);
    }

    // ---- R2b H2: a payment needs an approved hash and must fit the limit ----

    fn htlc(side: u8, amount_msat: u64, k: u8) -> Htlc {
        Htlc { side, amount_msat, payment_hash: [k; 32], cltv_expiry: 500 }
    }

    fn put_htlcs(w: &mut Writer, htlcs: &[Htlc]) {
        w.u16(htlcs.len() as u16);
        for h in htlcs {
            w.u8(h.side);
            w.u64(h.amount_msat);
            w.bytes(&h.payment_hash);
            w.u32(h.cltv_expiry);
        }
    }

    /// A commitment of ours (`local`) at number n, or the peer's, carrying
    /// `htlcs`: to_local of the commitment's holder, to_remote, each HTLC,
    /// the fee.
    fn commitment_with(s: &Signer, local: bool, n: u64, to_local: u64, to_remote: u64,
                       fee: u64, htlcs: &[Htlc]) -> Vec<u8> {
        let st0 = st(s).clone();
        let (side, pt) = if local { (Side::Local, our_point(s, n)) } else { (Side::Remote, point(s, 9)) };
        let local_spk = policy::expected_htlc_tx_to_local(s.kernel(), &PEER, DBID, &st0, side, &pt).unwrap();
        let remote_spk = if local {
            s.kernel().p2wpkh_scriptpubkey(&point(s, 2))
        } else {
            s.kernel().p2wpkh_scriptpubkey(&s.kernel().channel_basepoints(&PEER, DBID)[1])
        };
        let (lt, sq) = if local { obscured(s, n) } else { (0x2000_0000, 0x8000_0000) };
        let mut outs = Vec::new();
        if to_local > 0 {
            outs.push((local_spk, to_local));
        }
        if to_remote > 0 {
            outs.push((remote_spk, to_remote));
        }
        for h in htlcs {
            let spk = policy::htlc_output_script(s.kernel(), &PEER, DBID, &st0, side, &pt, h).unwrap();
            outs.push((spk, h.amount_msat / 1000));
        }
        outs.push((Vec::new(), fee));
        elements_tx(FUNDING_TXID, lt, sq, &outs)
    }

    /// VALIDATE_COMMITMENT_TX for our commitment n carrying `htlcs`.
    fn validate_with(s: &mut Signer, n: u64, to_local: u64, to_remote: u64, fee: u64,
                     htlcs: &[Htlc]) -> Outcome {
        let tx = commitment_with(s, true, n, to_local, to_remote, fee, htlcs);
        let sig = funding_sig(s, &tx, &PEER_FUNDING_SECRET);
        let psbt = funding_psbt();
        let mut w = Writer::new(msg::HSMD_VALIDATE_COMMITMENT_TX);
        w.u32(tx.len() as u32);
        w.bytes(&tx);
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        put_htlcs(&mut w, htlcs);
        w.u64(n);
        w.u32(7500);
        w.bytes(&sig);
        w.u8(SIGHASH_ALL as u8);
        w.u16(0);
        s.handle(&req(w.into_vec()))
    }

    /// SIGN_REMOTE_COMMITMENT_TX for the peer's commitment n carrying `htlcs`.
    fn sign_remote_with(s: &mut Signer, n: u64, to_local: u64, to_remote: u64, fee: u64,
                        htlcs: &[Htlc]) -> Outcome {
        let tx = commitment_with(s, false, n, to_local, to_remote, fee, htlcs);
        let psbt = funding_psbt();
        let mut w = Writer::new(msg::HSMD_SIGN_REMOTE_COMMITMENT_TX);
        w.u32(tx.len() as u32);
        w.bytes(&tx);
        w.u32(psbt.len() as u32);
        w.bytes(&psbt);
        w.bytes(&point(s, 5));
        w.bytes(&point(s, 9));
        w.bool(true);
        w.u64(n);
        put_htlcs(&mut w, htlcs);
        w.u32(7500);
        s.handle(&req(w.into_vec()))
    }

    fn approved(o: Outcome) -> bool {
        match o {
            Outcome::Reply(r) => {
                assert_eq!(r.len(), 3);
                r[2] == 1
            }
            o => panic!("preapprove answered {}", verdict(&o)),
        }
    }

    fn preapprove_keysend(s: &mut Signer, k: u8, amount_msat: u64, check: bool) -> bool {
        let mut w = Writer::new(if check { msg::HSMD_PREAPPROVE_KEYSEND_CHECK } else { msg::HSMD_PREAPPROVE_KEYSEND });
        w.bytes(&point(s, 7)); // destination
        w.bytes(&[k; 32]);
        w.u64(amount_msat);
        if check {
            w.bool(true);
        }
        let mut r = req(w.into_vec());
        r.is_main = true;
        approved(s.handle(&r))
    }

    fn preapprove_invoice(s: &mut Signer, inv: &str, check: bool) -> bool {
        let mut w = Writer::new(if check { msg::HSMD_PREAPPROVE_INVOICE_CHECK } else { msg::HSMD_PREAPPROVE_INVOICE });
        w.bytes(inv.as_bytes());
        w.u8(0);
        if check {
            w.bool(true);
        }
        let mut r = req(w.into_vec());
        r.is_main = true;
        approved(s.handle(&r))
    }

    fn spent(s: &Signer) -> u64 {
        let asset = st(s).pay.asset.expect("asset known");
        s.store.ledger.spent_msat(&asset, s.now, s.limits.period_secs)
    }

    /// A signer at t = 1000 with a limit of `atoms` per day, tracking a channel
    /// whose commitments 0 have been validated and signed.
    fn paying_signer(outbound: bool, atoms: u64, ours: u64, theirs: u64) -> Signer {
        let mut s = signer(Policy::Enforce);
        s.set_now(1_000);
        let mut l = payments::Limits::default();
        l.default_atoms = Some(atoms);
        s.set_limits(l);
        track(&mut s, outbound, &[]);
        assert!(matches!(validate(&mut s, 0, ours, theirs, 1_000), Outcome::Reply(_)));
        assert!(matches!(sign_remote(&mut s, 0, theirs, ours, 1_000), Outcome::Reply(_)));
        s
    }

    #[test]
    fn r2b_h2_offered_htlc_needs_an_approved_payment() {
        let mut s = paying_signer(true, 300_000, 600_000, 399_000);
        let a = htlc(0, 100_000_000, 0xA1);
        // Offered without approval: refused, on either commitment.
        let o = sign_remote_with(&mut s, 1, 399_000, 500_000, 1_000, &[a]);
        println!("H2 SIGN_REMOTE_COMMITMENT_TX adding an unapproved HTLC: {}", verdict(&o));
        assert!(matches!(&o, Outcome::Reject(r) if r.contains("adds an HTLC we offer (100000000 msat, \
            payment hash a1a1") && r.contains("not approved")), "{}", verdict(&o));
        let o = validate_with(&mut s, 1, 500_000, 399_000, 1_000, &[a]);
        println!("H2 VALIDATE_COMMITMENT_TX adding an unapproved HTLC: {}", verdict(&o));
        assert!(matches!(&o, Outcome::Reject(r) if r.contains("not approved")), "{}", verdict(&o));
        assert_eq!(st(&s).validated_through, Some(0));
        // Approved: signed, and charged once though both commitments carry it.
        assert!(preapprove_keysend(&mut s, 0xA1, 100_000_000, false));
        let o = sign_remote_with(&mut s, 1, 399_000, 500_000, 1_000, &[a]);
        println!("H2 the same HTLC once approved: {}", verdict(&o));
        assert!(matches!(o, Outcome::Reply(_)));
        assert_eq!(spent(&s), 100_000_000);
        assert!(matches!(validate_with(&mut s, 1, 500_000, 399_000, 1_000, &[a]), Outcome::Reply(_)));
        assert!(matches!(revoke(&mut s, 0), Outcome::Reply(_)));
        // Fulfilled: gone from both, the peer has it; nothing more is charged.
        assert!(matches!(validate_with(&mut s, 2, 500_000, 499_000, 1_000, &[]), Outcome::Reply(_)));
        assert!(matches!(sign_remote_with(&mut s, 2, 499_000, 500_000, 1_000, &[]), Outcome::Reply(_)));
        assert_eq!(spent(&s), 100_000_000);
        // An HTLC the peer offers us needs no approval.
        let theirs = htlc(1, 50_000_000, 0xB2);
        assert!(matches!(sign_remote_with(&mut s, 3, 449_000, 500_000, 1_000, &[theirs]), Outcome::Reply(_)));
        assert_eq!(spent(&s), 100_000_000);
        // A check-only approval records nothing.
        assert!(preapprove_keysend(&mut s, 0xC3, 1_000_000, true));
        let c = htlc(0, 1_000_000, 0xC3);
        assert!(matches!(sign_remote_with(&mut s, 4, 449_000, 499_000, 1_000, &[theirs, c]), Outcome::Reject(_)));
        // Permissive mode (the kill-switch) signs it.
        s.set_policy(Policy::Permissive);
        assert!(matches!(sign_remote_with(&mut s, 4, 449_000, 499_000, 1_000, &[theirs, c]), Outcome::Reply(_)));
    }

    #[test]
    fn r2b_h2_payment_over_the_limit_is_refused() {
        // A limit of 300,000 atoms a day; 100,000 paid.
        let mut s = paying_signer(true, 300_000, 600_000, 399_000);
        assert!(preapprove_keysend(&mut s, 0xA1, 100_000_000, false));
        let a = htlc(0, 100_000_000, 0xA1);
        assert!(matches!(sign_remote_with(&mut s, 1, 399_000, 500_000, 1_000, &[a]), Outcome::Reply(_)));
        // 250,000 more does not fit in the 200,000 left: declined, and so
        // never approved.
        assert!(!preapprove_keysend(&mut s, 0xB2, 250_000_000, true));
        assert!(!preapprove_keysend(&mut s, 0xB2, 250_000_000, false));
        println!("H2 PREAPPROVE_KEYSEND of 250000 atoms with 200000 left: declined");
        let b = htlc(0, 250_000_000, 0xB2);
        let o = sign_remote_with(&mut s, 2, 399_000, 250_000, 1_000, &[a, b]);
        assert!(matches!(&o, Outcome::Reject(r) if r.contains("not approved")), "{}", verdict(&o));
        // 150,000 is approved; an HTLC of 210,000 under that hash is over.
        assert!(preapprove_keysend(&mut s, 0xC3, 150_000_000, false));
        let big = htlc(0, 210_000_000, 0xC3);
        let o = sign_remote_with(&mut s, 2, 399_000, 290_000, 1_000, &[a, big]);
        println!("H2 an approved hash's HTLC of 210000 atoms with 200000 left: {}", verdict(&o));
        assert!(matches!(&o, Outcome::Reject(r) if r.contains("paying 210000000 more msat of asset") &&
            r.contains("would pass its limit of 300000000 msat per 86400 s (100000000 msat already spent)")),
            "{}", verdict(&o));
        let c = htlc(0, 150_000_000, 0xC3);
        assert!(matches!(sign_remote_with(&mut s, 2, 399_000, 350_000, 1_000, &[a, c]), Outcome::Reply(_)));
        assert_eq!(spent(&s), 250_000_000);
        // A restarted device (its store exported and imported) remembers the
        // approvals and the spending.
        let blob = s.export_channels();
        let mut t = signer(Policy::Enforce);
        t.set_now(2_000);
        t.set_limits(s.limits.clone());
        assert_eq!(t.import_channels(&blob), Ok(1));
        assert_eq!(spent(&t), 250_000_000);
        assert!(!preapprove_keysend(&mut t, 0xD4, 50_000_000, true));
        // A day after the charges, the allowance is back.
        t.set_now(1_000 + payments::DEFAULT_PERIOD_SECS);
        assert_eq!(spent(&t), 0);
        assert!(preapprove_keysend(&mut t, 0xD4, 250_000_000, true));
    }

    #[test]
    fn r2b_h2_invoice_approval() {
        // 300m: 30,000,000 atoms, over the default limit of 10,000,000.
        let inv = "lnsqrt300m1p4vqc54sp55mylrq4dfn3cjs7zxjg0urxrpxxnzxhkdx7rdwefsf2m57elkk9qpp5z63d3a3qx6qs73qvuth2pvmz9khh3jy6um87fy9hueuxse8mlw8sdq9da6hgxqyjw5qcqz959qxpqysgqhk7a8uc3wl6vu0mgxc4d59q0y3qkfjpxqe3t06w5ks5caha8xsp8rrt3fqvj7favpmpge79amfserdywnsy8g3jkqe43a7jjx7wj6esq387l4s";
        let (hash, _) = payments::decode_bolt11(inv).unwrap();
        let mut s = signer(Policy::Enforce);
        assert!(!preapprove_invoice(&mut s, inv, false));
        assert!(!s.store.ledger.is_approved(&hash, 0, payments::DEFAULT_PERIOD_SECS));
        let mut l = payments::Limits::default();
        l.default_atoms = Some(31_000_000);
        s.set_limits(l);
        assert!(preapprove_invoice(&mut s, inv, true));
        assert!(!s.store.ledger.is_approved(&hash, 0, payments::DEFAULT_PERIOD_SECS));
        assert!(preapprove_invoice(&mut s, inv, false));
        assert!(s.store.ledger.is_approved(&hash, 0, payments::DEFAULT_PERIOD_SECS));
        // A malformed invoice is declined, not answered with an error.
        assert!(!preapprove_invoice(&mut s, &inv[..inv.len() - 1], false));
        assert!(!preapprove_invoice(&mut s, "lnsqrt", false));
    }

    #[test]
    fn r2b_h2_value_leaving_without_a_listed_htlc_is_charged() {
        // We did not open: a trimmed HTLC we offer takes our to_local down
        // (its value goes to the fee) with nothing listed.
        let mut s = paying_signer(false, 10_000, 300_000, 699_000);
        let o = validate_with(&mut s, 1, 295_000, 699_000, 6_000, &[]);
        assert!(matches!(o, Outcome::Reply(_)), "{}", verdict(&o));
        assert_eq!(spent(&s), 4_999_000);
        // The peer's commitment shows the same loss: charged once.
        assert!(matches!(sign_remote_with(&mut s, 1, 699_000, 295_000, 6_000, &[]), Outcome::Reply(_)));
        assert_eq!(spent(&s), 4_999_000);
        // Another 6,000 would pass the 10,000 limit.
        let o = validate_with(&mut s, 2, 289_000, 699_000, 12_000, &[]);
        println!("H2 a further 6000 atoms gone with no listed HTLC, 10000 a day: {}", verdict(&o));
        assert!(matches!(&o, Outcome::Reject(r) if r.contains("would pass its limit")), "{}", verdict(&o));
        // The trimmed HTLC failing returns the value: nothing charged.
        assert!(matches!(validate_with(&mut s, 2, 300_000, 699_000, 1_000, &[]), Outcome::Reply(_)));
        assert_eq!(spent(&s), 4_999_000);

        // We opened: the fee is ours, so a feerate rise is not a payment,
        // and a trimmed HTLC is charged when the peer is credited with it.
        let mut s = paying_signer(true, 10_000, 600_000, 399_000);
        assert!(matches!(validate_with(&mut s, 1, 598_000, 399_000, 3_000, &[]), Outcome::Reply(_)));
        assert_eq!(spent(&s), 0);
        assert!(matches!(validate_with(&mut s, 2, 593_000, 399_000, 8_000, &[]), Outcome::Reply(_)));
        assert_eq!(spent(&s), 0);
        assert!(matches!(validate_with(&mut s, 3, 593_000, 404_000, 3_000, &[]), Outcome::Reply(_)));
        assert_eq!(spent(&s), 4_999_000);
    }

    /// A channel the device tracked before it kept payment records: the first
    /// commitment it sees is the baseline, whatever it carries; the next one
    /// may add nothing unapproved.
    #[test]
    fn r2b_h2_first_commitment_seen_is_the_baseline() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        let a = htlc(0, 100_000_000, 0xA1);
        assert!(matches!(sign_remote_with(&mut s, 5, 399_000, 500_000, 1_000, &[a]), Outcome::Reply(_)));
        let b = htlc(0, 10_000_000, 0xB2);
        assert!(matches!(sign_remote_with(&mut s, 6, 399_000, 490_000, 1_000, &[a, b]), Outcome::Reject(_)));
    }

    // ---- R2b L2: a close to the local upfront shutdown script ----

    /// setup_channel naming a local upfront shutdown script (`fundchannel
    /// close_to=...`) and, when lightningd recognised it as its wallet's,
    /// that script's wallet index.
    fn setup_msg_local(s: &Signer, local_shutdown: &[u8], index: Option<u32>) -> Vec<u8> {
        let mut w = Writer::new(msg::HSMD_SETUP_CHANNEL);
        w.bool(true);
        w.u64(FUNDING);
        w.u64(0);
        w.bytes(&FUNDING_TXID);
        w.u16(0);
        w.u16(144);
        w.u16(local_shutdown.len() as u16);
        w.bytes(local_shutdown);
        match index {
            Some(i) => {
                w.bool(true);
                w.u32(i);
            }
            None => w.bool(false),
        }
        for k in 1..=5u8 {
            w.bytes(&point(s, k));
        }
        w.u16(144);
        w.u16(0);
        w.u16(2);
        w.bytes(&[0x10, 0x00]);
        w.into_vec()
    }

    /// A signer tracking a channel we opened with `close_to`, whose
    /// commitment 0 gives us 600,000 and the 1,000 fee.
    fn close_to_signer(close_to: &[u8], index: Option<u32>) -> Signer {
        let mut s = signer(Policy::Enforce);
        assert!(matches!(s.handle(&req(setup_msg_local(&s, close_to, index))), Outcome::Reply(_)));
        assert!(matches!(validate(&mut s, 0, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        s
    }

    /// R2b L2: a close of our share to the channel's close_to script was
    /// refused. It is signed when the script is this device's wallet address
    /// at the index setup_channel named (here 6000, past the range the
    /// device scans for its own scripts; P2WPKH, wrapped P2WPKH and P2TR),
    /// and still refused when the device cannot derive it: setup_channel
    /// comes from the host, so such a script could be the host's.
    #[test]
    fn r2b_close_to_upfront_script() {
        let peer = peer_script();
        let k = |s: &Signer| s.kernel().p2wpkh_scriptpubkey(&s.kernel().bip86_child_pubkey(6000));
        let probe = signer(Policy::Enforce);
        let wpkh = k(&probe);
        let wrapped = {
            let mut v = vec![0xa9, 0x14];
            v.extend_from_slice(&kernel::hash160(&wpkh));
            v.push(0x87);
            v
        };
        let tr = probe.kernel().bip86_p2tr_scriptpubkey(6000);
        assert!(!probe.own_sweep_script_set().contains(&wpkh));
        for script in [wpkh.clone(), wrapped, tr] {
            let mut s = close_to_signer(&script, Some(6000));
            assert_eq!(st(&s).local_shutdown_wallet_index, Some(6000));
            let c = close(FUNDING_TXID, &[(script.clone(), 600_500), (peer.clone(), 399_000), (Vec::new(), 500)]);
            let o = sign_close(&mut s, &c);
            println!("L2 close of our share to our close_to wallet address {}: {:?}", hexbytes(&script), o);
            assert_eq!(o, Ok(()));
            // Still held to the balance.
            let short = close(FUNDING_TXID, &[(script.clone(), 500_500), (peer.clone(), 499_000), (Vec::new(), 500)]);
            assert!(sign_close(&mut s, &short).unwrap_err().contains("below its balance 601000"));
        }
        // The same address under another index is not recognised.
        let mut s = close_to_signer(&wpkh, Some(6001));
        let c = close(FUNDING_TXID, &[(wpkh.clone(), 600_500), (peer.clone(), 399_000), (Vec::new(), 500)]);
        let err = sign_close(&mut s, &c).unwrap_err();
        println!("L2 close to a close_to script under a wrong index: {err}");
        assert!(err.contains("0 outputs to us and 2 to the peer"), "{err}");
        // A script the device cannot derive (the review's case).
        let close_to: Vec<u8> = [0x00u8, 0x14].iter().copied().chain([0xCC; 20]).collect();
        let mut s = close_to_signer(&close_to, None);
        assert_eq!(st(&s).local_shutdown_script, close_to);
        let c = close(FUNDING_TXID, &[(close_to.clone(), 600_500), (peer.clone(), 399_000), (Vec::new(), 500)]);
        let err = sign_close(&mut s, &c).unwrap_err();
        println!("L2 close to a close_to script the device cannot derive: {err}");
        assert!(err.contains("0 outputs to us and 2 to the peer"), "{err}");
        // setup_channel's re-send at channeld start keeps the recorded index.
        let mut s = close_to_signer(&wpkh, Some(6000));
        track(&mut s, true, &[]);
        assert_eq!((st(&s).local_shutdown_script.clone(), st(&s).local_shutdown_wallet_index),
                   (wpkh.clone(), Some(6000)));
        let blob = s.export_channels();
        let mut t = signer(Policy::Enforce);
        assert_eq!(t.import_channels(&blob), Ok(1));
        assert_eq!(st(&t).local_shutdown_wallet_index, Some(6000));
    }

    // ---- R2b M3: a store without balances refuses closes ----

    /// The payload a version-2 device would have written for the same
    /// channels: each entry's fixed part and version-2 fields, no ledger.
    fn as_v2(s: &Signer) -> Vec<u8> {
        let v6 = policy::encode_channel_store(&s.store);
        let (entries, _, _) = policy::decode_channel_store(&v6).unwrap();
        let mut out = v6[..9].to_vec();
        out[4] = 2;
        let mut at = 9;
        for (_, st) in &entries {
            let opt = |v: Option<u64>| if v.is_some() { 9 } else { 1 };
            let len = policy::CHSTORE_ENTRY_LEN + 1 + opt(st.revoked_through) + opt(st.validated_through)
                + 2 + st.local_shutdown_script.len() + 2 + st.remote_shutdown_script.len();
            out.extend_from_slice(&v6[at..at + len]);
            at += len;
            // Skip the later versions' fields of this entry by re-encoding
            // (less the empty ledger and close record that close the store).
            let mut one = ChannelStore::new();
            one.insert(PEER, DBID, st.clone());
            at += policy::encode_channel_store(&one).len() - 9 - len - 4 - 2;
        }
        out
    }

    /// R2b M3: a channel imported from a version-2 store has no balance
    /// recorded. A close paying this wallet one atom, which a device on a
    /// current store refuses as below the balance, is refused too: no close
    /// is signed until the channel's next commitment gives the balance.
    #[test]
    fn r2b_v2_store_close_paying_one_atom_is_refused() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, true, &[]);
        for n in 0..2 {
            assert!(matches!(validate(&mut s, n, 600_000, 399_000, 1_000), Outcome::Reply(_)));
        }
        assert!(matches!(revoke(&mut s, 0), Outcome::Reply(_)));
        let v2 = as_v2(&s);
        let mut s2 = signer(Policy::Enforce);
        let (entries, ledger, _) = policy::decode_channel_store(&v2).unwrap();
        assert_eq!(ledger, payments::Ledger::default());
        for ((node, dbid), stv) in entries {
            assert_eq!((stv.local_split, stv.remote_split), (None, None));
            assert_eq!(stv.revoked_through, Some(0));
            s2.store.insert(node, dbid, stv);
        }
        let ours = s.wallet_sweep_script(4, false);
        let theft = close(FUNDING_TXID, &[(ours.clone(), 1), (host_script(), FUNDING - 1_001), (Vec::new(), 1_000)]);
        let o3 = s.handle(&req(mutual_close_msg(&s, &theft)));
        let o2 = s2.handle(&req(mutual_close_msg(&s2, &theft)));
        println!("M3 one-atom close, device on a current store: {}", verdict(&o3));
        println!("M3 one-atom close, same channel imported from a v2 store: {}", verdict(&o2));
        assert!(matches!(&o3, Outcome::Reject(r) if r.contains("pays this wallet 1, below its balance 601000")),
                "{}", verdict(&o3));
        assert!(matches!(&o2, Outcome::Reject(r) if r.contains("predates validation")),
                "{}", verdict(&o2));
        // The honest close too; and no later commitment teaches the device
        // the balance: the channel predates validation, and the device never
        // takes its state on the host's word.
        let honest = close(FUNDING_TXID, &[(ours, 600_500), (peer_script(), 399_000), (Vec::new(), 500)]);
        assert!(matches!(s2.handle(&req(mutual_close_msg(&s2, &honest))), Outcome::Reject(_)));
        assert!(matches!(validate(&mut s2, 2, 600_000, 399_000, 1_000),
                         Outcome::Reject(r) if r.contains("predates validation")));
        assert!(matches!(s2.handle(&req(mutual_close_msg(&s2, &honest))), Outcome::Reject(_)));
        assert!(matches!(s2.handle(&req(mutual_close_msg(&s2, &theft))), Outcome::Reject(_)));
    }

    // ---- A store from a device that validated nothing ----

    /// The store a version-1 device would have written for `s`'s channels
    /// (each entry's fixed part only, no ledger), MAC'd for `s`'s seed.
    fn as_v1_blob(s: &Signer) -> Vec<u8> {
        let full = policy::encode_channel_store(&s.store);
        let n = u32::from_le_bytes(full[5..9].try_into().unwrap()) as usize;
        assert_eq!(n, 1);
        let mut payload = full[..9].to_vec();
        payload[4] = 1;
        payload.extend_from_slice(&full[9..9 + policy::CHSTORE_ENTRY_LEN]);
        let mac = s.chstore_mac(&payload);
        payload.extend_from_slice(&mac);
        payload
    }

    /// D39: a channel imported from a version-1 store is marked as predating
    /// validation, and the device signs no commitment step for it, however
    /// far the channel has moved: no commitment of the peer's, no
    /// validation of ours, no revocation (not even of commitment 0), no
    /// commitment of ours for broadcast and no close. It reports the
    /// channel. A channel set up afterwards is validated as any other.
    #[test]
    fn v1_store_channels_predate_validation() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, false, &peer_script());
        for n in 0..3 {
            assert!(matches!(validate(&mut s, n, 300_000, 699_000, 1_000), Outcome::Reply(_)));
        }
        assert!(matches!(revoke(&mut s, 0), Outcome::Reply(_)));
        let blob = as_v1_blob(&s);

        let mut d = signer(Policy::Enforce);
        assert_eq!(d.import_channels(&blob), Ok(1));
        assert!(st(&d).predates_validation);
        let listed = d.predating_channels();
        assert_eq!(listed, vec![(PEER, DBID, FUNDING_TXID, 0, FUNDING)]);
        // channeld sends setup_channel again at every start: still marked.
        track(&mut d, false, &peer_script());
        assert!(st(&d).predates_validation);

        let why = |o: Outcome| match o {
            Outcome::Reject(r) => r,
            o => panic!("signed: {}", verdict(&o)),
        };
        let r = why(validate(&mut d, 3, 300_000, 699_000, 1_000));
        println!("VALIDATE on a v1-store channel: {r}");
        assert!(r.starts_with("VALIDATE_COMMITMENT_TX refused: channel 3 of peer 02020202 predates validation"), "{r}");
        let r = why(sign_remote(&mut d, 2, 699_000, 300_000, 1_000));
        assert!(r.starts_with("SIGN_REMOTE_COMMITMENT_TX refused: channel 3"), "{r}");
        for n in [0, 1] {
            let r = why(revoke(&mut d, n));
            assert!(r.starts_with("REVOKE_COMMITMENT_TX refused: channel 3"), "{r}");
        }
        let ours = d.wallet_sweep_script(4, false);
        let honest = close(FUNDING_TXID, &[(ours, 300_500), (peer_script(), 699_000), (Vec::new(), 500)]);
        let r = why(d.handle(&req(mutual_close_msg(&d, &honest))));
        assert!(r.starts_with("SIGN_MUTUAL_CLOSE_TX refused: channel 3"), "{r}");
        let r = why(d.handle(&req(sign_commitment_msg(&d, &honest, 2))));
        assert!(r.starts_with("SIGN_COMMITMENT_TX refused: channel 3"), "{r}");
        let commitment = local_commitment(&d, 2, 300_000, 699_000, 1_000);
        let r = why(d.handle(&req(sign_commitment_msg(&d, &commitment, 2))));
        assert!(r.starts_with("SIGN_COMMITMENT_TX refused: channel 3"), "{r}");

        // Nothing it refused moved its record.
        assert_eq!((st(&d).revoked_through, st(&d).validated_through), (None, None));
        // The mark survives the store's round trip, and a later import of
        // the same old store over a live record.
        let back = d.export_channels();
        let mut e = signer(Policy::Enforce);
        track(&mut e, false, &peer_script());
        assert!(!st(&e).predates_validation);
        assert_eq!(e.import_channels(&back), Ok(0));
        assert!(st(&e).predates_validation);
        // Permissive signs as libhsmd does.
        let mut p = signer(Policy::Permissive);
        p.import_channels(&blob).unwrap();
        assert!(matches!(validate(&mut p, 3, 300_000, 699_000, 1_000), Outcome::Reply(_)));
    }

    // ---- R9 F1: the hsmd version is not the host's to lower ----

    /// HSMD_INIT as the host sends it, offering versions min..=max.
    fn init_msg(min: u32, max: u32) -> Vec<u8> {
        let mut w = Writer::new(msg::HSMD_INIT);
        w.u32(BIP32_VER_TEST_PUBLIC);
        w.u32(BIP32_VER_TEST_PRIVATE);
        w.bytes(&[0u8; 32]); // genesis
        for _ in 0..5 {
            w.u8(0); // the five optional dev fields, absent
        }
        w.u32(min);
        w.u32(max);
        w.into_vec()
    }

    fn main_req(msg: Vec<u8>) -> Request {
        Request { is_main: true, node_id: [0; 33], dbid: 0, capabilities: 0, hsmd_msg: msg }
    }

    /// GET_PER_COMMITMENT_POINT(n): the point, and the reply's old secret if
    /// it carries one.
    fn point_reply(s: &mut Signer, n: u64) -> ([u8; 33], Option<[u8; 32]>) {
        let mut w = Writer::new(msg::HSMD_GET_PER_COMMITMENT_POINT);
        w.u64(n);
        match s.handle(&req(w.into_vec())) {
            Outcome::Reply(r) => {
                assert_eq!(u16::from_be_bytes([r[0], r[1]]), msg::HSMD_GET_PER_COMMITMENT_POINT_REPLY);
                assert_eq!(r.len(), 2 + 33 + 1 + if r[2 + 33] == 1 { 32 } else { 0 });
                let point = r[2..2 + 33].try_into().unwrap();
                let old = (r[2 + 33] == 1).then(|| r[2 + 33 + 1..2 + 33 + 1 + 32].try_into().unwrap());
                (point, old)
            }
            o => panic!("not answered: {}", verdict(&o)),
        }
    }

    /// Every INIT whose highest version is below 6 is refused, as the first
    /// INIT and as a later one, and a refused INIT changes nothing.
    #[test]
    fn init_below_version_6_is_refused() {
        // A fresh device: refused before it has a kernel.
        let seed = crate::kernel::bip39_seed(MNEMONIC, "");
        for (min, max) in [(4, 4), (4, 5), (5, 5), (1, 3)] {
            let mut fresh = Signer::with_policy(
                HsmSecret { seed, secret_type: 2, mnemonic: String::new() },
                Policy::Enforce,
            );
            match fresh.handle(&main_req(init_msg(min, max))) {
                Outcome::Fatal(m) => {
                    println!("first INIT {min}..{max}: FATAL: {m}");
                    assert!(m.starts_with(&format!("version {min}-{max} not valid: we need 6-6")), "{m}");
                }
                o => panic!("INIT {min}..{max} accepted: {}", verdict(&o)),
            }
            assert!(fresh.kernel.is_none());
        }
        // What lightningd offers (5..6), and any range reaching 6, gives 6.
        for (min, max) in [(5, 6), (4, 6), (6, 6), (6, 9)] {
            let mut fresh = Signer::with_policy(
                HsmSecret { seed, secret_type: 2, mnemonic: String::new() },
                Policy::Enforce,
            );
            match fresh.handle(&main_req(init_msg(min, max))) {
                Outcome::Reply(r) => {
                    assert_eq!(u16::from_be_bytes([r[0], r[1]]), msg::HSMD_INIT_REPLY_V4);
                    assert_eq!(u32::from_be_bytes(r[2..6].try_into().unwrap()), 6);
                }
                o => panic!("INIT {min}..{max} refused: {}", verdict(&o)),
            }
        }
        // A second INIT at a lower version, after the device served one.
        let mut s = signer(Policy::Enforce);
        assert!(matches!(s.handle(&main_req(init_msg(5, 6))), Outcome::Reply(_)));
        let before = point_reply(&mut s, 3);
        for (min, max) in [(4, 4), (5, 5), (4, 5)] {
            match s.handle(&main_req(init_msg(min, max))) {
                Outcome::Fatal(m) => println!("second INIT {min}..{max}: FATAL: {m}"),
                o => panic!("second INIT {min}..{max} accepted: {}", verdict(&o)),
            }
            assert_eq!(s.hsm_version, 6);
            assert_eq!(point_reply(&mut s, 3), before);
        }
    }

    /// R9 F1, the reviewer's attack turned around: the host re-sends INIT
    /// offering only version 4 and asks for the point of commitment n + 2.
    /// The INIT is refused, the point comes alone, the current commitment's
    /// secret stays on the device, and its record is unchanged. The secret
    /// comes out only through the revocation the device validated.
    #[test]
    fn r9_version4_init_reveals_no_secret() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, false, &peer_script());
        for n in 0..2 {
            assert!(matches!(validate(&mut s, n, 300_000, 699_000, 1_000), Outcome::Reply(_)));
        }
        assert!(matches!(revoke(&mut s, 0), Outcome::Reply(_)));
        let r = verdict(&revoke(&mut s, 1));
        assert!(r.starts_with("REFUSED: REVOKE_COMMITMENT_TX refused: commitment 2 is not validated"), "{r}");
        let shaseed = s.kernel().channel_secrets(&PEER, DBID).shaseed;
        assert!(matches!(s.handle(&main_req(init_msg(4, 4))), Outcome::Fatal(_)));
        for n in 0..8u64 {
            let (point, old) = point_reply(&mut s, n);
            assert_eq!(old, None, "GET_PER_COMMITMENT_POINT({n}) carried a secret");
            assert_eq!(point, s.kernel().per_commit_point_at(&shaseed, n));
        }
        println!("after INIT 4..4: GET_PER_COMMITMENT_POINT(0..7) carry no secret");
        assert_eq!(st(&s).revoked_through, Some(0));
        // Commitment 1 is still the one the device signs for broadcast, and
        // its secret is still refused.
        let c1 = local_commitment(&s, 1, 300_000, 699_000, 1_000);
        assert_eq!(verdict(&s.handle(&req(sign_commitment_msg(&s, &c1, 1)))), "SIGNED");
        assert!(verdict(&revoke(&mut s, 1)).starts_with("REFUSED"));
        // Once commitment 2 is validated, the revocation of 1 gives its secret.
        assert!(matches!(validate(&mut s, 2, 300_000, 699_000, 1_000), Outcome::Reply(_)));
        match revoke(&mut s, 1) {
            Outcome::Reply(r) => {
                assert_eq!(&r[2..34], &s.kernel().per_commit_secret_at(&shaseed, 1));
            }
            o => panic!("REVOKE(1) after 2 validated: {}", verdict(&o)),
        }
    }

    /// The same for a channel from a version-1 store: no commitment step,
    /// and no secret through GET_PER_COMMITMENT_POINT at any number.
    #[test]
    fn r9_predating_channel_reveals_no_secret() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, false, &peer_script());
        for n in 0..3 {
            assert!(matches!(validate(&mut s, n, 300_000, 699_000, 1_000), Outcome::Reply(_)));
        }
        let blob = as_v1_blob(&s);
        let mut d = signer(Policy::Enforce);
        assert_eq!(d.import_channels(&blob), Ok(1));
        assert!(st(&d).predates_validation);
        assert!(matches!(d.handle(&main_req(init_msg(4, 4))), Outcome::Fatal(_)));
        for n in 0..8u64 {
            assert_eq!(point_reply(&mut d, n).1, None, "GET_PER_COMMITMENT_POINT({n}) carried a secret");
        }
        for n in 0..3 {
            assert!(verdict(&revoke(&mut d, n)).contains("predates validation"));
        }
        println!("predating channel: no secret at any number, every revocation refused");
    }

    /// A version-6 store came from a validating device: its channels go on.
    #[test]
    fn v6_store_channels_are_carried_over() {
        let mut s = signer(Policy::Enforce);
        track(&mut s, false, &peer_script());
        for n in 0..2 {
            assert!(matches!(validate(&mut s, n, 300_000, 699_000, 1_000), Outcome::Reply(_)));
        }
        let full = policy::encode_channel_store(&s.store);
        // Version 8 less the entry's flag and the close record: version 6.
        let mut payload = [&full[..full.len() - 2 - 4 - 1], &full[full.len() - 2 - 4..full.len() - 2]].concat();
        payload[4] = 6;
        let mac = s.chstore_mac(&payload);
        payload.extend_from_slice(&mac);
        let mut d = signer(Policy::Enforce);
        assert_eq!(d.import_channels(&payload), Ok(1));
        assert!(!st(&d).predates_validation);
        assert!(d.predating_channels().is_empty());
        assert!(matches!(validate(&mut d, 2, 300_000, 699_000, 1_000), Outcome::Reply(_)));
        assert!(matches!(revoke(&mut d, 0), Outcome::Reply(_)));
    }
}

/// What a channel close paid this device (a peer's commitment's to_remote,
/// a mutual close output, a delayed sweep of our own commitment) is spent
/// only to the device's own scripts, with a fee within the payment limit.
#[cfg(test)]
mod close_output_spend_tests {
    use super::*;
    use crate::hsm_secret::HsmSecret;
    use crate::kernel::{Kernel, BIP32_VER_TEST_PRIVATE, BIP32_VER_TEST_PUBLIC};
    use crate::policy::Policy;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const PEER: [u8; 33] = [0x02; 33];
    const DBID: u64 = 7;
    const GOLD: [u8; 32] = [0x47; 32];
    const CLOSE_TXID: [u8; 32] = [0x5c; 32];

    fn signer(policy: Policy) -> Signer {
        let seed = crate::kernel::bip39_seed(MNEMONIC, "");
        let kernel = Kernel::new(seed.to_vec(), BIP32_VER_TEST_PUBLIC, BIP32_VER_TEST_PRIVATE);
        let secret = HsmSecret { seed, secret_type: 2, mnemonic: String::new() };
        let mut s = Signer::with_policy(secret, policy);
        s.kernel = Some(kernel);
        s.hsm_version = 6;
        s
    }

    fn compact(n: usize) -> Vec<u8> {
        compact_size(n)
    }

    fn rec(key: &[u8], val: &[u8]) -> Vec<u8> {
        let mut r = compact(key.len());
        r.extend_from_slice(key);
        r.extend_from_slice(&compact(val.len()));
        r.extend_from_slice(val);
        r
    }

    fn pset_key(t: u8) -> Vec<u8> {
        vec![0xfc, 0x04, 0x70, 0x73, 0x65, 0x74, t]
    }

    /// The key of a peer's-commitment output of channel (PEER, DBID): the
    /// static payment basepoint (no commitment point), as the C wallet
    /// records it for `option_static_remotekey` and `option_anchors`.
    fn payment_key(s: &Signer) -> (SecretKey, [u8; 33]) {
        let sk = s.kernel().channel_secrets(&PEER, DBID).payment;
        let pk = s.kernel().pubkey_of(&sk);
        (sk, pk)
    }

    fn to_remote_spk(s: &Signer, anchors: bool) -> Vec<u8> {
        let (_, pk) = payment_key(s);
        if anchors {
            policy::p2wsh_spk(&policy::to_remote_anchored_wscript(&pk, 1))
        } else {
            s.kernel().p2wpkh_scriptpubkey(&pk)
        }
    }

    fn foreign_spk() -> Vec<u8> {
        [0x00u8, 0x14].iter().copied().chain([0xeeu8; 20]).collect()
    }

    struct In {
        txid: [u8; 32],
        amount: u64,
        spk: Vec<u8>,
        keyindex: u32,
        close: Option<bool>, // Some(anchors) for a peer's-commitment output
    }

    /// An Elements v2 PSET spending `ins` (all GOLD) to `outs` (asset,
    /// amount, script; an empty script is the fee output). `blind` gives
    /// output 0 an ECDH pubkey, as a blinded output carries.
    fn pset(ins: &[In], outs: &[([u8; 32], u64, Vec<u8>)], blind: bool) -> Vec<u8> {
        let mut p = b"pset\xff".to_vec();
        p.extend(rec(&[0x02], &2u32.to_le_bytes()));
        p.extend(rec(&[0x03], &0u32.to_le_bytes()));
        p.extend(rec(&[0x04], &[ins.len() as u8]));
        p.extend(rec(&[0x05], &[outs.len() as u8]));
        p.push(0x00);
        for i in ins {
            let mut wu = vec![0x01u8];
            wu.extend_from_slice(&GOLD);
            wu.push(0x01);
            wu.extend_from_slice(&i.amount.to_be_bytes());
            wu.push(0x00);
            wu.extend(compact(i.spk.len()));
            wu.extend_from_slice(&i.spk);
            p.extend(rec(&[0x01], &wu));
            p.extend(rec(&[0x0e], &i.txid));
            p.extend(rec(&[0x0f], &0u32.to_le_bytes()));
            let seq: u32 = if i.close == Some(true) { 1 } else { 0xffff_fffd };
            p.extend(rec(&[0x10], &seq.to_le_bytes()));
            p.push(0x00);
        }
        for (n, (asset, amount, spk)) in outs.iter().enumerate() {
            p.extend(rec(&pset_key(0x02), asset));
            p.extend(rec(&[0x03], &amount.to_le_bytes()));
            p.extend(rec(&[0x04], spk));
            if blind && n == 0 {
                p.extend(rec(&pset_key(0x07), &[0x02; 33]));
            }
            p.push(0x00);
        }
        p
    }

    /// A Bitcoin v0 PSBT spending `ins` to `outs` (amount, script).
    fn psbt_v0(ins: &[In], outs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut t = 2u32.to_le_bytes().to_vec();
        t.push(ins.len() as u8);
        for i in ins {
            t.extend_from_slice(&i.txid);
            t.extend_from_slice(&0u32.to_le_bytes());
            t.push(0x00);
            let seq: u32 = if i.close == Some(true) { 1 } else { 0xffff_fffd };
            t.extend_from_slice(&seq.to_le_bytes());
        }
        t.push(outs.len() as u8);
        for (amount, spk) in outs {
            t.extend_from_slice(&amount.to_le_bytes());
            t.extend(compact(spk.len()));
            t.extend_from_slice(spk);
        }
        t.extend_from_slice(&0u32.to_le_bytes());
        let mut p = b"psbt\xff".to_vec();
        p.extend(rec(&[0x00], &t));
        p.push(0x00);
        for i in ins {
            let mut wu = i.amount.to_le_bytes().to_vec();
            wu.extend(compact(i.spk.len()));
            wu.extend_from_slice(&i.spk);
            p.extend(rec(&[0x01], &wu));
            p.push(0x00);
        }
        for _ in outs {
            p.push(0x00);
        }
        p
    }

    fn withdrawal(ins: &[In], psbt: &[u8]) -> Vec<u8> {
        let mut w = Writer::new(msg::HSMD_SIGN_WITHDRAWAL);
        w.u16(ins.len() as u16);
        for i in ins {
            w.bytes(&i.txid);
            w.u32(0);
            w.u64(i.amount);
            w.u32(i.keyindex);
            w.bool(false);
            w.u16(i.spk.len() as u16);
            w.bytes(&i.spk);
            match i.close {
                None => w.bool(false),
                Some(anchors) => {
                    w.bool(true);
                    w.u64(DBID);
                    w.bytes(&PEER);
                    w.bool(false); // no commitment point: static payment key
                    w.bool(anchors);
                    w.u32(if anchors { 1 } else { 0 });
                }
            }
            w.bool(false);
        }
        w.u32(psbt.len() as u32);
        w.bytes(psbt);
        w.into_vec()
    }

    fn req(msg: Vec<u8>) -> Request {
        Request { is_main: true, node_id: [0u8; 33], dbid: 0, capabilities: 0, hsmd_msg: msg }
    }

    /// The PSBT a withdrawal reply carries.
    fn reply_psbt(o: Outcome) -> Vec<u8> {
        match o {
            Outcome::Reply(r) => {
                assert_eq!(u16::from_be_bytes([r[0], r[1]]), msg::HSMD_SIGN_WITHDRAWAL_REPLY);
                let n = u32::from_be_bytes([r[2], r[3], r[4], r[5]]) as usize;
                r[6..6 + n].to_vec()
            }
            _ => panic!("a withdrawal is always answered"),
        }
    }

    /// The partial signature for `pubkey` in `psbt`, if there is one.
    fn partial_sig(psbt: &[u8], pubkey: &[u8; 33]) -> Option<Vec<u8>> {
        let mut key = vec![34u8, 0x02];
        key.extend_from_slice(pubkey);
        let pos = psbt.windows(key.len()).position(|w| w == key.as_slice())?;
        let vp = pos + key.len();
        let n = psbt[vp] as usize;
        Some(psbt[vp + 1..vp + 1 + n].to_vec())
    }

    fn close_in(s: &Signer, anchors: bool, amount: u64) -> In {
        In { txid: [0x11; 32], amount, spk: to_remote_spk(s, anchors), keyindex: 0, close: Some(anchors) }
    }

    #[test]
    fn peers_commitment_output_spent_to_own_address_elements() {
        let mut s = signer(Policy::Enforce);
        let own = s.wallet_sweep_script(3, false);
        for anchors in [false, true] {
            let ins = [close_in(&s, anchors, 500_000)];
            let psbt = pset(&ins, &[(GOLD, 499_000, own.clone()), (GOLD, 1_000, vec![])], false);
            let out = reply_psbt(s.handle(&req(withdrawal(&ins, &psbt))));
            assert_eq!(s.take_refusal(), None);
            let (sk, pk) = payment_key(&s);
            let sig = partial_sig(&out, &pk).expect("the close output is signed");
            // Over the Elements sighash of the transaction, with the channel's
            // payment key, the scriptCode the output's script needs.
            let tx = wire::reconstruct_elements_tx_from_pset(&psbt).unwrap();
            let code = if anchors {
                policy::to_remote_anchored_wscript(&pk, 1)
            } else {
                p2pkh_scriptcode(&kernel::hash160(&pk))
            };
            let mut v9 = [0u8; 9];
            v9[0] = 0x01;
            v9[1..].copy_from_slice(&500_000u64.to_be_bytes());
            let h = kernel::elements_sighash_sw_v0(&tx, 0, &code, &v9, SIGHASH_ALL);
            let der = s.kernel().sign_low_r_der_libwally_checked(&h, &sk, &pk).unwrap();
            assert_eq!(sig[..sig.len() - 1], der[..]);
            // The anchor channel's P2WSH: the witness script travels with it.
            assert_eq!(wire::psbt_input_has_key(&out, 0, &[0x05]), Some(anchors));
        }
    }

    #[test]
    fn peers_commitment_output_to_another_script_is_refused() {
        let mut s = signer(Policy::Enforce);
        let own = s.wallet_sweep_script(3, false);
        let ins = [close_in(&s, false, 500_000)];
        // All of it elsewhere; and only part of it elsewhere, beside our own.
        for outs in [
            vec![(GOLD, 499_000, foreign_spk()), (GOLD, 1_000, vec![])],
            vec![(GOLD, 400_000, own.clone()), (GOLD, 99_000, foreign_spk()), (GOLD, 1_000, vec![])],
        ] {
            let psbt = pset(&ins, &outs, false);
            let out = reply_psbt(s.handle(&req(withdrawal(&ins, &psbt))));
            assert_eq!(out, psbt, "nothing is signed");
            let why = s.take_refusal().expect("a reason");
            assert!(why.starts_with("SIGN_WITHDRAWAL refused: output "), "{why}");
            assert!(why.contains("not one of this device's own scripts"), "{why}");
        }
        // A blinded output to our own script is refused too: its value could
        // be unblindable for us.
        let psbt = pset(&ins, &[(GOLD, 499_000, own.clone()), (GOLD, 1_000, vec![])], true);
        let out = reply_psbt(s.handle(&req(withdrawal(&ins, &psbt))));
        assert_eq!(out, psbt);
        assert_eq!(s.take_refusal().unwrap(), "SIGN_WITHDRAWAL refused: output 0 is blinded");
        // Permissive signs it, as libhsmd does.
        let mut p = signer(Policy::Permissive);
        let psbt = pset(&ins, &[(GOLD, 499_000, foreign_spk()), (GOLD, 1_000, vec![])], false);
        let out = reply_psbt(p.handle(&req(withdrawal(&ins, &psbt))));
        assert!(partial_sig(&out, &payment_key(&p).1).is_some());
    }

    #[test]
    fn close_spend_fee_over_the_limit_is_refused() {
        let mut s = signer(Policy::Enforce);
        let own = s.wallet_sweep_script(3, false);
        let mut limits = Limits::default();
        limits.per_asset.insert(AssetKey::Asset(GOLD), Some(5_000));
        s.set_limits(limits);
        let ins = [close_in(&s, false, 500_000)];
        let psbt = pset(&ins, &[(GOLD, 494_000, own.clone()), (GOLD, 6_000, vec![])], false);
        let out = reply_psbt(s.handle(&req(withdrawal(&ins, &psbt))));
        assert_eq!(out, psbt);
        assert_eq!(
            s.take_refusal().unwrap(),
            format!(
                "SIGN_WITHDRAWAL refused: its fee, 6000 atoms of {}, is over this device's \
                 payment limit for that asset (5000 atoms)",
                AssetKey::Asset(GOLD).display()
            )
        );
        // At the limit it is signed.
        let psbt = pset(&ins, &[(GOLD, 495_000, own), (GOLD, 5_000, vec![])], false);
        let out = reply_psbt(s.handle(&req(withdrawal(&ins, &psbt))));
        assert!(partial_sig(&out, &payment_key(&s).1).is_some());
        assert_eq!(s.take_refusal(), None);
    }

    #[test]
    fn mutual_close_output_is_a_close_output() {
        let mut s = signer(Policy::Enforce);
        let own = s.wallet_sweep_script(3, false);
        let pk = s.kernel().bip86_child_pubkey(4);
        let wallet_in = |txid| In {
            txid,
            amount: 300_000,
            spk: s.kernel().p2wpkh_scriptpubkey(&pk),
            keyindex: 4,
            close: None,
        };
        let away = [(GOLD, 299_000, foreign_spk()), (GOLD, 1_000, vec![])];
        // An output of a transaction the device never signed as a close: a
        // wallet coin like any other, signed wherever it goes.
        let ins = [wallet_in(CLOSE_TXID)];
        let out = reply_psbt(s.handle(&req(withdrawal(&ins, &pset(&ins, &away, false)))));
        assert!(partial_sig(&out, &pk).is_some());
        // Once the device signed that transaction as a mutual close, what it
        // pays the wallet goes only to the device's own scripts.
        assert!(s.store.record_close(CLOSE_TXID));
        let psbt = pset(&ins, &away, false);
        let out = reply_psbt(s.handle(&req(withdrawal(&ins, &psbt))));
        assert_eq!(out, psbt);
        assert!(s.take_refusal().unwrap().contains("not one of this device's own scripts"));
        let out = reply_psbt(s.handle(&req(withdrawal(
            &ins,
            &pset(&ins, &[(GOLD, 299_000, own), (GOLD, 1_000, vec![])], false),
        ))));
        assert!(partial_sig(&out, &pk).is_some());
        // And the record survives the store's round trip.
        let blob = s.export_channels();
        let mut t = signer(Policy::Enforce);
        t.import_channels(&blob).unwrap();
        assert!(t.store.is_close(&CLOSE_TXID));
    }

    #[test]
    fn peers_commitment_output_bitcoin() {
        let mut s = signer(Policy::Enforce);
        let own = s.kernel().bip86_p2tr_scriptpubkey(2);
        let ins = [close_in(&s, true, 100_000)];
        let psbt = psbt_v0(&ins, &[(99_000, own.clone())]);
        let out = reply_psbt(s.handle(&req(withdrawal(&ins, &psbt))));
        assert_eq!(s.take_refusal(), None);
        let (sk, pk) = payment_key(&s);
        let sig = partial_sig(&out, &pk).expect("signed");
        let tx = wire::parse_bitcoin_tx(wire::psbt_global_unsigned_tx(&psbt).unwrap()).unwrap();
        let h = kernel::bitcoin_sighash_sw_v0(
            &tx, 0, &policy::to_remote_anchored_wscript(&pk, 1), &100_000u64.to_le_bytes(), SIGHASH_ALL);
        let der = s.kernel().sign_low_r_der_libwally_checked(&h, &sk, &pk).unwrap();
        assert_eq!(sig[..sig.len() - 1], der[..]);
        // To another script: refused.
        let psbt = psbt_v0(&ins, &[(60_000, own.clone()), (39_000, foreign_spk())]);
        assert_eq!(reply_psbt(s.handle(&req(withdrawal(&ins, &psbt)))), psbt);
        assert!(s.take_refusal().unwrap().contains("output 1 pays"));
        // A fee over the limit: refused.
        let mut limits = Limits::default();
        limits.per_asset.insert(AssetKey::Btc, Some(800));
        s.set_limits(limits);
        let psbt = psbt_v0(&ins, &[(99_000, own)]);
        assert_eq!(reply_psbt(s.handle(&req(withdrawal(&ins, &psbt)))), psbt);
        assert_eq!(
            s.take_refusal().unwrap(),
            "SIGN_WITHDRAWAL refused: its fee, 1000 atoms of btc, is over this device's payment \
             limit for that asset (800 atoms)"
        );
    }

    #[test]
    fn a_close_output_of_another_channel_key_is_not_signed() {
        // The host names a channel whose key does not give the output's
        // script: nothing is signed for it.
        let mut s = signer(Policy::Enforce);
        let own = s.wallet_sweep_script(3, false);
        let mut i = close_in(&s, false, 500_000);
        i.spk = foreign_spk();
        let ins = [i];
        let psbt = pset(&ins, &[(GOLD, 499_000, own), (GOLD, 1_000, vec![])], false);
        let out = reply_psbt(s.handle(&req(withdrawal(&ins, &psbt))));
        assert_eq!(out, psbt);
    }

    /// A Class A sweep: SIGN_DELAYED_PAYMENT_TO_US of an Elements output.
    fn delayed_sweep(s: &Signer, in_amount: u64, out_asset: [u8; 32], out_amount: u64,
                     out_spk: &[u8]) -> Request {
        sweep_req(s, msg::HSMD_SIGN_DELAYED_PAYMENT_TO_US, in_amount, out_asset, out_amount, out_spk)
    }

    /// The same sweep as a penalty, SIGN_PENALTY_TO_US.
    fn penalty_sweep(s: &Signer, in_amount: u64, out_asset: [u8; 32], out_amount: u64,
                     out_spk: &[u8]) -> Request {
        sweep_req(s, msg::HSMD_SIGN_PENALTY_TO_US, in_amount, out_asset, out_amount, out_spk)
    }

    fn sweep_req(s: &Signer, t_msg: u16, in_amount: u64, out_asset: [u8; 32], out_amount: u64,
                 out_spk: &[u8]) -> Request {
        let mut t = 2u32.to_le_bytes().to_vec();
        t.push(0x00);
        t.push(0x01);
        t.extend_from_slice(&[0x33; 32]);
        t.extend_from_slice(&0u32.to_le_bytes());
        t.push(0x00);
        t.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        t.push(0x02);
        for (asset, amount, spk) in [(out_asset, out_amount, out_spk.to_vec()),
                                     (GOLD, in_amount.saturating_sub(out_amount), vec![])] {
            t.push(0x01);
            t.extend_from_slice(&asset);
            t.push(0x01);
            t.extend_from_slice(&amount.to_be_bytes());
            t.push(0x00);
            t.extend(compact(spk.len()));
            t.extend_from_slice(&spk);
        }
        t.extend_from_slice(&0u32.to_le_bytes());
        let mut wu = vec![0x01u8];
        wu.extend_from_slice(&GOLD);
        wu.push(0x01);
        wu.extend_from_slice(&in_amount.to_be_bytes());
        wu.push(0x00);
        let in_spk = [0x00u8, 0x20].iter().copied().chain([0xab; 32]).collect::<Vec<u8>>();
        wu.extend(compact(in_spk.len()));
        wu.extend_from_slice(&in_spk);
        let mut p = b"pset\xff".to_vec();
        p.push(0x00);
        p.extend(rec(&[0x01], &wu));
        p.push(0x00);
        let _ = s;
        let mut w = Writer::new(t_msg);
        if t_msg == msg::HSMD_SIGN_PENALTY_TO_US {
            w.bytes(&[0x11; 32]); // the revocation secret
        } else {
            w.u64(0); // the commitment number
        }
        w.u32(t.len() as u32);
        w.bytes(&t);
        w.u32(p.len() as u32);
        w.bytes(&p);
        w.u16(1);
        w.bytes(&[0x51]);
        Request { is_main: false, node_id: PEER, dbid: DBID, capabilities: 0, hsmd_msg: w.into_vec() }
    }

    fn verdict(o: Outcome) -> Result<(), String> {
        match o {
            Outcome::Reply(_) => Ok(()),
            Outcome::Reject(r) => Err(r),
            Outcome::Sentinel => Err("sentinel".into()),
            Outcome::Fatal(m) => Err(m),
        }
    }

    #[test]
    fn delayed_sweep_lets_leave_at_most_the_limit() {
        let mut s = signer(Policy::Enforce);
        let own = s.wallet_sweep_script(3, false);
        let mut limits = Limits::default();
        limits.per_asset.insert(AssetKey::Asset(GOLD), Some(5_000));
        s.set_limits(limits);
        // Output 0 keeps all but 5,000: signed.
        assert_eq!(verdict(s.handle(&delayed_sweep(&s, 400_000, GOLD, 395_000, &own))), Ok(()));
        // Output 0 keeps one atom: under SIGHASH_SINGLE|ANYONECANPAY the host
        // could add an output taking the rest. Refused.
        assert_eq!(
            verdict(s.handle(&delayed_sweep(&s, 400_000, GOLD, 1, &own))),
            Err(format!(
                "SIGN_DELAYED_PAYMENT_TO_US refused: what it lets leave this device, 399999 \
                 atoms of {}, is over this device's payment limit for that asset (5000 atoms)",
                AssetKey::Asset(GOLD).display()
            ))
        );
        // Output 0 in another asset: the host could balance it with a
        // worthless one and take the input. Refused.
        let other = [0x99; 32];
        let r = verdict(s.handle(&delayed_sweep(&s, 400_000, other, 400_000, &own))).unwrap_err();
        assert!(r.contains("output 0 is not in the channel's asset"), "{r}");
        // To another script: refused, as before.
        let r = verdict(s.handle(&delayed_sweep(&s, 400_000, GOLD, 395_000, &foreign_spk()))).unwrap_err();
        assert!(r.contains("pays a non-owned script"), "{r}");
        // Once the device knows the channel's asset (here `other`), that is
        // the asset held to, whatever the request names for the input (its
        // witness UTXO says GOLD; the signature does not commit to it).
        s.store.insert(PEER, DBID, channel_in(AssetKey::Asset(other)));
        let r = verdict(s.handle(&delayed_sweep(&s, 400_000, GOLD, 395_000, &own))).unwrap_err();
        assert!(r.contains(&format!("output 0 is not in the channel's asset {}",
                                    AssetKey::Asset(other).display())), "{r}");
        let mut limits = Limits::default();
        limits.per_asset.insert(AssetKey::Asset(other), Some(5_000));
        s.set_limits(limits);
        assert_eq!(verdict(s.handle(&delayed_sweep(&s, 400_000, other, 395_000, &own))), Ok(()));
    }

    #[test]
    fn penalty_is_held_to_the_asset_not_the_limit() {
        // A penalty races the cheating peer: never refused over its fee.
        let mut s = signer(Policy::Enforce);
        let own = s.wallet_sweep_script(3, false);
        let mut limits = Limits::default();
        limits.per_asset.insert(AssetKey::Asset(GOLD), Some(5_000));
        s.set_limits(limits);
        assert_eq!(verdict(s.handle(&penalty_sweep(&s, 400_000, GOLD, 300_000, &own))), Ok(()));
        // But it pays our own script, in the channel's asset.
        let r = verdict(s.handle(&penalty_sweep(&s, 400_000, [0x99; 32], 400_000, &own))).unwrap_err();
        assert!(r.starts_with("SIGN_PENALTY_TO_US refused: output 0 is not in the channel's asset"), "{r}");
        let r = verdict(s.handle(&penalty_sweep(&s, 400_000, GOLD, 395_000, &foreign_spk()))).unwrap_err();
        assert!(r.contains("pays a non-owned script"), "{r}");
    }

    /// A channel record whose payment tracking names `asset`.
    fn channel_in(asset: AssetKey) -> ChannelState {
        ChannelState {
            funding_sats: 1_000_000,
            funding_txid: [0x44; 32],
            funding_txout: 0,
            local_to_self_delay: 144,
            remote_to_self_delay: 144,
            remote_revocation: [0x02; 33],
            remote_payment: [0x02; 33],
            remote_htlc: [0x02; 33],
            remote_delayed: [0x02; 33],
            remote_funding: [0x02; 33],
            option_static_remotekey: true,
            option_anchors: true,
            is_outbound: Some(false),
            local_shutdown_script: Vec::new(),
            remote_shutdown_script: Vec::new(),
            local_shutdown_wallet_index: None,
            revoked_through: None,
            validated_through: None,
            local_split: None,
            remote_split: None,
            validated: Vec::new(),
            pay: crate::payments::PayTrack { asset: Some(asset), ..Default::default() },
            predates_validation: false,
        }
    }
}
