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
    /// The reference libhsmd would `hsmd_status_failed` here; exit and close.
    Fatal(String),
}

pub struct Signer {
    secret: HsmSecret,
    kernel: Option<Kernel>,
    hsm_version: u32,
}

impl Signer {
    pub fn new(secret: HsmSecret) -> Self {
        Signer {
            secret,
            kernel: None,
            hsm_version: 0,
        }
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
            msg::HSMD_SIGN_COMMITMENT_TX => opt(self.h_sign_commitment_tx(&req.hsmd_msg)),
            msg::HSMD_SIGN_REMOTE_COMMITMENT_TX => opt(self.h_sign_remote_commitment_tx(req)),
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
            msg::HSMD_VALIDATE_COMMITMENT_TX => opt(self.h_validate_commitment_tx(req)),
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
            msg::HSMD_SETUP_CHANNEL => Outcome::Reply(empty_reply(msg::HSMD_SETUP_CHANNEL_REPLY)),
            msg::HSMD_FORGET_CHANNEL => Outcome::Reply(empty_reply(msg::HSMD_FORGET_CHANNEL_REPLY)),
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
    // M2b transaction-signing handlers. Each returns Some(reply_bytes) or
    // None (-> zero-length sentinel, matching a malformed/unsupported input;
    // real captured requests are always well-formed and produce a reply).
    // =================================================================

    /// The shared final step: BIP-143 Elements sighash over `scriptcode` with
    /// the input `sign_index` amount (from the PSBT), low-R sign, and frame the
    /// `bitcoin_signature` reply (compact 64 || sighash byte).
    fn sig_reply(
        &self,
        bt: &BitcoinTx,
        sign_index: usize,
        scriptcode: &[u8],
        privkey: &SecretKey,
        sighash: u32,
        reply_type: u16,
    ) -> Option<Vec<u8>> {
        let value9 = wire::psbt_input_value9(&bt.psbt, sign_index)?;
        let hash =
            kernel::elements_sighash_sw_v0(&bt.tx, sign_index, scriptcode, &value9, sighash);
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
        self.sig_reply(&bt, 0, &wscript, &privkey, SIGHASH_ALL, msg::HSMD_SIGN_TX_REPLY)
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
        self.sig_reply(&bt, 0, &wscript, &privkey, SIGHASH_ALL, msg::HSMD_SIGN_TX_REPLY)
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
        self.sig_reply(bt, 0, wscript, &privkey, SIGHASH_ALL, msg::HSMD_SIGN_TX_REPLY)
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

fn approve_reply(reply_type: u16) -> Vec<u8> {
    let mut w = Writer::new(reply_type);
    w.bool(true);
    w.into_vec()
}

fn empty_reply(msgtype: u16) -> Vec<u8> {
    Writer::new(msgtype).into_vec()
}
