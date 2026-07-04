//! Dispatch of one framed request to a reply, for the pure-derivation subset.
//!
//! This mirrors `signerd_handle` + `hsmd_handle_client_message` for the M2a
//! subset only. Messages outside the subset return the zero-length error
//! sentinel (so non-conformance is obvious). Cases where the reference libhsmd
//! calls `hsmd_status_failed` (fatal) are surfaced as `Outcome::Fatal`, so the
//! binary can exit and close the transport exactly like the oracle does.

use crate::frame::Request;
use crate::hsm_secret::HsmSecret;
use crate::kernel::Kernel;
use crate::wire::{self, msg, Writer};

/// Our supported hsmd wire version range, matching `signerd_init`.
const OUR_MIN_VERSION: u32 = 4;
const OUR_MAX_VERSION: u32 = 6;

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
}

fn empty_reply(msgtype: u16) -> Vec<u8> {
    Writer::new(msgtype).into_vec()
}
