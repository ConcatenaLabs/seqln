//! WASM/browser binding for the SeqLN Tier-2 device signer.
//!
//! This crate adds NO crypto and NO I/O: it is a thin wasm-bindgen shim over the
//! `seqln-signer` library (kernel + wire + frame + dispatch + policy + noise),
//! which is already pure and compiles to `wasm32-unknown-unknown` untouched. The
//! shim exists only to hand JavaScript an ergonomic API:
//!
//!   * [`Signer`] — construct from an `hsm_secret` (the mnemonic format, exactly
//!     the on-disk bytes) and drive one framed hsmd request -> reply per call
//!     with [`Signer::process_frame`]. Byte-for-byte identical to the native
//!     `seqln-signer` serve loop, but with a `&[u8]` in / `Vec<u8>` out instead
//!     of a socket. This is what a browser page (or a Node harness) calls.
//!
//!   * [`NoiseSession`] — the BOLT-8 Noise_XK **initiator** the browser device
//!     plays when it connects OUT to a hosted `hsmd-proxy` running in responder
//!     (listen) mode. wasm has no RNG, so the caller injects the 32-byte
//!     ephemeral entropy (from `crypto.getRandomValues`).
//!
//! Everything is a pure function of its inputs, so the same wasm module runs in
//! a browser (WebSocket adapter) or in Node (TCP adapter) with no change.

use seqln_signer::dispatch::{Outcome, Signer as InnerSigner};
use seqln_signer::frame;
use seqln_signer::hsm_secret;
use seqln_signer::noise::{self, Initiator, Transport};
use seqln_signer::policy::Policy;
use wasm_bindgen::prelude::*;

fn arr32(b: &[u8], what: &str) -> Result<[u8; 32], JsError> {
    b.try_into()
        .map_err(|_| JsError::new(&format!("{what} must be 32 bytes, got {}", b.len())))
}
fn arr33(b: &[u8], what: &str) -> Result<[u8; 33], JsError> {
    b.try_into()
        .map_err(|_| JsError::new(&format!("{what} must be 33 bytes, got {}", b.len())))
}

/// The device signer. Holds the mnemonic-derived crypto kernel and per-channel
/// policy state, exactly like the native `dispatch::Signer`.
#[wasm_bindgen]
pub struct Signer {
    inner: InnerSigner,
}

#[wasm_bindgen]
impl Signer {
    /// Construct from the raw `hsm_secret` bytes (mnemonic format:
    /// `32 zero bytes || mnemonic`, i.e. the exact on-disk file). Throws on a
    /// malformed / unsupported secret.
    #[wasm_bindgen(constructor)]
    pub fn new(hsm_secret_bytes: &[u8]) -> Result<Signer, JsError> {
        let secret = hsm_secret::parse(hsm_secret_bytes).map_err(|e| JsError::new(&e))?;
        Ok(Signer {
            inner: InnerSigner::new(secret),
        })
    }

    /// Convenience: construct from just the mnemonic string (no passphrase),
    /// synthesizing the `32 zero bytes || mnemonic` on-disk form.
    #[wasm_bindgen(js_name = fromMnemonic)]
    pub fn from_mnemonic(mnemonic: &str) -> Result<Signer, JsError> {
        let mut bytes = vec![0u8; 32];
        bytes.extend_from_slice(mnemonic.as_bytes());
        Signer::new(&bytes)
    }

    /// Turn the M4 validating policy on (`enforce`) or off (`permissive`). The
    /// browser build has no env, so this is how a caller selects enforce mode.
    #[wasm_bindgen(js_name = setEnforce)]
    pub fn set_enforce(&mut self, enforce: bool) {
        let policy = if enforce { Policy::Enforce } else { Policy::Permissive };
        self.inner.set_policy(policy);
    }

    /// Drive ONE hsmd request -> reply. `frame_bytes` is a single signer-split
    /// frame (`signer_frame.h`: little-endian `u32 len | is_main | node_id? |
    /// dbid | capabilities | hsmd_msg`); the return is the single framed reply
    /// (`u32 len | hsmd_reply`, a zero-length body being the error sentinel) —
    /// byte-for-byte what the native serve loop writes back. Throws only on a
    /// libhsmd-fatal condition (which closes the transport natively).
    #[wasm_bindgen(js_name = processFrame)]
    pub fn process_frame(&mut self, frame_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut rd: &[u8] = frame_bytes;
        let req = match frame::read_request(&mut rd) {
            Ok(Some(r)) => r,
            Ok(None) => return Err(JsError::new("short/empty frame")),
            Err(e) => return Err(JsError::new(&format!("frame decode error: {e}"))),
        };
        let reply: Vec<u8> = match self.inner.handle(&req) {
            Outcome::Reply(bytes) => bytes,
            // Sentinel and (policy) Reject are both the zero-length wire sentinel.
            Outcome::Sentinel | Outcome::Reject(_) => Vec::new(),
            Outcome::Fatal(m) => return Err(JsError::new(&format!("fatal: {m}"))),
        };
        let mut out = Vec::with_capacity(4 + reply.len());
        frame::write_reply(&mut out, &reply).expect("write to Vec never fails");
        Ok(out)
    }
}

/// The BOLT-8 Noise_XK **initiator** session (the browser device role in the
/// hosted topology: it connects OUT to the proxy responder). Holds the handshake
/// state until Act Two, then the post-handshake transport cipher.
#[wasm_bindgen]
pub struct NoiseSession {
    initiator: Option<Initiator>,
    transport: Option<Transport>,
}

#[wasm_bindgen]
impl NoiseSession {
    /// Begin an initiator handshake toward a hosted proxy whose static pubkey is
    /// `host_static_pubkey` (33 bytes, pinned), using our device transport
    /// static privkey `device_static_privkey` (32 bytes) and a fresh 32-byte
    /// `ephemeral_entropy` the caller draws from `crypto.getRandomValues`.
    #[wasm_bindgen(js_name = newInitiator)]
    pub fn new_initiator(
        host_static_pubkey: &[u8],
        device_static_privkey: &[u8],
        ephemeral_entropy: &[u8],
    ) -> Result<NoiseSession, JsError> {
        let host = arr33(host_static_pubkey, "host_static_pubkey")?;
        let priv_ = arr32(device_static_privkey, "device_static_privkey")?;
        let eph = arr32(ephemeral_entropy, "ephemeral_entropy")?;
        let ini = Initiator::new(&priv_, &eph, host).map_err(|e| JsError::new(&e.0))?;
        Ok(NoiseSession {
            initiator: Some(ini),
            transport: None,
        })
    }

    /// Produce Act One (50 bytes) to send to the responder.
    #[wasm_bindgen(js_name = writeActOne)]
    pub fn write_act_one(&mut self) -> Result<Vec<u8>, JsError> {
        let ini = self
            .initiator
            .as_mut()
            .ok_or_else(|| JsError::new("act one after handshake complete"))?;
        Ok(ini.write_act_one().to_vec())
    }

    /// Consume Act Two (50 bytes) from the responder, returning Act Three (66
    /// bytes) and transitioning to the ready transport. After this call
    /// [`encrypt`]/[`decrypt_header`]/[`decrypt_body`] are live.
    #[wasm_bindgen(js_name = readActTwo)]
    pub fn read_act_two(&mut self, act2: &[u8]) -> Result<Vec<u8>, JsError> {
        let ini = self
            .initiator
            .take()
            .ok_or_else(|| JsError::new("act two before act one / already done"))?;
        let (act3, transport) = ini
            .read_act_two_write_act_three(act2)
            .map_err(|e| JsError::new(&e.0))?;
        self.transport = Some(transport);
        Ok(act3.to_vec())
    }

    /// True once the handshake has completed and the transport is live.
    #[wasm_bindgen(js_name = isReady)]
    pub fn is_ready(&self) -> bool {
        self.transport.is_some()
    }

    fn transport_mut(&mut self) -> Result<&mut Transport, JsError> {
        self.transport
            .as_mut()
            .ok_or_else(|| JsError::new("transport not ready (handshake incomplete)"))
    }

    /// Encrypt one plaintext message into a full BOLT-8 transport record
    /// (18-byte encrypted length header || encrypted body+MAC).
    pub fn encrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self.transport_mut()?.encrypt(msg))
    }

    /// Decrypt an 18-byte length header, returning the body length that follows
    /// (so the caller knows how many bytes to read next off the socket).
    #[wasm_bindgen(js_name = decryptHeader)]
    pub fn decrypt_header(&mut self, hdr: &[u8]) -> Result<u32, JsError> {
        let h: [u8; noise::HDR_SIZE] = hdr
            .try_into()
            .map_err(|_| JsError::new("header must be 18 bytes"))?;
        self.transport_mut()?
            .decrypt_header(&h)
            .map(|l| l as u32)
            .map_err(|e| JsError::new(e.0))
    }

    /// Decrypt a body (`len + 16` bytes) into the plaintext message.
    #[wasm_bindgen(js_name = decryptBody)]
    pub fn decrypt_body(&mut self, body: &[u8]) -> Result<Vec<u8>, JsError> {
        self.transport_mut()?
            .decrypt_body(body)
            .map_err(|e| JsError::new(e.0))
    }
}

/// Derive the compressed static pubkey (33 bytes) for a transport static privkey
/// (32 bytes) — used to compute the device pubkey a hosted proxy must pin.
#[wasm_bindgen(js_name = devicePubkey)]
pub fn device_pubkey(static_privkey: &[u8]) -> Result<Vec<u8>, JsError> {
    let priv_ = arr32(static_privkey, "static_privkey")?;
    noise::static_pubkey(&priv_)
        .map(|p| p.to_vec())
        .map_err(|e| JsError::new(e.0))
}
