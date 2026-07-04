//! BOLT-8 Noise_XK secure transport for the SeqLN Tier-2 signer link.
//!
//! This is the SAME authenticated handshake + per-message cipher that CLN uses
//! for peer links (`connectd/handshake.c` + `common/cryptomsg.c`): protocol name
//! `Noise_XK_secp256k1_ChaChaPoly_SHA256`, prologue `lightning`, secp256k1 DH,
//! ChaCha20-Poly1305 (IETF, 96-bit nonce) AEAD, SHA-256 / HKDF, and the
//! 1000-nonce key rotation. Reusing the project's own idiom (rather than
//! inventing a handshake) is the point: the C proxy speaks it with the audited
//! `common/cryptomsg.c` code, and this module is the byte-compatible peer.
//!
//! It gives the signer link exactly what it needs:
//!   * confidentiality + integrity of every frame (AEAD),
//!   * forward secrecy (ephemeral-ephemeral DH), and
//!   * MUTUAL static-key authentication from pinned long-term keys:
//!       - the initiator must know the responder's static pubkey up front, so a
//!         wrong responder key fails the Act Two MAC — the responder is
//!         authenticated to the initiator intrinsically; and
//!       - the responder recovers the initiator's static pubkey in Act Three and
//!         we compare it to a pinned value (`pinned_remote`), rejecting a
//!         mismatch — the initiator is authenticated to the responder.
//!
//! Pure and I/O-free: it operates on byte buffers only, and the caller injects
//! the ephemeral entropy, so it compiles to `wasm32` for a future browser signer
//! where a WebSocket adapter (not a raw socket) will drive the same state
//! machine. All socket/file plumbing lives in `bin/seqln-signer.rs`, never here.

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use sha2::{Digest, Sha256};

use crate::kernel::hkdf_sha256;

const PROTOCOL_NAME: &[u8] = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"lightning";

pub const ACT_ONE_SIZE: usize = 50;
pub const ACT_TWO_SIZE: usize = 50;
pub const ACT_THREE_SIZE: usize = 66;

/// BOLT #8 transport framing: 2-byte encrypted length prefix + its 16-byte MAC.
pub const HDR_SIZE: usize = 18;
pub const BODY_OVERHEAD: usize = 16;
/// The length prefix is a u16, so a single BOLT-8 message body is <= 65535.
pub const MAX_MSG: usize = 65535;

#[derive(Debug)]
pub struct NoiseError(pub &'static str);

impl std::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "noise: {}", self.0)
    }
}
impl std::error::Error for NoiseError {}

// --- primitives, mirroring handshake.c one for one -------------------------

fn sha256_of(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// h = SHA-256(h || data)
fn mix_hash(h: &mut [u8; 32], data: &[u8]) {
    *h = sha256_of(&[&h[..], data]);
}

/// out1, out2 = HKDF(salt=ck, ikm) — the BOLT-8 two-key expansion.
fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let okm = hkdf_sha256(64, ck, ikm, &[]);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&okm[..32]);
    b.copy_from_slice(&okm[32..]);
    (a, b)
}

/// ECDH with the BOLT-8 / secp256k1 default hash (SHA-256 of the compressed
/// shared point) — identical to `secp256k1_ecdh(..., NULL, NULL)` and to the
/// kernel's `ecdh()` for the hsmd ECDH message.
fn ecdh(secret: &SecretKey, point: &PublicKey) -> [u8; 32] {
    SharedSecret::new(point, secret).secret_bytes()
}

/// nonce = 32 zero bits || little-endian u64 (Noise convention).
fn nonce_bytes(n: u64) -> [u8; 12] {
    let mut npub = [0u8; 12];
    npub[4..].copy_from_slice(&n.to_le_bytes());
    npub
}

fn encrypt_ad(k: &[u8; 32], n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes(n)),
            Payload { msg: plaintext, aad: ad },
        )
        .expect("chacha20poly1305 encrypt never fails")
}

fn decrypt_ad(k: &[u8; 32], n: u64, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes(n)),
            Payload { msg: ciphertext, aad: ad },
        )
        .map_err(|_| NoiseError("AEAD authentication failed"))
}

fn pubkey_compressed(pk: &PublicKey) -> [u8; 33] {
    pk.serialize()
}

// --- post-handshake transport cipher (mirrors common/cryptomsg.c) ----------

/// The symmetric sending/receiving state after a successful handshake. Encrypts
/// and decrypts BOLT-8 transport messages (each a 18-byte encrypted length
/// header followed by the encrypted body+MAC), rotating keys every 1000 nonces.
pub struct Transport {
    sk: [u8; 32],
    rk: [u8; 32],
    sn: u64,
    rn: u64,
    sck: [u8; 32],
    rck: [u8; 32],
}

fn maybe_rotate(n: &mut u64, k: &mut [u8; 32], ck: &mut [u8; 32]) {
    if *n != 1000 {
        return;
    }
    let (new_ck, new_k) = hkdf2(ck, k);
    *ck = new_ck;
    *k = new_k;
    *n = 0;
}

impl Transport {
    /// Encrypt one message into a full BOLT-8 record (header || body).
    pub fn encrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        assert!(msg.len() <= MAX_MSG);
        let l = (msg.len() as u16).to_be_bytes();

        let mut out = encrypt_ad(&self.sk, self.sn, &[], &l);
        self.sn += 1;
        out.extend_from_slice(&encrypt_ad(&self.sk, self.sn, &[], msg));
        self.sn += 1;

        maybe_rotate(&mut self.sn, &mut self.sk, &mut self.sck);
        out
    }

    /// Decrypt an 18-byte header, returning the body length that follows.
    pub fn decrypt_header(&mut self, hdr: &[u8; HDR_SIZE]) -> Result<u16, NoiseError> {
        let pt = decrypt_ad(&self.rk, self.rn, &[], hdr)?;
        self.rn += 1;
        Ok(u16::from_be_bytes([pt[0], pt[1]]))
    }

    /// Decrypt a body (`len + 16` bytes) into the plaintext message.
    pub fn decrypt_body(&mut self, body: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let pt = decrypt_ad(&self.rk, self.rn, &[], body)?;
        self.rn += 1;
        maybe_rotate(&mut self.rn, &mut self.rk, &mut self.rck);
        Ok(pt)
    }
}

// --- handshake --------------------------------------------------------------

fn secret_from(bytes: &[u8; 32]) -> Result<SecretKey, NoiseError> {
    SecretKey::from_slice(bytes).map_err(|_| NoiseError("invalid secp256k1 scalar"))
}

/// Shared running handshake state (`ck`, `h`, `temp_k`, ephemeral key).
struct HsState {
    secp: Secp256k1<All>,
    ck: [u8; 32],
    h: [u8; 32],
    temp_k: [u8; 32],
    e_priv: SecretKey,
    e_pub: PublicKey,
}

impl HsState {
    /// Initialize per BOLT #8: h = SHA-256(protocol), ck = h,
    /// h = SHA-256(h || prologue), h = SHA-256(h || responder_static.pub).
    fn new(
        secp: Secp256k1<All>,
        responder_static_pub: &[u8; 33],
        eph_entropy: &[u8; 32],
    ) -> Result<Self, NoiseError> {
        let e_priv = secret_from(eph_entropy)?;
        let e_pub = PublicKey::from_secret_key(&secp, &e_priv);
        let mut h = sha256_of(&[PROTOCOL_NAME]);
        let ck = h;
        mix_hash(&mut h, PROLOGUE);
        mix_hash(&mut h, responder_static_pub);
        Ok(HsState { secp, ck, h, temp_k: [0u8; 32], e_priv, e_pub })
    }
}

/// The Noise_XK responder — the role the device signer plays: it listens, and
/// the hosted proxy (initiator) connects. It authenticates the initiator by
/// pinning the initiator's static key (`pinned_remote`).
pub struct Responder {
    st: HsState,
    s_priv: SecretKey,
    pinned_remote: [u8; 33],
    re: Option<PublicKey>,
}

impl Responder {
    /// * `static_priv`     — the device's long-term transport static privkey.
    /// * `eph_entropy`     — 32 fresh random bytes for the ephemeral key.
    /// * `pinned_remote`   — the ONLY hosted-node static pubkey we will accept.
    pub fn new(
        static_priv: &[u8; 32],
        eph_entropy: &[u8; 32],
        pinned_remote: [u8; 33],
    ) -> Result<Self, NoiseError> {
        let secp = Secp256k1::new();
        let s_priv = secret_from(static_priv)?;
        let s_pub = pubkey_compressed(&PublicKey::from_secret_key(&secp, &s_priv));
        // Responder mixes in ITS OWN static key as the "responder static".
        let st = HsState::new(secp, &s_pub, eph_entropy)?;
        Ok(Responder { st, s_priv, pinned_remote, re: None })
    }

    /// Act One (receiver): recover the initiator's ephemeral key, run es-ECDH,
    /// verify the tag. A wrong tag means the initiator did not know our static
    /// key (or tampering): abort.
    pub fn read_act_one(&mut self, act1: &[u8]) -> Result<(), NoiseError> {
        if act1.len() != ACT_ONE_SIZE || act1[0] != 0 {
            return Err(NoiseError("bad act one"));
        }
        let re = PublicKey::from_slice(&act1[1..34]).map_err(|_| NoiseError("bad act one ephemeral"))?;
        mix_hash(&mut self.st.h, &act1[1..34]);
        let ss = ecdh(&self.s_priv, &re);
        let (ck, temp_k) = hkdf2(&self.st.ck, &ss);
        self.st.ck = ck;
        self.st.temp_k = temp_k;
        // AD = h; ciphertext = the 16-byte tag; plaintext = empty.
        decrypt_ad(&self.st.temp_k, 0, &self.st.h, &act1[34..50])?;
        mix_hash(&mut self.st.h, &act1[34..50]);
        self.re = Some(re);
        Ok(())
    }

    /// Act Two (sender): our ephemeral key, ee-ECDH, authenticating tag.
    pub fn write_act_two(&mut self) -> Result<[u8; ACT_TWO_SIZE], NoiseError> {
        let re = self.re.ok_or(NoiseError("act two before act one"))?;
        let e_pub = pubkey_compressed(&self.st.e_pub);
        mix_hash(&mut self.st.h, &e_pub);
        let ss = ecdh(&self.st.e_priv, &re);
        let (ck, temp_k) = hkdf2(&self.st.ck, &ss);
        self.st.ck = ck;
        self.st.temp_k = temp_k;
        let tag = encrypt_ad(&self.st.temp_k, 0, &self.st.h, &[]);
        mix_hash(&mut self.st.h, &tag);
        let mut act2 = [0u8; ACT_TWO_SIZE];
        act2[0] = 0;
        act2[1..34].copy_from_slice(&e_pub);
        act2[34..50].copy_from_slice(&tag);
        Ok(act2)
    }

    /// Act Three (receiver): decrypt+authenticate the initiator's static key,
    /// PIN-CHECK it against the accepted host key, run se-ECDH, verify the final
    /// tag, and derive the transport keys. Returns the ready transport, or an
    /// error (which the caller MUST treat as "reject, serve zero frames").
    pub fn read_act_three(mut self, act3: &[u8]) -> Result<Transport, NoiseError> {
        if act3.len() != ACT_THREE_SIZE || act3[0] != 0 {
            return Err(NoiseError("bad act three"));
        }
        let rs = decrypt_ad(&self.st.temp_k, 1, &self.st.h, &act3[1..50])?;
        // The remote static key is now authenticated by the handshake MAC. Pin
        // it: this is where the responder authenticates WHICH host it is.
        if rs.as_slice() != self.pinned_remote {
            return Err(NoiseError("remote static key not the pinned host key"));
        }
        let rs_pub = PublicKey::from_slice(&rs).map_err(|_| NoiseError("bad remote static key"))?;
        mix_hash(&mut self.st.h, &act3[1..50]);
        let ss = ecdh(&self.st.e_priv, &rs_pub);
        let (ck, temp_k) = hkdf2(&self.st.ck, &ss);
        self.st.ck = ck;
        self.st.temp_k = temp_k;
        decrypt_ad(&self.st.temp_k, 0, &self.st.h, &act3[50..66])?;
        // Responder split: rk = okm[0], sk = okm[1].
        let (rk, sk) = hkdf2(&self.st.ck, &[]);
        Ok(Transport {
            sk,
            rk,
            sn: 0,
            rn: 0,
            sck: self.st.ck,
            rck: self.st.ck,
        })
    }
}

/// The Noise_XK initiator. Not used in the current hosted topology (the C proxy
/// is the initiator), but kept for round-trip unit tests and the future
/// browser-connects-out flip. Authenticates the responder intrinsically (it must
/// hold the private key for `responder_static`, else Act Two fails).
pub struct Initiator {
    st: HsState,
    s_priv: SecretKey,
    s_pub: [u8; 33],
    responder_static: PublicKey,
}

impl Initiator {
    pub fn new(
        static_priv: &[u8; 32],
        eph_entropy: &[u8; 32],
        responder_static: [u8; 33],
    ) -> Result<Self, NoiseError> {
        let secp = Secp256k1::new();
        let s_priv = secret_from(static_priv)?;
        let s_pub = pubkey_compressed(&PublicKey::from_secret_key(&secp, &s_priv));
        let rs = PublicKey::from_slice(&responder_static)
            .map_err(|_| NoiseError("bad responder static key"))?;
        let st = HsState::new(secp, &responder_static, eph_entropy)?;
        Ok(Initiator { st, s_priv, s_pub, responder_static: rs })
    }

    pub fn write_act_one(&mut self) -> [u8; ACT_ONE_SIZE] {
        let e_pub = pubkey_compressed(&self.st.e_pub);
        mix_hash(&mut self.st.h, &e_pub);
        let ss = ecdh(&self.st.e_priv, &self.responder_static);
        let (ck, temp_k) = hkdf2(&self.st.ck, &ss);
        self.st.ck = ck;
        self.st.temp_k = temp_k;
        let tag = encrypt_ad(&self.st.temp_k, 0, &self.st.h, &[]);
        mix_hash(&mut self.st.h, &tag);
        let mut act1 = [0u8; ACT_ONE_SIZE];
        act1[0] = 0;
        act1[1..34].copy_from_slice(&e_pub);
        act1[34..50].copy_from_slice(&tag);
        act1
    }

    /// Process Act Two and produce Act Three + the ready transport.
    pub fn read_act_two_write_act_three(
        mut self,
        act2: &[u8],
    ) -> Result<([u8; ACT_THREE_SIZE], Transport), NoiseError> {
        if act2.len() != ACT_TWO_SIZE || act2[0] != 0 {
            return Err(NoiseError("bad act two"));
        }
        let re = PublicKey::from_slice(&act2[1..34]).map_err(|_| NoiseError("bad act two ephemeral"))?;
        mix_hash(&mut self.st.h, &act2[1..34]);
        let ss = ecdh(&self.st.e_priv, &re);
        let (ck, temp_k) = hkdf2(&self.st.ck, &ss);
        self.st.ck = ck;
        self.st.temp_k = temp_k;
        decrypt_ad(&self.st.temp_k, 0, &self.st.h, &act2[34..50])?;
        mix_hash(&mut self.st.h, &act2[34..50]);

        // Act Three: transmit our static key under strong forward secrecy.
        let c = encrypt_ad(&self.st.temp_k, 1, &self.st.h, &self.s_pub);
        mix_hash(&mut self.st.h, &c);
        let ss = ecdh(&self.s_priv, &re);
        let (ck, temp_k) = hkdf2(&self.st.ck, &ss);
        self.st.ck = ck;
        self.st.temp_k = temp_k;
        let t = encrypt_ad(&self.st.temp_k, 0, &self.st.h, &[]);

        let mut act3 = [0u8; ACT_THREE_SIZE];
        act3[0] = 0;
        act3[1..50].copy_from_slice(&c);
        act3[50..66].copy_from_slice(&t);
        // Initiator split: sk = okm[0], rk = okm[1].
        let (sk, rk) = hkdf2(&self.st.ck, &[]);
        Ok((
            act3,
            Transport { sk, rk, sn: 0, rn: 0, sck: self.st.ck, rck: self.st.ck },
        ))
    }
}

/// Derive the compressed static pubkey for a given transport privkey (used by
/// provisioning / `--genkey` and to log our own identity).
pub fn static_pubkey(static_priv: &[u8; 32]) -> Result<[u8; 33], NoiseError> {
    let secp = Secp256k1::new();
    let sk = secret_from(static_priv)?;
    Ok(pubkey_compressed(&PublicKey::from_secret_key(&secp, &sk)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A full initiator<->responder handshake in-process, then a few transport
    // messages both directions, proving the state machine is self-consistent
    // and the pin check gates the responder.
    fn keypair(seed: u8) -> ([u8; 32], [u8; 33]) {
        let priv_bytes = [seed; 32];
        (priv_bytes, static_pubkey(&priv_bytes).unwrap())
    }

    #[test]
    fn handshake_and_transport_roundtrip() {
        let (i_priv, i_pub) = keypair(0x11);
        let (r_priv, r_pub) = keypair(0x22);
        let i_eph = [0x33u8; 32];
        let r_eph = [0x44u8; 32];

        let mut ini = Initiator::new(&i_priv, &i_eph, r_pub).unwrap();
        let mut res = Responder::new(&r_priv, &r_eph, i_pub).unwrap();

        let act1 = ini.write_act_one();
        res.read_act_one(&act1).unwrap();
        let act2 = res.write_act_two().unwrap();
        let (act3, mut it) = ini.read_act_two_write_act_three(&act2).unwrap();
        let mut rt = res.read_act_three(&act3).unwrap();

        // Initiator -> responder.
        for msg in [b"hello".to_vec(), vec![7u8; 40000], Vec::new()] {
            let rec = it.encrypt(&msg);
            let mut hdr = [0u8; HDR_SIZE];
            hdr.copy_from_slice(&rec[..HDR_SIZE]);
            let l = rt.decrypt_header(&hdr).unwrap() as usize;
            let got = rt.decrypt_body(&rec[HDR_SIZE..HDR_SIZE + l + BODY_OVERHEAD]).unwrap();
            assert_eq!(got, msg);
        }
        // Responder -> initiator.
        let rec = rt.encrypt(b"reply");
        let mut hdr = [0u8; HDR_SIZE];
        hdr.copy_from_slice(&rec[..HDR_SIZE]);
        let l = it.decrypt_header(&hdr).unwrap() as usize;
        let got = it.decrypt_body(&rec[HDR_SIZE..HDR_SIZE + l + BODY_OVERHEAD]).unwrap();
        assert_eq!(got, b"reply");
    }

    #[test]
    fn responder_rejects_wrong_pinned_initiator() {
        let (i_priv, _i_pub) = keypair(0x11);
        let (r_priv, r_pub) = keypair(0x22);
        let (_wrong_priv, wrong_pub) = keypair(0x55);

        // Responder pins the WRONG initiator key.
        let mut ini = Initiator::new(&i_priv, &[0x33u8; 32], r_pub).unwrap();
        let mut res = Responder::new(&r_priv, &[0x44u8; 32], wrong_pub).unwrap();

        let act1 = ini.write_act_one();
        res.read_act_one(&act1).unwrap();
        let act2 = res.write_act_two().unwrap();
        let (act3, _it) = ini.read_act_two_write_act_three(&act2).unwrap();
        // Act Three authenticates the real initiator key, which != pinned.
        assert!(res.read_act_three(&act3).is_err());
    }

    #[test]
    fn initiator_rejects_wrong_responder_key() {
        let (i_priv, _i_pub) = keypair(0x11);
        let (r_priv, _r_pub) = keypair(0x22);
        let (_bad_priv, bad_pub) = keypair(0x66);
        let (i_priv2, i_pub) = (i_priv, static_pubkey(&i_priv).unwrap());
        let _ = (i_priv2, i_pub);

        // Initiator connects expecting bad_pub, but responder holds r_priv.
        let mut ini = Initiator::new(&i_priv, &[0x33u8; 32], bad_pub).unwrap();
        let mut res =
            Responder::new(&r_priv, &[0x44u8; 32], static_pubkey(&i_priv).unwrap()).unwrap();

        let act1 = ini.write_act_one();
        // Responder can't authenticate act1 (initiator used the wrong rs), so
        // the Act One MAC fails on the responder side.
        assert!(res.read_act_one(&act1).is_err());
    }
}
