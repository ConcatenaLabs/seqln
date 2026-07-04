//! The device-signer crypto kernel.
//!
//! This is a faithful, I/O-free Rust reimplementation of the derivation logic in
//! the reference `libhsmd` (`~/seqln/hsmd/libhsmd.c`,
//! `~/seqln/common/derive_basepoints.c`, `~/seqln/common/key_derive.c`) plus the
//! primitives it leans on (`ccan/crypto/hkdf_sha256`, `ccan/crypto/shachain`).
//!
//! Every function is annotated with the exact C source it mirrors so the two can
//! be diffed by eye; the `conformance` binary proves they agree byte-for-byte
//! against the real libhsmd via the `signerd` oracle.
//!
//! It is deliberately free of any socket / file / process code so it drops
//! straight into a `wasm32` build for the browser device signer, and so the M2b
//! tx-sighash + `sign_*` messages can be layered on top without touching I/O.

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{ecdsa, All, Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::NetworkKind;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;

/// libwally BIP32 version words (see `external/libwally-core/include/wally_bip32.h`).
pub const BIP32_VER_MAIN_PUBLIC: u32 = 0x0488_B21E;
pub const BIP32_VER_MAIN_PRIVATE: u32 = 0x0488_ADE4;
pub const BIP32_VER_TEST_PUBLIC: u32 = 0x0435_87CF;
pub const BIP32_VER_TEST_PRIVATE: u32 = 0x0435_8394;

/// libwally serialized ext_key length.
pub const BIP32_SERIALIZED_LEN: usize = 78;
/// BIP32 hardened offset.
const HARDENED: u32 = 0x8000_0000;
/// Sequentia/CLN uses a 48-bit shachain (see `common/derive_basepoints.h`).
const SHACHAIN_BITS: u32 = 48;

/// `hsm_secret->type` for a mnemonic-without-passphrase secret
/// (`enum hsm_secret_type` in `common/hsm_secret.h`).
pub const HSM_SECRET_MNEMONIC_NO_PASS: u8 = 2;

/// HKDF-SHA256, byte-for-byte per `ccan/crypto/hkdf_sha256/hkdf_sha256.c`.
///
/// Note the argument order mirrors the C call:
/// `hkdf_sha256(okm, okm_len, salt, salt_len, ikm, ikm_len, info, info_len)`.
/// Extract computes `PRK = HMAC-SHA256(key = salt, msg = ikm)`; an empty salt is
/// legal and (because HMAC zero-pads short keys to the block size) is identical
/// to the C code's `salt = NULL, salt_len = 0`.
pub fn hkdf_sha256(okm_len: usize, salt: &[u8], ikm: &[u8], info: &[u8]) -> Vec<u8> {
    // 2.2 Extract
    let mut mac = HmacSha256::new_from_slice(salt).expect("hmac accepts any key length");
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();

    // 2.3 Expand: T(i) = HMAC(PRK, T(i-1) | info | i), i starting at 1.
    let mut okm = Vec::with_capacity(okm_len);
    let mut t: Vec<u8> = Vec::new();
    let mut c: u8 = 1;
    while okm.len() < okm_len {
        let mut mac = HmacSha256::new_from_slice(&prk).expect("prk length is fixed");
        mac.update(&t);
        mac.update(info);
        mac.update(&[c]);
        t = mac.finalize().into_bytes().to_vec();
        let take = core::cmp::min(t.len(), okm_len - okm.len());
        okm.extend_from_slice(&t[..take]);
        c = c.wrapping_add(1);
    }
    okm
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// SHA256d = SHA256(SHA256(x)), the `WALLY_SIGTYPE`/`sha256_double` used by the
/// BIP-143 sighash and by `sign_hash` (which signs a `sha256_double`).
fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Bitcoin/Elements compact-size varint (`varint_from_bytes` inverse).
fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0xfd {
        out.push(v as u8);
    } else if v <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(v as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// BIP39 mnemonic -> 64-byte seed, per libwally `bip39_mnemonic_to_seed`
/// (PBKDF2-HMAC-SHA512, 2048 rounds, salt = "mnemonic" || passphrase). Our
/// hsm_secret is ASCII so no NFKD normalization is required.
pub fn bip39_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let mut salt = Vec::with_capacity(8 + passphrase.len());
    salt.extend_from_slice(b"mnemonic");
    salt.extend_from_slice(passphrase.as_bytes());
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), &salt, 2048, &mut seed);
    seed
}

fn child_number_raw(cn: ChildNumber) -> u32 {
    match cn {
        ChildNumber::Normal { index } => index,
        ChildNumber::Hardened { index } => index | HARDENED,
    }
}

/// Basepoints + shaseed derived from a per-channel seed, mirroring
/// `struct keys` in `common/derive_basepoints.c` (192 bytes = f,r,h,p,d,shaseed).
struct ChannelKeys {
    funding: [u8; 32],
    revocation: [u8; 32],
    htlc: [u8; 32],
    payment: [u8; 32],
    delayed: [u8; 32],
    shaseed: [u8; 32],
}

/// The initialized crypto kernel: the exact `secretstuff` of `libhsmd.c`, plus
/// the two BIP32 roots and the derived_secret, all cached at INIT time.
pub struct Kernel {
    secp: Secp256k1<All>,
    /// The raw hsm_secret payload = 64-byte BIP39 seed (`secretstuff.bip32_seed`).
    seed: Vec<u8>,
    pubkey_version: u32,
    /// `secretstuff.bip32` = m/0/0 of the bitcoin-address BIP32 tree.
    bip32: Xpriv,
    /// `secretstuff.bolt12`.
    bolt12: SecretKey,
    /// The BIP86 base key m/86'/0'/0' (from the raw 64-byte seed).
    bip86_base: Xpriv,
    /// `secretstuff.derived_secret`.
    derived_secret: [u8; 32],
}

impl Kernel {
    /// Mirrors `hsmd_init()` (`libhsmd.c`): builds the bitcoin BIP32 tree, the
    /// bolt12 key, the BIP86 base key and the derived_secret from the seed.
    pub fn new(seed: Vec<u8>, pubkey_version: u32, privkey_version: u32) -> Self {
        assert_eq!(seed.len(), 64, "M2a targets the mnemonic (64-byte) secret");
        let secp = Secp256k1::new();
        let net = if privkey_version == BIP32_VER_MAIN_PRIVATE {
            NetworkKind::Main
        } else {
            NetworkKind::Test
        };

        // secretstuff.derived_secret = HKDF(salt=empty, ikm=seed[full], "derived secrets")
        let derived_secret: [u8; 32] = hkdf_sha256(32, &[], &seed, b"derived secrets")
            .try_into()
            .unwrap();

        // Bitcoin-address tree: 32-byte HKDF'd seed -> BIP32 master. Loops on the
        // ~1-in-2^127 chance the seed is not a valid master (never in practice).
        let mut salt: u32 = 0;
        let master = loop {
            let s = hkdf_sha256(32, &salt.to_ne_bytes(), &seed, b"bip32 seed");
            match Xpriv::new_master(net, &s) {
                Ok(m) => break m,
                Err(_) => salt = salt.wrapping_add(1),
            }
        };

        // secretstuff.bip32 = master -> 0 -> 0 (both non-hardened).
        let bip32 = master
            .derive_priv(
                &secp,
                &[
                    ChildNumber::Normal { index: 0 },
                    ChildNumber::Normal { index: 0 },
                ],
            )
            .expect("m/0/0 derivation");

        // secretstuff.bolt12 = master -> 9735' private key.
        let bolt12 = master
            .derive_priv(&secp, &[ChildNumber::Hardened { index: 9735 }])
            .expect("m/9735' derivation")
            .private_key;

        // BIP86 base = master(from raw 64-byte seed) -> 86'/0'/0'.
        let bip86_master = Xpriv::new_master(net, &seed).expect("bip86 master");
        let bip86_base = bip86_master
            .derive_priv(
                &secp,
                &[
                    ChildNumber::Hardened { index: 86 },
                    ChildNumber::Hardened { index: 0 },
                    ChildNumber::Hardened { index: 0 },
                ],
            )
            .expect("m/86'/0'/0' derivation");

        Kernel {
            secp,
            seed,
            pubkey_version,
            bip32,
            bolt12,
            bip86_base,
            derived_secret,
        }
    }

    fn pubkey(&self, sk: &SecretKey) -> [u8; 33] {
        PublicKey::from_secret_key(&self.secp, sk).serialize()
    }

    /// `node_key()` (`libhsmd.c`): HKDF(salt=&salt(u32)=0, ikm=seed[0..32], "nodeid").
    pub fn node_privkey(&self) -> SecretKey {
        let mut salt: u32 = 0;
        loop {
            let bytes = hkdf_sha256(32, &salt.to_ne_bytes(), &self.seed[..32], b"nodeid");
            match SecretKey::from_slice(&bytes) {
                Ok(k) => return k,
                Err(_) => salt = salt.wrapping_add(1),
            }
        }
    }

    /// Compressed node id (`node_key(NULL, &key)` -> pubkey).
    pub fn node_id(&self) -> [u8; 33] {
        self.pubkey(&self.node_privkey())
    }

    /// The bolt12 base pubkey handed out in the init reply.
    pub fn bolt12_pubkey(&self) -> [u8; 33] {
        self.pubkey(&self.bolt12)
    }

    /// `hsm_channel_secret_base()`: HKDF(salt=empty, ikm=seed[0..32], "peer seed").
    fn channel_secret_base(&self) -> [u8; 32] {
        hkdf_sha256(32, &[], &self.seed[..32], b"peer seed")
            .try_into()
            .unwrap()
    }

    /// `get_channel_seed()`: HKDF(salt = node_id.k(33) || dbid(8 LE),
    /// ikm = channel_base(32), "per-peer seed").
    fn channel_seed(&self, peer_id: &[u8; 33], dbid: u64) -> [u8; 32] {
        let base = self.channel_secret_base();
        let mut input = Vec::with_capacity(33 + 8);
        input.extend_from_slice(peer_id);
        // The C code does `memcpy(input + 33, &dbid, 8)`: host-endian, i.e. LE on
        // the x86 box that runs the oracle.
        input.extend_from_slice(&dbid.to_le_bytes());
        hkdf_sha256(32, &input, &base, b"per-peer seed")
            .try_into()
            .unwrap()
    }

    /// `derive_keys()` (`derive_basepoints.c`): the 192-byte c-lightning HKDF.
    fn channel_keys(&self, seed: &[u8; 32]) -> ChannelKeys {
        let k = hkdf_sha256(192, &[], seed, b"c-lightning");
        let g = |a: usize| -> [u8; 32] { k[a..a + 32].try_into().unwrap() };
        ChannelKeys {
            funding: g(0),
            revocation: g(32),
            htlc: g(64),
            payment: g(96),
            delayed: g(128),
            shaseed: g(160),
        }
    }

    /// `handle_get_channel_basepoints()` reply payload: the four basepoints
    /// (revocation, payment, htlc, delayed) and the funding pubkey.
    pub fn channel_basepoints(&self, peer_id: &[u8; 33], dbid: u64) -> [[u8; 33]; 5] {
        let seed = self.channel_seed(peer_id, dbid);
        let keys = self.channel_keys(&seed);
        let pk = |raw: &[u8; 32]| self.pubkey(&SecretKey::from_slice(raw).expect("valid basepoint"));
        [
            pk(&keys.revocation),
            pk(&keys.payment),
            pk(&keys.htlc),
            pk(&keys.delayed),
            pk(&keys.funding),
        ]
    }

    /// `shachain_from_seed()` (`ccan/crypto/shachain`): flip-bit-then-sha256 walk.
    fn shachain_from_seed(seed: &[u8; 32], index: u64) -> [u8; 32] {
        let mut h = *seed;
        // derive(0, index, ...) visits bits from the highest set bit down to 0;
        // iterating the full 0..48 range with the per-bit guard is identical.
        for i in (0..SHACHAIN_BITS).rev() {
            if (index >> i) & 1 == 1 {
                h[(i / 8) as usize] ^= 1u8 << (i % 8);
                h = sha256(&h);
            }
        }
        h
    }

    /// `per_commit_secret()`: shachain over the reversed index.
    fn per_commit_secret(shaseed: &[u8; 32], n: u64) -> [u8; 32] {
        // shachain_index(n) = (2^48 - 1) - n
        let index = ((1u64 << SHACHAIN_BITS) - 1) - n;
        Self::shachain_from_seed(shaseed, index)
    }

    /// `handle_get_per_commitment_point()`: the per-commitment point for index
    /// `n`, and (only when `hsm_version < 6` and `n >= 2`) the n-2 secret.
    pub fn per_commitment_point(
        &self,
        peer_id: &[u8; 33],
        dbid: u64,
        n: u64,
        hsm_version: u32,
    ) -> ([u8; 33], Option<[u8; 32]>) {
        let seed = self.channel_seed(peer_id, dbid);
        let shaseed = self.channel_keys(&seed).shaseed;
        let secret = Self::per_commit_secret(&shaseed, n);
        let point = self.pubkey(&SecretKey::from_slice(&secret).expect("valid per-commit secret"));
        let old = if hsm_version < 6 && n >= 2 {
            Some(Self::per_commit_secret(&shaseed, n - 2))
        } else {
            None
        };
        (point, old)
    }

    /// `handle_ecdh()`: secp256k1 ECDH (default SHA256-of-compressed-point hash)
    /// between the node key and `point`.
    pub fn ecdh(&self, point: &[u8; 33]) -> Result<[u8; 32], ()> {
        let pk = PublicKey::from_slice(point).map_err(|_| ())?;
        let ss = SharedSecret::new(&pk, &self.node_privkey());
        Ok(ss.secret_bytes())
    }

    /// `handle_derive_secret()`: HKDF(salt=empty, ikm=derived_secret, info).
    pub fn derive_secret(&self, info: &[u8]) -> [u8; 32] {
        hkdf_sha256(32, &[], &self.derived_secret, info)
            .try_into()
            .unwrap()
    }

    /// `bitcoin_key()` for `handle_check_pubkey`: m/0/0/index (non-hardened).
    pub fn bip32_child_pubkey(&self, index: u32) -> [u8; 33] {
        assert!(index < HARDENED, "index too great");
        let child = self
            .bip32
            .derive_priv(&self.secp, &[ChildNumber::Normal { index }])
            .expect("m/0/0/index derivation");
        self.pubkey(&child.private_key)
    }

    /// `bip86_key()` for `handle_check_bip86_pubkey`: m/86'/0'/0'/0/index.
    pub fn bip86_child_pubkey(&self, index: u32) -> [u8; 33] {
        assert!(index < HARDENED, "index too great");
        let child = self
            .bip86_base
            .derive_priv(
                &self.secp,
                &[ChildNumber::Normal { index: 0 }, ChildNumber::Normal { index }],
            )
            .expect("m/86'/0'/0'/0/index derivation");
        self.pubkey(&child.private_key)
    }

    /// Serialize `secretstuff.bip32` (m/0/0) as a public ext_key, exactly as
    /// libwally's `bip32_key_serialize(.., BIP32_FLAG_KEY_PUBLIC, ..)` /
    /// `towire_ext_key` would (`common/bip32.c`).
    pub fn bip32_ext_key_public(&self) -> [u8; BIP32_SERIALIZED_LEN] {
        self.serialize_ext_key_public(&self.bip32)
    }

    /// Serialize the BIP86 base key m/86'/0'/0' as a public ext_key.
    pub fn bip86_base_ext_key_public(&self) -> [u8; BIP32_SERIALIZED_LEN] {
        self.serialize_ext_key_public(&self.bip86_base)
    }

    fn serialize_ext_key_public(&self, x: &Xpriv) -> [u8; BIP32_SERIALIZED_LEN] {
        let mut out = [0u8; BIP32_SERIALIZED_LEN];
        out[0..4].copy_from_slice(&self.pubkey_version.to_be_bytes());
        out[4] = x.depth;
        out[5..9].copy_from_slice(x.parent_fingerprint.as_ref());
        out[9..13].copy_from_slice(&child_number_raw(x.child_number).to_be_bytes());
        out[13..45].copy_from_slice(x.chain_code.as_ref());
        out[45..78].copy_from_slice(&self.pubkey(&x.private_key));
        out
    }

    // ===================================================================
    // M2b: channel signing keys, per-commitment derivation, and signing.
    // ===================================================================

    /// The five per-channel basepoint secrets + shaseed, exactly the `struct
    /// keys { privkey f, r, h, p, d; sha256 shaseed; }` layout of the 192-byte
    /// "c-lightning" HKDF (`common/derive_basepoints.c`).
    pub fn channel_secrets(&self, peer_id: &[u8; 33], dbid: u64) -> ChannelSecrets {
        let seed = self.channel_seed(peer_id, dbid);
        let k = self.channel_keys(&seed);
        let sk = |raw: &[u8; 32]| SecretKey::from_slice(raw).expect("valid channel secret");
        ChannelSecrets {
            funding: sk(&k.funding),
            revocation: sk(&k.revocation),
            htlc: sk(&k.htlc),
            payment: sk(&k.payment),
            delayed: sk(&k.delayed),
            shaseed: k.shaseed,
        }
    }

    /// `per_commit_point(shaseed, n)` -> compressed point.
    pub fn per_commit_point_at(&self, shaseed: &[u8; 32], n: u64) -> [u8; 33] {
        let secret = Self::per_commit_secret(shaseed, n);
        self.pubkey(&SecretKey::from_slice(&secret).expect("valid per-commit secret"))
    }

    /// `per_commit_secret(shaseed, n)` -> 32-byte secret.
    pub fn per_commit_secret_at(&self, shaseed: &[u8; 32], n: u64) -> [u8; 32] {
        Self::per_commit_secret(shaseed, n)
    }

    /// Compressed pubkey for a secret (`pubkey_from_privkey`).
    pub fn pubkey_of(&self, sk: &SecretKey) -> [u8; 33] {
        self.pubkey(sk)
    }

    /// `pubkey_from_secret`: the point for a 32-byte secret, or Err if invalid.
    pub fn point_from_secret(&self, secret: &[u8; 32]) -> Result<[u8; 33], ()> {
        let sk = SecretKey::from_slice(secret).map_err(|_| ())?;
        Ok(self.pubkey(&sk))
    }

    /// `derive_simple_privkey` (`common/key_derive.c`):
    /// `privkey = base_secret + SHA256(per_commitment_point || basepoint)`,
    /// where `basepoint = base_secret * G` (compressed).
    pub fn derive_simple_privkey(
        &self,
        base_secret: &SecretKey,
        per_commitment_point: &[u8; 33],
    ) -> SecretKey {
        let basepoint = self.pubkey(base_secret);
        let mut buf = [0u8; 66];
        buf[..33].copy_from_slice(per_commitment_point);
        buf[33..].copy_from_slice(&basepoint);
        let tweak = Scalar::from_be_bytes(sha256(&buf)).expect("tweak in range");
        base_secret.add_tweak(&tweak).expect("valid derived privkey")
    }

    /// PUBLIC-key `derive_simple_key` (`common/key_derive.c`), the validation
    /// counterpart of `derive_simple_privkey`:
    /// `key = basepoint + SHA256(per_commitment_point || basepoint) * G`.
    /// Used by the M4 validating policy to reconstruct the delayed/htlc/payment
    /// pubkeys a legitimate commitment output must pay to, WITHOUT any secret.
    pub fn derive_simple_key_pub(
        &self,
        basepoint: &[u8; 33],
        per_commitment_point: &[u8; 33],
    ) -> Result<[u8; 33], ()> {
        let bp = PublicKey::from_slice(basepoint).map_err(|_| ())?;
        let mut buf = [0u8; 66];
        buf[..33].copy_from_slice(per_commitment_point);
        buf[33..].copy_from_slice(basepoint);
        let tweak = Scalar::from_be_bytes(sha256(&buf)).map_err(|_| ())?;
        let key = bp.add_exp_tweak(&self.secp, &tweak).map_err(|_| ())?;
        Ok(key.serialize())
    }

    /// PUBLIC-key `derive_revocation_key` (`common/key_derive.c`):
    /// `revocationpubkey = basepoint * SHA256(basepoint || P)
    ///                   + P * SHA256(P || basepoint)`,
    /// where `basepoint` is the OTHER party's revocation basepoint and `P` the
    /// per-commitment point. Reconstructs the revocation pubkey the to_local /
    /// HTLC scripts must reference, WITHOUT any secret.
    pub fn derive_revocation_key_pub(
        &self,
        basepoint: &[u8; 33],
        per_commitment_point: &[u8; 33],
    ) -> Result<[u8; 33], ()> {
        let bp = PublicKey::from_slice(basepoint).map_err(|_| ())?;
        let pp = PublicKey::from_slice(per_commitment_point).map_err(|_| ())?;
        // add0 = basepoint * SHA256(basepoint || P)
        let mut b1 = [0u8; 66];
        b1[..33].copy_from_slice(basepoint);
        b1[33..].copy_from_slice(per_commitment_point);
        let s1 = Scalar::from_be_bytes(sha256(&b1)).map_err(|_| ())?;
        let add0 = bp.mul_tweak(&self.secp, &s1).map_err(|_| ())?;
        // add1 = P * SHA256(P || basepoint)
        let mut b2 = [0u8; 66];
        b2[..33].copy_from_slice(per_commitment_point);
        b2[33..].copy_from_slice(basepoint);
        let s2 = Scalar::from_be_bytes(sha256(&b2)).map_err(|_| ())?;
        let add1 = pp.mul_tweak(&self.secp, &s2).map_err(|_| ())?;
        let key = add0.combine(&add1).map_err(|_| ())?;
        Ok(key.serialize())
    }

    /// `derive_revocation_privkey` (`common/key_derive.c`):
    /// `base_secret * SHA256(basepoint || P) + per_commitment_secret * SHA256(P || basepoint)`,
    /// where `basepoint = revocation_basepoint_secret * G` and `P` is the
    /// `per_commitment_point` (= `per_commitment_secret * G`).
    pub fn derive_revocation_privkey(
        &self,
        base_secret: &SecretKey,
        per_commitment_secret: &SecretKey,
        per_commitment_point: &[u8; 33],
    ) -> SecretKey {
        let basepoint = self.pubkey(base_secret);
        // sha1 = SHA256(basepoint || per_commitment_point)
        let mut b1 = [0u8; 66];
        b1[..33].copy_from_slice(&basepoint);
        b1[33..].copy_from_slice(per_commitment_point);
        let s1 = Scalar::from_be_bytes(sha256(&b1)).expect("tweak in range");
        let part1 = base_secret.mul_tweak(&s1).expect("valid mul");
        // sha2 = SHA256(per_commitment_point || basepoint)
        let mut b2 = [0u8; 66];
        b2[..33].copy_from_slice(per_commitment_point);
        b2[33..].copy_from_slice(&basepoint);
        let s2 = Scalar::from_be_bytes(sha256(&b2)).expect("tweak in range");
        let part2 = per_commitment_secret.mul_tweak(&s2).expect("valid mul");
        let part2_scalar =
            Scalar::from_be_bytes(part2.secret_bytes()).expect("part2 in range");
        part1.add_tweak(&part2_scalar).expect("valid revocation privkey")
    }

    /// The BOLT-3 funding `witnessScript`: `OP_2 <lo> <hi> OP_2 OP_CHECKMULTISIG`,
    /// keys sorted by their compressed serialization (`bitcoin_redeem_2of2`).
    pub fn funding_wscript(&self, local_funding: &[u8; 33], remote_funding: &[u8; 33]) -> Vec<u8> {
        let (a, b) = if local_funding[..] < remote_funding[..] {
            (local_funding, remote_funding)
        } else {
            (remote_funding, local_funding)
        };
        let mut s = Vec::with_capacity(71);
        s.push(0x52); // OP_2
        s.push(0x21); // push 33
        s.extend_from_slice(a);
        s.push(0x21);
        s.extend_from_slice(b);
        s.push(0x52); // OP_2
        s.push(0xae); // OP_CHECKMULTISIG
        s
    }

    /// `scriptpubkey_p2wpkh`: `OP_0 <20-byte HASH160(compressed pubkey)>`.
    pub fn p2wpkh_scriptpubkey(&self, pubkey: &[u8; 33]) -> Vec<u8> {
        let h = hash160::Hash::hash(pubkey);
        let mut s = Vec::with_capacity(22);
        s.push(0x00); // OP_0
        s.push(0x14); // push 20
        s.extend_from_slice(&h[..]);
        s
    }

    /// `sign_hash` (`bitcoin/signature.c`): ECDSA with low-R grinding, matching
    /// libhsmd BYTE-FOR-BYTE. libhsmd calls `secp256k1_ecdsa_sign(.., NULL,
    /// extra_entropy)` where `extra_entropy` starts at 32 zero bytes and the
    /// first u32 (host-endian = little on x86) increments each grind round,
    /// looping until the compact signature's first byte is `< 0x80` (low R).
    /// rust-secp's own `sign_ecdsa_low_r` passes `noncedata = NULL` on the FIRST
    /// round (not 32 zeros), so it does NOT reproduce these bytes — we must
    /// drive `sign_ecdsa_with_noncedata` ourselves. Returns the 64-byte compact
    /// signature (low-S, low-R), as `towire_secp256k1_ecdsa_signature` emits.
    pub fn sign_hash_low_r(&self, hash: &[u8; 32], sk: &SecretKey) -> [u8; 64] {
        let msg = Message::from_digest(*hash);
        let mut extra = [0u8; 32];
        loop {
            let sig: ecdsa::Signature = self.secp.sign_ecdsa_with_noncedata(&msg, sk, &extra);
            let compact = sig.serialize_compact();
            // Increment first u32 (little-endian) BEFORE the low-R test, exactly
            // as `sign_hash` does `((u32*)extra_entropy)[0]++` then `while(...)`.
            let c = u32::from_le_bytes([extra[0], extra[1], extra[2], extra[3]]).wrapping_add(1);
            extra[..4].copy_from_slice(&c.to_le_bytes());
            if compact[0] < 0x80 {
                return compact;
            }
        }
    }

    /// `secp256k1_ecdsa_sign_recoverable` (RFC6979, no grind) over `hash` with
    /// the node key, serialized as `towire_secp256k1_ecdsa_recoverable_signature`
    /// does: 64-byte compact || recid(u8). Used by `handle_sign_invoice`.
    pub fn node_sign_recoverable(&self, hash: &[u8; 32]) -> [u8; 65] {
        let msg = Message::from_digest(*hash);
        let sk = self.node_privkey();
        let rsig = self.secp.sign_ecdsa_recoverable(&msg, &sk);
        let (recid, compact) = rsig.serialize_compact();
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&compact);
        out[64] = recid.to_i32() as u8;
        out
    }
}

/// The five per-channel basepoint secrets + the shaseed.
pub struct ChannelSecrets {
    pub funding: SecretKey,
    pub revocation: SecretKey,
    pub htlc: SecretKey,
    pub payment: SecretKey,
    pub delayed: SecretKey,
    pub shaseed: [u8; 32],
}

/// A parsed input of a linearized Elements tx, only the fields the BIP-143
/// sighash needs (`bitcoin/signature.c` -> `wally_tx_get_elements_signature_hash`).
pub struct TxInput {
    pub txhash: [u8; 32],
    pub index: u32,
    pub sequence: u32,
    pub is_issuance: bool,
}

/// A parsed output: the raw confidential-commitment bytes (asset/value/nonce, as
/// serialized, so `hash_commmitment` reproduces them verbatim) and the script.
pub struct TxOutput {
    pub asset: Vec<u8>,
    pub value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub script: Vec<u8>,
}

pub struct ElementsTx {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
}

fn hash_output_elements(out: &mut Vec<u8>, o: &TxOutput) {
    // asset/value/nonce commitments are hashed verbatim (a null field is its
    // single 0x00 byte, which equals libwally's `hash_u8(0)`); script is varbuff.
    out.extend_from_slice(&o.asset);
    out.extend_from_slice(&o.value);
    out.extend_from_slice(&o.nonce);
    write_varint(out, o.script.len() as u64);
    out.extend_from_slice(&o.script);
}

/// The Elements segwit-v0 (BIP-143) signature hash, a faithful port of
/// `bip143_signature_hash` (`external/libwally-core/src/tx_io.c`) for the
/// `WALLY_SIGTYPE_SW_V0` + Elements path. `value` is the 9-byte confidential
/// value of the input being signed (`0x01 || uint64_be(amount)`). Returns the
/// 32-byte `sha256_double` preimage hash that `sign_hash` then signs.
pub fn elements_sighash_sw_v0(
    tx: &ElementsTx,
    index: usize,
    scriptcode: &[u8],
    value: &[u8],
    sighash: u32,
) -> [u8; 32] {
    let acp = sighash & 0x80 != 0;
    let base = sighash & 0x1f; // WALLY_SIGHASH_MASK
    let none = base == 0x02;
    let single = base == 0x03;
    let zero = [0u8; 32];

    let mut m: Vec<u8> = Vec::new();
    m.extend_from_slice(&tx.version.to_le_bytes());

    // hashPrevouts
    if acp {
        m.extend_from_slice(&zero);
    } else {
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(&i.txhash);
            b.extend_from_slice(&i.index.to_le_bytes());
        }
        m.extend_from_slice(&sha256d(&b));
    }

    // hashSequence
    if acp || single || none {
        m.extend_from_slice(&zero);
    } else {
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(&i.sequence.to_le_bytes());
        }
        m.extend_from_slice(&sha256d(&b));
    }

    // hashIssuances (Elements). Our txs carry no issuances -> 0x00 per input.
    if acp {
        m.extend_from_slice(&zero);
    } else {
        let mut b = Vec::new();
        for i in &tx.inputs {
            assert!(!i.is_issuance, "issuance inputs not supported in M2b sighash");
            b.push(0u8);
        }
        m.extend_from_slice(&sha256d(&b));
    }

    // Input being signed: outpoint || scriptCode(varbuff) || value(9) || sequence.
    let inp = &tx.inputs[index];
    m.extend_from_slice(&inp.txhash);
    m.extend_from_slice(&inp.index.to_le_bytes());
    write_varint(&mut m, scriptcode.len() as u64);
    m.extend_from_slice(scriptcode);
    m.extend_from_slice(value);
    m.extend_from_slice(&inp.sequence.to_le_bytes());

    // hashOutputs
    if none || (single && index >= tx.outputs.len()) {
        m.extend_from_slice(&zero);
    } else if single {
        let mut b = Vec::new();
        hash_output_elements(&mut b, &tx.outputs[index]);
        m.extend_from_slice(&sha256d(&b));
    } else {
        let mut b = Vec::new();
        for o in &tx.outputs {
            hash_output_elements(&mut b, o);
        }
        m.extend_from_slice(&sha256d(&b));
    }

    m.extend_from_slice(&tx.locktime.to_le_bytes());
    m.extend_from_slice(&sighash.to_le_bytes());
    sha256d(&m)
}

/// `sha256_double` over a byte range (BOLT-7 gossip-message signing hash).
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256d(data)
}

/// BOLT-11 `hash_u5` (`common/hash_u5.c`): the SHA256 over `hrp` followed by the
/// 5-bit-per-byte data, packed MSB-first. Used by `handle_sign_invoice`.
pub fn hash_u5(hrp: &[u8], u5: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(hrp);
    let mut buf: u64 = 0;
    let mut num_bits: usize = 0;
    for &b in u5 {
        buf = (buf << 5) | (b as u64 & 0x1f);
        num_bits += 5;
        if num_bits >= 8 {
            num_bits -= 8;
            h.update([((buf >> num_bits) & 0xff) as u8]);
        }
    }
    if num_bits > 0 {
        h.update([((buf << (8 - num_bits)) & 0xff) as u8]);
    }
    h.finalize().into()
}
