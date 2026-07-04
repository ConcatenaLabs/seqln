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
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey};
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
}
