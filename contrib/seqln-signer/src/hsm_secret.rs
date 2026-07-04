//! Loading the `hsm_secret` file (mnemonic format), mirroring
//! `common/hsm_secret.c` (`detect_hsm_secret_type` / `extract_mnemonic_secret`).
//!
//! On-disk layout for a mnemonic secret: `seed_hash(32) || mnemonic`, where
//! `seed_hash` is all-zero for the no-passphrase case. `secret_data` (what
//! libhsmd consumes) is the 64-byte BIP39 seed derived from the mnemonic.
//!
//! M2a targets the mnemonic-without-passphrase secret (the format the fork's
//! `create_hsm` writes); the encrypted / legacy-32-byte / with-passphrase forms
//! are out of scope here and rejected explicitly.

use crate::kernel::{bip39_seed, HSM_SECRET_MNEMONIC_NO_PASS};

pub struct HsmSecret {
    /// The 64-byte BIP39 seed = `secretstuff.bip32_seed`.
    pub seed: [u8; 64],
    /// `hsm_secret->type`, echoed in the init reply TLV.
    pub secret_type: u8,
    /// The recovered mnemonic (kept for completeness / future validation).
    pub mnemonic: String,
}

pub fn parse(bytes: &[u8]) -> Result<HsmSecret, String> {
    if bytes.len() <= 32 {
        return Err(format!(
            "hsm_secret is {} bytes: not a mnemonic secret (M2a supports mnemonic only)",
            bytes.len()
        ));
    }
    let first32 = &bytes[..32];
    if !first32.iter().all(|&b| b == 0) {
        return Err("hsm_secret has a non-zero passphrase hash: only \
                    mnemonic-without-passphrase is supported in M2a"
            .to_string());
    }
    let mnemonic = std::str::from_utf8(&bytes[32..])
        .map_err(|e| format!("mnemonic is not valid UTF-8: {e}"))?
        .to_string();
    // No-passphrase: bip39 seed with an empty passphrase.
    let seed = bip39_seed(&mnemonic, "");
    Ok(HsmSecret {
        seed,
        secret_type: HSM_SECRET_MNEMONIC_NO_PASS,
        mnemonic,
    })
}
