//! SeqLN Tier-2 device signer (milestone M2a).
//!
//! A Rust reimplementation of the reference `libhsmd` crypto kernel and the
//! PURE-DERIVATION subset of the hsmd wire protocol, conformance-tested
//! byte-for-byte against libhsmd via the `signerd` oracle (see `bin/conformance`).
//!
//! Layering (kept clean so M2b's tx-sighash / `sign_*` messages and a later
//! `wasm32` browser build slot in without rework):
//!
//! * [`kernel`]  — I/O-free crypto: BIP39/32/86, HKDF-SHA256, shachain,
//!                 basepoints, per-commitment points, ECDH. WASM-ready.
//! * [`wire`]    — the big-endian hsmd wire codec for the subset.
//! * [`frame`]   — the little-endian signer-split transport (`signer_frame.h`).
//! * [`hsm_secret`] — parsing the on-disk mnemonic `hsm_secret`.
//! * [`dispatch`] — request -> reply for the implemented subset.
//!
//! Only `bin/seqln-signer` (the native serving loop) and `bin/conformance`
//! (the harness) touch sockets/files/processes.

pub mod dispatch;
pub mod frame;
pub mod hsm_secret;
pub mod kernel;
pub mod wire;
