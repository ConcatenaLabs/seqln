//! Channel-store persistence: the restart contract that keeps a signer from
//! orphaning its channels. `setup_channel` is only ever sent at channel
//! CREATION, so a restarted signer that lost its in-memory store refuses every
//! commitment sign (enforce mode) and channeld dies at init — the funds are
//! frozen, close included. The host therefore persists `export_channels` and
//! restores it with `import_channels` on boot; these tests pin that contract:
//! deterministic roundtrip, seed-keyed MAC refusal of tampered/foreign blobs,
//! and live-state-wins merge semantics.

use seqln_signer::dispatch::Signer;
use seqln_signer::hsm_secret;
use seqln_signer::policy::{ChannelState, Policy};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn secret_bytes(mnemonic: &str) -> Vec<u8> {
    let mut b = vec![0u8; 32]; // no-passphrase hash
    b.extend_from_slice(mnemonic.as_bytes());
    b
}

fn signer(mnemonic: &str) -> Signer {
    Signer::with_policy(
        hsm_secret::parse(&secret_bytes(mnemonic)).expect("parse hsm_secret"),
        Policy::Enforce,
    )
}

fn chan(seed: u8) -> ChannelState {
    ChannelState {
        funding_sats: 1_000_000 + seed as u64,
        funding_txid: [seed; 32],
        funding_txout: seed as u16,
        local_to_self_delay: 144,
        remote_to_self_delay: 288,
        remote_revocation: [seed.wrapping_add(1); 33],
        remote_payment: [seed.wrapping_add(2); 33],
        remote_htlc: [seed.wrapping_add(3); 33],
        remote_delayed: [seed.wrapping_add(4); 33],
        remote_funding: [seed.wrapping_add(5); 33],
        option_static_remotekey: true,
        option_anchors: seed % 2 == 0,
    }
}

#[test]
fn roundtrip_restores_every_channel_byte_for_byte() {
    let mut a = signer(MNEMONIC);
    assert!(!a.take_channels_dirty(), "a fresh signer is not dirty");
    a.arm_channel([0x02; 33], 1, chan(10)).unwrap();
    a.arm_channel([0x03; 33], 7, chan(20)).unwrap();
    assert!(a.take_channels_dirty(), "arming dirties the store");
    assert!(!a.take_channels_dirty(), "dirty is take-and-clear");

    let blob = a.export_channels();

    let mut b = signer(MNEMONIC);
    assert!(!b.has_channel(&[0x02; 33], 1));
    let added = b.import_channels(&blob).expect("import own blob");
    assert_eq!(added, 2);
    assert!(b.has_channel(&[0x02; 33], 1));
    assert!(b.has_channel(&[0x03; 33], 7));
    // Deterministic encoding: a faithful restore re-exports the SAME blob.
    assert_eq!(b.export_channels(), blob);
}

#[test]
fn tampered_and_foreign_blobs_are_refused_whole() {
    let mut a = signer(MNEMONIC);
    a.arm_channel([0x02; 33], 1, chan(10)).unwrap();
    let blob = a.export_channels();

    // One flipped payload byte: MAC mismatch, nothing imported.
    let mut bad = blob.clone();
    bad[9] ^= 0x01;
    let mut b = signer(MNEMONIC);
    assert!(b.import_channels(&bad).is_err());
    assert!(!b.has_channel(&[0x02; 33], 1));

    // A blob from a DIFFERENT seed: refused (the MAC key is seed-derived).
    let mut c = signer(OTHER_MNEMONIC);
    assert!(c.import_channels(&blob).is_err());

    // Truncated garbage: refused.
    assert!(b.import_channels(&blob[..20]).is_err());
    assert!(b.import_channels(&[]).is_err());
}

#[test]
fn import_never_overwrites_live_state_and_arm_never_overwrites_tracked() {
    let mut a = signer(MNEMONIC);
    a.arm_channel([0x02; 33], 1, chan(10)).unwrap();
    a.arm_channel([0x03; 33], 7, chan(20)).unwrap();
    let blob = a.export_channels();

    // b already tracks (0x02,1) with DIFFERENT (live) state.
    let mut b = signer(MNEMONIC);
    b.arm_channel([0x02; 33], 1, chan(99)).unwrap();
    b.take_channels_dirty();
    let added = b.import_channels(&blob).expect("import");
    assert_eq!(added, 1, "only the missing channel is added");
    assert!(b.take_channels_dirty(), "a real addition re-dirties the store");
    // The live entry survived: b's export differs from a's blob (chan 99 != chan 10).
    assert_ne!(b.export_channels(), blob);

    // arm_channel refuses to replace a tracked channel (returns false).
    assert_eq!(b.arm_channel([0x02; 33], 1, chan(50)).unwrap(), false);
}

#[test]
fn empty_store_roundtrips() {
    let a = signer(MNEMONIC);
    let blob = a.export_channels();
    let mut b = signer(MNEMONIC);
    assert_eq!(b.import_channels(&blob).expect("import empty"), 0);
}
