//! The native signer binary keeps its channel store across a restart: the
//! revocation counters and the balance a close is held to survive the process.
//!
//! The test runs the real `seqln-signer` in fd mode (as the proxy does), on a
//! socketpair, in a scratch directory holding an `hsm_secret`. A first session
//! sets up a channel, validates commitments 0 and 1 (signed by the peer) and
//! revokes commitment 0. A second session, a new process in the same directory,
//! must then refuse to sign the revoked commitment 0 for broadcast and refuse a
//! close that pays this wallet one atom, while still signing an honest close. A
//! third session pointed at an empty store signs the one-atom close, and signs
//! commitment 0 once it has validated commitments 0 and 1 itself: that is what
//! a signer that forgot its store would do.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::SecretKey;
use seqln_signer::frame;
use seqln_signer::kernel::{self, Kernel, BIP32_VER_TEST_PRIVATE, BIP32_VER_TEST_PUBLIC};
use seqln_signer::policy::{self, ChannelState, Side};
use seqln_signer::wire::{self, msg, Writer};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PEER: [u8; 33] = [0x02; 33];
const DBID: u64 = 3;
const FUNDING_TXID: [u8; 32] = [0x44; 32];
const FUNDING: u64 = 1_000_000;

struct Session {
    child: Child,
    stream: Option<UnixStream>,
}

impl Session {
    fn start(dir: &Path, store: Option<&Path>) -> Session {
        let (parent, child_end) = UnixStream::pair().expect("socketpair");
        let child_fd = child_end.as_raw_fd();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_seqln-signer"));
        cmd.arg("3")
            .current_dir(dir)
            .env_remove("SEQLN_SIGNER_POLICY")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match store {
            Some(p) => cmd.env("SEQLN_SIGNER_STORE", p),
            None => cmd.env_remove("SEQLN_SIGNER_STORE"),
        };
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(child_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn seqln-signer");
        drop(child_end);
        let mut s = Session { child, stream: Some(parent) };
        assert!(!s.ask(true, &init_msg()).is_empty(), "INIT failed");
        s
    }

    /// Send one request; the reply bytes (empty: refused).
    fn ask(&mut self, is_main: bool, m: &[u8]) -> Vec<u8> {
        let st = self.stream.as_mut().unwrap();
        frame::write_request(st, is_main, &PEER, DBID, u64::MAX, m).expect("write request");
        frame::read_reply(st).expect("read reply").expect("signer closed the link")
    }

    fn stop(mut self) {
        drop(self.stream.take());
        let status = self.child.wait().expect("wait");
        assert!(status.success(), "signer exited with {status}");
    }
}

fn init_msg() -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_INIT);
    w.u32(BIP32_VER_TEST_PUBLIC);
    w.u32(BIP32_VER_TEST_PRIVATE);
    w.bytes(&[0u8; 32]);
    for _ in 0..5 {
        w.bool(false);
    }
    w.u32(4);
    w.u32(6);
    w.into_vec()
}

fn kernel() -> Kernel {
    Kernel::new(kernel::bip39_seed(MNEMONIC, "").to_vec(), BIP32_VER_TEST_PUBLIC, BIP32_VER_TEST_PRIVATE)
}

fn point(k: &Kernel, n: u8) -> [u8; 33] {
    k.pubkey_of(&SecretKey::from_slice(&[n; 32]).unwrap())
}

/// The channel as `setup_msg` describes it: we opened it, the peer's
/// basepoints are the public keys of [1;32]..[5;32], option_static_remotekey.
fn channel(k: &Kernel) -> ChannelState {
    ChannelState {
        funding_sats: FUNDING,
        funding_txid: FUNDING_TXID,
        funding_txout: 0,
        local_to_self_delay: 144,
        remote_to_self_delay: 144,
        remote_revocation: point(k, 1),
        remote_payment: point(k, 2),
        remote_htlc: point(k, 3),
        remote_delayed: point(k, 4),
        remote_funding: point(k, 5),
        option_static_remotekey: true,
        option_anchors: false,
        is_outbound: Some(true),
        local_shutdown_script: Vec::new(),
        remote_shutdown_script: Vec::new(),
        revoked_through: None,
        validated_through: None,
        local_split: None,
        remote_split: None,
        validated: Vec::new(),
    }
}

fn setup_msg(k: &Kernel) -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_SETUP_CHANNEL);
    w.bool(true);
    w.u64(FUNDING);
    w.u64(0);
    w.bytes(&FUNDING_TXID);
    w.u16(0);
    w.u16(144);
    w.u16(0);
    w.bool(false);
    for n in 1..=5u8 {
        w.bytes(&point(k, n));
    }
    w.u16(144);
    w.u16(0);
    w.u16(2);
    w.bytes(&[0x10, 0x00]);
    w.into_vec()
}

fn elements_tx(locktime: u32, sequence: u32, outs: &[(Vec<u8>, u64)]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&2u32.to_le_bytes());
    t.push(0x00);
    t.push(0x01);
    t.extend_from_slice(&FUNDING_TXID);
    t.extend_from_slice(&0u32.to_le_bytes());
    t.push(0x00);
    t.extend_from_slice(&sequence.to_le_bytes());
    t.push(outs.len() as u8);
    for (script, value) in outs {
        t.push(0x01);
        t.extend_from_slice(&[0x55; 32]);
        t.push(0x01);
        t.extend_from_slice(&value.to_be_bytes());
        t.push(0x00);
        t.push(script.len() as u8);
        t.extend_from_slice(script);
    }
    t.extend_from_slice(&locktime.to_le_bytes());
    t
}

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
    p.push(0x00);
    p.extend_from_slice(&[0x01, 0x01]);
    p.push(wu.len() as u8);
    p.extend_from_slice(&wu);
    p.push(0x00);
    p
}

fn put_tx(w: &mut Writer, tx: &[u8]) {
    let psbt = funding_psbt();
    w.u32(tx.len() as u32);
    w.bytes(tx);
    w.u32(psbt.len() as u32);
    w.bytes(&psbt);
}

/// Commitment number `n` obscured into (locktime, sequence), opener first.
fn obscured(k: &Kernel, n: u64) -> (u32, u32) {
    let mut pre = k.channel_basepoints(&PEER, DBID)[1].to_vec();
    pre.extend_from_slice(&point(k, 2));
    let h = sha256::Hash::hash(&pre).to_byte_array();
    let f = h[26..32].iter().fold(0u64, |a, b| (a << 8) | *b as u64);
    let o = n ^ f;
    (0x2000_0000 | (o & 0xff_ffff) as u32, 0x8000_0000 | ((o >> 24) & 0xff_ffff) as u32)
}

/// Our commitment n: to_local 600,000, to_remote 399,000, fee 1,000.
fn commitment(k: &Kernel, n: u64) -> Vec<u8> {
    let sec = k.channel_secrets(&PEER, DBID);
    let pt = k.per_commit_point_at(&sec.shaseed, n);
    let local = policy::expected_htlc_tx_to_local(k, &PEER, DBID, &channel(k), Side::Local, &pt).unwrap();
    let remote = k.p2wpkh_scriptpubkey(&point(k, 2));
    let (locktime, sequence) = obscured(k, n);
    elements_tx(locktime, sequence, &[(local, 600_000), (remote, 399_000), (Vec::new(), 1_000)])
}

fn validate_msg(k: &Kernel, n: u64) -> Vec<u8> {
    let tx = commitment(k, n);
    let mut w = Writer::new(0);
    put_tx(&mut w, &tx);
    let bt = wire::read_bitcoin_tx(&mut wire::Reader::new(&w.into_vec()[2..])).unwrap();
    let sec = k.channel_secrets(&PEER, DBID);
    let ws = k.funding_wscript(&k.pubkey_of(&sec.funding), &point(k, 5));
    let v9 = wire::psbt_input_value9(&bt.psbt, 0).unwrap();
    let h = kernel::elements_sighash_sw_v0(&bt.tx, 0, &ws, &v9, 1);
    let sig = k.sign_hash_low_r(&h, &SecretKey::from_slice(&[5; 32]).unwrap());
    let mut w = Writer::new(msg::HSMD_VALIDATE_COMMITMENT_TX);
    put_tx(&mut w, &tx);
    w.u16(0);
    w.u64(n);
    w.u32(7500);
    w.bytes(&sig);
    w.u8(1);
    w.u16(0);
    w.into_vec()
}

fn revoke_msg(n: u64) -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_REVOKE_COMMITMENT_TX);
    w.u64(n);
    w.into_vec()
}

/// SIGN_COMMITMENT_TX (lightningd's, on its main connection) for `tx`.
fn sign_commitment_msg(k: &Kernel, tx: &[u8], claimed: u64) -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_SIGN_COMMITMENT_TX);
    w.bytes(&PEER);
    w.u64(DBID);
    put_tx(&mut w, tx);
    w.bytes(&point(k, 5));
    w.u64(claimed);
    w.into_vec()
}

fn mutual_close_msg(k: &Kernel, ours: u64, theirs: u64, fee: u64) -> Vec<u8> {
    let our_spk = k.p2wpkh_scriptpubkey(&k.bip86_child_pubkey(4));
    let peer_spk: Vec<u8> = [0x00u8, 0x14].iter().copied().chain([0x99; 20]).collect();
    let tx = elements_tx(0, 0xffff_ffff, &[(our_spk, ours), (peer_spk, theirs), (Vec::new(), fee)]);
    let mut w = Writer::new(msg::HSMD_SIGN_MUTUAL_CLOSE_TX);
    put_tx(&mut w, &tx);
    w.bytes(&point(k, 5));
    w.into_vec()
}

fn scratch_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = std::env::temp_dir().join(format!("seqln-signer-store-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let mut secret = vec![0u8; 32];
    secret.extend_from_slice(MNEMONIC.as_bytes());
    std::fs::write(d.join("hsm_secret"), secret).unwrap();
    d
}

#[test]
fn restarted_native_signer_keeps_its_counters_and_balance() {
    let k = kernel();
    let dir = scratch_dir();

    // Session 1: open, validate 0 and 1, revoke 0.
    let mut s = Session::start(&dir, None);
    assert!(!s.ask(false, &setup_msg(&k)).is_empty());
    assert!(!s.ask(false, &validate_msg(&k, 0)).is_empty(), "validate 0 refused");
    assert!(!s.ask(false, &validate_msg(&k, 1)).is_empty(), "validate 1 refused");
    assert!(!s.ask(false, &revoke_msg(0)).is_empty(), "revoke 0 refused");
    s.stop();
    let file = dir.join("seqln-signer-channels");
    let blob = std::fs::read(&file).expect("the store file was written");
    println!("store file after session 1: {} bytes", blob.len());

    // Session 2: a new process in the same directory, no setup_channel.
    let mut s = Session::start(&dir, None);
    let old = s.ask(true, &sign_commitment_msg(&k, &commitment(&k, 0), 0));
    println!("after restart, SIGN_COMMITMENT_TX of revoked commitment 0: {}",
             if old.is_empty() { "REFUSED" } else { "SIGNED" });
    assert!(old.is_empty(), "the restarted signer signed a revoked commitment");
    let theft = s.ask(false, &mutual_close_msg(&k, 1, 998_999, 1_000));
    println!("after restart, close paying this wallet 1 of 601000: {}",
             if theft.is_empty() { "REFUSED" } else { "SIGNED" });
    assert!(theft.is_empty(), "the restarted signer forgot the balance");
    assert!(s.ask(false, &revoke_msg(1)).is_empty(), "revoked 1 with 2 never validated");
    assert!(!s.ask(false, &revoke_msg(0)).is_empty(), "a repeated revocation must answer");
    assert!(!s.ask(false, &mutual_close_msg(&k, 600_500, 399_000, 500)).is_empty(),
            "the honest close was refused");
    assert!(!s.ask(true, &sign_commitment_msg(&k, &commitment(&k, 1), 1)).is_empty(),
            "the current commitment was refused");
    s.stop();

    // Control: the same requests to a signer with an empty store are signed,
    // so the refusals above come from the persisted store. With no record it
    // signs no commitment of ours for broadcast at all; once it has validated
    // commitments 0 and 1 itself, without revoking 0, it signs 0.
    let mut s = Session::start(&dir, Some(&dir.join("empty-store")));
    assert!(!s.ask(false, &setup_msg(&k)).is_empty());
    assert!(!s.ask(false, &mutual_close_msg(&k, 1, 998_999, 1_000)).is_empty(),
            "control: the one-atom close refused without a store");
    assert!(s.ask(true, &sign_commitment_msg(&k, &commitment(&k, 0), 0)).is_empty(),
            "control: commitment 0 signed with nothing validated");
    assert!(!s.ask(false, &validate_msg(&k, 0)).is_empty(), "control: validate 0 refused");
    assert!(!s.ask(false, &validate_msg(&k, 1)).is_empty(), "control: validate 1 refused");
    assert!(!s.ask(true, &sign_commitment_msg(&k, &commitment(&k, 0), 0)).is_empty(),
            "control: commitment 0 refused without a store");
    println!("control, empty store: one-atom close SIGNED; commitment 0 REFUSED until \
              validated, then SIGNED");
    s.stop();

    std::fs::remove_dir_all(&dir).unwrap();
}
