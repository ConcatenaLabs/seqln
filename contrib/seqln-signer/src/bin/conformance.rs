//! Byte-for-byte conformance harness (milestone M2a).
//!
//! Drives BOTH the reference `lightning_signerd` (the oracle, which links the
//! real libhsmd) and our `seqln-signer` with the SAME fixed `hsm_secret` and the
//! SAME sequence of framed requests, then compares the reply bytes EXACTLY.
//!
//! Each signer is fork/exec'd with one end of a socketpair dup'd onto fd 3 and
//! "3" passed as argv[1] (exactly how `hsmd-proxy` starts `signerd`). We speak
//! the `signer_frame.h` protocol directly over the other end.
//!
//! SUCCESS = identical replies from both across the whole implemented subset,
//! proving the Rust derivations match libhsmd.
//!
//! Usage: conformance [ORACLE_BIN [PROXY_BIN]]
//!   defaults: $SEQLN_ORACLE or /home/aejkohl/seqln/lightningd/lightning_signerd,
//!             $SEQLN_PROXY  or the sibling `seqln-signer` next to this binary.

use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use seqln_signer::kernel::{
    Kernel, BIP32_VER_TEST_PRIVATE, BIP32_VER_TEST_PUBLIC,
};
use seqln_signer::wire::{msg, Writer};
use seqln_signer::{frame, kernel};

/// The canonical all-zero-entropy BIP39 test vector (public, not a real secret).
const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// secp256k1 generator point, compressed — a convenient valid pubkey for
/// message fields that must parse as a point (SETUP_CHANNEL, ECDH input, etc.).
const G: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

const ALL_CAPS: u64 = u64::MAX;

struct SignerProc {
    child: Child,
    stream: UnixStream,
}

fn spawn(bin: &str, dir: &std::path::Path) -> SignerProc {
    let (parent, child_end) = UnixStream::pair().expect("socketpair");
    let child_fd = child_end.as_raw_fd();

    let mut cmd = Command::new(bin);
    cmd.arg("3")
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(move || {
            // Move the socket onto fd 3 (dup2 clears CLOEXEC on the new fd, so it
            // survives exec). The signer reads/writes frames on fd 3.
            if libc::dup2(child_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {bin}: {e}"));
    // Parent no longer needs the child end.
    drop(child_end);
    SignerProc {
        child,
        stream: parent,
    }
}

impl SignerProc {
    /// Send a framed request and read the framed reply. Returns None on EOF
    /// (signer died / closed the transport, e.g. a fatal rejection).
    fn roundtrip(
        &mut self,
        is_main: bool,
        node_id: &[u8; 33],
        dbid: u64,
        caps: u64,
        hsmd_msg: &[u8],
    ) -> Option<Vec<u8>> {
        frame::write_request(&mut self.stream, is_main, node_id, dbid, caps, hsmd_msg)
            .expect("write request");
        match frame::read_reply(&mut self.stream) {
            Ok(v) => v,
            Err(_) => None,
        }
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// One test case: a label, the frame context, and the raw hsmd request bytes.
struct Case {
    name: String,
    is_main: bool,
    node_id: [u8; 33],
    dbid: u64,
    caps: u64,
    msg: Vec<u8>,
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let oracle = argv
        .get(1)
        .cloned()
        .or_else(|| std::env::var("SEQLN_ORACLE").ok())
        .unwrap_or_else(|| "/home/aejkohl/seqln/lightningd/lightning_signerd".to_string());
    let proxy = argv
        .get(2)
        .cloned()
        .or_else(|| std::env::var("SEQLN_PROXY").ok())
        .unwrap_or_else(|| {
            let mut p: PathBuf = std::env::current_exe().unwrap();
            p.pop();
            p.push("seqln-signer");
            p.to_string_lossy().into_owned()
        });

    eprintln!("oracle: {oracle}");
    eprintln!("proxy : {proxy}");

    // M2b: offline replay of a captured corpus (SEQLN_CORPUS = a stream of
    // signer frames from a real channel; SEQLN_HSM_SECRET = that node's secret).
    // Replays every real request to BOTH signers and byte-compares the replies.
    if let Ok(corpus) = std::env::var("SEQLN_CORPUS") {
        let secret_path = std::env::var("SEQLN_HSM_SECRET")
            .expect("SEQLN_HSM_SECRET (the captured node's hsm_secret) is required for corpus replay");
        replay_corpus(&oracle, &proxy, &corpus, &secret_path);
        return;
    }

    // Single SIGN_WITHDRAWAL (type 7) vector: a hex file holding ONE raw hsmd
    // message. Frames it as a main-daemon withdrawal and drives BOTH signers, then
    // compares the extracted PSBT_IN_PARTIAL_SIG (+ PSBT_IN_TAP_KEY_SIG) records
    // byte-for-byte. This is the correct comparison for a withdrawal reply: unlike
    // a commitment, libhsmd ALSO splices a PSBT_IN_BIP32_DERIVATION keypath before
    // signing (`psbt_input_add_pubkey`), so the WHOLE reply PSBTs differ; the
    // security-critical artefact is the signature over the sighash, and IT must be
    // byte-identical to libhsmd's. Used to anchor the Elements-asset funding
    // withdrawal reconstruction against the real libhsmd.
    if let Ok(vec_path) = std::env::var("SEQLN_WITHDRAWAL_VECTOR") {
        let secret_path = std::env::var("SEQLN_HSM_SECRET")
            .expect("SEQLN_HSM_SECRET (the node's hsm_secret) is required for the withdrawal vector");
        compare_withdrawal_vector(&oracle, &proxy, &vec_path, &secret_path);
        return;
    }

    // Fixed hsm_secret (mnemonic, no passphrase): 32 zero bytes || mnemonic.
    let mut hsm_secret = vec![0u8; 32];
    hsm_secret.extend_from_slice(MNEMONIC.as_bytes());

    // Two isolated working dirs, each with an identical hsm_secret.
    let base = std::env::temp_dir().join(format!("seqln-signer-conf-{}", std::process::id()));
    let oracle_dir = base.join("oracle");
    let proxy_dir = base.join("proxy");
    for d in [&oracle_dir, &proxy_dir] {
        std::fs::create_dir_all(d).expect("mkdir");
        std::fs::write(d.join("hsm_secret"), &hsm_secret).expect("write hsm_secret");
    }

    // A local kernel to compute the "correct" pubkeys that CHECK_PUBKEY /
    // CHECK_BIP86_PUBKEY must accept. The oracle returning ok (rather than dying)
    // proves these derivations match libhsmd.
    let seed = kernel::bip39_seed(MNEMONIC, "").to_vec();
    let k = Kernel::new(seed, BIP32_VER_TEST_PUBLIC, BIP32_VER_TEST_PRIVATE);

    let cases = build_cases(&k);

    let mut oracle_proc = spawn(&oracle, &oracle_dir);
    let mut proxy_proc = spawn(&proxy, &proxy_dir);

    let mut passed = 0usize;
    let mut failed = 0usize;
    println!(
        "\n== SeqLN device-signer M2a conformance: {} cases ==\n",
        cases.len()
    );
    for c in &cases {
        let a = oracle_proc.roundtrip(c.is_main, &c.node_id, c.dbid, c.caps, &c.msg);
        let b = proxy_proc.roundtrip(c.is_main, &c.node_id, c.dbid, c.caps, &c.msg);
        let ok = a == b;
        if ok {
            passed += 1;
            let bytes = a.as_ref().map(|v| v.len()).unwrap_or(0);
            println!("  PASS  {:<34} ({} reply bytes)", c.name, bytes);
        } else {
            failed += 1;
            println!("  FAIL  {}", c.name);
            match (&a, &b) {
                (Some(av), Some(bv)) => {
                    println!("        oracle: {}", hex(av));
                    println!("        proxy : {}", hex(bv));
                }
                (a, b) => {
                    println!("        oracle: {}", opt(a));
                    println!("        proxy : {}", opt(b));
                }
            }
        }
    }

    // Clean shutdown: dropping the streams closes the transport; the signers
    // then see EOF and exit.
    drop(oracle_proc.stream);
    drop(proxy_proc.stream);
    let _ = oracle_proc.child.wait();
    let _ = proxy_proc.child.wait();
    let _ = std::fs::remove_dir_all(&base);

    println!("\n== {passed} passed, {failed} failed ==");
    std::io::stdout().flush().ok();
    if failed != 0 {
        std::process::exit(1);
    }
}

fn opt(v: &Option<Vec<u8>>) -> String {
    match v {
        Some(v) => hex(v),
        None => "<EOF: signer died / closed transport>".to_string(),
    }
}

/// M2b: replay a captured corpus of real signer frames to the oracle and to
/// seqln-signer, byte-comparing every reply. The corpus is a stream of frames
/// exactly as `signer_frame.h` / `frame::write_request` serializes them.
fn replay_corpus(oracle: &str, proxy: &str, corpus_path: &str, secret_path: &str) {
    let secret = std::fs::read(secret_path).expect("read hsm_secret");
    let base = std::env::temp_dir().join(format!("seqln-corpus-{}", std::process::id()));
    let oracle_dir = base.join("oracle");
    let proxy_dir = base.join("proxy");
    for d in [&oracle_dir, &proxy_dir] {
        std::fs::create_dir_all(d).expect("mkdir");
        std::fs::write(d.join("hsm_secret"), &secret).expect("write hsm_secret");
    }

    let mut oracle_proc = spawn(oracle, &oracle_dir);
    let mut proxy_proc = spawn(proxy, &proxy_dir);

    let mut file = std::fs::File::open(corpus_path).expect("open corpus");
    // Optional: dump the ORACLE's framed replies (u32-LE len || reply bytes, in
    // corpus order) to this path, so an out-of-process harness (e.g. the wasm
    // Node conformance runner) can byte-compare against libhsmd's own replies
    // without re-spawning the oracle. The oracle-vs-native check below still
    // runs, so one invocation both anchors native==oracle AND emits the
    // reference the wasm proof consumes.
    let mut dump = std::env::var("SEQLN_DUMP_REPLIES")
        .ok()
        .map(|p| std::io::BufWriter::new(std::fs::File::create(p).expect("create dump")));
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut per_type: std::collections::BTreeMap<u16, (usize, usize)> = std::collections::BTreeMap::new();

    println!("\n== SeqLN device-signer M2b corpus replay ==\n");
    loop {
        let req = match frame::read_request(&mut file) {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => {
                eprintln!("corpus read error: {e}");
                break;
            }
        };
        let t = seqln_signer::wire::peektype(&req.hsmd_msg).unwrap_or(0);
        let a = oracle_proc.roundtrip(req.is_main, &req.node_id, req.dbid, req.capabilities, &req.hsmd_msg);
        let b = proxy_proc.roundtrip(req.is_main, &req.node_id, req.dbid, req.capabilities, &req.hsmd_msg);
        if let Some(w) = dump.as_mut() {
            frame::write_reply(w, a.as_deref().unwrap_or(&[])).expect("dump reply");
        }
        let e = per_type.entry(t).or_insert((0, 0));
        if a == b {
            passed += 1;
            e.0 += 1;
        } else {
            failed += 1;
            e.1 += 1;
            println!("  FAIL type={t}");
            println!("        oracle: {}", opt(&a));
            println!("        proxy : {}", opt(&b));
        }
    }

    drop(oracle_proc.stream);
    drop(proxy_proc.stream);
    let _ = oracle_proc.child.wait();
    let _ = proxy_proc.child.wait();
    let _ = std::fs::remove_dir_all(&base);

    println!("\n  per hsmd message type (type: pass/fail):");
    for (t, (p, f)) in &per_type {
        println!("    {t:>4}: {p} pass, {f} fail");
    }
    println!("\n== {passed} passed, {failed} failed ==");
    std::io::stdout().flush().ok();
    if failed != 0 {
        std::process::exit(1);
    }
}

/// Decode a hex string (whitespace-tolerant) to bytes.
fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The reply body is `type(u16) || u32(len) || psbt`. Return the psbt slice.
fn reply_psbt(reply: &[u8]) -> Option<&[u8]> {
    if reply.len() < 6 {
        return None;
    }
    let len = u32::from_be_bytes([reply[2], reply[3], reply[4], reply[5]]) as usize;
    reply.get(6..6 + len)
}

/// Extract the signature-bearing records from a withdrawal reply PSBT: every
/// PSBT_IN_PARTIAL_SIG (key `0x02||pubkey33`, value `DER||sighash`) and every
/// PSBT_IN_TAP_KEY_SIG (key `0x13`, value = 64/65-byte schnorr sig). Returned as
/// a sorted Vec of `(kind, key_or_pubkey, sig_value)` so two replies can be
/// compared regardless of record ordering. Scans the raw bytes for the record
/// shapes (sufficient here: these key bytes do not otherwise collide in a PSET).
fn extract_sig_records(psbt: &[u8]) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < psbt.len() {
        // PSBT_IN_PARTIAL_SIG: keylen=0x22, 0x02, 33-byte pubkey, then vallen, val.
        if psbt[i] == 0x22
            && i + 2 + 33 < psbt.len()
            && psbt[i + 1] == 0x02
        {
            let pk = psbt[i + 2..i + 2 + 33].to_vec();
            let vp = i + 2 + 33;
            let vallen = psbt[vp] as usize;
            if vp + 1 + vallen <= psbt.len() {
                let val = psbt[vp + 1..vp + 1 + vallen].to_vec();
                out.push((0x02, pk, val));
                i = vp + 1 + vallen;
                continue;
            }
        }
        // PSBT_IN_TAP_KEY_SIG: keylen=0x01, 0x13, then vallen, val.
        if psbt[i] == 0x01 && i + 2 < psbt.len() && psbt[i + 1] == 0x13 {
            let vp = i + 2;
            let vallen = psbt[vp] as usize;
            if vp + 1 + vallen <= psbt.len() && (vallen == 64 || vallen == 65) {
                let val = psbt[vp + 1..vp + 1 + vallen].to_vec();
                out.push((0x13, vec![0x13], val));
                i = vp + 1 + vallen;
                continue;
            }
        }
        i += 1;
    }
    out.sort();
    out
}

fn compare_withdrawal_vector(oracle: &str, proxy: &str, vec_path: &str, secret_path: &str) {
    let hex_str = std::fs::read_to_string(vec_path).expect("read withdrawal vector");
    let msg = unhex(&hex_str);
    assert!(
        seqln_signer::wire::peektype(&msg) == Some(msg::HSMD_SIGN_WITHDRAWAL),
        "vector is not a SIGN_WITHDRAWAL (type 7); got type {:?}",
        seqln_signer::wire::peektype(&msg)
    );
    let secret = std::fs::read(secret_path).expect("read hsm_secret");

    let base = std::env::temp_dir().join(format!("seqln-wdvec-{}", std::process::id()));
    let oracle_dir = base.join("oracle");
    let proxy_dir = base.join("proxy");
    for d in [&oracle_dir, &proxy_dir] {
        std::fs::create_dir_all(d).expect("mkdir");
        std::fs::write(d.join("hsm_secret"), &secret).expect("write hsm_secret");
    }

    let mut oracle_proc = spawn(oracle, &oracle_dir);
    let mut proxy_proc = spawn(proxy, &proxy_dir);

    let zero = [0u8; 33];
    // Both signers must be INITialized (kernel + wire version) before they will
    // handle any signing request — exactly as lightningd does at startup.
    let init = init_msg();
    let ia = oracle_proc.roundtrip(true, &zero, 0, ALL_CAPS, &init);
    let ib = proxy_proc.roundtrip(true, &zero, 0, ALL_CAPS, &init);
    assert!(ia.is_some() && ib.is_some(), "INIT failed (oracle {} / proxy {})", ia.is_some(), ib.is_some());

    let a = oracle_proc.roundtrip(true, &zero, 0, ALL_CAPS, &msg);
    let b = proxy_proc.roundtrip(true, &zero, 0, ALL_CAPS, &msg);

    drop(oracle_proc.stream);
    drop(proxy_proc.stream);
    let _ = oracle_proc.child.wait();
    let _ = proxy_proc.child.wait();
    let _ = std::fs::remove_dir_all(&base);

    println!("\n== SeqLN SIGN_WITHDRAWAL vector: libhsmd vs seqln-signer ==\n");
    let (ap, bp) = match (&a, &b) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            println!("  oracle reply: {}", opt(&a));
            println!("  proxy  reply: {}", opt(&b));
            println!("\n== FAIL: a signer produced no reply (crashed / rejected) ==");
            std::process::exit(1);
        }
    };
    let a_psbt = reply_psbt(ap).expect("oracle reply psbt");
    let b_psbt = reply_psbt(bp).expect("proxy reply psbt");
    let a_sigs = extract_sig_records(a_psbt);
    let b_sigs = extract_sig_records(b_psbt);

    println!("  oracle reply psbt: {} bytes, {} signature record(s)", a_psbt.len(), a_sigs.len());
    println!("  proxy  reply psbt: {} bytes, {} signature record(s)", b_psbt.len(), b_sigs.len());
    for (kind, k, v) in &a_sigs {
        let label = if *kind == 0x02 { "PARTIAL_SIG" } else { "TAP_KEY_SIG" };
        println!("  oracle {label}: pubkey/key {} sig {}", hex(k), hex(v));
    }
    for (kind, k, v) in &b_sigs {
        let label = if *kind == 0x02 { "PARTIAL_SIG" } else { "TAP_KEY_SIG" };
        println!("  proxy  {label}: pubkey/key {} sig {}", hex(k), hex(v));
    }

    if a_sigs.is_empty() {
        println!("\n== FAIL: oracle produced no signature records (unexpected) ==");
        std::process::exit(1);
    }
    if a_sigs == b_sigs {
        println!(
            "\n== PASS: {} signature record(s) BYTE-IDENTICAL to libhsmd ==",
            a_sigs.len()
        );
    } else {
        println!("\n== FAIL: signature records differ from libhsmd ==");
        std::process::exit(1);
    }
    std::io::stdout().flush().ok();
}

fn build_cases(k: &Kernel) -> Vec<Case> {
    let mut cases = Vec::new();
    let zero_id = [0u8; 33];

    // A distinct, valid second point for node-id variety (node ids are only
    // hashed by get_channel_seed, so any 33 bytes work; a valid point is tidy).
    let id_b: [u8; 33] = k.node_id();

    let main = |name: &str, msg: Vec<u8>| Case {
        name: name.to_string(),
        is_main: true,
        node_id: zero_id,
        dbid: 0,
        caps: ALL_CAPS,
        msg,
    };
    let peer = |name: &str, id: [u8; 33], dbid: u64, msg: Vec<u8>| Case {
        name: name.to_string(),
        is_main: false,
        node_id: id,
        dbid,
        caps: ALL_CAPS,
        msg,
    };

    // --- INIT (must be first) ---
    cases.push(main("INIT (v4 reply)", init_msg()));

    // --- DERIVE_SECRET: several info labels incl. empty + binary ---
    for (lbl, info) in [
        ("empty", &b""[..]),
        ("bolt12-invoice-base", &b"bolt12-invoice-base"[..]),
        ("scb secret", &b"scb secret"[..]),
        ("commando", &b"commando"[..]),
        ("binary", &[0x00u8, 0x01, 0xff, 0x80, 0x7f][..]),
    ] {
        cases.push(main(
            &format!("DERIVE_SECRET [{lbl}]"),
            derive_secret_msg(info),
        ));
    }

    // --- GET_CHANNEL_BASEPOINTS: a couple of (node_id, dbid) pairs ---
    cases.push(main(
        "GET_CHANNEL_BASEPOINTS G/1",
        get_channel_basepoints_msg(&G, 1),
    ));
    cases.push(main(
        "GET_CHANNEL_BASEPOINTS idB/7",
        get_channel_basepoints_msg(&id_b, 7),
    ));
    cases.push(main(
        "GET_CHANNEL_BASEPOINTS G/big",
        get_channel_basepoints_msg(&G, 0xdead_beef_1234),
    ));

    // --- GET_PER_COMMITMENT_POINT: several indices incl. shachain extremes ---
    // (peer-client context: seed comes from the FRAME node_id + dbid.)
    let pcp_indices: [u64; 8] = [
        0,
        1,
        2,
        3,
        42,
        1_000_000,
        281_474_976_710_654, // 2^48 - 2
        281_474_976_710_655, // 2^48 - 1 (shachain index 0)
    ];
    for n in pcp_indices {
        cases.push(peer(
            &format!("GET_PER_COMMITMENT_POINT n={n} (G/1)"),
            G,
            1,
            get_per_commitment_point_msg(n),
        ));
    }
    // Same indices, different channel (idB/7) to exercise seed variation.
    cases.push(peer(
        "GET_PER_COMMITMENT_POINT n=2 (idB/7)",
        id_b,
        7,
        get_per_commitment_point_msg(2),
    ));

    // --- ECDH: against a couple of known points ---
    cases.push(main("ECDH vs G", ecdh_req_msg(&G)));
    cases.push(main("ECDH vs node_id", ecdh_req_msg(&k.node_id())));

    // --- CHECK_PUBKEY: correct m/0/0/index pubkeys (oracle validates) ---
    for index in [0u32, 1, 5, 1000, 0x7fff_ffff] {
        cases.push(main(
            &format!("CHECK_PUBKEY index={index}"),
            check_pubkey_msg(msg::HSMD_CHECK_PUBKEY, index, &k.bip32_child_pubkey(index)),
        ));
    }

    // --- CHECK_BIP86_PUBKEY: correct m/86'/0'/0'/0/index pubkeys ---
    for index in [0u32, 1, 5, 1000] {
        cases.push(main(
            &format!("CHECK_BIP86_PUBKEY index={index}"),
            check_pubkey_msg(
                msg::HSMD_CHECK_BIP86_PUBKEY,
                index,
                &k.bip86_child_pubkey(index),
            ),
        ));
    }

    // --- Trivial bookkeeping messages -> constant replies ---
    cases.push(main("NEW_CHANNEL", new_forget_msg(msg::HSMD_NEW_CHANNEL, &G, 3)));
    cases.push(main(
        "FORGET_CHANNEL",
        new_forget_msg(msg::HSMD_FORGET_CHANNEL, &G, 3),
    ));
    cases.push(main(
        "CHECK_OUTPOINT",
        outpoint_msg(msg::HSMD_CHECK_OUTPOINT, 2),
    ));
    cases.push(main(
        "LOCK_OUTPOINT",
        outpoint_msg(msg::HSMD_LOCK_OUTPOINT, 2),
    ));
    cases.push(main("SETUP_CHANNEL", setup_channel_msg()));

    // --- An unknown message type must yield the zero-length sentinel on both ---
    cases.push(main("UNKNOWN type 9999 (sentinel)", unknown_type_msg()));

    cases
}

// ---- hsmd request builders (big-endian wire) ----

fn init_msg() -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_INIT);
    w.u32(BIP32_VER_TEST_PUBLIC);
    w.u32(BIP32_VER_TEST_PRIVATE);
    w.bytes(&[0u8; 32]); // chainparams genesis blockhash (unused by the subset)
    for _ in 0..5 {
        w.bool(false); // the five ?-optional dev fields, all absent
    }
    w.u32(4); // hsm_wire_min_version
    w.u32(6); // hsm_wire_max_version
    // empty init tlv stream
    w.into_vec()
}

fn derive_secret_msg(info: &[u8]) -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_DERIVE_SECRET);
    w.u16(info.len() as u16);
    w.bytes(info);
    w.into_vec()
}

fn get_channel_basepoints_msg(peer_id: &[u8; 33], dbid: u64) -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_GET_CHANNEL_BASEPOINTS);
    w.bytes(peer_id);
    w.u64(dbid);
    w.into_vec()
}

fn get_per_commitment_point_msg(n: u64) -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_GET_PER_COMMITMENT_POINT);
    w.u64(n);
    w.into_vec()
}

fn ecdh_req_msg(point: &[u8; 33]) -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_ECDH_REQ);
    w.bytes(point);
    w.into_vec()
}

fn check_pubkey_msg(msgtype: u16, index: u32, pubkey: &[u8; 33]) -> Vec<u8> {
    let mut w = Writer::new(msgtype);
    w.u32(index);
    w.bytes(pubkey);
    w.into_vec()
}

fn new_forget_msg(msgtype: u16, id: &[u8; 33], dbid: u64) -> Vec<u8> {
    let mut w = Writer::new(msgtype);
    w.bytes(id);
    w.u64(dbid);
    w.into_vec()
}

fn outpoint_msg(msgtype: u16, txout: u16) -> Vec<u8> {
    let mut w = Writer::new(msgtype);
    w.bytes(&[0u8; 32]); // funding_txid
    w.u16(txout);
    w.into_vec()
}

fn setup_channel_msg() -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_SETUP_CHANNEL);
    w.bool(true); // is_outbound
    w.u64(1_000_000); // channel_value (amount_sat)
    w.u64(0); // push_value (amount_msat)
    w.bytes(&[0u8; 32]); // funding_txid
    w.u16(0); // funding_txout
    w.u16(144); // local_to_self_delay
    w.u16(0); // local_shutdown_script_len
    w.bool(false); // local_shutdown_wallet_index (?u32) absent
    // remote_basepoints: 4 pubkeys (revocation, payment, htlc, delayed).
    for _ in 0..4 {
        w.bytes(&G);
    }
    w.bytes(&G); // remote_funding_pubkey
    w.u16(144); // remote_to_self_delay
    w.u16(0); // remote_shutdown_script_len
    w.u16(0); // channel_type: features len = 0
    w.into_vec()
}

fn unknown_type_msg() -> Vec<u8> {
    // An unknown message type: libhsmd's capability switch has no case for it, so
    // the oracle returns the zero-length sentinel; our signer does too (the `_`
    // arm). (SIGN_INVOICE etc. are real libhsmd handlers, so they would NOT
    // sentinel on the oracle — this must be a genuinely-unknown type.)
    Writer::new(9999).into_vec()
}
