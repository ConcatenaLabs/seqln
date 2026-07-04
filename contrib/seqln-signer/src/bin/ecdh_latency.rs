//! ECDH hot-path latency measurement (M4 open-decision input).
//!
//! ECDH (`common/ecdh_hsmd.c`) is on the critical path of BOTH peer-connect AND
//! every onion hop a payment forwards through. In the Tier-2 split the request
//! must round-trip to the device signer, so a naive per-ECDH network round-trip
//! to a phone would tax connect + forward time. This tool quantifies the cost:
//!
//!  1. the pure in-process ECDH crypto time (kernel only, no transport);
//!  2. the ECDH round-trip over the real signer-split network transport
//!     (`seqln-signer --listen`, localhost TCP), i.e. the M1 topology baseline;
//!
//! then projects the localhost number onto a realistic device RTT so the design
//! decision (per-ECDH round-trip vs a device-authorized ECDH session key vs
//! delegated node-ECDH) can be made on numbers, not vibes.
//!
//! Self-contained: it spins up a signer over the all-zero-entropy BIP39 test
//! vector (public, not a real secret), so it needs no external node.

use std::net::TcpStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use seqln_signer::kernel::{
    self, Kernel, BIP32_VER_TEST_PRIVATE, BIP32_VER_TEST_PUBLIC,
};
use seqln_signer::wire::{msg, Writer};
use seqln_signer::{frame, hsm_secret};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// secp256k1 generator point (a valid ECDH peer point).
const G: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

fn init_msg() -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_INIT);
    w.u32(BIP32_VER_TEST_PUBLIC);
    w.u32(BIP32_VER_TEST_PRIVATE);
    w.bytes(&[0u8; 32]); // chainparams genesis
    for _ in 0..5 {
        w.bool(false); // the 5 optional dev fields, absent
    }
    w.u32(4); // min version
    w.u32(6); // max version
    w.into_vec()
}

fn ecdh_msg(point: &[u8; 33]) -> Vec<u8> {
    let mut w = Writer::new(msg::HSMD_ECDH_REQ);
    w.bytes(point);
    w.into_vec()
}

fn pct(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

fn report(label: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let n = samples.len();
    let sum: Duration = samples.iter().sum();
    let mean = sum / n as u32;
    let us = |d: Duration| d.as_secs_f64() * 1e6;
    println!("  {label}: n={n}");
    println!(
        "     min {:.1}us  median {:.1}us  mean {:.1}us  p90 {:.1}us  p99 {:.1}us  max {:.1}us",
        us(samples[0]),
        us(pct(&samples, 0.50)),
        us(mean),
        us(pct(&samples, 0.90)),
        us(pct(&samples, 0.99)),
        us(samples[n - 1]),
    );
}

fn main() {
    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let warmup = 100.min(iters / 10);

    println!("== SeqLN Tier-2 ECDH latency ({iters} iters, {warmup} warmup) ==\n");

    // ---- (1) pure in-process ECDH crypto (no transport) ----
    let seed = kernel::bip39_seed(MNEMONIC, "").to_vec();
    let k = Kernel::new(seed, BIP32_VER_TEST_PUBLIC, BIP32_VER_TEST_PRIVATE);
    let mut crypto = Vec::with_capacity(iters);
    for i in 0..iters {
        let t = Instant::now();
        let _ = k.ecdh(&G).expect("ecdh");
        if i >= warmup {
            crypto.push(t.elapsed());
        }
    }
    report("in-process ECDH crypto only", crypto);

    // ---- (2) ECDH round-trip over the network transport (localhost TCP) ----
    let (mut child, mut stream) = spawn_listening_signer();
    // INIT first (the kernel must be initialized before ECDH).
    frame::write_request(&mut stream, true, &[0u8; 33], 0, u64::MAX, &init_msg())
        .expect("write init");
    let _ = frame::read_reply(&mut stream).expect("init reply");

    let em = ecdh_msg(&G);
    let mut net = Vec::with_capacity(iters);
    for i in 0..iters {
        let t = Instant::now();
        frame::write_request(&mut stream, true, &[0u8; 33], 0, u64::MAX, &em).expect("write ecdh");
        let reply = frame::read_reply(&mut stream).expect("ecdh reply");
        let dt = t.elapsed();
        assert!(matches!(&reply, Some(r) if r.len() == 34), "ecdh reply shape");
        if i >= warmup {
            net.push(dt);
        }
    }
    report("ECDH round-trip over localhost TCP transport", net.clone());

    drop(stream); // signer sees EOF and exits
    let _ = child.kill();
    let _ = child.wait();

    // ---- projection onto a realistic device RTT ----
    net.sort();
    let median_net = net[net.len() / 2].as_secs_f64() * 1e3; // ms
    println!("\n== projection (per-ECDH round-trip model) ==");
    println!(
        "  localhost transport adds ~{:.3} ms over the ~few-us crypto; the dominant cost on a\n  \
         real device is the NETWORK RTT, which replaces the ~localhost figure roughly 1:1.",
        median_net
    );
    // Where ECDH actually happens for a leaf pure-LN wallet node: the Noise XK
    // handshake at each peer-connect does 2 ECDH; each onion the node unwraps
    // (every payment it receives/forwards) does 1 ECDH. With a naive per-ECDH
    // round-trip, each of those becomes one device RTT on the hot path.
    for rtt in [1.0f64, 25.0, 50.0, 100.0, 150.0] {
        println!(
            "  device RTT {rtt:>5.0} ms  ->  peer-connect handshake +~{:>5.0} ms (2 ECDH); \
             each payment onion +{rtt:>5.0} ms",
            rtt * 2.0
        );
    }
    println!(
        "\n  A device-authorized ECDH SESSION KEY (provisioned once at channel open, or a\n  \
         connectd-held ECDH subkey) collapses all of these to the in-process figure, at the\n  \
         cost of that subkey living on the hosted side between rotations. See the report."
    );
}

/// Spawn `seqln-signer --listen 127.0.0.1:PORT` over an all-zero-entropy test
/// hsm_secret in a temp dir, and connect a TCP stream to it.
fn spawn_listening_signer() -> (Child, TcpStream) {
    // Pick a free port by binding :0, then hand it to the signer.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let addr = format!("127.0.0.1:{port}");

    let dir = std::env::temp_dir().join(format!("seqln-ecdh-lat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let mut hsm_secret_bytes = vec![0u8; 32];
    hsm_secret_bytes.extend_from_slice(MNEMONIC.as_bytes());
    std::fs::write(dir.join("hsm_secret"), &hsm_secret_bytes).expect("write hsm_secret");
    // Sanity: the secret parses (fail loudly if not).
    let _ = hsm_secret::parse(&hsm_secret_bytes).expect("hsm_secret parses");

    let bin = {
        let mut p = std::env::current_exe().unwrap();
        p.pop();
        p.push("seqln-signer");
        p
    };
    let mut cmd = Command::new(&bin);
    cmd.arg("--listen")
        .arg(&addr)
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // New session so a stray signal to us doesn't take the child with unexpected effects.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn seqln-signer --listen");

    // Retry-connect until the listener is up.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(&addr) {
            Ok(s) => {
                s.set_nodelay(true).ok();
                return (child, s);
            }
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("could not connect to signer at {addr}: {e}"),
        }
    }
}
