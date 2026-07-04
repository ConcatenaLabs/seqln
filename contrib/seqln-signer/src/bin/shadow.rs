//! M2b live conformance shadow (capture + byte-compare on REAL inputs).
//!
//! Drop-in replacement for `signerd` (same CLI: fd as argv[1], hsm_secret in
//! cwd) that `hsmd-proxy` fork/execs. For every framed request from the proxy it:
//!
//!   1. forwards the request verbatim to a CHILD `lightning_signerd` (the oracle,
//!      real libhsmd) and reads its reply;
//!   2. computes our OWN reply with the Rust `Signer`;
//!   3. byte-compares the two and logs PASS/FAIL (with a hexdump diff on FAIL);
//!   4. appends the request frame to a replay corpus (`SEQLN_CORPUS`);
//!   5. returns the ORACLE's reply to the proxy, so the live channel keeps working
//!      even while a Rust bug is being diagnosed.
//!
//! This is the required conformance proof driven by a real channel: it replays
//! every real sign_* request to BOTH signers and compares the bytes, live.
//!
//! Env:  SEQLN_ORACLE (oracle binary, default lightning_signerd),
//!       SEQLN_CORPUS (append captured frames here for offline replay),
//!       SEQLN_SHADOW_LOG (default ./seqln-shadow.log).

use std::fs::File;
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use seqln_signer::dispatch::{Outcome, Signer};
use seqln_signer::{frame, hsm_secret, wire};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <socket-fd>", args[0]);
        std::process::exit(1);
    }
    let fd: i32 = args[1].parse().unwrap_or_else(|_| fatal("bad fd"));

    let oracle_bin = std::env::var("SEQLN_ORACLE")
        .unwrap_or_else(|_| "/home/aejkohl/seqln/lightningd/lightning_signerd".to_string());
    let corpus_path = std::env::var("SEQLN_CORPUS").ok();
    let log_path =
        std::env::var("SEQLN_SHADOW_LOG").unwrap_or_else(|_| "seqln-shadow.log".to_string());

    let mut log = File::create(&log_path).ok();
    logln(&mut log, &format!("shadow: pid {} fd {fd} oracle {oracle_bin}", std::process::id()));

    // Our own signer over the same hsm_secret in the cwd.
    let bytes = std::fs::read("hsm_secret").unwrap_or_else(|e| fatal(&format!("hsm_secret: {e}")));
    let secret = hsm_secret::parse(&bytes).unwrap_or_else(|e| fatal(&format!("hsm_secret: {e}")));
    let mut signer = Signer::new(secret);

    // Spawn the oracle (real signerd) over a socketpair, fd 3, same cwd.
    let (mut oracle, _child) = spawn_oracle(&oracle_bin);

    let mut proxy = unsafe { UnixStream::from_raw_fd(fd) };
    let mut corpus = corpus_path.as_ref().map(|p| File::create(p).expect("corpus"));

    let (mut pass, mut fail) = (0u64, 0u64);
    loop {
        let req = match frame::read_request(&mut proxy) {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => {
                logln(&mut log, &format!("shadow: proxy read error: {e}"));
                break;
            }
        };
        let t = wire::peektype(&req.hsmd_msg).unwrap_or(0);

        // 1. Oracle round-trip.
        if frame::write_request(
            &mut oracle,
            req.is_main,
            &req.node_id,
            req.dbid,
            req.capabilities,
            &req.hsmd_msg,
        )
        .is_err()
        {
            logln(&mut log, "shadow: oracle write failed");
            break;
        }
        let oracle_reply = match frame::read_reply(&mut oracle) {
            Ok(Some(v)) => v,
            _ => {
                logln(&mut log, &format!("shadow: oracle EOF/err on type {t}"));
                break;
            }
        };

        // 2. Our reply.
        let ours = match signer.handle(&req) {
            Outcome::Reply(b) => b,
            Outcome::Sentinel => Vec::new(),
            Outcome::Reject(reason) => {
                logln(&mut log, &format!("shadow: OUR POLICY REJECT on type {t}: {reason}"));
                Vec::new()
            }
            Outcome::Fatal(m) => {
                logln(&mut log, &format!("shadow: OUR FATAL on type {t}: {m}"));
                Vec::new()
            }
        };

        // 3. Compare (skip pure bookkeeping we already prove in M2a: only score
        //    the messages, but log everything).
        let ok = ours == oracle_reply;
        if ok {
            pass += 1;
            logln(
                &mut log,
                &format!("PASS type={t:<4} main={} dbid={} ({} bytes)", req.is_main, req.dbid, oracle_reply.len()),
            );
        } else {
            fail += 1;
            logln(&mut log, &format!("FAIL type={t:<4} main={} dbid={}", req.is_main, req.dbid));
            logln(&mut log, &format!("     oracle: {}", hex(&oracle_reply)));
            logln(&mut log, &format!("     ours  : {}", hex(&ours)));
        }

        // 4. Corpus (verbatim frame for offline replay).
        if let Some(c) = corpus.as_mut() {
            let _ = frame::write_request(
                c,
                req.is_main,
                &req.node_id,
                req.dbid,
                req.capabilities,
                &req.hsmd_msg,
            );
        }

        // 5. Return the oracle's reply so the channel keeps working.
        if frame::write_reply(&mut proxy, &oracle_reply).is_err() {
            break;
        }
    }

    logln(&mut log, &format!("shadow: done. {pass} PASS, {fail} FAIL"));
}

fn spawn_oracle(bin: &str) -> (UnixStream, std::process::Child) {
    let (parent, child_end) = UnixStream::pair().expect("socketpair");
    let child_fd = child_end.as_raw_fd();
    let mut cmd = Command::new(bin);
    cmd.arg("3")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(child_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().unwrap_or_else(|e| fatal(&format!("spawn oracle: {e}")));
    drop(child_end);
    (parent, child)
}

fn logln(log: &mut Option<File>, s: &str) {
    if let Some(l) = log.as_mut() {
        let _ = writeln!(l, "{s}");
        let _ = l.flush();
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn fatal(msg: &str) -> ! {
    eprintln!("shadow: {msg}");
    std::process::exit(2);
}
