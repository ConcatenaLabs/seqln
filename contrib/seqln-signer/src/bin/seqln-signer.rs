//! The native SeqLN Tier-2 device signer.
//!
//! CLI matches the reference `signerd` (`hsmd/signerd.c`): the single argument is
//! the socket fd to serve the signer-split frame protocol on, and the
//! `hsm_secret` is loaded from the current working directory (we are typically
//! fork/exec'd by `hsmd-proxy`, inheriting its lightning network dir).

use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;

use seqln_signer::dispatch::{Outcome, Signer};
use seqln_signer::{frame, hsm_secret};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <socket-fd>", args[0]);
        std::process::exit(1);
    }
    let fd: i32 = args[1]
        .parse()
        .unwrap_or_else(|_| fatal(&format!("bad fd argument: {}", args[1])));

    // Load hsm_secret from the working directory (mnemonic format).
    let bytes = std::fs::read("hsm_secret")
        .unwrap_or_else(|e| fatal(&format!("could not read hsm_secret: {e}")));
    let secret =
        hsm_secret::parse(&bytes).unwrap_or_else(|e| fatal(&format!("bad hsm_secret: {e}")));

    let mut signer = Signer::new(secret);

    // SAFETY: the fd is handed to us by our parent and owned by this process.
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };

    // A per-process log next to the running dir, mirroring signerd.log; best
    // effort, never fatal.
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("seqln-signer.log")
        .ok();
    if let Some(l) = log.as_mut() {
        let _ = writeln!(l, "seqln-signer: started, transport fd {fd}, pid {}", std::process::id());
    }

    loop {
        let req = match frame::read_request(&mut stream) {
            Ok(Some(r)) => r,
            Ok(None) => break, // transport closed
            Err(e) => {
                eprintln!("seqln-signer: transport read error: {e}");
                break;
            }
        };

        let reply: Vec<u8> = match signer.handle(&req) {
            Outcome::Reply(bytes) => bytes,
            Outcome::Sentinel => Vec::new(), // zero-length error sentinel
            Outcome::Fatal(m) => {
                if let Some(l) = log.as_mut() {
                    let _ = writeln!(l, "seqln-signer: FATAL: {m}");
                }
                eprintln!("seqln-signer: FATAL: {m}");
                std::process::exit(2);
            }
        };

        if let Err(e) = frame::write_reply(&mut stream, &reply) {
            eprintln!("seqln-signer: transport write error: {e}");
            break;
        }
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("seqln-signer: {msg}");
    std::process::exit(2);
}
