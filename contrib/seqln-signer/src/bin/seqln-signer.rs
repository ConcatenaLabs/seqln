//! The native SeqLN Tier-2 device signer.
//!
//! Two transports, sharing one serve loop:
//!
//!   1. **fd mode** (default, matches the reference `signerd`, `hsmd/signerd.c`):
//!      the single argument is the already-connected socket fd to serve the
//!      signer-split frame protocol on.  This is the local fork+socketpair split
//!      used since M1 (the proxy fork/exec's us, we inherit its cwd).
//!
//!   2. **listen mode** (Tier-2 network transport): `--listen <host:port>` (or env
//!      `SEQLN_SIGNER_LISTEN`) binds a TCP listener, accepts ONE connection, and
//!      serves the exact same frame protocol over that stream.  This is the "we
//!      host the node, the device signs remotely" topology: the hosted
//!      `hsmd-proxy` sets `SEQLN_SIGNER_ADDR=host:port` and connect()s to us
//!      instead of fork/exec'ing us.  One connection == one hosted node.
//!
//! Either way the `hsm_secret` is loaded from the current working directory
//! (mnemonic format).  M4 will move the secret onto the actual device; for now
//! this remote signer process holds it.
//!
//! ============================ SECURITY (READ ME) ============================
//! The listen transport is RAW TCP: UNAUTHENTICATED and UNENCRYPTED.  Whoever
//! connects to the listener DRIVES the signer, and the frames carry signing
//! requests for the node's funds.  This is a demo/dev transport that proves the
//! remote-signer topology ONLY.  Production MUST wrap this in an authenticated,
//! encrypted channel (Noise/TLS) with per-wallet authentication before the
//! device signer holds real keys or faces the network.  Do NOT ship listen mode
//! on a public interface as-is.  See also the matching note in
//! `hsmd/hsmd_proxy.c:connect_remote_signer()`.
//! ==========================================================================

use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;

use seqln_signer::dispatch::{Outcome, Signer};
use seqln_signer::{frame, hsm_secret};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Transport selection: --listen <addr> / SEQLN_SIGNER_LISTEN => TCP listen
    // mode; otherwise argv[1] is the pre-connected socket fd (fork mode).
    let mut listen_addr: Option<String> = std::env::var("SEQLN_SIGNER_LISTEN").ok();
    let mut fd_arg: Option<String> = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "--listen" {
            listen_addr = Some(
                it.next()
                    .cloned()
                    .unwrap_or_else(|| fatal("--listen requires a <host:port> argument")),
            );
        } else if let Some(v) = a.strip_prefix("--listen=") {
            listen_addr = Some(v.to_string());
        } else if fd_arg.is_none() {
            fd_arg = Some(a.clone());
        }
    }

    // Load hsm_secret from the working directory (mnemonic format).  Both
    // transports hold it here for now (M4 moves it onto the device).
    let bytes = std::fs::read("hsm_secret")
        .unwrap_or_else(|e| fatal(&format!("could not read hsm_secret: {e}")));
    let secret =
        hsm_secret::parse(&bytes).unwrap_or_else(|e| fatal(&format!("bad hsm_secret: {e}")));

    let mut signer = Signer::new(secret);

    // A per-process log next to the running dir, mirroring signerd.log; best
    // effort, never fatal.
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("seqln-signer.log")
        .ok();

    match listen_addr {
        Some(addr) => {
            // Network transport: bind, accept ONE hosted node, serve it.
            let listener = TcpListener::bind(&addr)
                .unwrap_or_else(|e| fatal(&format!("could not bind {addr}: {e}")));
            let bound = listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| addr.clone());
            logline(
                &mut log,
                &format!(
                    "seqln-signer: LISTENING (raw TCP, UNAUTHENTICATED) on {bound}, pid {} — awaiting one hosted node",
                    std::process::id()
                ),
            );
            eprintln!("seqln-signer: listening on {bound} (raw TCP, dev transport)");
            let (mut stream, peer) = listener
                .accept()
                .unwrap_or_else(|e| fatal(&format!("accept failed: {e}")));
            // Low latency for the synchronous request/response signer traffic.
            let _ = stream.set_nodelay(true);
            logline(
                &mut log,
                &format!("seqln-signer: hosted node connected from {peer}"),
            );
            eprintln!("seqln-signer: hosted node connected from {peer}");
            serve(&mut stream, &mut signer, &mut log);
        }
        None => {
            // fd mode (fork+socketpair): argv[1] is the connected socket fd.
            let fd_str = fd_arg
                .unwrap_or_else(|| fatal(&format!("usage: {} <socket-fd> | --listen <host:port>", args[0])));
            let fd: i32 = fd_str
                .parse()
                .unwrap_or_else(|_| fatal(&format!("bad fd argument: {fd_str}")));
            // SAFETY: the fd is handed to us by our parent and owned by this process.
            let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
            logline(
                &mut log,
                &format!(
                    "seqln-signer: started, transport fd {fd}, pid {}",
                    std::process::id()
                ),
            );
            serve(&mut stream, &mut signer, &mut log);
        }
    }
}

/// The shared serve loop: read framed requests off `stream`, dispatch to the
/// signer, write framed replies back.  Transport-agnostic — `stream` is a
/// local `UnixStream` (fd mode) or a remote `TcpStream` (listen mode); both are
/// `Read + Write` and the signer frame protocol is identical over either.
fn serve<S: Read + Write>(stream: &mut S, signer: &mut Signer, log: &mut Option<File>) {
    loop {
        let req = match frame::read_request(stream) {
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
            Outcome::Reject(reason) => {
                // M4 validating policy refused to sign: log the reason and send
                // the zero-length sentinel (lightningd treats it as a signer
                // failure and does not get a theft-shaped signature).
                logline(log, &format!("seqln-signer: POLICY REJECT: {reason}"));
                eprintln!("seqln-signer: POLICY REJECT: {reason}");
                Vec::new()
            }
            Outcome::Fatal(m) => {
                logline(log, &format!("seqln-signer: FATAL: {m}"));
                eprintln!("seqln-signer: FATAL: {m}");
                std::process::exit(2);
            }
        };

        if let Err(e) = frame::write_reply(stream, &reply) {
            eprintln!("seqln-signer: transport write error: {e}");
            break;
        }
    }
}

/// Best-effort append to the per-process log; never fatal.
fn logline(log: &mut Option<File>, line: &str) {
    if let Some(l) = log.as_mut() {
        let _ = writeln!(l, "{line}");
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("seqln-signer: {msg}");
    std::process::exit(2);
}
