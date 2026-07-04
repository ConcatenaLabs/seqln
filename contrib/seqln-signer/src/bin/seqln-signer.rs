//! The native SeqLN Tier-2 device signer.
//!
//! Two transports, sharing one serve loop:
//!
//!   1. **fd mode** (default, matches the reference `signerd`, `hsmd/signerd.c`):
//!      the single argument is the already-connected socket fd to serve the
//!      signer-split frame protocol on. This is the local fork+socketpair split
//!      used since M1 (the proxy fork/exec's us, we inherit its cwd). It is a
//!      trusted local UNIX socket, so it runs in the clear, UNCHANGED.
//!
//!   2. **listen mode** (Tier-2 network transport): `--listen <host:port>` (or env
//!      `SEQLN_SIGNER_LISTEN`) binds a TCP listener and serves the frame protocol
//!      to the hosted node's `hsmd-proxy`. This link is SECURED: every connection
//!      first runs a BOLT-8 Noise_XK handshake (`noise` module), so the frames
//!      are encrypted + integrity-protected and BOTH ends are authenticated by a
//!      pinned long-term static key. A connector that does not present the
//!      pinned host key (or speaks no handshake) is rejected at the handshake and
//!      served ZERO frames.
//!
//! Either way the `hsm_secret` is loaded from the current working directory
//! (mnemonic format).
//!
//! ============================ SECURITY ====================================
//! listen mode is fail-closed: it REFUSES to start without both its own static
//! privkey (SEQLN_SIGNER_PRIVKEY[_FILE]) and the pinned host static pubkey
//! (SEQLN_HOST_PEER_PUBKEY). There is no raw-TCP remote fallback anymore. The
//! matching knobs on the proxy are SEQLN_HOST_PRIVKEY[_FILE] +
//! SEQLN_SIGNER_PEER_PUBKEY (see hsmd/hsmd_proxy.c).
//! ==========================================================================

use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;

use seqln_signer::dispatch::{Outcome, Signer};
use seqln_signer::noise::{self, Responder, Transport, ACT_ONE_SIZE, ACT_THREE_SIZE};
use seqln_signer::{frame, hsm_secret};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Provisioning helper: print a fresh transport static keypair (privkey +
    // compressed pubkey) for out-of-band pinning, then exit. No secret loaded.
    if args.iter().any(|a| a == "--genkey") {
        let priv_bytes = loop {
            let b = rand32();
            if noise::static_pubkey(&b).is_ok() {
                break b;
            }
        };
        let pubkey = noise::static_pubkey(&priv_bytes).unwrap();
        println!("privkey {}", hex(&priv_bytes));
        println!("pubkey  {}", hex(&pubkey));
        return;
    }

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

    // Load hsm_secret from the working directory (mnemonic format).
    let bytes = std::fs::read("hsm_secret")
        .unwrap_or_else(|e| fatal(&format!("could not read hsm_secret: {e}")));
    let secret =
        hsm_secret::parse(&bytes).unwrap_or_else(|e| fatal(&format!("bad hsm_secret: {e}")));

    let mut signer = Signer::new(secret);

    // A per-process log next to the running dir; best effort, never fatal.
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("seqln-signer.log")
        .ok();

    match listen_addr {
        Some(addr) => serve_listen(&addr, &mut signer, &mut log),
        None => {
            // fd mode (fork+socketpair): argv[1] is the connected socket fd.
            let fd_str = fd_arg.unwrap_or_else(|| {
                fatal(&format!("usage: {} <socket-fd> | --listen <host:port>", args[0]))
            });
            let fd: i32 = fd_str
                .parse()
                .unwrap_or_else(|_| fatal(&format!("bad fd argument: {fd_str}")));
            // SAFETY: the fd is handed to us by our parent and owned by this process.
            let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
            logline(
                &mut log,
                &format!(
                    "seqln-signer: started, transport fd {fd}, pid {} (local trusted socket)",
                    std::process::id()
                ),
            );
            serve(&mut stream, &mut signer, &mut log);
        }
    }
}

/// listen mode: bind, then accept connections; SECURE each with a Noise_XK
/// handshake before serving. A failed/rejected handshake is logged, the
/// connection is dropped (zero frames served) and we keep listening; a
/// successful handshake is served until it closes, then we exit.
fn serve_listen(addr: &str, signer: &mut Signer, log: &mut Option<File>) {
    // Fail closed: no keys => refuse to run in listen mode.
    let static_priv = load_static_priv().unwrap_or_else(|e| {
        fatal(&format!(
            "listen mode requires the device transport privkey: {e}"
        ))
    });
    let pinned_host = load_pinned_host().unwrap_or_else(|e| {
        fatal(&format!(
            "listen mode requires the pinned host static pubkey (SEQLN_HOST_PEER_PUBKEY): {e}"
        ))
    });
    let my_static = noise::static_pubkey(&static_priv)
        .unwrap_or_else(|_| fatal("SEQLN_SIGNER_PRIVKEY is not a valid secp256k1 key"));

    let listener = TcpListener::bind(addr)
        .unwrap_or_else(|e| fatal(&format!("could not bind {addr}: {e}")));
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| addr.to_string());
    logline(
        log,
        &format!(
            "seqln-signer: LISTENING (BOLT-8 Noise_XK, mutual-auth) on {bound}, pid {}; \
             my static pubkey {}, pinned host {}",
            std::process::id(),
            hex(&my_static),
            hex(&pinned_host),
        ),
    );
    eprintln!(
        "seqln-signer: listening on {bound} (Noise_XK secured); my pubkey {}",
        hex(&my_static)
    );

    for incoming in listener.incoming() {
        let mut tcp = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("seqln-signer: accept failed: {e}");
                continue;
            }
        };
        let peer = tcp
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());
        let _ = tcp.set_nodelay(true);

        // SECURITY GATE: run the handshake before ANY frame is served.
        match responder_handshake(&mut tcp, &static_priv, pinned_host) {
            Ok(transport) => {
                logline(
                    log,
                    &format!("seqln-signer: hosted node {peer} AUTHENTICATED (Noise_XK); serving"),
                );
                eprintln!("seqln-signer: hosted node {peer} authenticated; serving");
                let mut secure = NoiseStream::new(tcp, transport);
                serve(&mut secure, signer, log);
                // One authenticated hosted node per process; done.
                logline(log, "seqln-signer: authenticated session closed; exiting");
                return;
            }
            Err(e) => {
                // Wrong key / no handshake / tampering: reject, serve 0 frames.
                logline(
                    log,
                    &format!("seqln-signer: REJECTED connector {peer}: {e} (0 frames served)"),
                );
                eprintln!("seqln-signer: REJECTED connector {peer}: {e}");
                // Drop `tcp`, keep listening for the legitimate host.
            }
        }
    }
}

/// Drive the Noise_XK responder over a raw stream. Returns the ready transport
/// or an error, in which case the caller MUST serve zero frames.
fn responder_handshake<S: Read + Write>(
    inner: &mut S,
    static_priv: &[u8; 32],
    pinned_host: [u8; 33],
) -> Result<Transport, Box<dyn Error>> {
    // Fresh ephemeral entropy (retry the vanishingly rare invalid scalar).
    let mut res = loop {
        let eph = rand32();
        match Responder::new(static_priv, &eph, pinned_host) {
            Ok(r) => break r,
            Err(_) => continue,
        }
    };
    let mut act1 = [0u8; ACT_ONE_SIZE];
    inner.read_exact(&mut act1)?;
    res.read_act_one(&act1)?;
    let act2 = res.write_act_two()?;
    inner.write_all(&act2)?;
    inner.flush()?;
    let mut act3 = [0u8; ACT_THREE_SIZE];
    inner.read_exact(&mut act3)?;
    let transport = res.read_act_three(&act3)?;
    Ok(transport)
}

/// A `Read + Write` adapter that transparently BOLT-8-encrypts/decrypts the byte
/// stream over an inner transport. It reassembles the plaintext stream so the
/// unchanged `frame` codec rides on top exactly as over a raw socket. This is
/// the raw-socket-specific glue; a browser build would supply a WebSocket
/// adapter around the same `noise::Transport`.
struct NoiseStream<S> {
    inner: S,
    transport: Transport,
    rbuf: Vec<u8>,
    rpos: usize,
}

impl<S: Read + Write> NoiseStream<S> {
    fn new(inner: S, transport: Transport) -> Self {
        NoiseStream { inner, transport, rbuf: Vec::new(), rpos: 0 }
    }
}

impl<S: Read + Write> Read for NoiseStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Refill from the next decrypted BOLT-8 message(s) as needed.
        while self.rpos >= self.rbuf.len() {
            let mut hdr = [0u8; noise::HDR_SIZE];
            match self.inner.read_exact(&mut hdr) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
            let l = self
                .transport
                .decrypt_header(&hdr)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.0))? as usize;
            let mut body = vec![0u8; l + noise::BODY_OVERHEAD];
            self.inner.read_exact(&mut body)?;
            let pt = self
                .transport
                .decrypt_body(&body)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.0))?;
            self.rbuf = pt;
            self.rpos = 0;
            // Empty plaintext record: loop and read the next one.
        }
        let n = std::cmp::min(buf.len(), self.rbuf.len() - self.rpos);
        buf[..n].copy_from_slice(&self.rbuf[self.rpos..self.rpos + n]);
        self.rpos += n;
        Ok(n)
    }
}

impl<S: Read + Write> Write for NoiseStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for chunk in buf.chunks(noise::MAX_MSG) {
            let rec = self.transport.encrypt(chunk);
            self.inner.write_all(&rec)?;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The shared serve loop: read framed requests off `stream`, dispatch to the
/// signer, write framed replies back. Transport-agnostic — `stream` is a local
/// `UnixStream` (fd mode) or a `NoiseStream` over TCP (listen mode); both are
/// `Read + Write` and the signer frame protocol is identical over either.
fn serve<S: Read + Write>(stream: &mut S, signer: &mut Signer, log: &mut Option<File>) {
    let trace = std::env::var("SEQLN_SIGNER_TRACE").is_ok();
    loop {
        let req = match frame::read_request(stream) {
            Ok(Some(r)) => r,
            Ok(None) => break, // transport closed
            Err(e) => {
                eprintln!("seqln-signer: transport read error: {e}");
                break;
            }
        };

        if trace {
            let t = seqln_signer::wire::peektype(&req.hsmd_msg);
            logline(
                log,
                &format!(
                    "seqln-signer: TRACE req type={:?} is_main={} dbid={} msglen={}",
                    t,
                    req.is_main,
                    req.dbid,
                    req.hsmd_msg.len()
                ),
            );
        }

        let reply: Vec<u8> = match signer.handle(&req) {
            Outcome::Reply(bytes) => bytes,
            Outcome::Sentinel => Vec::new(), // zero-length error sentinel
            Outcome::Reject(reason) => {
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

// --- key provisioning + small helpers --------------------------------------

/// Load the device's own transport static privkey from SEQLN_SIGNER_PRIVKEY
/// (hex) or SEQLN_SIGNER_PRIVKEY_FILE (a file holding the hex).
fn load_static_priv() -> Result<[u8; 32], String> {
    let hexstr = read_env_or_file("SEQLN_SIGNER_PRIVKEY", "SEQLN_SIGNER_PRIVKEY_FILE")
        .ok_or_else(|| "set SEQLN_SIGNER_PRIVKEY or SEQLN_SIGNER_PRIVKEY_FILE".to_string())?;
    let v = unhex(hexstr.trim()).map_err(|e| format!("privkey: {e}"))?;
    v.try_into()
        .map_err(|_| "privkey must be 32 bytes (64 hex chars)".to_string())
}

/// Load the pinned hosted-node static pubkey we will accept (33-byte compressed).
fn load_pinned_host() -> Result<[u8; 33], String> {
    let hexstr = std::env::var("SEQLN_HOST_PEER_PUBKEY")
        .map_err(|_| "set SEQLN_HOST_PEER_PUBKEY".to_string())?;
    let v = unhex(hexstr.trim()).map_err(|e| format!("host pubkey: {e}"))?;
    v.try_into()
        .map_err(|_| "host pubkey must be 33 bytes (66 hex chars)".to_string())
}

fn read_env_or_file(env_key: &str, file_key: &str) -> Option<String> {
    if let Ok(v) = std::env::var(env_key) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    if let Ok(path) = std::env::var(file_key) {
        if let Ok(s) = std::fs::read_to_string(&path) {
            return Some(s);
        }
    }
    None
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .unwrap_or_else(|e| fatal(&format!("/dev/urandom: {e}")));
    b
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "bad hex digit".to_string()))
        .collect()
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
