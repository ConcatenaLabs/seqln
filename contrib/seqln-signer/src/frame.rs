//! The SeqLN Tier-2 signer-split transport frame (milestone M1), reimplemented
//! from `hsmd/signer_frame.h`.
//!
//! Request  (proxy -> signer):
//!   u32  len            byte length of everything after this field
//!   u8   is_main        1 = dbid-0 client, 0 = per-peer client
//!   [33] node_id        present ONLY when is_main == 0
//!   u64  dbid
//!   u64  capabilities
//!   ...  hsmd_msg
//!
//! Reply    (signer -> proxy):
//!   u32  len            byte length of the reply (0 = error sentinel)
//!   ...  hsmd_msg
//!
//! ALL scalars here are LITTLE-endian (unlike the inner hsmd wire, which is
//! big-endian). Exactly one request is in flight at a time.

use std::io::{self, Read, Write};

const PUBKEY_CMPR_LEN: usize = 33;

/// A parsed framed request.
pub struct Request {
    pub is_main: bool,
    pub node_id: [u8; 33],
    pub dbid: u64,
    pub capabilities: u64,
    pub hsmd_msg: Vec<u8>,
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    match r.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

/// Read one framed request. Returns `Ok(None)` on clean EOF (transport closed),
/// mirroring `signer_read_request` returning NULL.
pub fn read_request<R: Read>(r: &mut R) -> io::Result<Option<Request>> {
    let mut lenbuf = [0u8; 4];
    if !read_exact_or_eof(r, &mut lenbuf)? {
        return Ok(None);
    }
    let payload_len = u32::from_le_bytes(lenbuf) as usize;
    // Smallest legal frame: is_main(1) + dbid(8) + caps(8).
    if payload_len < 1 + 8 + 8 {
        return Ok(None);
    }
    let mut payload = vec![0u8; payload_len];
    if !read_exact_or_eof(r, &mut payload)? {
        return Ok(None);
    }

    let mut off = 0usize;
    let is_main = payload[off] != 0;
    off += 1;
    let header = 1 + 8 + 8 + if is_main { 0 } else { PUBKEY_CMPR_LEN };
    if payload_len < header {
        return Ok(None);
    }
    let mut node_id = [0u8; 33];
    if !is_main {
        node_id.copy_from_slice(&payload[off..off + PUBKEY_CMPR_LEN]);
        off += PUBKEY_CMPR_LEN;
    }
    let dbid = u64::from_le_bytes(payload[off..off + 8].try_into().unwrap());
    off += 8;
    let capabilities = u64::from_le_bytes(payload[off..off + 8].try_into().unwrap());
    off += 8;
    let hsmd_msg = payload[off..].to_vec();

    Ok(Some(Request {
        is_main,
        node_id,
        dbid,
        capabilities,
        hsmd_msg,
    }))
}

/// Write one framed reply. An empty `msg` is the error sentinel (`len == 0`),
/// mirroring `signer_write_reply`.
pub fn write_reply<W: Write>(w: &mut W, msg: &[u8]) -> io::Result<()> {
    let lenbuf = (msg.len() as u32).to_le_bytes();
    w.write_all(&lenbuf)?;
    if !msg.is_empty() {
        w.write_all(msg)?;
    }
    w.flush()
}

/// Write one framed request (used by the conformance harness, mirrors
/// `signer_write_request`).
pub fn write_request<W: Write>(
    w: &mut W,
    is_main: bool,
    node_id: &[u8; 33],
    dbid: u64,
    capabilities: u64,
    hsmd_msg: &[u8],
) -> io::Result<()> {
    let idlen = if is_main { 0 } else { PUBKEY_CMPR_LEN };
    let payload_len = 1 + idlen + 8 + 8 + hsmd_msg.len();
    let mut frame = Vec::with_capacity(4 + payload_len);
    frame.extend_from_slice(&(payload_len as u32).to_le_bytes());
    frame.push(is_main as u8);
    if !is_main {
        frame.extend_from_slice(node_id);
    }
    frame.extend_from_slice(&dbid.to_le_bytes());
    frame.extend_from_slice(&capabilities.to_le_bytes());
    frame.extend_from_slice(hsmd_msg);
    w.write_all(&frame)?;
    w.flush()
}

/// Read one framed reply (used by the harness, mirrors `signer_read_reply`).
/// Returns `Ok(None)` on EOF; an empty Vec is the signer's error sentinel.
pub fn read_reply<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut lenbuf = [0u8; 4];
    if !read_exact_or_eof(r, &mut lenbuf)? {
        return Ok(None);
    }
    let len = u32::from_le_bytes(lenbuf) as usize;
    let mut msg = vec![0u8; len];
    if len > 0 && !read_exact_or_eof(r, &mut msg)? {
        return Ok(None);
    }
    Ok(Some(msg))
}
