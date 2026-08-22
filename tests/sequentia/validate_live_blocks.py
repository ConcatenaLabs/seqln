#!/usr/bin/env python3
"""Broad live-chain validation of the SeqLN anchored-header parser.

Reimplements bitcoin_block_from_hex (bitcoin/block.c) EXACTLY for Sequentia's
has_anchor_header case, over a sample of real blocks fetched from the live
testnet node. For each block: recompute the block hash from the header bytes
and assert it equals the node's authoritative getblockhash(height).

Hashed region (non-dynafed signed block, SER_GETHASH):
  version(4) prev(32) merkle(32) time(4) height(4)
  anchor_height(4) anchor_hash(32)          <-- Sequentia anchor
  challenge_varint challenge_bytes          <-- proof challenge (hashed)
  [solution excluded from the hash]
blockhash = double_SHA256(that region), reversed for display.
"""
import hashlib, os, subprocess, sys

# Point this at any reachable Sequentia testnet node (local, or an SSH tunnel to
# a remote one). Connection comes from the environment so no host or credential
# is baked into the repo; unset values fall back to sequentia-cli's own config.
ELEMCLI = os.environ.get("ELEMCLI", "sequentia-cli")
RPC = ["-chain=test"]
for flag, var in (("-rpcconnect=", "SEQ_RPC_HOST"), ("-rpcport=", "SEQ_RPC_PORT"),
                  ("-rpcuser=", "SEQ_RPC_USER"), ("-rpcpassword=", "SEQ_RPC_PASS")):
    if os.environ.get(var):
        RPC.append(flag + os.environ[var])

def cli(*args):
    return subprocess.run([ELEMCLI, *RPC, *args], capture_output=True,
                          text=True, timeout=30).stdout.strip()

def read_varint(b, off):
    """Return (value, new_off) for a Bitcoin CompactSize at b[off]."""
    n = b[off]; off += 1
    if n < 0xfd:  return n, off
    if n == 0xfd: return int.from_bytes(b[off:off+2], "little"), off+2
    if n == 0xfe: return int.from_bytes(b[off:off+4], "little"), off+4
    return int.from_bytes(b[off:off+8], "little"), off+8

def recompute(block_hex):
    b = bytes.fromhex(block_hex)
    off = 4 + 32 + 32 + 4            # version, prev, merkle, time
    height = int.from_bytes(b[off:off+4], "little"); off += 4
    version = int.from_bytes(b[0:4], "little")
    dynafed = (version >> 31) == 1   # MSB signals dynafed
    anchor_height = int.from_bytes(b[off:off+4], "little"); off += 4
    anchor_hash = b[off:off+32][::-1].hex(); off += 32
    if dynafed:
        return None, height, anchor_height, anchor_hash, True
    clen, off = read_varint(b, off)  # challenge varint (proper CompactSize)
    off += clen                      # challenge bytes (hashed); solution excluded
    hashed = b[:off]
    h = hashlib.sha256(hashlib.sha256(hashed).digest()).digest()[::-1].hex()
    return h, height, anchor_height, anchor_hash, False

def main():
    tip = int(cli("getblockcount"))
    # spread across the whole chain + dense near the tip + exact tip
    heights = sorted(set([1, 2, 3, 50, 100, 500, 1000, 2500, 5000, 7777,
                          10000, 12500, 15000, 16000, 17000, 18000, 18100,
                          18150, tip-2, tip-1, tip]))
    heights = [h for h in heights if 1 <= h <= tip]
    ok = fail = dyna = 0
    print(f"node tip = {tip}; validating {len(heights)} sampled blocks\n")
    print(f"  {'height':>7}  {'anchor_h':>8}  clen  result")
    for h in heights:
        node_hash = cli("getblockhash", str(h))
        blk = cli("getblock", node_hash, "0")
        if not blk:
            print(f"  {h:>7}  (could not fetch block)"); fail += 1; continue
        got, height, ah, ahash, is_dyna = recompute(blk)
        if is_dyna:
            print(f"  {h:>7}  {ah:>8}   -    DYNAFED (mirror skips; C path handles separately)")
            dyna += 1; continue
        # recover clen for display
        b = bytes.fromhex(blk); o = 4+32+32+4+4+4+32; cl,_ = read_varint(b, o)
        status = "ok" if got == node_hash and height == h else "MISMATCH"
        if status == "ok": ok += 1
        else:
            fail += 1
            print(f"  {h:>7}  {ah:>8}  {cl:>4}  {status}\n       node={node_hash}\n       got ={got}")
            continue
        print(f"  {h:>7}  {ah:>8}  {cl:>4}  ok  {got}")
    print(f"\nPASS={ok}  FAIL={fail}  DYNAFED={dyna}")
    sys.exit(0 if fail == 0 else 1)

if __name__ == "__main__":
    main()
