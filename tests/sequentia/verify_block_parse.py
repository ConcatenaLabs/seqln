#!/usr/bin/env python3
"""Regression check for the Sequentia anchored-block-header parser.

Mirrors the exact parse in bitcoin/block.c (bitcoin_block_from_hex) for a chain
with has_anchor_header: version, prev, merkle, time, block_height, then the
Bitcoin anchor (anchor_height u32 + anchor_hash 32 bytes), then the Elements
legacy proof (challenge is hashed, solution is not). The block hash is
double-SHA256 over version..challenge, reversed for display.

Vector: live Sequentia testnet block 1000. Run: python3 verify_block_parse.py
"""
import hashlib
import sys

# Raw header of testnet block 1000 through the challenge (solution truncated; it
# is not part of the hash). Captured from `elements-cli -chain=test getblock <h> 0`.
BLOCK1000_HEADER = (
    "000000200cd22735fd965687db0a7aa84b02443761ff39453cbe22d8ded0cb7233e238b5"
    "e0a0c052d2b1028dbf8dc5bcd1969572f0feffa544098e8b764266a7f226f87f"
    "72d3376a"          # time
    "e8030000"          # block_height = 1000
    "94260200"          # anchor_height = 140948
    "fcc15218012013e5cc136400c1397b3ad8c3a44eab4a63cfaf48880000000000"  # anchor_hash (LE)
    "23"                # challenge varint length = 35
    "522102ff7d3b107ec6954c917686d18c4271d003ae828eadae890a9fab97c2837fa336f"  # challenge (35 bytes)
)
EXPECT_HASH = "5af2c678a64524c9864e39d0c0cd729fea475feb2e6d322df1017560887bd2ce"
EXPECT_HEIGHT = 1000
EXPECT_ANCHOR_HEIGHT = 140948
EXPECT_ANCHOR_HASH = "00000000008848afcf634aab4ea4c3d83a7b39c1006413cce51320011852c1fc"


def parse(h):
    off = 0

    def take(n):
        nonlocal off
        b = bytes.fromhex(h[off * 2:(off + n) * 2])
        off += n
        return b

    take(4)                                   # version
    take(32)                                  # prev
    take(32)                                  # merkle
    take(4)                                   # time
    height = int.from_bytes(take(4), "little")
    anchor_height = int.from_bytes(take(4), "little")
    anchor_hash = take(32)[::-1].hex()        # display order
    clen = take(1)[0]                         # challenge varint (assumes < 0xfd)
    take(clen)                                # challenge (hashed); solution excluded
    hashed = bytes.fromhex(h[:off * 2])
    blockhash = hashlib.sha256(hashlib.sha256(hashed).digest()).digest()[::-1].hex()
    return height, anchor_height, anchor_hash, len(hashed), blockhash


def main():
    height, anchor_height, anchor_hash, nbytes, blockhash = parse(BLOCK1000_HEADER)
    ok = True
    for name, got, exp in (
        ("height", height, EXPECT_HEIGHT),
        ("anchor_height", anchor_height, EXPECT_ANCHOR_HEIGHT),
        ("anchor_hash", anchor_hash, EXPECT_ANCHOR_HASH),
        ("blockhash", blockhash, EXPECT_HASH),
    ):
        status = "ok" if got == exp else "FAIL"
        if got != exp:
            ok = False
        print(f"  {name:14} {status}  got={got}")
    print(f"  bytes hashed = {nbytes}")
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
