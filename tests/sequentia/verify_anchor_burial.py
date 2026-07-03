#!/usr/bin/env python3
"""Regression check for the SeqLN two-stage SCID anchor-burial gate (spec 6.2).

Mirrors topo_anchor_buried() in lightningd/chaintopology.c and checks the
bounded-walk optimisation against a brute-force oracle over REAL anchor heights
pulled from the live chain, plus the boundary cases (tip, k-1 vs k, ancient,
above-tip). The gate holds a channel_announcement until the funding block's
Bitcoin anchor is buried by >= k anchor blocks; a certified block can still fall
to tail truncation until then, and an SCID must never be invalidated.

Point at a node via ELEMCLI + SEQ_RPC_{HOST,PORT,USER,PASS}.
"""
import json, os, subprocess, sys

ELEMCLI = os.environ.get("ELEMCLI", "elements-cli")
RPC = ["-chain=test"]
for flag, var in (("-rpcconnect=", "SEQ_RPC_HOST"), ("-rpcport=", "SEQ_RPC_PORT"),
                  ("-rpcuser=", "SEQ_RPC_USER"), ("-rpcpassword=", "SEQ_RPC_PASS")):
    if os.environ.get(var):
        RPC.append(flag + os.environ[var])

def cli(*a):
    return subprocess.run([ELEMCLI, *RPC, *a], capture_output=True,
                          text=True, timeout=30).stdout.strip()

def main():
    tip = int(cli("getblockcount"))

    def anchor_at(h):
        return json.loads(cli("getblockheader", cli("getblockhash", str(h))))["anchorheight"]

    # Grow the window backward until the anchor spans >= 3 blocks (so the k=2
    # boundary True-path is exercised), capped so the test stays quick.
    tip_anchor = anchor_at(tip)
    lo = tip
    for back in (60, 200, 500, 1000, 2000):
        lo = max(1, tip - back)
        if tip_anchor - anchor_at(lo) >= 3 or lo == 1:
            break
    root_height = lo
    anchors = {h: anchor_at(h) for h in range(lo, tip + 1)}

    # anchor_height must be monotonic non-decreasing (the property the walk relies on)
    mono = all(anchors[h] <= anchors[h + 1] for h in range(lo, tip))
    span = anchors[tip] - anchors[lo]
    print(f"tip={tip} window=[{lo},{tip}] anchor span={span} monotonic={mono}")

    # Exact mirror of topo_anchor_buried() (bounded walk from tip).
    def buried_walk(funding, k):
        b = tip
        if funding > b:
            return False
        if funding < root_height:
            return True
        best = anchors[b]
        while b > funding:
            if best - anchors[b] >= k:
                return True
            b -= 1
        return best - anchors[funding] >= k

    # Independent brute-force oracle (no walk optimisation).
    def buried_oracle(funding, k):
        if funding > tip:
            return False
        if funding < root_height:
            return True
        return anchors[tip] - anchors[funding] >= k

    ok = mono
    # 1. walk == oracle for every funding height and several k.
    mismatches = 0
    for k in (1, 2, 3):
        for funding in range(lo - 2, tip + 3):
            if buried_walk(funding, k) != buried_oracle(funding, k):
                mismatches += 1
    r1 = "ok" if mismatches == 0 else f"FAIL ({mismatches} mismatch)"
    ok &= mismatches == 0
    print(f"  [1] bounded walk == brute-force oracle (k=1..3, all heights)  {r1}")

    # 2. tip is never buried (anchor_depth 0).
    r2 = "ok" if not buried_walk(tip, 1) else "FAIL"
    ok &= not buried_walk(tip, 1)
    print(f"  [2] funding == tip -> not buried (k=1)                        {r2}")

    # 3. ancient (below window root) -> buried.
    r3 = "ok" if buried_walk(root_height - 1, 2) else "FAIL"
    ok &= buried_walk(root_height - 1, 2)
    print(f"  [3] funding below root -> buried                              {r3}")

    # 4. above tip -> not buried yet.
    r4 = "ok" if not buried_walk(tip + 1, 2) else "FAIL"
    ok &= not buried_walk(tip + 1, 2)
    print(f"  [4] funding above tip -> not buried                           {r4}")

    # 5. exact k boundary: find the deepest height whose anchor is exactly the
    #    tip anchor (depth 0) and the shallowest buried by >=2; verify k-edge.
    if span >= 2:
        # highest funding with anchor_depth >= 2
        cand = [h for h in range(lo, tip + 1) if anchors[tip] - anchors[h] >= 2]
        edge = max(cand)
        r5 = "ok" if buried_walk(edge, 2) and not buried_walk(edge + 1, 2) else "FAIL"
        ok &= buried_walk(edge, 2) and not buried_walk(edge + 1, 2)
        print(f"  [5] k=2 boundary at height {edge} (buried) / {edge+1} (not)     {r5}")
    else:
        print(f"  [5] k=2 boundary: SKIP (anchor span {span} < 2 in window)")

    print("\nPASS" if ok else "\nFAIL")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
