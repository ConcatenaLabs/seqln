#!/usr/bin/env python3
"""Regression check for the SeqLN certified-frontier clamp (spec section 6.1).

Mirrors sequentia_certified_frontier() in plugins/bcli.c: given the node tip and
its hash, return the highest quorum-certified height at or below the tip. bcli
reports that frontier as blockcount so CLN's confirmation/minimum_depth math is
denominated in certified depth, not raw Sequentia tip-distance.

Point at a node via ELEMCLI + SEQ_RPC_{HOST,PORT,USER,PASS} (see
validate_live_blocks.py). Three checks:
  1. healthy live chain: frontier == tip (no spurious clamp that would stall LN)
  2. walk mechanics on live data: forcing the tip "uncertified" returns tip-1
  3. synthetic uncertified suffix: top 3 blocks uncertified -> frontier == tip-3
"""
import json, os, subprocess, sys

ELEMCLI = os.environ.get("ELEMCLI", "sequentia-cli")
RPC = ["-chain=test"]
for flag, var in (("-rpcconnect=", "SEQ_RPC_HOST"), ("-rpcport=", "SEQ_RPC_PORT"),
                  ("-rpcuser=", "SEQ_RPC_USER"), ("-rpcpassword=", "SEQ_RPC_PASS")):
    if os.environ.get(var):
        RPC.append(flag + os.environ[var])

LOOKBACK = 144  # must match SEQUENTIA_CERT_LOOKBACK in bcli.c

def cli(*args):
    return subprocess.run([ELEMCLI, *RPC, *args], capture_output=True,
                          text=True, timeout=30).stdout.strip()

def real_certified(h, hsh):
    return json.loads(cli("getblockheader", hsh))["poscertified"]

def frontier(tip, tip_hash, is_cert):
    """Exact mirror of sequentia_certified_frontier()."""
    if is_cert(tip, tip_hash):
        return tip
    back = 1
    while back <= LOOKBACK and back <= tip:
        h = tip - back
        hsh = cli("getblockhash", str(h))
        if is_cert(h, hsh):
            return h
        back += 1
    return tip  # fail-open (committee stalled)

def main():
    info = json.loads(cli("getblockchaininfo"))
    tip, tip_hash = info["blocks"], info["bestblockhash"]
    print(f"node tip = {tip}  ({tip_hash[:16]}...)\n")
    ok = True

    # 1. Healthy chain: certified frontier must equal the tip.
    f1 = frontier(tip, tip_hash, real_certified)
    r1 = "ok" if f1 == tip else "FAIL"
    ok &= f1 == tip
    print(f"  [1] healthy-chain frontier == tip           {r1}  (frontier={f1}, tip={tip})")

    # 2. Force the tip uncertified -> must walk down one and return tip-1
    #    (tip-1 is certified on a healthy chain). Exercises getblockhash +
    #    getblockheader against live data.
    once = lambda h, hsh: False if h == tip else real_certified(h, hsh)
    f2 = frontier(tip, tip_hash, once)
    r2 = "ok" if f2 == tip - 1 else "FAIL"
    ok &= f2 == tip - 1
    print(f"  [2] tip uncertified -> frontier == tip-1     {r2}  (frontier={f2})")

    # 3. Synthetic: top 3 blocks uncertified -> frontier == tip-3.
    synth = lambda h, hsh: h <= tip - 3
    f3 = frontier(tip, tip_hash, synth)
    r3 = "ok" if f3 == tip - 3 else "FAIL"
    ok &= f3 == tip - 3
    print(f"  [3] uncertified suffix(3) -> frontier==tip-3 {r3}  (frontier={f3})")

    print("\nPASS" if ok else "\nFAIL")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
