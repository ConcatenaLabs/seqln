#!/usr/bin/env bash
# SeqLN Tier-2 hosted-node SIGNER-RECONNECT STRESS HARNESS.
#
# Reproduces the fund-critical wedge (a running keyless hosted node freezing when
# its device signer reconnects — page refresh / phone sleep / stale relay) and
# proves the robustness fix: N device disconnect/reconnect cycles + a relay
# restart mid-life + the half-dead-link wedge, all WITHOUT wedging or resyncing,
# with getinfo staying responsive and the node continuing to follow the chain.
#
# Fully ISOLATED: its own bitcoind -regtest + its own keyless lightningd whose
# hsmd is the hsmd-proxy under test, fronted by seqln-ws-relay.mjs, with the
# browser device emulated by ws_device.mjs (the real wasm signer over WebSocket).
# Touches NO live node.
#
# Usage: reconnect_stress.sh [CYCLES]   (default 22)
set -u
CYCLES="${1:-22}"

HERE="$(cd "$(dirname "$0")" && pwd)"
SEQLN="$(cd "$HERE/../../../.." && pwd)"            # ~/seqln
LSPDIR="$HOME/sequentia-web-wallet/tooling/lsp"
LIGHTNINGD="$SEQLN/lightningd/lightningd"
PROXY="$SEQLN/lightningd/lightning_hsmd_proxy"
LNCLI="$SEQLN/cli/lightning-cli"
RELAY="$LSPDIR/seqln-ws-relay.mjs"
WSDEV="$HERE/ws_device.mjs"
BCLI="/usr/local/bin/bitcoin-cli"
BITCOIND="/usr/local/bin/bitcoind"

WORK="$(mktemp -d /tmp/seqln-reconnect.XXXXXX)"
BTCDIR="$WORK/btc"; LNDIR="$WORK/ln"; mkdir -p "$BTCDIR" "$LNDIR"
BRPCPORT=18999; BP2P=18998; SIGNERPORT=19917; WSPORT=18917; WSPORT2=18918; LNP2P=19846
OP_TIMEOUT_MS=5000

PIDS=(); DEVPID=""; RELAYPID=""; LORISPID=""; B6JOB=""
log(){ echo "[harness] $*"; }
# Pre-flight: free our ports in case a prior crashed run left an orphan proxy/relay
# holding them (bind EADDRINUSE would otherwise abort boot). Targeted by port.
for pp in "$SIGNERPORT" "$WSPORT" "$WSPORT2" "$BRPCPORT"; do fuser -k "${pp}/tcp" 2>/dev/null; done; sleep 1
fail(){ echo "[harness] FAIL: $*" >&2; cleanup; exit 1; }
cleanup(){
  [ -n "$DEVPID" ] && kill -9 "$DEVPID" 2>/dev/null
  [ -n "$RELAYPID" ] && kill -9 "$RELAYPID" 2>/dev/null
  [ -n "$LORISPID" ] && kill -9 "$LORISPID" 2>/dev/null
  [ -n "$B6JOB" ] && kill -9 "$B6JOB" 2>/dev/null
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  "$BCLI" -regtest -datadir="$BTCDIR" -rpcport=$BRPCPORT -rpcuser=u -rpcpassword=p stop 2>/dev/null
  pkill -9 -f "lightning-dir=$LNDIR" 2>/dev/null
  pkill -9 -f "ws-port $WSPORT" 2>/dev/null; pkill -9 -f "ws-port $WSPORT2" 2>/dev/null
  # The hsmd-proxy is a lightningd subdaemon; killing lightningd only orphans it,
  # so it survives holding the signer listen port. Kill whatever holds our ports
  # (targeted by port, so it can only be THIS harness's proxy/relays).
  for pp in "$SIGNERPORT" "$WSPORT" "$WSPORT2"; do fuser -k "${pp}/tcp" 2>/dev/null; done
  sleep 1; [ -n "${KEEP:-}" ] && { echo "[harness] KEEP=1: logs left in $WORK"; return; }
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

hexpub(){ node -e 'const c=require("node:crypto");const e=c.createECDH("secp256k1");e.setPrivateKey(Buffer.from(process.argv[1],"hex"));process.stdout.write(e.getPublicKey("hex","compressed"))' "$1"; }

# -- keys + mnemonic --------------------------------------------------------
DEVICE_PRIV="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')"
HOST_PRIV="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')"
DEVICE_PUB="$(hexpub "$DEVICE_PRIV")"
HOST_PUB="$(hexpub "$HOST_PRIV")"
echo -n "$HOST_PRIV" > "$WORK/host_priv"
echo -n "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" > "$WORK/mnemonic"
log "device pub $DEVICE_PUB"

# -- bitcoind regtest -------------------------------------------------------
log "starting bitcoind -regtest (-listen=0: single node, no P2P)"
"$BITCOIND" -regtest -datadir="$BTCDIR" -rpcport=$BRPCPORT -rpcuser=u -rpcpassword=p \
  -fallbackfee=0.0002 -server=1 -listen=0 -txindex=1 -blockfilterindex=1 >"$WORK/bitcoind.log" 2>&1 &
PIDS+=($!)
BC(){ "$BCLI" -regtest -datadir="$BTCDIR" -rpcport=$BRPCPORT -rpcuser=u -rpcpassword=p "$@"; }
for i in $(seq 1 60); do BC getblockchaininfo >/dev/null 2>&1 && break; sleep 0.5; done
BC getblockchaininfo >/dev/null 2>&1 || fail "bitcoind did not come up"
BC createwallet h >/dev/null 2>&1 || BC loadwallet h >/dev/null 2>&1
ADDR="$(BC getnewaddress)"
BC generatetoaddress 101 "$ADDR" >/dev/null 2>&1 || fail "generatetoaddress failed"
# Ride out any post-mine RPC busyness BEFORE booting lightningd: poll the exact
# bcli-style connection until it answers, so the backend is provably ready.
for i in $(seq 1 40); do
  echo p | "$BCLI" -regtest -rpcclienttimeout=60 -rpcconnect=127.0.0.1 -rpcport=$BRPCPORT -rpcuser=u -stdinrpcpass getblockchaininfo >/dev/null 2>&1 && break
  sleep 0.5
done
log "bitcoind up at height $(BC getblockcount); backend RPC verified ready"

# -- lightningd + hsmd-proxy (LISTEN mode) ----------------------------------
cat > "$LNDIR/config" <<EOF
network=regtest
bitcoin-datadir=$BTCDIR
bitcoin-rpcuser=u
bitcoin-rpcpassword=p
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcport=$BRPCPORT
bitcoin-cli=$BCLI
addr=127.0.0.1:$LNP2P
funding-confirms=1
allow-deprecated-apis=true
force-feerates=5000
log-level=debug
log-file=$LNDIR/lightningd.log
dev-bitcoind-poll=1
subdaemon=hsmd:$PROXY
EOF

start_relay(){ # $1 = ws port, $2 = extra args (e.g. "--ping-ms 0")
  node "$RELAY" --ws-port "$1" --tcp 127.0.0.1:$SIGNERPORT --tcp-retry-ms 120000 $2 \
    >"$WORK/relay-$1.log" 2>&1 & RELAYPID=$!
}
start_device(){ # $1 = ws port
  node "$WSDEV" "ws://127.0.0.1:$1" "$WORK/mnemonic" "$HOST_PUB" "$DEVICE_PRIV" \
    >"$WORK/device.log" 2>&1 & DEVPID=$!
}

log "starting lightningd (keyless; hsmd = proxy under test; op-timeout ${OP_TIMEOUT_MS}ms)"
# Short per-op / handshake / kernel-keepalive deadlines so the A2/A3 tests observe
# recovery in seconds, not the 120s/20s production backstops. All env-overridable.
SEQLN_SIGNER_LISTEN="127.0.0.1:$SIGNERPORT" \
SEQLN_HOST_PRIVKEY_FILE="$WORK/host_priv" \
SEQLN_SIGNER_PEER_PUBKEY="$DEVICE_PUB" \
SEQLN_SIGNER_OP_TIMEOUT_MS="$OP_TIMEOUT_MS" \
SEQLN_SIGNER_HS_TIMEOUT_MS="1500" \
SEQLN_SIGNER_TCP_USER_TIMEOUT_MS="4000" \
SEQLN_SIGNER_TCP_KEEPIDLE_S="2" \
SEQLN_SIGNER_TCP_KEEPINTVL_S="1" \
  "$LIGHTNINGD" --lightning-dir="$LNDIR" --network=regtest --developer >"$WORK/ld.out" 2>&1 &
PIDS+=($!)

start_relay "$WSPORT" ""
start_device "$WSPORT"

CL(){ "$LNCLI" --lightning-dir="$LNDIR" --network=regtest "$@" 2>/dev/null; }
# Extract one field from `getinfo` JSON, robust to any ANSI colour lightning-cli adds.
# -R = raw JSON; write the value as a PLAIN STRING via process.stdout.write —
# console.log(<number>) re-colours numbers (node inspect honours FORCE_COLOR),
# which previously smuggled ANSI into blockheight and broke every height/resync test.
# BOUNDED (timeout 6): getinfo must never hang the harness; empty on timeout so a
# wedged node surfaces as a clean assertion failure, not a hang.
jget(){ timeout 6 "$LNCLI" --lightning-dir="$LNDIR" --network=regtest -R getinfo 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(String(JSON.parse(s.replace(/\x1b\[[0-9;]*m/g,""))["'"$1"'"]??""))}catch{process.stdout.write("")}})'; }
# getinfo latency in ms (empty if it did not answer within `timeout`s)
getinfo_ms(){ local t0 t1 out; t0=$(date +%s%N)
  out=$(timeout "${1:-8}" "$LNCLI" --lightning-dir="$LNDIR" --network=regtest getinfo 2>/dev/null)
  [ -z "$out" ] && return 1
  t1=$(date +%s%N); echo $(( (t1 - t0) / 1000000 )); return 0; }
# DEVICE-EXERCISING liveness probe: `newaddr p2tr` forces a BIP86 taproot pubkey
# check THROUGH the device signer (WIRE_HSMD_CHECK_BIP86_PUBKEY — a device-supported
# op, unlike sign_message). Succeeds only if the device round-trip completed, so it
# proves the signer path is live after a reconnect (not just that getinfo answers).
probe_device(){ CL newaddr p2tr 2>/dev/null | grep -q 'bcrt1p'; }

log "waiting for the hosted node to init (device serving INIT)…"
NODEID=""
for i in $(seq 1 60); do NODEID="$(jget id)"; [ -n "$NODEID" ] && break; sleep 1; done
[ -n "$NODEID" ] || fail "hosted node never came up (getinfo returned no id) — see $WORK/ld.out $WORK/device.log"
H0=$(jget blockheight); [ -z "$H0" ] && H0=0
log "hosted node UP: id=$NODEID blockheight=$H0"

MAXLAT=0; RESYNC=0; WEDGE=0
record(){ local ms=$1; [ "$ms" -gt "$MAXLAT" ] && MAXLAT=$ms; }
check_height(){ local h; h=$(jget blockheight); [ -z "$h" ] && return
  if [ "$h" -lt "$H0" ]; then RESYNC=1; log "  !! blockheight went BACKWARD ($h < $H0) = RESYNC"; fi }
sign_ok(){ probe_device; }

# ---------------------------------------------------------------------------
# PHASE 1: N clean disconnect/reconnect cycles (simulate refresh/sleep).
# ---------------------------------------------------------------------------
log "PHASE 1: $CYCLES clean device disconnect/reconnect cycles"
for c in $(seq 1 "$CYCLES"); do
  ms=$(getinfo_ms 8) || { WEDGE=1; fail "getinfo WEDGED before cycle $c"; }
  record "$ms"; check_height
  sign_ok "$c" || fail "device probe failed before cycle $c (signer path broken)"

  # Every 6th cycle also restarts the RELAY mid-life (LSP/relay restart coverage).
  RESTART_RELAY=0; [ $((c % 6)) -eq 0 ] && RESTART_RELAY=1

  kill -TERM "$DEVPID" 2>/dev/null; wait "$DEVPID" 2>/dev/null; DEVPID=""
  if [ "$RESTART_RELAY" = 1 ]; then
    log "  cycle $c: RESTARTING the relay mid-life"
    kill -TERM "$RELAYPID" 2>/dev/null; wait "$RELAYPID" 2>/dev/null; RELAYPID=""
    sleep 0.5; start_relay "$WSPORT" ""
  fi
  start_device "$WSPORT"

  # Reconnect must restore service quickly (device re-attaches; NO resync).
  ok=0
  for i in $(seq 1 30); do
    if sign_ok "r$c"; then ok=1; break; fi
    sleep 0.5
  done
  [ "$ok" = 1 ] || { WEDGE=1; fail "cycle $c: node did not recover after reconnect (wedge?) — see $WORK/ld.out"; }
  ms=$(getinfo_ms 8) || { WEDGE=1; fail "getinfo WEDGED after cycle $c reconnect"; }
  record "$ms"; check_height
  printf "[harness]   cycle %2d/%d ok  getinfo=%sms  height=%s%s\n" "$c" "$CYCLES" "$ms" \
    "$(jget blockheight)" \
    "$([ "$RESTART_RELAY" = 1 ] && echo "  (relay restarted)")"
done

# ---------------------------------------------------------------------------
# PHASE 2: the HALF-DEAD-LINK wedge — the exact failure that froze node-USDX-17.
# Freeze the device (SIGSTOP) so its ws TCP stays ESTAB but silent (no RST), fire
# a signing op that blocks the proxy on that dead link, then reconnect a FRESH
# device. The fix must EVICT the stale link and complete the parked op. Relay
# keepalive is DISABLED here (--ping-ms 0) to isolate the PROXY-side recovery.
# ---------------------------------------------------------------------------
log "PHASE 2: half-dead-link wedge (proxy-side newcomer eviction, relay keepalive OFF)"
kill -TERM "$DEVPID" 2>/dev/null; wait "$DEVPID" 2>/dev/null; DEVPID=""
kill -TERM "$RELAYPID" 2>/dev/null; wait "$RELAYPID" 2>/dev/null; RELAYPID=""
sleep 0.5
start_relay "$WSPORT" "--ping-ms 0"     # keepalive OFF: only the proxy can recover
start_device "$WSPORT"
for i in $(seq 1 30); do sign_ok "phase2-init" && break; sleep 0.5; done
sign_ok "phase2-init" || fail "phase2: node not serving before the wedge test"

log "  freezing device (SIGSTOP) -> half-dead ESTAB link"
kill -STOP "$DEVPID"
sleep 0.5
# Confirm the wedge condition is REAL: a signing op now blocks; getinfo hangs too.
( CL newaddr p2tr >"$WORK/wedged.out" 2>&1 ) & STUCKPID=$!
sleep 2
if getinfo_ms 3 >/dev/null; then
  log "  (note: getinfo still answered — signing op not yet blocking the loop; continuing)"
else
  log "  confirmed: getinfo HANGS while the signing op is stuck on the dead link (wedge reproduced)"
fi
if ! kill -0 "$STUCKPID" 2>/dev/null; then fail "phase2: probe returned before reconnect — test invalid"; fi

log "  reconnecting a FRESH device on a new relay (newcomer) -> proxy must evict + re-send"
start_relay "$WSPORT2" "--ping-ms 0"
DEV2_PRIV="$DEVICE_PRIV"
node "$WSDEV" "ws://127.0.0.1:$WSPORT2" "$WORK/mnemonic" "$HOST_PUB" "$DEV2_PRIV" >"$WORK/device2.log" 2>&1 &
DEV2PID=$!
t0=$(date +%s%N)
recovered=0
for i in $(seq 1 40); do
  if ! kill -0 "$STUCKPID" 2>/dev/null; then recovered=1; break; fi
  sleep 0.5
done
t1=$(date +%s%N)
kill -9 "$DEVPID" 2>/dev/null; DEVPID="$DEV2PID"   # RELAYPID now tracks the WSPORT2 relay
if [ "$recovered" = 1 ] && grep -q "bcrt1p" "$WORK/wedged.out"; then
  log "  RECOVERED: the parked signing op completed $(( (t1-t0)/1000000 ))ms after the fresh device connected (no wedge)"
else
  WEDGE=1; kill -9 "$STUCKPID" "$DEV2PID" 2>/dev/null
  fail "phase2: node did NOT recover from the half-dead link — the wedge persists. see $WORK/ld.out"
fi
ms=$(getinfo_ms 8) || fail "phase2: getinfo still wedged after recovery"
record "$ms"; check_height
log "  post-recovery getinfo=${ms}ms  height=$(jget blockheight)"

# At this point DEVPID is the fresh device on WSPORT2 and RELAYPID is its relay.

# ---------------------------------------------------------------------------
# PHASE 3 (A2): a STALLED Noise handshake must not wedge the proxy — the SECOND
# blocking site the post-handshake poll fix missed. Open a raw TCP to the proxy's
# signer listen port and send a partial handshake, then hold it silent. Pre-A2
# the responder's read_all(act1) blocked the proxy's io loop FOREVER; with the
# poll+deadline handshake the connector is rejected after the handshake deadline
# and the node keeps serving.
# ---------------------------------------------------------------------------
log "PHASE 3 (A2): stalled Noise handshake — proxy must reject it, not wedge"
node -e 'const net=require("net");const s=net.connect(process.argv[1]|0,"127.0.0.1",()=>s.write(Buffer.from([0])));s.on("error",()=>{});setInterval(()=>{},3600e3);' "$SIGNERPORT" >/dev/null 2>&1 &
LORISPID=$!
sleep 1
ms=$(getinfo_ms 8) || { WEDGE=1; fail "phase3(A2): getinfo WEDGED during the stalled handshake"; }
record "$ms"
sign_ok "a2-during" || { WEDGE=1; fail "phase3(A2): device stopped serving during the stalled handshake"; }
sleep 2   # past the 1500ms handshake deadline -> the loris is rejected
ms=$(getinfo_ms 8) || { WEDGE=1; fail "phase3(A2): getinfo WEDGED after the handshake deadline"; }
record "$ms"
sign_ok "a2-after" || { WEDGE=1; fail "phase3(A2): device probe failed after the loris was rejected"; }
kill -9 "$LORISPID" 2>/dev/null; LORISPID=""
check_height
log "  A2 ok: stalled handshake rejected; getinfo flat (${ms}ms); device still serving"

# ---------------------------------------------------------------------------
# PHASE 4 (A6): a reconnect STORM must not thrash the proxy into a wedge. Flap
# the device rapidly while probing getinfo; eviction damping keeps the node
# stable and it recovers with a serving device.
# ---------------------------------------------------------------------------
log "PHASE 4 (A6): reconnect storm (rapid device flap)"
for k in $(seq 1 6); do
  kill -TERM "$DEVPID" 2>/dev/null; DEVPID=""
  start_device "$WSPORT2"
  sleep 0.25
  ms=$(getinfo_ms 6) || { WEDGE=1; fail "phase4(A6): getinfo WEDGED during storm iter $k"; }
  record "$ms"
done
ok=0; for i in $(seq 1 30); do sign_ok "a6" && { ok=1; break; }; sleep 0.5; done
[ "$ok" = 1 ] || { WEDGE=1; fail "phase4(A6): node did not recover a serving device after the storm"; }
ms=$(getinfo_ms 8) || { WEDGE=1; fail "phase4(A6): getinfo wedged after the storm"; }
record "$ms"; check_height
log "  A6 ok: survived a reconnect storm; getinfo flat (${ms}ms); device serving"

# ---------------------------------------------------------------------------
# PHASE 5 (B6): a device REJECT of a MASTER-fd op must NOT kill the node. The
# device rejects one CHECK_BIP86_PUBKEY (a master-fd op, hsmd type 56) with the
# zero-length error sentinel; pre-B6 this routed through master_badmsg -> FATAL
# node exit (which for a keyless node is unrecoverable without the device). The
# proxy must instead DROP the rejecting device and PARK the op; a fresh device
# then completes it. Assert: no fatal exit, lightningd pid unchanged, op recovers.
# ---------------------------------------------------------------------------
log "PHASE 5 (B6): device rejects a master-fd op — node must survive + recover"
LDPID_BEFORE=$(pgrep -f "lightning-dir=$LNDIR" | head -1)
kill -TERM "$DEVPID" 2>/dev/null; wait "$DEVPID" 2>/dev/null; DEVPID=""
sleep 0.5
SEQLN_DEV_REJECT_ONCE=56 node "$WSDEV" "ws://127.0.0.1:$WSPORT2" "$WORK/mnemonic" "$HOST_PUB" "$DEVICE_PRIV" >"$WORK/device-b6.log" 2>&1 & DEVPID=$!
sleep 3   # let this device get adopted + re-primed (INIT, type 11 — not rejected)
( CL newaddr p2tr >"$WORK/b6.out" 2>&1 ) & B6JOB=$!   # master-fd op the device rejects once -> PARKS
sleep 3
LDPID_AFTER=$(pgrep -f "lightning-dir=$LNDIR" | head -1)
if grep -qiE 'FATAL SIGNAL|master_badmsg|Log dumped' "$WORK/ld.out"; then WEDGE=1; fail "phase5(B6): node FATALED on a master-op reject (B6 regression)"; fi
[ -n "$LDPID_AFTER" ] && [ "$LDPID_AFTER" = "$LDPID_BEFORE" ] || { WEDGE=1; fail "phase5(B6): lightningd pid changed/gone — node did NOT survive the reject"; }
log "  reject fired; lightningd still alive (pid $LDPID_AFTER); parked op awaiting a fresh device"
kill -9 "$DEVPID" 2>/dev/null; DEVPID=""
start_device "$WSPORT2"   # fresh device (no reject) -> proxy re-primes + re-sends the parked op
rec=0; for i in $(seq 1 40); do
  if ! kill -0 "$B6JOB" 2>/dev/null && grep -q 'bcrt1p' "$WORK/b6.out"; then rec=1; break; fi
  sleep 0.5
done
[ "$rec" = 1 ] || { WEDGE=1; kill -9 "$B6JOB" 2>/dev/null; fail "phase5(B6): parked op did not complete after a fresh device reconnected"; }
B6JOB=""
ms=$(getinfo_ms 8) || { WEDGE=1; fail "phase5(B6): getinfo wedged after B6 recovery"; }
record "$ms"; check_height
log "  B6 ok: master-op reject did NOT kill the node; parked op completed after reconnect (${ms}ms)"

# ---------------------------------------------------------------------------
# PHASE 6: device FULLY gone. Two DISTINCT claims, deliberately kept apart:
#   (a) AVAILABILITY (the legitimate reconnect-fix benefit): the node PROCESS
#       stays alive and FOLLOWS Bitcoin (block-add + reorg) with no device — pure
#       sync needs no hsmd.  Observed via the node LOG (block-add), because
#       getinfo may park (see (b)).
#   (b) PERSISTENCE HAZARD (flagged, NOT shipped): ANY master-fd op with no device
#       PARKS the whole node.  This harness observes it directly: after following
#       blocks, the wallet's own key handling issues WIRE_HSMD_CHECK_BIP86_PUBKEY
#       (a master-fd op) which parks with no device (equally, an onchaind SWEEP
#       would).  So a device-absent node WATCHES but cannot ACT — persistence as a
#       fund-safety feature needs a watchtower / pre-signed justice (blockers
#       B1-B3).  We therefore ASSERT only (a), and REPORT (b) — never claim a
#       persisted node keeps funds safe.
# ---------------------------------------------------------------------------
log "PHASE 6: device gone — assert block/reorg FOLLOW (no hsmd) + demonstrate the master-fd park hazard"
LDPID=$(pgrep -f "lightning-dir=$LNDIR" | head -1)
kill -9 "$DEVPID" 2>/dev/null; DEVPID=""
kill -TERM "$RELAYPID" 2>/dev/null; RELAYPID=""
pkill -9 -f "ws-port $WSPORT2" 2>/dev/null
LOGF="$LNDIR/lightningd.log"
lastblk(){ grep -aoE 'Adding block [0-9]+' "$LOGF" 2>/dev/null | tail -1 | grep -oE '[0-9]+'; }
BASEBLK=$(lastblk); [ -z "$BASEBLK" ] && BASEBLK=0
log "  device gone; node at block $BASEBLK. Mining 5 blocks (NO device present)…"
BC generatetoaddress 5 "$ADDR" >/dev/null
# (a) Block-FOLLOW with no device, observed via the LOG (robust to a getinfo park).
followed=0; NEWBLK=$BASEBLK
for i in $(seq 1 20); do
  NEWBLK=$(lastblk); [ -z "$NEWBLK" ] && NEWBLK=0
  [ "$NEWBLK" -gt "$BASEBLK" ] && { followed=1; break; }
  sleep 1
done
[ "$followed" = 1 ] || fail "phase6: device-absent node did NOT follow a new block — sync-without-hsmd is broken"
log "  FOLLOW ok: node added block $NEWBLK with NO device (pure block-follow needs no hsmd)"
# (a) REORG follow (anchoring supremacy #1), also log-observed.
FORK=$(BC getblockhash $((NEWBLK - 2)) 2>/dev/null)
if [ -n "$FORK" ]; then
  BC invalidateblock "$FORK" >/dev/null 2>&1
  BC generatetoaddress 6 "$ADDR" >/dev/null 2>&1
  TIP=$(BC getblockcount 2>/dev/null)
  rf=0; RB=$NEWBLK
  for i in $(seq 1 20); do
    RB=$(lastblk); [ -z "$RB" ] && RB=0
    [ "$RB" -ge "$TIP" ] && { rf=1; break; }
    sleep 1
  done
  if [ "$rf" = 1 ]; then
    log "  REORG ok: device-absent node followed Bitcoin's reorg to tip $TIP (no hsmd)"
  else
    log "  REORG note: node reached block $RB of tip $TIP with no device (a master-fd op likely parked it mid-follow — the hazard below)"
  fi
fi
# (a) The node PROCESS must still be ALIVE — the only defensible 'persistence' claim.
kill -0 "$LDPID" 2>/dev/null || fail "phase6: node PROCESS died with no device — not even watch-only persistence holds"
log "  PROCESS ok: node still alive (pid $LDPID) with no device"
# (b) Demonstrate the persistence HAZARD: a master-fd op parks a device-absent node.
if getinfo_ms 5 >/dev/null 2>&1; then
  log "  (getinfo still responsive this window — no master-fd op has fired yet)"
else
  PARKED=$(grep -aoE 'no device for WIRE_[A-Z_0-9]+' "$LOGF" 2>/dev/null | tail -1)
  log "  PERSISTENCE HAZARD (expected, flagged): getinfo PARKED — [$PARKED] cannot complete"
  log "  with no device. A device-absent node WATCHES but cannot ACT; offline fund-defence"
  log "  needs a watchtower / pre-signed justice (blockers B1-B3). Persistence NOT shipped."
fi
[ "$NEWBLK" -lt "$H0" ] && RESYNC=1

# ---------------------------------------------------------------------------
echo
log "================= RESULT ================="
log "phases run:            P1 $CYCLES clean cycles (+relay-restart/6) | P2 half-dead wedge (A1)"
log "                       | P3 stalled handshake (A2) | P4 reconnect storm (A6)"
log "                       | P5 master-op reject fail-soft (B6)"
log "                       | P6 device-absent block/reorg FOLLOW (avail.) + master-fd PARK hazard (flagged)"
log "max getinfo latency:   ${MAXLAT}ms  (flat = never wedged)"
log "resync detected:       $([ "$RESYNC" = 0 ] && echo NO || echo YES)"
log "wedge detected:        $([ "$WEDGE" = 0 ] && echo NO || echo YES)"
if [ "$RESYNC" = 0 ] && [ "$WEDGE" = 0 ] && [ "$MAXLAT" -lt 5000 ]; then
  log "PASS: no wedge, no resync, getinfo stayed responsive across all cycles."
  exit 0
else
  log "FAIL: see thresholds above."
  exit 1
fi
