# seqln-signer: the SeqLN device signer

A Rust reimplementation of Core Lightning's signer (the crypto kernel of `libhsmd` plus the hsmd
wire subset a running node exercises), built so that a **thin wallet can hold the keys while a
host runs the node**. The device (native binary, or a browser via the WASM build) holds the
`hsm_secret` mnemonic and serves signing requests; the hosted `lightningd` never sees a key, and
in enforce mode the device refuses to sign theft-shaped transactions.

This is one half of SeqLN's signer split; the other half lives in the node tree:

```
lightningd --subdaemon=hsmd:/path/to/lightning_hsmd_proxy
    |
    v
hsmd-proxy  (hsmd/hsmd_proxy.c: all fd multiplexing, NO secret)
    |  framed requests (hsmd/signer_frame.h; u32-LE length prefix)
    v
the signer, one of:
  a) lightning_signerd        (hsmd/signerd.c, C, links real libhsmd: the reference/oracle)
  b) seqln-signer, fd mode    (this crate, local fork+socketpair, drop-in for signerd)
  c) seqln-signer, TCP mode   (this crate, remote device, BOLT-8 Noise_XK secured)
  d) browser WASM signer      (wasm/, over a WebSocket relay, same Noise_XK)
```

The proxy is selected with CLN's stock `--subdaemon=hsmd:PATH` option, so the node build is
otherwise unchanged; `SEQLN_SIGNERD` overrides which signer binary the proxy fork/execs in local
mode. Either way the `hsm_secret` (mnemonic format) is loaded from the signer's working
directory.

## Verified properties

- **Byte-exact against libhsmd.** The `conformance` harness drives the reference
  `lightning_signerd` (the oracle) and `seqln-signer` with the same `hsm_secret` and the same
  framed requests, and compares reply bytes exactly; `wasm/test/conformance.mjs` repeats the
  comparison for the WASM build against captured oracle replies. The `shadow` binary is a
  `signerd` drop-in that byte-compares live channel traffic and captures a replay corpus.
- **Validating signer (enforce mode, the default).** Before signing a commitment the device
  reconstructs every legitimate output script from the channel keys and the request's
  per-commitment point (`src/policy.rs`), and refuses if any output pays elsewhere or value is
  created. `tests/tamper.rs` proves a redirected-output commitment is rejected in enforce mode
  and signed in permissive mode (i.e. the policy, not a parse error, blocks it).
  `SEQLN_SIGNER_POLICY=permissive` (or `enforce=false` in the WASM build) is the kill-switch:
  sign any well-formed request, as libhsmd's stub validator does.
- **Fail-closed remote transport.** The TCP modes run BOLT-8 Noise_XK (`src/noise.rs`, pure state
  machine, WASM-ready): encryption, integrity, and mutual authentication against pinned static
  keys. Listen mode refuses to start without its own private key and the pinned peer key; an
  unauthenticated connector is served zero frames. There is no raw-TCP fallback.
- **Seed never leaves the device.** The host holds no key material, so losing or rebuilding the
  hosted node does not endanger funds; recovery uses the device's mnemonic with CLN's standard
  recovery flow.

## Scope

Implements hsmd wire version 6 and the message subset a running SeqLN node exercises:
derivation (BIP39/32/86, basepoints, per-commitment points, shachain), ECDH, commitment and HTLC
signing, withdrawal/funding signing for both Elements/Sequentia (explicit, unblinded outputs) and
Bitcoin (BIP-143 segwit v0 and BIP-86 taproot key-path wallet inputs), and BOLT11 invoice
signing. Messages outside the subset return an error sentinel rather than a wrong answer.

What enforce mode checks:

- **Commitments**, ours and the peer's: every output is one the channel's keys produce, every
  output is in the channel's one asset, and the funding input issues no asset (with an issuance
  there, a commitment or a close could pay this side in a fresh, worthless asset while the
  channel's own value went to the peer). A
  commitment of ours counts as validated only when the peer's signature on it verifies against
  the channel's remote funding key. From the latest of our commitments it validated, and the
  latest of the peer's it signed, the device records this side's balance: its own output, plus
  the fee and anchors when this side opened the channel.
- **The balance split of every commitment**, ours and the peer's: the device holds each
  commitment to the balance it tracks for this side, against the latest commitment on the same
  side. This side's value there is its main output, the HTLCs it offered, and, when it opened
  the channel, the fee and anchors less the HTLCs trimmed as dust (whose value is in the fee).
  channeld lists every HTLC a commitment carries, trimmed ones included, so between two honest
  commitments that value moves only with HTLCs: it falls by the HTLCs this side offered that the
  new commitment settles, and by nothing else; a fee change moves none of it. A commitment that
  leaves this side less, beyond an atom of rounding per HTLC, is refused ("it leaves this wallet
  … atoms of the channel, … fewer than it tracks"), whatever the payment limit would allow. In
  permissive mode the shortfall is signed and charged to the limit instead. When this side opened the channel, and
  so pays the commitment's fee, that fee is at most the payment limit of the channel's asset: a
  host that also ran the peer could otherwise raise the feerate (`update_fee`, which the opener
  sends) until our balance was the fee, and on Sequentia a fee goes to the block proposer.
- **Broadcasting a commitment of ours** (`SIGN_COMMITMENT_TX`, the signature that lets the host
  put it on chain): the device signs only a transaction whose txid is one of our commitments it
  validated and has not revoked. That request carries no HTLC list, so the device could not
  rebuild a commitment it had not already validated; lightningd never needs one, because what it
  signs is the commitment channeld last had validated. A device with no such record (a store
  from before commitments were recorded, or a lost store) signs none of our commitments for
  broadcast until the channel's next commitment step.
- **Mutual closes** (closingd's request, and the closing transaction lightningd signs again with
  the commitment message when a close completes and whenever it starts with a channel closing):
  one input, the funding output, issuing no asset; every output in one asset, the channel's; at
  most one output to this device's own wallet and at most one
  to the peer, which must be the peer's upfront shutdown script when the channel named one; no
  value created. A close paying our share anywhere but our own wallet is refused, and so is one
  whose fee, when this side opened the channel and pays it, is over the payment limit. The local
  upfront shutdown script (`fundchannel close_to=`) counts as our wallet only when it is one of
  this device's wallet addresses at the key index `setup_channel` gives for it, because the host
  supplies that script: a channel opened with `close_to` an address outside this wallet cannot be
  closed mutually, and closes unilaterally instead (the device sweeps its delayed output to its
  own wallet). The output to our wallet must be at least the recorded balance (the larger of the
  two commitments' figures), less the close fee when this side opened the channel. That fee is
  counted only up to four times the commitment's fee and anchors: a close paying more (`close`
  with a `feerange` far above the channel's feerate, say) is refused, lightningd keeps running,
  and `close` falls back to a unilateral close after its `unilateraltimeout`. Our output may be
  left out only when what is due is under the channel's dust limit, and the peer's output may not
  exceed the funding less our balance. The node sets a channel's dust limit in its asset, at what
  546 reference atoms are worth there, and names both sides' limits in `setup_channel`; the device
  takes the larger, held to one percent of the funding (a host naming a larger one could otherwise
  have a close burn our share as fee). From a node that names none, the limit is 546 atoms. While no balance is recorded, every close is refused,
  however much it pays this wallet: the device cannot tell an honest close from one paying it a
  single atom.
- **Reserve**: once a commitment the device validated or signed has paid the peer at least the
  reserve this side requires of it (`setup_channel` names it), the device refuses any commitment,
  ours or the peer's, whose output to the peer is below it: the reserve is what a peer that
  broadcasts a revoked commitment loses at least, and a host that also runs the peer could otherwise
  drain it, as channeld would not. The peer's output is net of the commitment fee when the peer
  opened the channel, as BOLT 2 asks.
- **Revocations**: a commitment's secret leaves the device only through its revocation. The
  device speaks hsmd version 6 alone and refuses an INIT whose highest version is below it, the
  first INIT and any later one (lightningd offers 5 to 6): below version 6 a commitment point
  comes with the secret of the commitment two before it, which a host that lowered the version
  could read for a commitment the device has not revoked. The device reveals the secret of our
  commitment n only when n is the next to
  revoke (or already revealed: channeld re-sends a revocation after a reconnect) and commitment
  n + 1 has been validated; and it never signs a commitment of ours numbered at or below the
  highest it revealed. The number is read off the transaction's obscured locktime and sequence,
  not taken from the request. A device with no record of the channel's commitments (a channel
  armed from the node's own data after the store was lost) reveals only commitment 0 until it has
  validated a later commitment.
- **Channels from a device that validated nothing**: every channel in a store older than version
  6 (the version the first validating device wrote) predates validation. The device does not know
  such a channel's state before it, and does not take the host's word for it: it signs no
  commitment step for the channel, neither side's commitment, no revocation (not even of
  commitment 0) and no close, so the channel moves no more. Its peer closes it, and the device
  signs the spends of what that close pays this node (the "Withdrawals" rule below). The mark is
  kept in the store and never cleared. The native signer logs each such channel when it loads its
  store; the WASM build reports them (`predatingChannels()`, and the SDK's `predatingChannels()`
  and `onPredating`) so the wallet can tell the user the channel is not carried over.
- **Sweeps, penalties and HTLC transactions**: they pay only the node's own outputs, and a sweep
  of a channel's commitment output pays it in the channel's asset (the one the device recorded
  from the channel's commitments; for a channel it never validated a commitment of, the one the
  request names). These are signed `SIGHASH_SINGLE|ANYONECANPAY` (a watchtower attaches its own
  fee input), which commits to the swept input and output 0 only: whatever the input carries
  beyond output 0, a host could take with an output it adds. So the sweep of our own commitment's
  `to_local` once its delay is over, a penalty and an HTLC claim are each signed only when what the
  signature lets leave the node's outputs (that difference, or under `SIGHASH_ALL` the fee) is
  within the payment limit of the channel's asset, and so is our own HTLC transaction. A penalty
  and an HTLC claim race the peer, and their fee is held to the limit all the same: on Sequentia a
  fee goes to the block proposer, so an unbounded one would move the value rather than burn it.
  Each output is spent once, so the bound is per transaction, not against what payments left of
  the period. lightningd has the `to_local` sweep signed as soon as the commitment confirms and
  cannot start without it, and channeld has the watchtower's penalty set pre-signed at every
  commitment step: a device whose limit is below such a fee refuses it, and the node, or the
  channel at that step, stops until the limit is raised. A limit set for a day's spending is far
  above such a fee at ordinary feerates.
- **Withdrawals** (every spend of the node's wallet: `withdraw`, `signpsbt`, a channel funding, an
  anchor fee bump): every output but the fee pays one of the device's own wallet scripts (P2WPKH or
  BIP-86 P2TR of its wallet keys at indices below 5,000), unblinded, or is the funding output of a
  channel this side is opening. A spend to any other address is refused until the device has a way
  for its user to approve an address on it: the host's word is not that. A funding output counts
  only at the outpoint `setup_channel` named for a channel this side opened, paying exactly that
  channel's 2-of-2 (the device's funding key for it and the peer's), unblinded, its whole funding
  amount in the asset of its commitments, and only once the device holds a commitment of ours for
  it that the peer signed (openingd validates commitment 0 before the funding is signed), so the
  coins can always come back by a unilateral close. The txid is the one the unsigned transaction
  gives, so a funding from a P2SH-wrapped input, whose txid its scriptSig changes, is refused.
  What leaves the device is the fee (on Sequentia the explicit fee outputs, which the signature
  commits to with every other output; on Bitcoin what the inputs the device signs carry beyond the
  outputs) and what the channel's first commitments give the peer (a `push_msat`). For a
  withdrawal it counts against what the payment limit has left for the period, as a payment does,
  and is charged once signed: wallet coins come back to the wallet, so a bound per transaction
  would let a host spend the wallet on fees through a chain of transfers to itself. An anchor fee
  bump spends its anchor once, so its fee is held to the limit itself. A spend that breaks the
  rule is returned unsigned: the node cannot finalize it (`withdraw` and `sendpsbt` fail with "not
  finalizeable"), sends nothing and keeps running, and the device logs why (native: its log; WASM:
  `lastReject` and the SDK's `onReject`). This covers what a channel close paid the node: the
  output a peer's commitment pays it, which the wallet holds with its channel noted and the device
  signs with that channel's payment key, and what a mutual close this device signed pays it (the
  device keeps the txids of the closes it signs).
- **Payments** (`src/payments.rs`): `pay` and `keysend` ask the device to approve each payment
  (`PREAPPROVE_INVOICE`, `PREAPPROVE_KEYSEND`) before offering an HTLC. The device approves the
  payment hash when the amount, with a routing-fee allowance (half a percent, at least 5,000
  msat), fits in what the payment limit leaves for the period. An invoice names the asset it is
  paid in (its `a` field on a Sequentia network, where an invoice without one is declined;
  bitcoin on a Bitcoin network), and the amount must fit in that asset's limit. A keysend
  request names no asset, so its amount must fit for every asset the device has channels in.
  A commitment, ours or the
  peer's, that lists for the first time an HTLC this node offers is signed only when that HTLC's
  payment hash was approved, and its amount is charged to the channel asset; that holds for an
  HTLC trimmed as dust too, which the request lists although it has no output. A commitment that
  would take the asset over its limit is refused. A payment sent without approval (`sendpay`, `sendonion` or
  `xpay` on their own) is therefore refused at the commitment: channeld stops, lightningd fails
  the HTLC back, and the channel is idle until the peer reconnects. Call `preapproveinvoice` or
  `preapprovekeysend` first.

The payment limit is an amount of each asset, in its own atoms, over a sliding period: by default
10,000,000 atoms of each asset (Bitcoin included) a day: a default for a day's spending, which a
channel can hold more than. What withdrawals let leave (their fees) counts against it too. Native: `SEQLN_SIGNER_PAY_LIMIT` (atoms, or `none`), `SEQLN_SIGNER_PAY_LIMITS`
(`<asset>=<atoms|none>,...`, each asset `btc` or a display-order asset id) and
`SEQLN_SIGNER_PAY_PERIOD` (seconds); the signer refuses to start on a malformed value. WASM:
`setPaymentLimit(asset, atoms)` and `setPaymentPeriod(seconds)`, or the SDK's `paymentLimits`
option. An HTLC is charged when it is first committed, so an attempt that then fails still counts
until the period has passed. A channel the device tracked before it kept payment records takes
its first commitment as the baseline, whatever HTLCs it carries, and so does the first commitment
the device sees on each side of a channel.

Not checked: whether an HTLC paid to this side was settled. The device never sees a preimage, so
a commitment that drops an HTLC the peer offered us, without crediting it, looks to it like a
failed payment. And the device does not protect a user from a host that also runs the channel's
peer: such a host can broadcast a commitment the device signed for the watchtower's preempt slot
before the device revoked it, which the peer then takes whole with the revocation secret.

The channel store (each channel's parameters, dust limits and reserves, revocation counters,
recorded balance, whether the peer has reached its reserve, the unrevoked commitments it validated,
its payment tracking and whether it predates validation, the
approvals and charges against the payment limits, and the txids of the mutual closes the device
signed) carries no secret and is authenticated by a MAC keyed from the seed. The native signer keeps it in
`seqln-signer-channels` in its working directory (or the path in `SEQLN_SIGNER_STORE`): it
loads the file at start and rewrites it durably (temporary file, sync, rename) after every
request that changed it, before the reply leaves. If the file cannot be written it refuses the
request, and every request after it until a write succeeds, so channeld asking again for what
was refused gets no answer the store does not record. It never runs without the store: a store
it cannot read, whose MAC fails, or that a newer signer wrote stops it at start, and so does a
missing one once the device has made one (it leaves `seqln-signer-store-made` beside
`hsm_secret` when it does). A signer started without its store would take the host's word for
every channel: a host could replay a channel's old commitments, all signed by the peer, and have
it validate and sign for broadcast one it revoked long ago. A device that has never made a store
creates it, empty, at its first start. Restore a lost store from a backup; removing the marker
starts the device afresh, with every existing channel's revocations forgotten. The WASM build
hands the same blob to the wallet's `channelStore` to keep.

A channel armed from the node's own data after the store was lost has no balance and no validated
commitments: it can neither close mutually nor be closed unilaterally by the device until its
next commitment step (a payment either way, or an `update_fee`, which the opener sends when its
feerate changes). A channel that predates validation never gets that step: its peer closes it.
A channel already closing (`CLOSINGD_COMPLETE` or `AWAITING_UNILATERAL`) when the device has no
record of its closing transaction stays closing: lightningd signs that transaction again at every
start, the device refuses it, and lightningd logs the refusal and sends nothing. The channel
closes when the peer's transaction confirms, and onchaind resolves it from the chain as it does
any channel.

## Layout

| Path | What |
| --- | --- |
| `src/kernel.rs` | I/O-free crypto kernel (BIP39/32/86, HKDF, shachain, ECDH, tx sighash/sign). WASM-ready. |
| `src/wire.rs` | Big-endian hsmd wire codec for the subset. |
| `src/frame.rs` | Little-endian signer-split transport framing (`hsmd/signer_frame.h`). |
| `src/noise.rs` | BOLT-8 Noise_XK transport state machine (no sockets). |
| `src/policy.rs` | Enforce-mode commitment validation. |
| `src/payments.rs` | Payment approval, the per-asset payment limits and their accounting, BOLT 11 decoding. |
| `src/dispatch.rs` | Request -> reply dispatch; channel-state tracking for the policy. |
| `src/hsm_secret.rs` | On-disk mnemonic `hsm_secret` parsing. |
| `src/bin/seqln-signer.rs` | The device signer binary (fd / `--listen` / `--connect` modes, `--genkey`). |
| `src/bin/conformance.rs` | Byte-exact conformance harness vs the libhsmd oracle. |
| `src/bin/shadow.rs` | Live shadow comparator + corpus capture. |
| `src/bin/ecdh_latency.rs` | ECDH hot-path latency probe (in-process vs transport round-trip). |
| `src/bin/emit_elements_vector.rs` | Emits an Elements v2 PSET `sign_withdrawal` vector for the conformance harness's `SEQLN_WITHDRAWAL_VECTOR` mode. |
| `tests/tamper.rs` | Enforce-mode theft-rejection test (skips without a captured corpus). |
| `tests/chstore.rs` | Channel-store persistence contract (`export_channels`/`import_channels` round-trip, MAC refusal, merge semantics). The store carries each channel's opener, upfront shutdown scripts (and the local one's wallet index), dust limits and reserves, revocation counters, recorded balance and unrevoked validated commitments, and imports an older store without them. |
| `tests/native_store.rs` | The native binary keeps its store across a restart: a new process refuses a revoked commitment and a close below the recorded balance, which a signer with an empty store signs (the commitment once it has validated it itself). It refuses to start with its store missing, failing its MAC or written by a newer signer, and starts again once the store is back. With the store unwritable it refuses every request, a re-sent revocation included, until a write succeeds. |
| `wasm/` | `wasm-bindgen` build of the same library for browsers/Node, plus SDK, relay, tests, demo page. |
| `wasm/test/version_floor.mjs` | The WASM build refuses an INIT below version 6, first or later, and returns no secret with a commitment point. |
| `wasm/test/enforce.mjs` | WASM enforce-mode proof: corpus replay byte-exact, tampered commitment refused. |
| `wasm/test/ws_device.mjs` | The browser-shaped device path over a real WebSocket, driven by the wallet SDK. |
| `wasm/test/device_serve.mjs` | The WASM build as a drop-in for `seqln-signer --connect` (same files and environment), so the node's keyless tests run on it with `SEQLN_DEVICE=wasm`. |
| `wasm/test/reconnect_stress.sh` | Isolated regtest harness: N device disconnect/reconnect cycles and a relay restart without wedging the hosted node. |

## Build and test

Standalone crate (kept out of the seqln root workspace):

```bash
cd contrib/seqln-signer
cargo build --release           # target/release/seqln-signer, conformance, shadow, ecdh_latency
cargo test                      # unit tests + tamper.rs (skips if no captured corpus present)
```

Conformance against the reference signer (build the node first so
`lightningd/lightning_signerd` exists; see the top-level README):

```bash
./target/release/conformance /path/to/seqln/lightningd/lightning_signerd \
                             ./target/release/seqln-signer
```

## Running the split

Local (signer on the same machine, trusted socketpair; useful to validate the seam):

```bash
SEQLN_SIGNERD=/path/to/seqln-signer \
lightningd --network=sequentia-testnet \
  --subdaemon=hsmd:/path/to/seqln/lightningd/lightning_hsmd_proxy ...
```

Remote device (keys on the device, node on the host). Generate and pin transport static keys
out-of-band first (`seqln-signer --genkey` prints a keypair):

- Device listens, host connects out:
  device `seqln-signer --listen <host:port>` with `SEQLN_SIGNER_PRIVKEY[_FILE]` +
  `SEQLN_HOST_PEER_PUBKEY`; host proxy with `SEQLN_SIGNER_ADDR=<host:port>` +
  `SEQLN_HOST_PRIVKEY[_FILE]` + `SEQLN_SIGNER_PEER_PUBKEY`.
- Device connects out (browser topology; also `seqln-signer --connect` for native testing):
  host proxy with `SEQLN_SIGNER_LISTEN=<bind:port>` (reconnect-tolerant), same key pinning.

Other environment knobs: `SEQLN_SIGNER_POLICY=enforce|permissive` (default enforce), the payment
limits `SEQLN_SIGNER_PAY_LIMIT`, `SEQLN_SIGNER_PAY_LIMITS` and `SEQLN_SIGNER_PAY_PERIOD` (see
"Scope"),
`SEQLN_SIGNER_TRACE` (per-request trace logging), `SEQLN_SIGNER_STORE` (the channel store's path,
default `seqln-signer-channels` in the working directory), `SEQLN_SIGNER_CONNECT` (the env form of
`--connect`), and `SEQLN_SIGNER_NETWORK=bitcoin|elements`, which selects the sighash family when one
binary serves both a Bitcoin and a Sequentia node (unset: sniffed from the request's witness UTXO,
defaulting to Elements; `src/wire.rs`). On the proxy side: `SEQLN_SIGNER_HS_TIMEOUT_MS` (Noise
handshake timeout, `hsmd/signer_noise.c`), `SEQLN_SIGNER_OP_TIMEOUT_MS` (per-request timeout,
default 120000) and `SEQLN_SIGNER_TCP_{USER_TIMEOUT_MS,KEEPIDLE_S,KEEPINTVL_S,KEEPCNT}` (TCP
keepalive; `hsmd/hsmd_proxy.c`). `SEQLN_HSM_SECRET` is read only by the conformance harness.

## Browser / WASM

`wasm/` wraps the same library with `wasm-bindgen`: `Signer` (feed one framed request, get the
reply, byte-identical to native) and `NoiseSession` (the Noise_XK initiator; the page injects
entropy from `crypto.getRandomValues`). Because a browser cannot open TCP,
`wasm/relay/seqln-ws-relay.mjs` is a dumb, keyless WebSocket-to-TCP byte pipe in front of the
proxy's listen socket; Noise runs end-to-end browser-to-proxy, so the relay never sees plaintext
and holds no key. `wasm/sdk/seqln-signer-sdk.js` is the wallet-facing class (mnemonic in, live
non-custodial signer out; no npm dependencies), and `wasm/web/` is a minimal demo page.

```bash
cd contrib/seqln-signer/wasm
wasm-pack build --target nodejs --out-dir pkg        # for the node test scripts
wasm-pack build --target web    --out-dir web/pkg    # for the SDK / demo page
node test/conformance.mjs <corpus.bin> <hsm_secret> <oracle_replies.bin>
node test/device_link.mjs <host:port> <hsm_secret> <host_pub_hex> <device_priv_hex> [--enforce]
```

## Status

Testnet software, like everything Sequentia. The split, the Noise transport, enforce-mode theft
rejection, and browser-driven signing have all been exercised end-to-end against a hosted SeqLN
node, but the code is young: treat it as a working proof of the architecture, not a hardened
production signer (see the deferred validations under "Scope").
