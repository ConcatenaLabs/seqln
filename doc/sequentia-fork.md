# SeqLN: Core Lightning for Sequentia

This fork adds Sequentia (an Elements-family, Bitcoin-anchored sidechain) as a network to Core
Lightning, using the same binary that runs Bitcoin. Full design spec:
`SequentiaByClaude/doc/sequentia/seqln-core-lightning-fork-spec.md`. This file records the concrete
decisions and the verified facts the code depends on.

## Networks (bitcoin/chainparams.c)

| network_name | onchain HRP | lightning HRP | bip70 (chain) | is_elements | anchor header |
| --- | --- | --- | --- | --- | --- |
| sequentia-testnet | tb | tsqt | test | yes | yes |
| sequentia (mainnet) | bc | sqt | sequentia | yes | yes |

- The onchain HRP is shared with Bitcoin (`tb`/`bc`) by design (Sequentia's shared-address invariant).
  The lightning HRP is the one distinct wire identifier, so invoices are `lntsqt...` / `lnsqt...`
  (regtest would be `lnsqrt...`). Rationale: an asset invoice on Sequentia carries the network HRP, so
  `lnseq` would misread as the SEQ token; `sqt`/`tsqt` read as "Sequentia network", asset in a TLV.
- `bip70_name` must equal the node's `getblockchaininfo.chain`. The live testnet returns `test`
  (colliding with Bitcoin testnet3's bip70 name); benign because network selection is by the unique
  `network_name` and the wire disambiguates by `chain_hash`.
- `genesis_blockhash` is stored in internal (reversed-display) byte order, matching the bitcoin
  entries. Testnet genesis display hash: `c2a0a99b4c307e8423b98140af1f539aa4e1feec25c62d655d91d8df51c7dfba`.
- `fee_asset_tag` = `0x01` + the policy asset id in display order (matches CLN's L-BTC convention;
  its constant is `0x01` + the well-known display id). Testnet policy asset (dumpassetlabels
  "bitcoin"): `c8eccacf0953e1931cd31e434d8319101cc36e6c38b0e2104d8687552fae3e40`. See `amount_asset_is_main`.
- Mainnet genesis/fee_asset are TODO placeholders until launch/re-genesis.

## Anchored block header (bitcoin/block.c, verified)

Sequentia inserts a Bitcoin anchor into the block header. The full header serialization is:

```
version(4) prev(32) merkle(32) time(4) block_height(4) anchor_height(4) anchor_hash(32) CProof(challenge+solution)
```

No bits/nonce (signed blocks, blockheightinheader). The block hash is double-SHA256 over
`version .. challenge` (anchor fields included, solution excluded, exactly as CLN already handles the
Elements legacy proof), reversed for display.

The parser (`bitcoin_block_from_hex`) pulls and hashes `anchor_height` (le32) + `anchor_hash` (32
bytes) between `block_height` and the proof, gated on `chainparams->has_anchor_header`.

Verified against live testnet block 1000 (`tests/sequentia/verify_block_parse.py`): height 1000,
anchor_height 140948, anchor_hash `00000000008848afcf634aab4ea4c3d83a7b39c1006413cce51320011852c1fc`,
148 bytes hashed, recomputed block hash `5af2c678a64524c9864e39d0c0cd729fea475feb2e6d322df1017560887bd2ce`.

## Status

**Phase 0 CLOSED** — the anchored-header parser is proven end-to-end against the live testnet.

Done (network + parser):
- `chainparams.h`: `has_anchor_header` field.
- `chainparams.c`: sequentia-testnet (accurate) + sequentia mainnet (placeholder) entries + testnet
  fee-asset constant.
- `block.c`: anchored-header parse.

Live-node proof (the exit criterion — "computed block hashes match"):
- `lightningd --network=sequentia-testnet` was pointed (bcli) at a live node via an SSH-tunnelled
  RPC. It connected, fetched real block 18119, ran it through `bitcoin_block_from_hex`, and computed
  `d08622c1…514b77` — an EXACT match to the node's `getblockhash 18119`. End-to-end through the real
  daemon + bcli path, not a mirror.
- Breadth: `tests/sequentia/validate_live_blocks.py` reimplements the parse byte-for-byte and checks
  21 blocks spanning the whole chain (height 1 → tip, anchor heights 140850 → 142700, 35-byte
  challenge). PASS=21, FAIL=0. Run with `ELEMCLI`/`SEQ_RPC_{HOST,PORT,USER,PASS}` env pointing at a
  node (local or tunnelled).
- Build: needs the full subdaemon set next to `lightningd/` — `has_all_subdaemons()` (lightningd.c)
  selects in-tree mode only when `lightning_{channeld,closingd,connectd,gossipd,gossip_compactd,
  hsmd,onchaind,openingd}` are all built; otherwise it looks under `libexec` and aborts. In-tree
  mode also auto-loads `bcli` from `../plugins`, so do NOT also pass `--plugin=.../bcli` (duplicate
  registration error). Build recipe: the two Phase-0 targets plus
  `make lightningd/lightning_{channeld,closingd,connectd,dualopend,gossipd,gossip_compactd,hsmd,
  onchaind,openingd,websocketd}` (all pure C).

Known environmental caveat (NOT a Sequentia issue): in this sandbox `lightning_connectd` exits
(goes zombie ~4s in) during startup, so lightningd hangs in `connectd_activate` before "Server
started" and never runs the main block-polling loop — it adds only the single initial block. This
is connectd's peer-networking subdaemon (sockets), independent of the anchored-header code, and is
reproducible on `--network=regtest` too. A normal (non-sandboxed / installed) host does not hit it.
The parser proof above does not depend on full multi-block catch-up.

Next:
- Re-run the full multi-block catch-up on a non-sandboxed host to confirm lightningd walks the whole
  chain (expected to just work once connectd survives).
- Test-harness duplicates (`contrib/pyln-testing/.../{utils,fixtures}.py`, `tests/utils.py`,
  `devtools/gossipwith.c`) need Sequentia entries before the pytest suite runs.
- A proper `bitcoin/test/run-*.c` unit test asserting the block-1000 hash (the Python files are the
  interim regression + live-breadth checks).
- sequentia-regtest: needs a custom-params node (con_bitcoin_anchor + a local bitcoind mainchain) to
  exercise the anchor path locally. Confirm build against Elements Core 23.3.3 (CI pins 23.2.1).
- Then Phase 1 (policy-asset channels) per the spec.

## Phase 1 — policy-asset (Sequence-token) channels + anchor-aware safety layer

Phase 1 is the maintained CLN-on-Elements channel path pointed at Sequentia: the channel asset IS the
policy asset (`fee_asset_tag`, already configured), so the per-channel `channel_asset` threading is
deferred to Phase 3. The novel, load-bearing Phase-1 delta is the section-6 anchor-aware safety layer.

Grounding (live testnet RPC shapes, verified):
- `getblockheader` returns `poscertified` (bool), `poscountersigs`/`posquorum`, `anchorheight`,
  `anchorhash`. The chain tip is certified essentially immediately (committee signs at the tip).
- `getanchorstatus` returns `validateanchor`, `tipheight`, `anchorheight` (the tip's Bitcoin anchor,
  ~= the node's Bitcoin-tip view), `anchorstatus`. Anchor height is monotonic across Sequentia height.
- Measured Sequentia block time ~58s (16000-block sample): 1 day ~= 1496 blocks, 3h ~= 187, 2 weeks
  ~= 20938.

Implemented + verified this pass:
- **6.1 certified-frontier confirmations** (`plugins/bcli.c` `getchaininfo`, guarded by
  `chainparams->has_anchor_header`). bcli reports the *certified frontier* — the highest
  `poscertified` height at or below the node tip — as `blockcount`/`headercount`, so every
  `minimum_depth`/confirmation check in CLN is denominated in certified depth, not raw Sequentia
  tip-distance. A certified block is only displaced by a Bitcoin-anchor reorg (tail truncation), which
  CLN's normal reorg handling absorbs when the frontier retreats. Fast path is one `getblockheader`
  (tip is normally certified); it walks down bounded by `SEQUENTIA_CERT_LOOKBACK`=144 and fails open
  with a loud warning only if the committee has stalled that long. Verified: regression test
  `tests/sequentia/verify_certified_frontier.py` (healthy-chain no-clamp; walk mechanics; synthetic
  uncertified-suffix clamp — 3/3 PASS on live data) and end-to-end in the real daemon (bcli returned
  the certified tip, lightningd anchored to it, no clamp warning / JSON error).
- **6.2 minimum_depth = 1** and **6.3 wall-clock timelocks** (`lightningd/options.c`, guarded by
  `has_anchor_header`, overriding the testnet/mainnet preset for any Sequentia network): a certified
  funding block is final, so `funding_confirms = 1`; timelocks are sized in wall-clock at the measured
  ~58s cadence and each is >= its Bitcoin-mainnet wall-clock equivalent — `locktime_blocks`
  (to_self_delay) 1440 (~1 day), `cltv_expiry_delta` 270 (~4.3h, ample for same-chain fast finality),
  `cltv_final` 180 (~2.9h), `max_htlc_cltv` 20160 (~2 weeks; otherwise HTLCs would cap at ~32h).

- **6.2 two-stage SCID / anchor-burial announcement gate** (implemented). A certified block can still
  fall to tail truncation until its Bitcoin anchor is buried, and a `channel_announcement` SCID
  (height:txindex:output) must never be invalidated. So a Sequentia channel is usable at certified
  depth-1 but its SCID is announced only once the funding block's anchor is buried by
  `SEQUENTIA_ANCHOR_BURY_DEPTH` (=2, spec's "k small, 1-2") Bitcoin-anchor blocks. Implementation
  (simpler and self-contained — supersedes the "extend the backend + cache on the channel + DB
  migration" sketch, because the anchor already rides in the block CLN parses): the parsed
  `anchor_height` is retained in `struct bitcoin_block_hdr` (`bitcoin/block.c`), which chaintopology
  already stores per block; `topo_anchor_buried()` (`lightningd/chaintopology.c`) answers "is the
  funding block buried by >= k anchor blocks" with a *bounded* walk back from the tip — since
  `anchor_height` is monotonic, it stops as soon as the anchor drops by k (an O(k·BTC/Seq-blocktime)
  window, not O(tip − funding)), so it stays cheap even for long-announced channels; `has_announce_depth()`
  (`lightningd/channel_gossip.c`) gains a `has_anchor_header` branch that requires it. No backend-protocol
  change, no DB migration (the funding anchor is re-derived from the in-memory chain; ancient funding
  below the scan root is treated as buried). Verified: `tests/sequentia/verify_anchor_burial.py`
  mirrors the bounded walk and checks it against a brute-force oracle over real anchor heights (all
  heights, k=1..3) plus the tip / ancient / above-tip / k-boundary cases.
- **6.4 fee asset for penalty/claim txs** (inherited, not deferred). In Phase 1 the channel asset is
  the policy asset, so the node already holds a committee-accepted fee asset for justice/HTLC-claim
  txs. Explicit fee-in-channel-asset generalization is Phase 3 (`channel_asset`).

Exit criterion (open/route/close a Sequence-token channel between two SeqLN nodes, plus a force-close
and a penalty case across an induced tail-truncation reorg): requires a running two-node testnet,
which needs a non-sandboxed host (the connectd startup caveat above blocks it on this laptop). The
safety-layer code above is unit/logic-verified and builds green; the two-node runtime is the open
item for a normal host.

## Decisions still provisional (worth Alberto's sign-off before Phase 3)

- Lightning HRPs (`sqt`/`tsqt`/`sqrt`).
- Asset invoice encoding: standard BOLT11 for the Sequence token and BTC; issued-asset invoices add
  `asset_id` (32-byte, internal order) + `asset_amount` (integer atoms) tagged fields and omit the HRP
  amount (BOLT11's msat/multiplier encoding is BTC-specific). Field type numbers are SeqLN-local until
  standardized.
