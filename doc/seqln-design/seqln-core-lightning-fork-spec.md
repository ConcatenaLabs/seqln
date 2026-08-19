# SeqLN: a Core Lightning fork for Sequentia (and Bitcoin) — design spec

A plan for a Core Lightning (CLN) fork that runs Lightning on Sequentia, using the same binary that runs
Lightning on Bitcoin (testnet4 now, mainnet later). Grounded in the codebase (CLN master `066056d915`,
Elements support CI-tested against Elements Core 23.2.1; Sequentia = Elements 23.3.3) and in the safety
analysis already done in `seqdex/docs/seqdex-lightning-feasibility.md`. This document supersedes that memo's one wrong
claim that CLN "dropped Liquid entirely": CLN's Elements support is in-tree and maintained.

Path convention in this document: `src/...` paths are in the **Sequentia node**
repository ([`Sequentia`](https://github.com/GracedEternalKingCabbageMan/Sequentia)),
which has no `src/` of its own to confuse them with here; everything else is a path
in this repository.

## 0. Goal, and why CLN is the right base

Goal: one Lightning implementation where `--network=bitcoin|testnet4` behaves exactly like upstream CLN, and
`--network=sequentia|sequentia-testnet|sequentia-regtest` runs Lightning on Sequentia, including channels
denominated in an issued Sequentia asset (a stablecoin, GOLD, etc.), not only the Sequence token.

CLN is the only Lightning implementation with Elements transaction support already in mainline and under CI
(a dedicated `TEST_NETWORK=liquid-regtest` pytest matrix job against Elements Core 23.2.1). It already
handles the Elements wire format, the explicit fee output, PSET (PSBT v2 + `WALLY_PSBT_INIT_PSET`), and
Elements sighashes; libwally-core's Elements support is compiled by default and is chain-agnostic (asset ids
and genesis are runtime parameters). So the fork starts from a working Elements base and adds two things
nobody has shipped anywhere: (1) a Sequentia network definition, and (2) channels denominated in an
arbitrary issued asset. The second has no prior art in any Lightning codebase; Blockstream's 2019 Liquid work
shipped L-BTC-only channels and the promised asset channels were never even publicly specified.

Why Sequentia is structurally the right chain for asset channels (it is easier here than anywhere else):
- Assets are native to consensus. An asset channel is just a channel whose funding and HTLC outputs are
  Elements outputs of asset X. The entire Taproot-Assets overlay apparatus (overlay commitments, custom
  records, sat-anchored HTLCs, litd glue) exists only because Bitcoin cannot see assets; on Sequentia it
  disappears. The multi-year-unsolved BOLT question "what does an asset commitment tx look like" is answered
  by Elements itself.
- Any-asset fees remove Liquid's two-asset problem. On Liquid an L-USDT channel still needs L-BTC to pay the
  on-chain fee output. On Sequentia the funding/commitment/close fee output can be paid in the channel's own
  asset, so an asset channel is self-contained.
- Transparent-by-default matches CLN exactly. CLN on Elements generates only unblinded addresses and never
  blinds channel outputs; it refuses P2TR/confidential on Elements today. Sequentia is transparent-by-default
  with confidentiality opt-in, so there is no confidential-transaction work to do in channels at all.

Non-goals (v1): confidential (blinded) amounts inside channels; taproot channels on Sequentia; splicing on
Sequentia; a public asset-routing gossip graph. Rationale in section 8.

## 1. Naming and repo

- Working name: SeqLN. Fork of `github.com/ElementsProject/lightning`, kept rebaseable onto upstream (all
  Sequentia changes isolated behind chainparams flags and a small number of `is_sequentia` guards, mirroring
  the existing `is_elements` pattern so upstream merges stay clean). Repo `GracedEternalKingCabbageMan/seqln`
  (public, per the everything-public rule).
- The same binary serves Bitcoin and Sequentia; network is selected per daemon instance at startup
  (`--network`), exactly as upstream. There is no compile-time Elements flag to toggle.

## 2. Network definitions (chainparams)

CLN's network table lives in one file, `bitcoin/chainparams.c` (a static `networks[]` array; struct in
`bitcoin/chainparams.h`), with test-harness duplicates in `contrib/pyln-testing/pyln/testing/{utils,fixtures}.py`,
`tests/utils.py`, and `devtools/gossipwith.c`. Add three Sequentia entries. Each is roughly a 30-line struct
literal.

Fields per Sequentia entry, with the Sequentia-specific values:
- `network_name`: `sequentia` / `sequentia-testnet` / `sequentia-regtest`.
- `bip70_name`: MUST equal the Sequentia node's `getblockchaininfo.chain` string (CLN's only startup network
  check is `bip70_name` vs that RPC field; a mismatch is a fatal "Wrong network!"). Confirm the exact strings
  from `src/chainparams.cpp` before writing them.
- `onchain_hrp`: `bc` (mainnet) / `tb` (testnet + regtest). Sequentia deliberately shares Bitcoin's bech32
  HRPs (the shared-address invariant), so this is not a fresh prefix. Sequentia's blech32 HRPs (`sqb`/`tsqb`)
  are irrelevant to CLN, which has no blech32 and never blinds.
- `lightning_hrp`: a fresh BOLT11 prefix, since it must be distinct on the wire and cannot collide with
  `bc`/`tb`. Proposal: `seq` (mainnet) / `tseq` (testnet) / `sqrt` (regtest), giving invoice prefixes
  `lnseq` / `lntseq` / `lnsqrt`. The signet precedent (onchain `tb`, lightning `tbs`) shows onchain and
  lightning HRPs legitimately differ. Register these in a short table in the spec repo so wallets agree.
- `genesis_blockhash` (= the wire `chain_hash`): the Sequentia genesis hash. Pick a byte-order convention and
  be self-consistent; CLN only ever compares chain_hash CLN-to-CLN, so the choice is free as long as every
  SeqLN node agrees. (Note the existing liquid entry stores the display-order hash while bitcoin entries store
  internal order; harmless because nothing checks it against the chain. We standardize on internal order.)
- `is_elements`: true.
- `fee_asset_tag`: 33 bytes = `0x01` explicit prefix followed by the policy (Sequence-token) asset id in
  internal (reversed-display) byte order. This and the L-BTC constant are the only hardcoded asset ids in the
  CLN tree; everything else routes through `chainparams->fee_asset_tag` and `amount_asset_is_main()`. See
  section 4 for why this becomes a per-node option rather than a pure per-network constant.
- `p2pkh_version` / `p2sh_version`, `bip32_key_version`, `testnet` bool, ports (`rpc_port`, `ln_port`),
  `cli` = `sequentia-cli`, `cli_args` = `-chain=<name>`, `dust_limit` 546, `max_funding`, `max_supply`,
  `when_lightning_became_cool`: fill from `src/chainparams.cpp`.

Implication: adding the networks is genuinely small. The hard parts are the block-header parser (section 3),
the asset-channel work (section 5), and the anchor-aware safety layer (section 6).

## 3. Consensus-format delta: the anchored block header

The one non-cosmetic wire difference between a Sequentia block and a Liquid block is the header. Sequentia
inserts, after `block_height` and before the dynafed/legacy-proof fields (in both serialization branches,
committed under SER_GETHASH), an `m_anchor_height` (u32 LE) and `m_anchor_hash` (32 bytes) — 36 extra bytes
(`src/primitives/block.h`; `g_con_bitcoin_anchor` and `g_con_blockheightinheader` are true on Sequentia
nets). Sequentia forces dynafed OFF and uses the legacy signed-blocks `CProof`.

CLN work:
- `bitcoin/block.c` `bitcoin_block_from_hex()` must, gated on a new chainparams bool (e.g. `has_anchor_header`),
  read and hash those 36 bytes at the correct position, so the block hash CLN computes matches consensus.
  CLN already has the legacy signed-blocks path (challenge hashed, solution excluded); confirm the Sequentia
  PoS proof still serializes as the two var-length fields that path expects.
- CLN only needs to parse blocks well enough to (a) compute the correct block hash and (b) find funding /
  spend / close transactions and their confirmation heights. It does not validate PoS or anchoring itself;
  it delegates that to the Sequentia node via the backend plugin (section 6). So the header patch is small and
  self-contained.

This is the only place CLN's block parser needs Sequentia-specific code. Everything downstream (tx parsing,
PSET, sighash) is standard Elements and already handled.

## 4. The policy-asset assumption, and any-asset fees

CLN's deepest Elements assumption is one policy asset per network: `amount_asset_is_main()` memcmps an
output's asset against `chainparams->fee_asset_tag`, "sat" means one unit of that asset, and every wallet /
watch / close path skips outputs of any other asset (they are invisible and unspendable). This is why CLN on
Liquid is L-BTC-only.

Two distinct needs, two distinct changes:

1. The channel's asset (section 5). To hold GOLD in a channel, the node's notion of "the asset this channel
   is denominated in" must become GOLD, not the policy asset. The cheap, correct move is to make the
   denominating asset a per-node (and ultimately per-channel) value rather than the hardcoded per-network
   `fee_asset_tag`. Concretely: keep `fee_asset_tag` as the chain's policy asset for genuinely policy-level
   things, but thread a `channel_asset` (33-byte asset id) through the channel state so commitment/HTLC/close
   math denominates in it. `amount_asset_is_main()` becomes "is this output in the current context's asset".

2. On-chain fees on Sequentia (funding, commitment, close). Sequentia lets the fee output be any accepted
   asset. The simplest self-consistent rule, and the one that removes Liquid's two-asset problem: pay the
   on-chain fee output in the channel's own asset. Then an asset channel needs only that asset to open, run,
   and close. `elements_tx_add_fee_output()` already adds an explicit fee output; it must be generalized to
   emit the fee in `channel_asset` and price it via the Sequentia fee/exchange-rate machinery (the node's
   fee-asset value logic, already a Sequentia concept). Paying the fee in a third asset (neither channel
   asset nor policy asset) is possible but is not worth the coin-selection complexity in v1; defer.

Commitment-fee accounting (BOLT 3's implicit-fee subtraction from the funder's output) must be denominated in
`channel_asset` consistently on both sides so both peers reconstruct byte-identical commitment transactions.
This is the core correctness constraint of the asset-channel work.

## 5. Asset channels (the novel core)

Design consensus from the prior art (Taproot Assets, RGB, the dead multi-asset BOLT PR #72, ZmnSCPxj's
free-option argument): one asset per channel; BTC/policy-asset as the routing backbone; cross-asset only at
explicit rate-locked boundaries. SeqLN adopts all of it, simplified by native Elements assets.

### 5.1 Channel open

- Add an `asset_id` TLV to `open_channel2` / `accept_channel2` (dual-funding v2 is the modern open flow; v1
  `open_channel` can carry the same TLV if needed). The opener declares the channel asset; the accepter MUST
  fail the open if it does not support that asset or the TLV is absent on a Sequentia channel. A Bitcoin
  channel has no such TLV (absence = the policy asset, preserving upstream behavior).
- The funding output is an Elements output of `asset_id`. Commitment transactions, HTLC outputs, and
  to_local/to_remote outputs are all outputs of `asset_id`; the fee output is separate and explicit
  (section 4). No overlay, no custom records, no sat-anchoring: the asset is a first-class output value.
- Reject mixing: all channel value is one asset. Dust/trim thresholds are computed in the channel asset;
  Elements keeps the 546-unit dust floor.

### 5.2 Commitments and HTLCs

- Commitment format v1: `option_static_remotekey` (what CLN uses on Elements today; anchors and taproot are
  off on Elements, cdecker's draft PR #8097 is the future upgrade path). HTLC hashlock+CLTV, revocation /
  penalty, and `to_self_delay` via CSV are plain Bitcoin Script that Elements is a strict superset of, so the
  script builders are chain-agnostic; only the value denomination changes.
- HTLC amount math, dust-trim, and the funder's implicit fee are denominated in the channel asset. This is the
  bulk of the diff: audit every place amounts are summed/compared in `channeld`, `onchaind`, the commitment
  builders, and the closing paths to ensure they use `channel_asset`, not implicit policy-asset msat.
- Amounts: Elements assets carry no decimals in consensus (integer atoms). Follow the Taproot Assets lesson
  and keep BOLT11/onion amount fields structurally intact; carry the asset id and integer amount, and let the
  wallet layer apply the registry's display precision. Internally denominate in the asset's atoms (no msat
  sub-unit for assets unless a future need arises).

### 5.3 Invoices and routing

- BOLT11: keep it structurally intact (do not fork the amount encoding). Use the Sequentia `lightning_hrp`
  prefix. For asset invoices, carry the asset id in a TLV/field and denominate the amount in that asset's
  atoms, following how Taproot Assets kept invoices amount-typed rather than extending BOLT11's core. Register
  the exact encoding in the SeqLN spec repo.
- Routing v1: require same-asset end-to-end paths. Gossip carries chain_hash already (BOLT 7); extend
  channel_announcement with the asset id (or run asset channels unannounced in v1, see 5.4). No cross-asset
  auto-routing.
- Cross-asset hops (later): only via a signed RFQ quote with a short absolute expiry (seconds, following
  tapd's 10-second minimum) and a maker-priced spread, carried in an onion TLV referencing the quote id.
  Never offer open-ended cross-asset forwarding: an unpriced cross-asset HTLC forwarder is writing a free
  American call option (the canonical reason multi-asset LN routing was declared dead, and the mechanism that
  drained early Boltz). A Sequentia-aware forwarding node can match the quote id in the onion directly, so
  the SCID-alias hack tapd needs is unnecessary here.

### 5.4 Announced vs unannounced

v1: asset channels are unannounced (unpublished), like Taproot Assets channels. Per-asset liquidity graphs
are thin for years; an edge/RFQ model fits reality and avoids specifying asset gossip prematurely. Policy-asset
(Sequence-token) and Bitcoin channels announce normally. A public asset-routing graph is a later,
separately-specified phase.

## 6. Anchor-aware safety layer (Sequentia-specific, load-bearing)

The safety analysis is settled in `seqdex/docs/seqdex-lightning-feasibility.md` and is a net upgrade over generic-sidechain
LN: a Sequentia reorg is always a tail truncation (anchor height is monotonic; the watcher disconnects a
contiguous suffix), so causal order is preserved across reorgs, the CSV clock resets on a disconnected
commitment (re-extending the defender's window, never shortening it), and no Sequentia-only reorg exists
(reverting certified history needs an actual Bitcoin reorg). The revoked-state penalty-evasion attack fails:
any Bitcoin reorg deep enough to orphan the justice tx necessarily orphans the revoked commitment too
(it is at a lower height), both fall to the mempool, CSV resets, and the defender re-broadcasts with a fresh
full window. Penalty enforcement is strictly stronger than on Bitcoin; watchtower logic is unchanged (re-derive
and re-broadcast after a Bitcoin-driven reorg).

What this means in CLN, concretely:

### 6.1 Backend plugin: confirmations denominated in Bitcoin-anchor depth

CLN's backend is a documented 5-method plugin interface (`getchaininfo`, `getrawblockbyheight`,
`estimatefees`, `sendrawtransaction`, `getutxout`); `plugins/bcli.c` is the stock implementation and is a
first-class replaceable seam (`--disable-plugin bcli`). Since the Sequentia node speaks Elements RPC, stock
bcli works for the basics once the chainparams entry exists.

The Sequentia-specific need is that "confirmed" must mean quorum-certified AND anchor-safe, never Sequentia
tip-distance. Provide a thin Sequentia backend plugin (a bcli variant, or a small companion plugin) that:
- Reports a funding/commitment/close tx as confirmed only when its block is quorum-certified (the shipped
  `getblockheader.poscertified` field) AND the block's Bitcoin anchor has >= k Bitcoin confirmations (via
  `getanchorstatus` plus bitcoind anchor-block depth). `minimum_depth` on Sequentia is then "certified and
  anchor-buried", not a raw block count.
- Surfaces anchor status so the node can detect a stalled or reorging Sequentia chain (a node that also
  watches Bitcoin gets a free liveness signal).

### 6.2 minimum_depth and the two-stage rule

- `minimum_depth = 1` is the Sequentia default and is well-founded: a quorum-certified funding block cannot be
  displaced except by a Bitcoin-anchor reorg. Do NOT use `option_zeroconf` (that is a trust model, not a
  finality claim). This mirrors PeerSwap's "2 confs on Liquid" precedent with a stronger consensus basis; CLN
  already defaults `funding_confirms` to 1 on testnet-class networks and exposes `--funding-confirms` plus
  per-open `mindepth`.
- Two-stage SCID rule: a channel is usable once its funding block is certified (depth 1), but
  `channel_announcement` (which pins the SCID = height:txindex:output and must not be invalidated by a reorg)
  is gated on the anchor being buried by k Bitcoin blocks (k small, 1-2). This is the single place
  Bitcoin-anchoring supremacy must be visible in the LN layer: a certified block can still fall to tail
  truncation until its anchor is buried, so announce only after that.

### 6.3 Timelocks in wall-clock, not copied block counts

Sequentia's block cadence differs from Bitcoin's, so `to_self_delay` and `cltv_expiry_delta` must be sized in
wall-clock and translated to Sequentia block counts (PeerSwap's precedent: CSV 1008 on Bitcoin -> 60 on
Liquid). From the feasibility memo: `to_self_delay` ~1000-2000 Sequentia blocks (~1-2 days) for routing nodes;
per-hop CLTV delta ~270 Sequentia blocks (exceeding Bitcoin's ~40-block delta in wall-clock). For a hop that
crosses a Bitcoin channel and a Sequentia channel, compute the absolute-CLTV gap in wall-clock, normalizing
each leg by its own chain's block time; do not add a cross-chain reorg buffer (the legs share Bitcoin as their
one finality domain), but do normalize cadence. Time-dilation/eclipse risk (Riard-Naumenko) is unchanged by
finality: the node must still see the chain and react within the timelock window; finality removes reorg risk,
not the online-liveness requirement.

### 6.4 Fee asset for penalty/claim txs

A defender's justice/HTLC-claim tx must be includable under Sequentia's open fee market, so the node must hold
a committee-accepted fee asset (naturally the channel asset, per section 4) to fund those txs. Watchtowers
inherit the same requirement.

## 7. Multi-chain: same binary, one daemon per chain (v1), single daemon (v2)

The BOLTs support multiple chains cleanly: `init` carries a `networks` TLV; `open_channel`/`channel_announcement`
carry `chain_hash`; `node_announcement` has no chain_hash, so one node_id can announce channels on two chains,
and gossip is filtered per chain. But no implementation ships simultaneous multi-chain in one daemon (lnd's was
never finished; CLN is strictly one `--network` per `lightningd`). One-daemon-per-chain is an implementation
artifact, not a spec constraint.

- v1: the same SeqLN binary runs as two daemons, `--network=testnet4` (pure Bitcoin, upstream-compatible) and
  `--network=sequentia-testnet` (Elements path), each with its own datadir/db/pidfile as upstream already does.
  This satisfies "the same client works on real BTC and Sequentia" with minimal risk. A thin supervisor / CLI
  wrapper can present both as one wallet to the user.
- v2 (differentiator, no competitor has shipped it): a single daemon that is genuinely dual-chain from one
  node_id, advertising both chain_hashes in the `networks` TLV with per-chain gossip stores. This is where a
  cross-chain BTC<->Sequentia-asset payment can be forwarded inside one node. Scope it separately; it is not
  required for any earlier phase.

## 8. Cross-chain payments (the DEX tie-in)

The SeqOB order-book DEX already reserves a Lightning settlement variant (`LightningTerms = 22` in the offer
schema) and its relay couriers opaque swap-session messages. SeqLN provides the node side of that.

- Submarine swaps (Sequentia asset on-chain <-> BTC over vanilla LN) are the near-term cross-chain path and
  need no new cryptography: same SHA256 preimage across both legs, a hold invoice on the LN side, an
  Elements HTLC (asset-agnostic) on the Sequentia side. The maker runs the Boltz role. This works with plain
  upstream LN on the Bitcoin side and only the on-chain HTLC primitive on the Sequentia side, so it does not
  even require asset channels; it is the first cross-chain deliverable and can ship before section 5.
- Pure-LN both-sides (Sequentia-asset LN <-> Bitcoin LN) requires asset channels (section 5) and a translating
  node binding two independently-routed LN payments by one shared secret (HTLC now, PTLC later). Later phase.
- Every cross-chain swap is rate-bearing (Sequentia has no pegged-BTC asset to make it 1:1 like PeerSwap), so
  the free-option problem is real: mandate RFQ with seconds-scale expiry and a maker-priced spread at the
  boundary; never open-ended cross-chain forwarding. The cross-leg secret-reveal safety rule from the
  feasibility memo applies: the secret-revealing on-chain claim must reach Bitcoin-anchor depth before the
  counterparty settles the other leg (never settle on 0/1 conf across the LN/anchored-ledger boundary).

Reusable components identified in research: PeerSwap (already a CLN plugin, already Elements-aware; its
LN<->Elements swap protocol shape and script are close to what the Sequentia side needs, extend from L-BTC to
any Sequentia asset with an RFQ rate); Boltz's taproot swap scripts and its magic-routing-hint convention
(a clean deployed pattern for "this invoice is also payable on the sidechain"). Nothing in the Taproot Assets
stack is directly reusable (lnd/tapd/litd-coupled); only its economic architecture (edge nodes, RFQ,
seconds-scale quote expiry) transfers.

## 9. Phased plan

Phase 0 — Network bring-up (smallest working delta). Add the three Sequentia chainparams entries (+ test-harness
duplicates); implement the anchored-block-header parse in `bitcoin/block.c` behind `has_anchor_header`; confirm
the legacy signed-blocks proof path handles the Sequentia PoS proof; get stock bcli talking to a Sequentia
regtest node. Exit criterion: `lightningd --network=sequentia-regtest` starts, syncs, and CLN's computed block
hashes match the node's. No channels yet.

Phase 1 — Policy-asset (Sequence-token) channels on Sequentia, unblinded, static-remotekey. This is the
maintained-upstream Liquid path pointed at Sequentia: standard BOLT scripts, on-chain fee output paid in the
Sequence token. Apply the anchor-aware safety layer (section 6): minimum_depth=1 on certification, two-stage
SCID rule, wall-clock timelocks, anchor-depth confirmations via the Sequentia backend plugin. Exit criterion:
open/route/close a Sequence-token channel between two SeqLN nodes on Sequentia testnet, with a force-close and
a penalty case exercised across an induced tail-truncation reorg.

Phase 2 — Submarine swaps (Sequentia asset on-chain <-> BTC over vanilla LN). Cross-chain value with no asset
channels required; the maker is the swap counterparty. Reuse the SeqOB HTLC primitive and PeerSwap/Boltz
patterns; enforce the anchor-depth secret-reveal gate and Boltz-style 0-conf mitigations. Exit criterion: a
non-custodial asset<->BTC-LN swap on testnets, refund path exercised.

Phase 3 — Asset channels (the novel core, section 5). Per-channel asset denomination; `asset_id` TLV in
open/accept; commitment/HTLC/close math in the channel asset; fee output in the channel asset; asset invoices;
same-asset routing; unannounced channels. Exit criterion: open/route/close a GOLD channel; a USDX channel;
correct dust-trim and force-close in the asset.

Phase 4 — Cross-asset and cross-chain over LN. RFQ boundary nodes with signed, seconds-expiry quotes;
pure-LN both-sides asset<->BTC swaps via a translating node; optionally the v2 single-daemon dual-chain node.
PTLCs as the long-term upgrade over hash-based HTLCs (no wormhole, scriptless), gated on upstream taproot-channel
support landing on Elements (track cdecker's PR #8097).

Permanently deferred — confidential (blinded) amounts inside channels: heavy tx-weight and force-close cost for
little privacy gain (the counterparty already knows the balance); every prior implementation deferred it, and
it clashes with the explicit-fee model. Ship unblinded, matching CLN-on-Elements and Sequentia's
transparent-by-default.

## 10. Risks and open questions

- Upstream rebase burden. Mitigate by isolating Sequentia behind chainparams flags + an `is_sequentia` guard
  mirroring `is_elements`, and by upstreaming anything generic (e.g. the header-parser hook could be a general
  "extra header bytes" mechanism).
- Anchors/taproot/splicing are off on Elements in CLN today (static-remotekey only). v1 accepts that. Track
  cln PR #8097 (draft: enables anchors + taproot channels on liquid via newer libwally; 13 failing tests as of
  2025-07) as the upgrade path; do not depend on it for phases 0-3.
- Elements Core version: CLN CI pins 23.2.1; Sequentia is 23.3.3 (one minor ahead). Verify SeqLN builds and
  the pytest liquid-style suite passes against a Sequentia node before Phase 1 exit.
- The asset-channel commitment math is the correctness-critical surface: both peers must reconstruct
  byte-identical commitment txs denominated in the channel asset. Budget adversarial review here (a symmetric
  commitment-reconstruction test between two independent nodes is the acceptance gate).
- BOLT11 asset encoding and the `lightning_hrp` choices should be published in a small SeqLN spec repo so any
  future wallet agrees; treat bLIP-29's TLV numbers as unstable and do not adopt them wholesale.
- "Lightning on a sidechain" failed to bootstrap once (Liquid's LN never grew, because L-BTC channels offered
  too little over BTC channels). SeqLN's symmetry-breakers are concrete: asset-denominated channels merchants
  actually want (stablecoins), 1-conf channel opens on certification, and fees payable in the channel's own
  asset. Lead with those; the technology is necessary but not sufficient, so pair it with the DEX/wallet
  liquidity that already exists.

## 11. Grounding

CLN: `bitcoin/chainparams.{c,h}`, `common/amount.{c,h}`, `bitcoin/{block,tx,psbt,signature}.c`,
`plugins/bcli.c`, `doc/developers-guide/plugin-development/bitcoin-backend.md`, `lightningd/options.c`
(elements anchor disable, funding-confirms), CI `.github/workflows/ci.yaml` (liquid-regtest matrix),
draft PR #8097 (elements anchors/taproot), issue #7794. BOLTs 0/1/2/3/7/11/12 (chain_hash, networks TLV,
minimum_depth, HRP registry, offer_chains). Prior art: Blockstream Lightning-on-Liquid (2019, L-BTC-only),
Taproot Assets + bLIP-29 (edge/RFQ architecture), RGB-over-LN, dead multi-asset BOLT PR #72, ZmnSCPxj's
free-option argument, PeerSwap, Boltz. Sequentia: `src/primitives/block.h` (anchor header),
`src/chainparams.cpp` (network params, shared HRPs, dynafed off, signed-blocks proof), the shipped
`getblockheader.poscertified` + `getanchorstatus` RPCs, `seqdex/docs/seqdex-lightning-feasibility.md`
(safety analysis, timelock/anchor-depth policy), `seqdex/docs/seqdex-orderbook-design.md` (LightningTerms=22).
