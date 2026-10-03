# SeqLN: Sequentia changes vs upstream Core Lightning

This document lists precisely what the SeqLN fork changes relative to upstream Core Lightning
(base: CLN v26.06.2), at file/subsystem level, and the known hazards. The front door is the
top-level [README.md](../README.md); the design spec is
[seqln-design/seqln-core-lightning-fork-spec.md](seqln-design/seqln-core-lightning-fork-spec.md),
alongside the rest of this fork's design documents in
[seqln-design/](seqln-design/README.md).

Branches: `sequentia-stable` is the only maintained branch (deployed; all of the below; PRs
target it). `sequentia` is an older, diverged line kept for history; do not build from it.
Everything here is testnet software.

## 1. Networks (`bitcoin/chainparams.c`, `bitcoin/chainparams.h`)

Three Elements-family network entries are added, plus a `has_anchor_header` field on
`struct chainparams` that gates every Sequentia-specific code path:

| network_name | onchain HRP | lightning HRP | bip70 (chain) | is_elements | has_anchor_header |
| --- | --- | --- | --- | --- | --- |
| `sequentia-testnet` (live) | `tb` | `tsqt` | `test` | yes | yes |
| `sequentia-regtest` (local tests) | `bcrt` | `sqrt` | `sequentia-regtest` | yes | yes |
| `sequentia` (placeholder) | `bc` | `sqt` | `sequentia` | yes | yes |

- The on-chain HRP is shared with Bitcoin (`tb`/`bc`) by design: Sequentia is transparent by
  default and its unblinded addresses are byte-identical to Bitcoin's bech32 format, so a
  dual-chain wallet uses one `tb1` address on both chains. The Lightning HRP is the one distinct
  wire identifier; invoices read `lntsqt...` on testnet.
- `bip70_name` must equal the node's `getblockchaininfo.chain`, which the live testnet reports as
  `test`. The collision with Bitcoin testnet3's bip70 name is benign: network selection is by the
  unique `network_name` and the wire protocol disambiguates by `chain_hash`.
- `genesis_blockhash` (stored in internal, reversed-display byte order) is the live testnet
  genesis of the 2026-07-05 re-genesis, display
  `ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e`.
- `fee_asset_tag` is `0x01` (explicit prefix) + the policy-asset id in internal byte order,
  matching CLN's L-BTC convention. The testnet policy asset (the Sequence token, tSEQ; display id
  from the node's `dumpassetlabels` entry for "bitcoin") is
  `c8eccacf0953e1931cd31e434d8319101cc36e6c38b0e2104d8687552fae3e40`. Display order here breaks
  wallet detection: `wally_tx_output_get_amount()` returns assets in internal order and
  `amount_asset_is_main()` does a straight memcmp.
- `sequentia-regtest` is the local custom chain the pytest harness starts (section 10): a
  `sequentiad -chain=sequentia-regtest` node anchored to a Bitcoin Core regtest parent, sharing
  the parent's `bcrt` prefix as the testnet shares `tb`. A custom chain's genesis and policy asset
  follow from its arguments, so the entry carries the values the harness's arguments produce, and
  the harness refuses to start a node that reports different ones.
- The `sequentia` mainnet entry is an explicit placeholder (all-zero genesis, NULL
  `fee_asset_tag`); there is no Sequentia mainnet. It must be filled before any use.
- `cli` is `sequentia-cli` with `cli_args` `-chain=test`: the `bcli` backend drives a Sequentia
  Core node (`sequentiad`) through its CLI, exactly like the Liquid entries drive Elements. Pass
  `--bitcoin-cli=/path/to/sequentia-cli` when it is not on PATH (Fulmen stages it under the name
  `elements-cli` for historical reasons and passes the explicit path). `rpc_port` is the node's
  own RPC port: 18776 on chain `test`, 7332 on `sequentia` (18332 is the port the node uses to
  reach its Bitcoin parent). `bcli` never reads `rpc_port`, so with `--bitcoin-datadir` the CLI
  finds the right port and cookie on its own.

## 2. Anchored block header (`bitcoin/block.c`, `bitcoin/block.h`)

Sequentia inserts a Bitcoin anchor into every block header. The full serialization is:

```
version(4) prev(32) merkle(32) time(4) block_height(4)
anchor_height(4) anchor_hash(32)            <- Sequentia anchor
CProof(challenge + solution)                <- signed blocks, no bits/nonce
```

The block hash is double-SHA256 over `version .. challenge` (anchor fields included, proof
solution excluded, as CLN already handles the Elements legacy proof), reversed for display.
`bitcoin_block_from_hex()` parses `anchor_height` (le32) + `anchor_hash` between `block_height`
and the proof, gated on `chainparams->has_anchor_header`, and retains `anchor_height` in
`struct bitcoin_block_hdr` for the burial gate (section 3). Verified byte-for-byte against the
live chain by `tests/sequentia/validate_live_blocks.py` and end-to-end through the real
`lightningd` + `bcli` path.

## 3. Anchor-aware safety layer

Sequentia's consensus gives two facts Lightning can build on: a quorum-certified block is final
unless its Bitcoin anchor is reorganized away (Bitcoin anchoring is supreme, and a node follows a
Bitcoin reorg in real time), and the chain tip is normally certified immediately. SeqLN encodes
that honestly, all gated on `has_anchor_header`:

- **Certified-frontier confirmations** (`plugins/bcli.c`, `getchaininfo` and
  `getrawblockbyheight`): `bcli` reports the highest `poscertified` height at or below the node
  tip as `blockcount`/`headercount`, and answers a request for a block above that height as "not
  yet known", so the chain CLN follows ends at the certified frontier and every
  `minimum_depth`/confirmation check is denominated in certified depth, not raw tip-distance. A
  block certified below quorum (accepted only under the escaping stall) joins CLN's chain once a
  certified block lands on top of it. The walk down is bounded by `SEQUENTIA_CERT_LOOKBACK` (144); a gap that large
  means the committee has stalled, and the clamp fails open with a loud warning. A frontier
  retreat (Bitcoin-anchor reorg / tail truncation) is absorbed by CLN's normal reorg handling.
- **`minimum_depth` = 1 and wall-clock timelocks** (`lightningd/options.c`): a certified funding
  block is final in the sense above, so `funding_confirms = 1`. Timelocks are sized in wall-clock
  at Sequentia's 60-second block spacing (the consensus minimum since the testnet's 93,800 fork),
  each at least its Bitcoin-mainnet wall-clock equivalent: `locktime_blocks` (to_self_delay) 1440
  (~1 day), `cltv_expiry_delta` 270 (~4.3h), `cltv_final` 180 (~2.9h), `max_htlc_cltv` 20160
  (~2 weeks). These are defaults; operators and per-open flags can still override.
- **Two-stage SCID / anchor-burial announcement gate** (`lightningd/chaintopology.c`
  `topo_anchor_buried()`, `lightningd/channel_gossip.c` `has_announce_depth()`): a certified block
  can still fall to tail truncation until its Bitcoin anchor is buried, and a
  `channel_announcement` short-channel-id (height:txindex:output) must never be invalidated. So a
  channel is *usable* at certified depth 1 but *announced* only once the funding block's anchor is
  buried by `SEQUENTIA_ANCHOR_BURY_DEPTH` (2) Bitcoin-anchor blocks. The funding anchor is
  re-derived from the in-memory chain (no backend-protocol change, no DB migration) with a bounded
  walk that exploits the monotonicity of `anchor_height`.
- **`rescan` defaults to `-1`** (`lightningd/options.c`): upstream pins the in-memory chain root
  only `rescan` blocks below the tip and calls `fatal()` when a reorg walks past it. A Bitcoin
  reorg unwinds roughly ten Sequentia blocks per Bitcoin block, so on Sequentia networks the
  default is `-1`, which `chaintopology.c` reads as an absolute start height of 1: the root sits
  just above genesis and no anchor-driven reorg can reach it. The cost is a full rescan on every
  restart; `--rescan` overrides.
- `lightningd/watch.c`: output-spend logging tolerates non-policy assets.

## 4. Fees: open fee market, no on-chain estimation

Sequentia has an open fee market (fees payable in any asset the block producers accept, no
privileged fee asset), so a node returns no `estimatesmartfee`-style feerate:

- `plugins/bcli.c`: Sequentia networks use bcli's existing fixed-feerate path (as regtest does),
  because without any estimate `unknown_feerates()` rejects every channel open. Operators can
  still `--force-feerates`. Fee-rate units are always the chosen fee asset's own units per vByte.
- `plugins/bcli.c` `getfeeexchangerates`: a thin passthrough of the Sequentia node's
  `getfeeexchangerates` RPC, exposing the producer's any-asset fee whitelist (for each accepted
  asset a rate R: one atom of it is worth R / `EXCHANGE_RATE_SCALE` (1e8) reference atoms). A
  plain `bitcoind` backend yields an empty whitelist rather than an error.
- `lightningd/bitcoind.c`, `lightningd/chaintopology.{c,h}`, `common/amount.{c,h}`: plumb and
  cache those exchange rates (`EXCHANGE_RATE_SCALE`, per-asset rate lookup), read once before any
  channel starts and refreshed on the feerate poll. The policy asset, the Sequence token, is one
  asset among equals: `bcli` resolves the node's labels (its "bitcoin" among them) to hex ids, so
  it arrives at the rate its node gives it, and a node that does not list it does not accept it
  for fees. On Liquid the policy asset stays at par.
- `wallet/reservation.c` `asset_tx_fee()`: the on-chain fee of a wallet transaction is converted
  from the reference fee into atoms of the funding asset preserving fee *value*:
  `asset_fee_atoms = ceil(reference_fee_atoms * 1e8 / rate)`, the Sequence token included.
- `common/amount.c` `amount_tx_fee()`: on a Sequentia network every fee is rounded up rather than
  down, so a positive feerate never yields a fee of 0 atoms (which consensus refuses) and a fee is
  always worth at least its feerate times the weight. An atom of a valuable asset can be worth
  thousands of reference atoms, so the relay floor can be 1 atom per kw. Both sides of a channel
  size its commitment and HTLC transactions with this, and onchaind also matches HTLC signatures
  made by a build that rounded down.
- Channel transactions pay their fee in the channel asset, so every feerate a channel uses is
  stated in that asset's atoms per kw, converted the same way (`feerate_in_asset()`,
  `channel_asset_feerate()`): the commitment feerate the opener proposes at open and in
  `update_fee`, the limits each side judges the other's feerate by, the mutual-close feerates and
  the onchaind sweep fees. HTLC transactions take the commitment feerate, so they follow. A rate
  change moves an open channel's feerates as a new estimate would. No peer-wire change:
  `update_fee` carries a number in the channel asset's atoms, and each side values it at its own
  rate:
  - the opener proposes at least one and a half times its relay floor
    (`commitment_feerate_floor()`), so a peer that values the asset up to a third lower still
    sees the feerate clear its own floor;
  - the receiver's limits are its relay floor and `feerate_max()` (ten times its highest
    estimate), each converted at its own rate (`peer_commitment_feerate_min()`; `openingd_init`
    carries the node's rates for an open). An `update_fee` outside them is refused with a warning,
    and lightningd refreshes its rates at once: each node takes rates from its own feed, so the
    receiver may be judging by a rate older than the opener's. It keeps refusing (and
    disconnecting) while its rate for the channel asset is unchanged, and fails the channel,
    saying why, only when a refusal persists after that rate has changed, or for more than five
    minutes, longer than a lagging feed takes to catch up (`channel_update_fee_refused()`);
  - a fundee with no rate for the channel asset refuses a channel in it, and in an open channel
    holds the opener to the last limits its rate gave, or, with none since it started, to the
    current feerate; with no rate to judge by, it never fails the channel over a feerate.
- The cap on HTLCs trimmed to dust in flight (`--max-dust-htlc-exposure-msat`) is a reference
  amount like the fee settings, so lightningd values it at the node's rate for the channel asset
  (`channel_dust_cap()` in `lightningd/channel_control.c`) and channeld receives it at start and
  with every feerate update (`channeld_feerates`). When a repriced asset would still take the
  HTLCs in flight over the cap at the new feerate, the opener does not send the `update_fee` with
  that commitment but commits what is pending, as BOLT 2 allows, and sends it with a later one
  once the dust has cleared, instead of disconnecting at every reestablish
  (`channeld/channeld.c` `send_commit()`). Bitcoin channels keep upstream's behaviour.

## 5. Asset-aware channels

A channel is denominated in exactly one asset (`channel_asset`, a 33-byte version+tag id; the
policy asset by default). File-level map of the threading:

- `common/amount.{c,h}`: `amount_asset_is(amount, asset_id)`, the asset-aware primitive;
  `amount_asset_is_main()` is now defined in terms of it.
- `bitcoin/tx.{c,h}`, `bitcoin/psbt.{c,h}`, `bitcoin/tx_parts.c`: a per-tx `output_asset`
  (`bitcoin_tx_set_output_asset()`, `wally_tx_output_asset()`), issued-asset PSBT outputs and
  witness-UTXOs (`psbt_insert_output_asset()`, `psbt_input_set_wit_utxo_asset()`), and relaxed
  policy-asset assertions on the paths asset channels traverse.
- `wire/peer_wire.csv`: `open_channel_tlvs.asset_id` (TLV type 3, SeqLN-local until standardized)
  carries the channel asset in the v1 open.
- `openingd/openingd.c` + `openingd/openingd_wire.csv`, `lightningd/opening_control.c`,
  `lightningd/opening_common.h`: single-funder open in an issued asset (funder and fundee sides).
- `common/initial_channel.{c,h}`, `common/initial_commit_tx.{c,h}`, `channeld/commit_tx.{c,h}`,
  `common/htlc_tx.{c,h}`, `channeld/full_channel.c`, `channeld/channeld.c` +
  `channeld/channeld_wire.csv`: commitment transactions and HTLC transactions denominated in the
  channel asset.
- `common/close_tx.{c,h}`, `closingd/closingd.c` + `closingd/closingd_wire.csv`,
  `lightningd/closing_control.c`: the mutual-close transaction in the channel asset (both outputs
  and the fee), and the closing fee read from the outputs in that asset.
- `lightningd/channel.{c,h}`, `lightningd/channel_control.c`, `lightningd/peer_control.c`,
  `wallet/wallet.{c,h}`, `wallet/migrations.c`: `channel_asset` on the channel state, persisted
  across restarts (DB migration), surfaced in `listpeerchannels` as `channel_asset` (32-byte
  display hex) for non-policy channels.
- `wallet/wallet.c`, `wallet/reservation.c`, `wallet/walletrpc.c`: the on-chain wallet records
  UTXOs of any issued asset, selects coins per-asset, funds single-asset transactions (change and
  fee in the funding asset, fee sized per section 4), and `listfunds` shows an `asset` field on
  issued-asset UTXOs (amounts are that asset's atoms). The per-asset selection, including the
  fee-bump coins of anchor spends and HTLC transactions, applies on Sequentia networks only; a
  Bitcoin node selects from all its UTXOs, as upstream does.
- `plugins/spender/fundchannel.c`, `plugins/spender/multifundchannel.{c,h}`: the `asset` parameter
  (32-byte display-hex id); all channels in one funding tx must share one asset.
- `onchaind/onchaind.c` + `onchaind/onchaind_wire.csv`, `lightningd/onchain_control.c`,
  `lightningd/anchorspend.c`: force-close resolution and anchor CPFP in the channel asset
  (single-asset CPFP; no privileged coin is assumed for fee-bumping).

## 6. Asset-aware gossip, routing, payments

- `common/gossip_store_wire.csv`: `gossip_store_channel_asset` (4108) records a channel's
  denominating asset immediately after its amount record; absent means the policy asset.
- `gossipd/gossipd.c`, `gossipd/gossmap_manage.{c,h}`, `gossipd/gossipd_wire.csv`,
  `lightningd/gossip_control.c`: the asset is learned on-chain from the funding output during
  announcement verification (`gossipd_get_txout_reply` gains an asset field) and written to the
  gossip store.
- `common/gossmap.{c,h}`: `gossmap_chan_get_asset()` reads it back.
- `plugins/topology.c`: `getroute ... asset=<id>` filters pathfinding to channels of that asset.
- `plugins/pay.c`, `plugins/libplugin-pay.{c,h}`: `pay ... asset=<id>` stores the asset on the
  root payment; `payment_route_check()` (the single choke point for all routing variants,
  including MPP splits) skips any channel whose gossip-recorded asset differs, and a routehint
  through a channel the gossip records in another asset is dropped. Without `asset=`, `pay`
  pays in the asset of this node's channels when they all hold one, and refuses when they hold
  several: which asset to pay in is then the caller's choice. On Sequentia networks xpay does not
  take over `pay` (`plugins/xpay/xpay.c`): xpay, askrene and renepay route over channels of any
  asset.
- `lightningd/peer_htlcs.c` `best_channel()`: a forwarding node may move an HTLC to another
  channel with the same peer, but only one in the same asset.
- `lightningd/pay.c`: an all-zero first hop ("any channel to this peer") in `sendpay`, and a first
  hop by node in `injectpaymentonion`, are refused when the peer's channels hold several assets.
- `lightningd/peer_htlcs.c` `forward_htlc()`: the backstop. A node refuses to forward an HTLC
  across an asset boundary (incoming and outgoing `channel_asset` must match), failing with
  `unknown_next_peer`, so a hand-crafted or buggy cross-asset route can never swap one asset for
  another at par.
- `lightningd/invoice.c`, `wallet/invoices.c` (column `invoices.asset`): `invoice ... asset=<id>`
  records the asset an invoice is to be paid in, and `invoice_check_payment()` refuses an HTLC
  arriving on a channel in any other asset (`incorrect_or_unknown_payment_details`, logged as
  "paid in asset X, invoice wants Y"). Without `asset=`, the invoice records the asset of this
  node's channels when they all hold one; on a node with channels in several assets, or none, it
  names no asset and accepts any. `listinvoices` and the `wait*invoice` results show it.
- `lightningd/htlc_set.c`: the parts of one payment must arrive in one asset; a part in another
  asset than the first is refused (`incorrect_or_unknown_payment_details`, logged as "in asset X,
  the payment set is in asset Y"), so an invoice that names no asset never adds one asset's atoms
  to another's.
- `lightningd/peer_htlcs.c`, `lightningd/invoice.c`, `lightningd/notification.c`: the
  `htlc_accepted` hook (`htlc.asset`), the `invoice_payment` hook (`payment.asset`), and the
  `forward_event` and `invoice_payment` notifications (`asset`) name the asset of the channel the
  HTLC arrived on, as a 32-byte display id, the Sequence token's included; the amounts are in
  thousandths of that asset's atoms. The fields appear on Sequentia networks only. The schemas in
  `doc/schemas/hook/` and `doc/schemas/notification/` describe them; the generated typed bindings
  (`.msggen.json`, `cln-rpc`, `cln-grpc`) are not regenerated from them, so a typed client does
  not see the fields.

Invoices: standard BOLT11 with the `tsqt` HRP, and no asset field: the asset an invoice wants is
known to the payee, which enforces it, and is told to the payer out of band (`pay ... asset=`).
Invoice amounts are numeric msat fields read as thousandths of the payment asset's atoms.

## 7. Signer split (hsmd proxy + out-of-process signer)

The stock `hsmd` holds the seed inside the node process. SeqLN splits it so the keys can live on
a user device while a host runs the node:

- `hsmd/hsmd_proxy.c` (built as `lightningd/lightning_hsmd_proxy`): a modified copy of
  `hsmd/hsmd.c` that keeps all fd multiplexing and capability checks but holds **no secret**; it
  forwards every secret-bearing request as a framed `{client_ctx, hsmd_msg}` to a separate signer
  process and relays the reply. Selected with CLN's stock option
  `--subdaemon=hsmd:/path/to/lightning_hsmd_proxy`.
- `hsmd/signerd.c` (built as `lightningd/lightning_signerd`): the reference signer, linking the
  real libhsmd; by default the proxy fork/execs it locally over a socketpair (override the binary
  with `SEQLN_SIGNERD`).
- `hsmd/signer_frame.h`: the little-endian framed transport between proxy and signer.
- `hsmd/signer_noise.{c,h}`: a BOLT-8 Noise_XK secure transport for a *remote* signer link
  (encryption, integrity, mutual static-key authentication, fail-closed). The proxy either
  connects out (`SEQLN_SIGNER_ADDR`) or listens for a connecting device
  (`SEQLN_SIGNER_LISTEN`, reconnect-tolerant, used by browser devices), keyed by
  `SEQLN_HOST_PRIVKEY[_FILE]` + `SEQLN_SIGNER_PEER_PUBKEY`.
- `hsmd/Makefile`: build wiring for the two daemons.
- `contrib/seqln-signer/`: the Rust device signer (native + WASM) that replaces `signerd` on the
  device side. It keeps a per-channel store (revocation counters, the balance its latest
  commitments give this side, the commitments of ours it validated) on the device, holds each
  close and revocation to it, and signs a commitment of ours for broadcast only when it is one it
  validated and has not revoked. It approves payments (`preapproveinvoice`, `preapprovekeysend`,
  which `pay` and `keysend` call) within a per-asset limit, and refuses a commitment that adds an
  HTLC this node offers for a payment it did not approve. See
  [its README](../contrib/seqln-signer/README.md).
- A device that refuses a request on lightningd's own connection is dropped and the request is
  sent again when a device reconnects (a device that was missing state is re-primed then); a
  request refused three times ends the node, with the request named in its log, rather than
  holding the node unanswering.

## 7b. Specula keyless watchtower

Built on the signer split: the device pre-signs the transactions a watchtower would need, so a
host can defend the channel while the device is offline, without ever holding a key.

- `channeld/watchtower.{c,h}`, `common/penalty_base.{c,h}`, `common/presign_templates.{c,h}`: at
  every commitment advance channeld has the signer pre-sign the justice (penalty) set for the
  newly revoked commitment: one transaction for the peer's `to_local` output and one for each
  non-dust HTLC output, in the channel asset. A commitment that carries HTLC outputs but no
  `to_local` (a peer with no balance of its own) gets a justice set too. The templates are
  `SIGHASH_SINGLE|ANYONECANPAY`, so output 0 carries the swept value and a fee input can be
  attached later without the device.
- `lightningd/onchain_presign.{c,h}`: the same for the honest force-close sweeps (delayed
  `to_local`, offered-HTLC timeout) at every advance, the HTLC-success sweep at fulfil, and the
  sweeps of our HTLC outputs on the peer's commitment.
- `lightningd/watchtower_store.{c,h}`: the fsync-durable, secret-free on-disk store they are
  written to (format documented in the header): one file of fixed size per revoked commitment
  (its size set by the HTLCs that commitment carried) and one state file per channel. Penalty
  channels need one device signature per revoked state, so a channel's store grows with every
  state it revokes for as long as it is open; lightningd removes the channel's directory when it
  forgets the closed channel. `wallet/migrations.c` adds the `penalty_htlcs` table;
  `lightningd/peer_control.c` adds the `setpreemptarmed` RPC (`id`, `armed`), which persists a
  per-channel flag in that store. `--watchtower-store=auto|on|off` (default `auto`: kept only
  when hsmd is a signer proxy).
- `speculad/speculad.c` (built as `speculad/speculad`, `speculad/Makefile`): a standalone daemon,
  not a plugin and not spawned by `lightningd`, that loads the store, watches each channel's
  funding output through the node's CLI, and on a revoked commitment confirming broadcasts its
  justice set as one transaction. It never loads a secret. It pays the fee from a box-owned
  node wallet (`--fee-wallet`) holding UTXOs in the channel asset: it appends one fee input and
  change, pays the fee in the channel asset at the node's exchange rate for it
  (`getfeeexchangerates`; `--fee-base-perkw` and `--fee-max-perkw` are in reference atoms), and
  raises it by replacement each round until the justice confirms. A round costs a few CLI calls
  per channel; the stored revoked commitments are polled only once a channel's funding output is
  spent. It needs the node to run with `txindex=1`.

The Specula design note is not yet published in this repository; the header comment of
`speculad/speculad.c` is the fullest description of the model.

## 8. Plugins and daemons affected (summary)

| Component | Change |
| --- | --- |
| `plugins/bcli.c` | Certified-frontier clamp, fixed feerates on Sequentia, `getfeeexchangerates` passthrough |
| `plugins/pay.c`, `plugins/libplugin-pay.{c,h}` | `asset` parameter, per-asset route filter |
| `plugins/topology.c` | `getroute` `asset` parameter |
| `plugins/spender/*` | `fundchannel`/`multifundchannel` `asset` parameter, single-asset funding txs |
| `channeld`, `openingd`, `closingd`, `onchaind` | Channel asset threading (section 5) |
| `gossipd` | On-chain asset learning + gossip store records (section 6) |
| `hsmd` | Proxy/signer split (section 7); stock in-process `hsmd` is unchanged and remains the default |
| `channeld`, `lightningd/onchain_presign.c`, `speculad` | Specula watchtower: pre-signed justice/sweep sets and their offline broadcaster (section 7b) |
| `lightningd/plugin.c` | Startup fix: skip the `plugins_config` wait loop when every plugin is already `INIT_COMPLETE` (a hang reachable with a minimal plugin set, not Sequentia-specific) |
| `contrib/holdinvoice-seq/` | New plugin: hold-invoice primitive for pure-Lightning swaps |
| `contrib/seqln-signer/` | New crate: Rust device signer (native + WASM) |

## 9. libwally dependency

`.gitmodules` pins `external/libwally-core` to
https://github.com/ConcatenaLabs/libwally-core, branch
`sequentia-issuance-denomination`. Sequentia extends the Elements `CAssetIssuance` serialization
with a 1-byte `nDenomination` (asset decimal precision) after `nInflationKeys`. Stock libwally
under-reads every issuance input by one byte, so `wally_tx_from_bytes` fails on any issuance
transaction and a node syncing an issuance block crashes. The fork's patch (libwally
`src/transaction.c`) consumes and preserves the byte so issuance transactions round-trip
byte-exact; non-issuance inputs are untouched. Build with `git submodule update --init
--recursive` (or clone with `--recurse-submodules`); no manual patching is needed.

## 10. Tests

`tests/sequentia/test_*.py` run SeqLN on a local Sequentia chain through the upstream pytest
harness. With `TEST_NETWORK=sequentia-regtest`, the harness's `bitcoind` fixture is a
`SequentiaD` (`contrib/pyln-testing/pyln/testing/utils.py`): `sequentiad` on the custom chain
`sequentia-regtest`, with anchored headers validated against a Bitcoin Core regtest node
(`bitcoind.parent`), a three-member proof-of-stake committee that certifies every block it
produces, transparent addresses by default, no block subsidy, and a fee whitelist holding only
the policy asset at par until a test lists more. `generate_block` mines one parent block before
each Sequentia block (pass `advance_parent=False` to hold the parent still);
`generate_uncertified_block` produces a block below quorum once `mine_parent(spacing=600)` has
opened the escaping stall. Lightning nodes run the network's own timelock and `rescan` defaults.
The tests cover an asset channel opened, paid over and mutually closed, the anchor-burial gate,
the certified-frontier clamp, a Bitcoin reorg unwinding Sequentia blocks under a running node,
the network defaults, a breach of an asset channel with a pending HTLC answered by `speculad`
while the victim is offline (`test_watchtower.py`), a keyless node, as either side of a channel,
closing it and restarting with it closing (`test_keyless_close.py`), the fees of channels in
assets of any value and between peers that value an asset differently (`test_fee_market.py`),
and the asset plugins see on an HTLC, with `holdinvoice-seq` holding only the asset it was
registered in, across a restart (`test_hold_asset.py`). They need `sequentiad`, `sequentia-cli`
and a Bitcoin Core `bitcoind` on `PATH`, and the keyless test needs the device signer built
(`cargo build --release` in `contrib/seqln-signer`, or `SEQLN_SIGNER=/path/to/seqln-signer`):

```sh
PATH=/path/to/bitcoin/bin:/path/to/Sequentia/src:$PATH TEST_NETWORK=sequentia-regtest \
  python3 -m pytest tests/sequentia/
```

Live-chain scripts:

- `tests/sequentia/validate_live_blocks.py`: reimplements the anchored-header parse
  byte-for-byte and checks recomputed block hashes across a sample of live blocks.
- `tests/sequentia/verify_block_parse.py`: single-block parser regression.
- `tests/sequentia/verify_certified_frontier.py`: mirrors the bcli frontier walk (healthy chain,
  walk mechanics, synthetic uncertified suffix).
- `tests/sequentia/verify_anchor_burial.py`: checks the bounded burial walk against a brute-force
  oracle over real anchor heights plus boundary cases.

These four point at any reachable Sequentia node via `ELEMCLI` (path to `sequentia-cli`, the
default) and `SEQ_RPC_{HOST,PORT,USER,PASS}` environment variables; no host or credential is
baked into the repo.

Signer tests: `cargo test` in `contrib/seqln-signer/` plus the byte-exact conformance harness and
WASM test scripts (see that README).

There is no `bitcoin/test/run-*.c` unit test for the anchored header; the Python scripts are the
regression.

## Known hazards and limitations

Each verified present in the code as of 2026-07-08:

1. **Dual-funded (v2) opens and splicing are not asset-aware.** `amount_asset_to_sat()` still
   asserts the policy asset (`common/amount.c`), and the interactive-tx path calls it on arbitrary
   PSBT outputs (`common/interactivetx.c`, `openingd/dualopend.c`), so a non-policy output there
   aborts the daemon. Asset channels must use the ordinary single-funder `fundchannel`.
2. **Payment paths other than `pay` are asset-blind.** xpay, askrene, renepay and keysend know
   no asset. Use `pay` with `asset=` and invoices that name their asset. A plugin that settles
   HTLCs itself must check the `asset` the `htlc_accepted` hook names, as
   `contrib/holdinvoice-seq` does.
3. **Local/private channels have no asset record in pathfinding.** The gossmap local
   modifications (`common/gossmods_listpeerchannels.c`) carry no asset, so unannounced channels
   are treated as policy-asset channels by the `pay`/`getroute` asset filter.
4. **No asset field in invoices.** A payee enforces the asset its invoice was issued in, but the
   BOLT11 string does not carry it: the payer learns it out of band and passes `pay ... asset=`.
5. **Mainnet chainparams are placeholders.** All-zero genesis, NULL fee asset; the `sequentia`
   network entry must not be used.
6. **Committee-stall fail-open.** If the certified frontier is more than 144 blocks behind the tip
   (a stalled committee), the bcli clamp fails open with a warning rather than halting; operators
   should monitor for that log message.
7. **Penalty across an induced anchor reorg is untested.** Open, payment and mutual close of an
   issued-asset channel, and a breach of one answered by `speculad`, run in `tests/sequentia/`,
   and force-close resolution has been exercised on the testnet, but no test covers a penalty
   across a Bitcoin-anchor tail truncation.
8. **`speculad` pays a justice transaction's fee only in the channel asset.** If the node stops
   accepting that asset for fees, the tower cannot fund the justice transaction (it logs the
   asset and broadcasts it unfunded, which the network refuses). Its fee wallet must also hold a
   UTXO in each channel asset it defends.
