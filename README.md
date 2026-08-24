# SeqLN: Core Lightning for Sequentia (and Bitcoin, same binary)

SeqLN is a fork of [Core Lightning](https://github.com/ElementsProject/lightning) (CLN, base
version v26.06.2) that adds the Sequentia network to `lightningd`. One binary runs Lightning on
Bitcoin (mainnet, testnet4, regtest, signet), on Liquid, and on Sequentia: the network is chosen
with `--network`. On Sequentia it adds what the chain makes possible: channels denominated in any
issued asset, asset-aware routing and payments, and an anchor-aware safety layer that turns
Sequentia's Bitcoin-anchored finality into fast, honest confirmation counting.

Sequentia is a Bitcoin sidechain for asset tokenization and decentralized exchange, built as a
fork of Blockstream Elements. Every Sequentia block references a Bitcoin block header, and if
Bitcoin reorganizes away an anchor, Sequentia reorganizes with it, in real time. That real-time
reorg-following is what makes Lightning on a sidechain safe, and SeqLN is built around it.

**This is testnet software.** The Sequentia network runs as a public testnet (parent chain:
Bitcoin testnet4). There is no Sequentia mainnet; the `sequentia` mainnet entry in
`bitcoin/chainparams.c` is an explicit placeholder that must not be used.

## Where SeqLN fits in the Sequentia ecosystem

| Repo | One-liner |
|---|---|
| [Sequentia](https://github.com/ConcatenaLabs/Sequentia) | Sequentia Core, the node (`sequentiad`/`sequentia-cli`, a fork of Elements 23.3.3): consensus, anchoring, proof of stake, open fee market, plus the canonical protocol documentation in `doc/sequentia/`. |
| [seqln](https://github.com/ConcatenaLabs/seqln) | SeqLN: a Core Lightning fork that runs on Sequentia and Bitcoin from the same binary, with asset channels, any-asset payments, pure-Lightning swaps. |
| [seqdex](https://github.com/ConcatenaLabs/seqdex) | SeqDEX: non-custodial order-book DEX: the SeqOB covenant on-chain order book, same-chain swaps, and cross-chain BTC↔asset and pure-Lightning swaps made safe by Bitcoin anchoring. |
| [fulmen](https://github.com/ConcatenaLabs/fulmen) | Fulmen: desktop (Electron) wallet for SeqLN with a bundled Lightning node. |
| [libwally-core](https://github.com/ConcatenaLabs/libwally-core) | libwally fork with the Sequentia transaction-parsing patch (issuance denomination byte) used by SeqLN. |

Protocol-level documentation (anchoring, proof of stake, fees) lives in the node repo under
[doc/sequentia/](https://github.com/ConcatenaLabs/Sequentia/tree/HEAD/doc/sequentia).
The SeqLN design spec is this repository's own:
[doc/seqln-design/seqln-core-lightning-fork-spec.md](doc/seqln-design/seqln-core-lightning-fork-spec.md),
with the rest of the fork's design documents in [doc/seqln-design/](doc/seqln-design/README.md).
The public testnet explorer and API are at https://sequentiatestnet.com.

## Status: what works today

Everything below is committed on the `sequentia-stable` branch and was proven against the live
public testnet (re-genesis 2026-07-05) unless noted. The precise file-level change list, with
known hazards, is in [doc/sequentia-fork.md](doc/sequentia-fork.md).

- **Sequentia as a network.** `--network=sequentia-testnet` selects the live testnet
  (`bitcoin/chainparams.c`). On-chain addresses share Bitcoin's `tb1` bech32 format (Sequentia is
  transparent by default); invoices use the distinct Lightning HRP `tsqt` (`lntsqt...`).
- **Anchored block headers.** Sequentia block headers carry a Bitcoin anchor
  (`anchor_height` + `anchor_hash`); the parser (`bitcoin/block.c`) recomputes block hashes that
  match the live chain byte-for-byte.
- **Anchor-aware safety layer.** Confirmations are counted in quorum-certified blocks (the
  "certified frontier", `plugins/bcli.c`), `minimum_depth` is 1 (a certified block is displaced
  only by a Bitcoin-anchor reorg), timelocks are sized in wall-clock at Sequentia's 60-second
  block spacing (the consensus minimum since the testnet's 93,800 fork), and a channel's
  short-channel-id is announced only after its funding block's Bitcoin anchor is buried
  (`lightningd/chaintopology.c`, `lightningd/channel_gossip.c`). `rescan` defaults to `-1` on
  Sequentia networks (`lightningd/options.c`): the node re-walks the chain from height 1 on every
  restart, so a Bitcoin-anchor reorg of any depth can never abort it; `--rescan` overrides.
- **Sequence-token channels.** Channels in the policy asset, the Sequence token (tSEQ on testnet):
  open, route, and mutually close, demonstrated live on the public testnet.
- **Asset channels.** `fundchannel ... asset=<32-byte hex asset id>` opens a single-funder channel
  denominated in any issued asset (e.g. GOLD): per-asset coin selection and funding, commitment
  transactions and HTLCs in the channel asset, force-close resolution and anchor CPFP in the
  channel asset, and on-chain fees sized per-asset via the node's `getfeeexchangerates` whitelist
  (Sequentia's open fee market: fees are payable in any accepted asset).
- **Asset-aware gossip and payments.** Channel gossip records each channel's asset from its
  funding output; `getroute` and `pay` take an `asset=<id>` parameter and route only over channels
  of that asset. Nodes refuse to forward an HTLC across an asset boundary (no silent at-par
  asset swaps).
- **Pure-Lightning swap primitive.** `contrib/holdinvoice-seq/` is a hold-invoice plugin (hold an
  externally-supplied payment hash until settle/cancel), the safety primitive for pure-Lightning
  asset↔BTC swaps. The swap orchestration itself lives in
  [seqdex](https://github.com/ConcatenaLabs/seqdex).
- **Signer split (non-custodial hosted nodes).** `hsmd/hsmd_proxy.c` + `hsmd/signerd.c` split the
  key-holding signer out of the node process, and `contrib/seqln-signer/` is a Rust device signer
  (byte-exact against libhsmd, BOLT-8 Noise_XK secured transport, WASM build for browsers) so a
  thin wallet can hold the keys while a host runs the node. See
  [contrib/seqln-signer/README.md](contrib/seqln-signer/README.md).
- **Specula keyless watchtower.** `channeld/watchtower.c` and `lightningd/onchain_presign.c` have
  the signing device pre-sign justice and sweep transactions at every commitment advance into a
  secret-free on-disk store (`lightningd/watchtower_store.c`, DB table `penalty_htlcs`);
  `speculad/speculad` is a standalone daemon that watches the chain through the node's CLI and
  broadcasts them while the signing device is offline. Attaching a fee input to the pre-signed
  justice transactions is an open seam on testnet (see `speculad/speculad.c`). The design note is
  not yet published in this repository.

Experimental / known limitations (details and file pointers in
[doc/sequentia-fork.md](doc/sequentia-fork.md#known-hazards-and-limitations)):

- Dual-funded (v2) channel opens and splicing are not asset-aware; asset channels must use the
  ordinary single-funder `fundchannel`.
- Holding channels of *different* assets to the *same* peer is unsafe: parts of channel selection
  are asset-blind and can put an HTLC on the wrong-asset channel. One asset per peer, and verify
  per-asset balance movement.
- BOLT11 invoices carry no asset field yet; the payer chooses the asset with `pay ... asset=<id>`.
- The upstream CLN integration-test harness has no Sequentia network entries; Sequentia coverage
  is standalone scripts under `tests/sequentia/` plus the signer conformance harness.

## Building from source

SeqLN builds exactly like upstream CLN (see the
[installation guide](doc/getting-started/getting-started/installation.md) for distro package
lists), with one fork-specific point: the `external/libwally-core` submodule is pinned to the
[Sequentia libwally fork](https://github.com/ConcatenaLabs/libwally-core) (branch
`sequentia-issuance-denomination`). Stock libwally under-reads Sequentia asset-issuance
transactions by one byte (Sequentia adds a denomination byte to `CAssetIssuance`), which would
crash a node syncing any issuance block; the pinned fork parses and round-trips it. Cloning with
`--recurse-submodules` picks the right commit automatically.

```bash
git clone --recurse-submodules -b sequentia-stable https://github.com/ConcatenaLabs/seqln.git
cd seqln
uv sync --all-extras --all-groups --frozen   # python deps (msggen, test harness)
./configure
make -j$(nproc)
```

Binaries land in-tree: `lightningd/lightningd`, `cli/lightning-cli`, the subdaemons next to
`lightningd/`, the signer-split daemons `lightningd/lightning_hsmd_proxy` and
`lightningd/lightning_signerd`, and the watchtower broadcaster `speculad/speculad`.

Contributions go as PRs against `sequentia-stable`, the only maintained branch (and the deployed
one). `sequentia` is an older, diverged line kept for history; do not build from it.

## Running against the Sequentia public testnet

SeqLN needs a synced Sequentia Core node (`sequentiad`, from
[Sequentia](https://github.com/ConcatenaLabs/Sequentia)) with RPC enabled, plus its
`sequentia-cli` binary; the `bcli` backend plugin shells out to it with `-chain=test`. The
chainparams default is `sequentia-cli` (`bitcoin/chainparams.c`); pass
`--bitcoin-cli=/path/to/sequentia-cli` when it is not on PATH (Fulmen stages it under the name
`elements-cli` for historical reasons and passes the explicit path).

```bash
lightningd --network=sequentia-testnet \
  --bitcoin-cli=/path/to/sequentia-cli \
  --bitcoin-datadir=/path/to/sequentia-datadir \
  --lightning-dir=$HOME/.seqln
```

(`--bitcoin-rpcconnect/--bitcoin-rpcport/--bitcoin-rpcuser/--bitcoin-rpcpassword` work as usual if
you prefer explicit RPC credentials over a datadir/cookie. The node's RPC port on chain `test` is
18776; 18332 is the port the node uses to reach its Bitcoin parent, and the `rpc_port` value in
`bitcoin/chainparams.c` still says 18332.)

There is no public SeqLN routing node or LSP yet; run two nodes (or use Fulmen) to test.

Then, for example:

```bash
# Fund the on-chain wallet (tSEQ or any issued asset), e.g. from the faucet at
# https://sequentiatestnet.com/faucet, then:
alias scli='lightning-cli --lightning-dir=$HOME/.seqln --network=sequentia-testnet'
scli newaddr                                                # a shared-format tb1... address
scli listfunds                                              # issued-asset UTXOs carry an "asset" field
scli fundchannel id=<node_id> amount=100000                 # tSEQ channel
scli fundchannel id=<node_id> amount=100000 asset=<hex_id>  # issued-asset channel
scli pay bolt11=<lntsqt1...> asset=<hex_id>                 # pay routed over that asset only
```

Amounts for an asset channel are that asset's own atoms (there is no privileged unit; "sat" and
"msat" field names are inherited from upstream wire formats but denominate the channel asset).

## Running against Bitcoin testnet4

Unchanged from upstream: point it at a `bitcoind` on testnet4.

```bash
lightningd --network=testnet4 --lightning-dir=$HOME/.cln-testnet4
```

The same binary, database format, plugins, and RPC surface apply; see the upstream docs below.

## Testing

- **Upstream suites** (Bitcoin regtest / liquid-regtest; no Sequentia entries yet):
  `make check-units` for unit tests, `make pytest` (or
  `uv run python -m pytest -v tests/`) for integration tests. See
  [doc/contribute-to-core-lightning/testing.md](doc/contribute-to-core-lightning/testing.md).
- **Sequentia live-chain checks** (`tests/sequentia/`): standalone scripts that point at any
  reachable Sequentia node via `ELEMCLI` (path to `sequentia-cli`, the default) and
  `SEQ_RPC_{HOST,PORT,USER,PASS}`:
  ```bash
  ELEMCLI=/path/to/sequentia-cli python3 tests/sequentia/validate_live_blocks.py      # header parser vs live chain
  ELEMCLI=/path/to/sequentia-cli python3 tests/sequentia/verify_certified_frontier.py # confirmation clamp
  ELEMCLI=/path/to/sequentia-cli python3 tests/sequentia/verify_anchor_burial.py      # SCID announce gate
  ELEMCLI=/path/to/sequentia-cli python3 tests/sequentia/verify_block_parse.py        # single-block regression
  ```
- **Signer**: `cargo test` in `contrib/seqln-signer/`, plus the byte-exact conformance harness
  against libhsmd; see [contrib/seqln-signer/README.md](contrib/seqln-signer/README.md).

## Upstream documentation

Everything generic about Core Lightning (configuration, RPC reference, plugins, man pages,
developer guides) is unchanged in this fork and documented upstream: the in-tree
[doc/](doc/index.rst) tree and https://docs.corelightning.org/docs. The Sequentia-specific delta
is documented in [doc/sequentia-fork.md](doc/sequentia-fork.md).

## License

[BSD-MIT](LICENSE), same as upstream Core Lightning (modules under `ccan/` carry their own
licenses).
