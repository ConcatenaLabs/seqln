# SeqLN

A fork of Core Lightning (base version v26.06.2) that runs Lightning on Sequentia as well as on
Bitcoin. `upstream` is `ElementsProject/lightning`; keep it configured, because telling upstream
code from fork code is the first question in almost every change here.

`doc/sequentia-fork.md` is the authoritative file-level delta and hazard list, and
`doc/seqln-design/` holds this fork's design specs — start at
`doc/seqln-design/seqln-core-lightning-fork-spec.md`. The canonical *protocol* spec is a
different thing and lives outside this repo, in
[`Sequentia`](https://github.com/ConcatenaLabs/Sequentia) under
`doc/sequentia/`: that repo specifies anchoring, proof of stake and the fee market, and
owns nothing about how Lightning is built on top of them.

## Branches

`sequentia-stable` is the only maintained branch: deployed, and the one to open PRs against.
`sequentia` is an older, diverged line kept for history; do not build from it or develop on it.
`master` tracks pristine upstream; never commit fork work there.

## Building

**Clone with `--recurse-submodules`.** `external/libwally-core` is pinned to a Sequentia fork,
because Sequentia adds a one-byte `nDenomination` to `CAssetIssuance` and stock libwally
under-reads issuance inputs by exactly that byte. A node built against stock libwally **crashes**
when it syncs a block containing an issuance. A clone without submodules produces a build that
looks fine and fails in production.

```sh
git clone --recurse-submodules -b sequentia-stable \
  https://github.com/ConcatenaLabs/seqln.git
cd seqln
uv sync --all-extras --all-groups --frozen   # python deps (msggen, test harness)
./configure
make -j$(nproc)
```

There are **no Sequentia-specific `./configure` flags**. Network selection is entirely at
runtime via `--network` (`sequentia-testnet`, or the Bitcoin/Liquid networks upstream supports).

```sh
lightningd --network=sequentia-testnet \
  --bitcoin-cli=/path/to/sequentia-cli \
  --bitcoin-datadir=/path/to/sequentia-datadir \
  --lightning-dir=$HOME/.seqln
```

The node is Sequentia Core (`sequentiad`/`sequentia-cli`). The chainparams `cli` default is
`sequentia-cli`; pass `--bitcoin-cli=/path/to/sequentia-cli` when it is not on PATH (Fulmen stages
it under the name `elements-cli` for historical reasons and passes the explicit path). The
chainparams `rpc_port` is the node's own RPC port on chain `test`, 18776 (18332 is the port the
node uses to reach its Bitcoin parent).

Binaries land in-tree: `lightningd/lightningd`, `cli/lightning-cli`, the subdaemons beside
`lightningd/`, and the signer-split daemons `lightningd/lightning_hsmd_proxy` and
`lightningd/lightning_signerd` (selected at runtime with `--subdaemon=hsmd:...`).

## Testing

```sh
make check-units
make pytest                       # or: uv run python -m pytest -v tests/
```

Sequentia-specific checks need a node's CLI:

```sh
ELEMCLI=/path/to/sequentia-cli python3 tests/sequentia/validate_live_blocks.py
ELEMCLI=/path/to/sequentia-cli python3 tests/sequentia/verify_certified_frontier.py
ELEMCLI=/path/to/sequentia-cli python3 tests/sequentia/verify_anchor_burial.py
ELEMCLI=/path/to/sequentia-cli python3 tests/sequentia/verify_block_parse.py
```

The device signer has its own workspace: `cargo test` in `contrib/seqln-signer/`.

**The GitHub workflows are unmodified upstream CLN CI. Nothing in CI builds or tests anything
Sequentia-specific.** Whatever you do not run locally is not run at all.

`tests/plugins/channeld_fakenet` and `wallet/test/run-wallet` are known broken on a clean tree
(pre-existing drift). Do not treat their failure as something you caused.

## One binary, not two

There is no build-time gating anywhere: no `#ifdef`, no configure flag, no separate install
prefix. Every Sequentia path is selected at runtime on `chainparams->has_anchor_header`. The same
binary runs Bitcoin and Sequentia, with the same database format, plugins and RPC surface.

What *is* true, and bites: **a single node's `lightningd` and its subdaemons must be the exact
same build.** Each subdaemon reports its version string, and on a mismatch `lightningd` logs
"version ... : restarting" and re-execs itself. A partial rebuild that leaves mixed version
strings puts a node in a re-exec loop.

## Hazards that are live in the code

- **Mainnet chainparams are placeholders** — all-zero genesis hash, `fee_asset_tag = NULL`, with
  a TODO. The `sequentia` network entry must not be used.
- **Asset channels must use single-funder `fundchannel`.** Dual-funded (v2) opens and splicing are
  not asset-aware: `amount_asset_to_sat()` still asserts the policy asset, and the interactive-tx
  and dualopend paths abort the daemon on a non-policy output.
- **At most one asset per peer.** Origin-side channel selection is asset-blind, so two channels of
  different assets to the same peer can misroute.
- **Policy-asset asserts fire on asset channels and take the whole daemon down.** Reading an output
  amount with the policy-asset-asserting helper on an asset-denominated channel SIGABRTs
  `lightningd` on *both* sides the moment a commitment is negotiated. Read amounts asset-agnostically.
- **A subdaemon that dies at init leaves an unowned zombie channel.** `listpeerchannels` still shows
  `CHANNELD_NORMAL` and a connected peer; the only tell is the missing `owner` field, and every
  payment fails with "unowned" or "First peer not ready". This has happened from two independent
  causes — the split signer not being re-primed with a channel on restart, and a stored
  `penalty_base` crashing channeld deterministically on any channel that has seen a payment. When
  a channel goes dead after a restart, check `owner` first.
- **Wire bytes are the compatibility contract.** The penalty-base fix was made specifically so the
  wire encoding was unchanged and old and new daemons interoperate. Keep that discipline.
- **The testnet was re-genesised on 2026-07-05.** Older chain state is invalid.
- **Cross-asset forwards are refused** at `forward_htlc()` as a deliberate backstop. Do not
  "fix" it into forwarding.
- The certified-frontier committee-stall check **fails open** with a warning when the frontier is
  more than 144 blocks behind. Penalty across an induced anchor reorg is untested.
- Asset ids are stored as a 33-byte version+tag blob; `NULL` means the policy asset. There is no
  asset field in BOLT11 invoices — selection is payer-side only.

The Specula watchtower layer (`speculad/`, `channeld/watchtower.*`, `lightningd/watchtower_store.*`,
`lightningd/onchain_presign.*`, `common/presign_templates.*`, the `penalty_htlcs` table, the
`setpreemptarmed` RPC) is summarised in `doc/sequentia-fork.md` section 7b. Its design note is not
yet published in this repository; the header comment of `speculad/speculad.c` is the fullest
description.

## Working in this repo

- **Repository is public.** Never commit keys, seeds, `hsm_secret`, credentials or tokens. Build
  artifacts and logs have been committed by accident before and had to be untracked — do not
  `git add -A` in a built tree.
- **Commit author:**
  `GracedEternalKingCabbageMan <151803062+GracedEternalKingCabbageMan@users.noreply.github.com>`
- **Always open a pull request, then merge it yourself immediately.** The PR exists so the change
  and its reasoning are recorded, not because anyone is waiting to review it. There is no review
  process. If you are ever told to leave one specific PR open, that applies to that PR only and
  never becomes the default.
- **Deployment is pull-only.** Servers pull this repo from GitHub and build there. Never edit
  source on a server and never copy source or binaries onto one.
- Upstream files should stay diffable against upstream. Prefer new files and runtime-gated call
  sites over sprinkling edits through upstream code.

<!-- BEGIN SHARED AGENT CONVENTIONS: identical in every Sequentia repo. Change it in all of them together. -->
## Working with git and GitHub here

These rules are the same in every Sequentia repository. They are repeated in each
one because this file is the only thing an agent is guaranteed to read, whatever
machine it is working from.

**Nothing pushed to GitHub credits Claude, Anthropic, or any AI tool.** No
`Co-Authored-By: Claude` trailer, no `Claude-Session:` trailer or `claude.ai`
link, no "Generated with Claude Code" in a commit message or a pull request body,
no `claude/*` branch names or session ids, and no mention in source, comments,
docs or issue text. Agent tooling offers several of these by default; compose the
message without them rather than stripping them afterwards.

**Author every commit as**
`GracedEternalKingCabbageMan <151803062+GracedEternalKingCabbageMan@users.noreply.github.com>`.
Never a personal address.

**Every change lands through a pull request that you merge yourself, at once.**
There is no reviewer on this project; the pull request exists so the reasoning is
recorded beside the diff. Branch, push, open it, merge it, delete the branch, all
in one sitting. Pushing straight to the default branch is the rule most often
broken here, and it is the one that costs the record. A pull request stays open
only when the repository owner asks for that specific one, and that never carries
over to the next.

**Name branches `area/short-description`**: `fix/`, `doc/`, `feature/`, `test/`,
`build/`, or the component being changed. Never a tool name, a session id, or
`worktree-*`.

**Write the subject as `area: what changed`**, one line, 72 characters at the
outside and 50 where you can manage it. Put the reasoning in the body, and
explain why rather than what.

**These repositories are public and world-readable.** Never commit private keys,
seeds, `wallet.dat`, RPC credentials, `.env` files or API tokens. Read the diff
before every commit. Secrets belong on the server and in offline backups.

**A file belongs to the repository whose code it describes.** Decide which repo
owns it before writing it; if it landed in the wrong one, move it rather than
deleting it.

**Push the same day you commit.** The testnet server pulls only from GitHub, so a
branch left on one laptop is invisible to every other machine and to the box.
<!-- END SHARED AGENT CONVENTIONS -->
