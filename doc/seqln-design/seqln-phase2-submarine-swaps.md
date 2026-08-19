# SeqLN Phase 2 — Submarine swaps (Sequentia asset on-chain ↔ BTC over Lightning)

Phase 1 shipped policy-asset channels (live open/route/mutual-close). Phase 2 is the first **cross-chain**
SeqLN deliverable, and per the fork spec it can ship before asset channels (Phase 3) because it needs no
asset-aware Lightning and no consensus/BOLT change.

Grounding: `seqln-core-lightning-fork-spec.md` §8, `seqdex/docs/seqdex-lightning-feasibility.md` §5 (Analysis D — the
full submarine-swap safety analysis), and the SeqDEX order-book design (`seqdex/docs/seqdex-orderbook-design.md`), whose
`CrossChainTerms` (=21) + `pkg/xchain` orchestrator already do the on-chain BTC↔asset version. Phase 2 is
that construction with the **BTC leg moved onto Lightning**.

## 1. Scope (v1 = Case A only)

- **Case A — Sequentia asset ON-CHAIN ↔ BTC over VANILLA Lightning.** The only v1 target. The Sequentia
  leg is an Elements HTLC output (asset-agnostic, already built for CrossChainTerms); the BTC leg is a
  plain BOLT11 payment on Bitcoin, so it works with any upstream LN node and needs no asset-LN.
- **Case B (Sequentia asset over LN ↔ BTC on-chain)** needs asset-aware channels (Phase 3); without them
  it collapses into the on-chain↔on-chain swap the DEX already does. Out of scope for Phase 2.
- Both directions of Case A:
  - **normal swap (on-chain → LN):** taker locks the Sequentia asset HTLC; the LN invoice payee holds the
    secret and reveals it by claiming, which lets the taker's counterparty claim the asset.
  - **reverse swap (LN → on-chain):** uses a **hold invoice** so the on-chain receiver generates and
    retains the preimage `P`. This is the important pattern for a DEX taker buying an asset with BTC-LN.

## 2. Mechanism (one shared SHA256 preimage)

`H = SHA256(P)`. Sequentia HTLC: claim path = `P` + receiver sig (spends immediately); refund path =
`OP_CHECKLOCKTIMEVERIFY` (CLTV) + funder sig. The same `H` gates the LN HTLC (BOLT11 payment_hash). Whoever
claims first reveals `P`; the other leg is then claimable with the same `P`. Both chains share SHA256, so
no new cryptography. PTLCs (scriptless, no hash reuse) are the long-term upgrade — deferred.

**The maker is the Boltz role** (spec §8): a well-capitalized, NON-custodial peer that runs an LN node
(Bitcoin) and is the Sequentia on-chain HTLC counterparty. The relay stays a pure matchmaker (couriers
opaque swap-session messages). No escrow, no accounts; worst case is a timelock refund.

## 3. Load-bearing safety (from feasibility §5 / DEX blocker B4)

1. **Timelock ladder:** the leg claimed SECOND (using the now-public `P`) must have the LONGER timelock.
   For asset→BTC-LN the maker's held (incoming) LN leg carries a longer CLTV than the outgoing leg it pays.
2. **Anchor-depth secret-reveal gate (the Sequentia-specific rule).** A Sequentia tx is final only to its
   **Bitcoin-anchor depth**, not its Sequentia confirmations. When the asset HTLC is claimed on-chain, `P`
   becomes public; if the counterparty acts on it and Bitcoin then reorgs out the claim's anchor, the asset
   claim un-happens while BTC has settled → atomicity broken. **Rule: the secret-revealing on-chain claim
   must reach Bitcoin-anchor depth (N > plausible reorg depth) BEFORE the other leg is settled.** Concretely
   the maker must NOT settle the held BTC-LN hold invoice until the taker's asset-claim tx is anchor-deep.
   `min_conf`/`min_anchor_depth = 1` is UNSAFE for this cross-leg point (contradicts real-time reorg
   following). Reuse the SeqLN §6.1 certified+anchor-buried backend + `getanchorstatus` for the depth check.
3. **Boltz-style 0-conf mitigations on the Sequentia leg:** reject RBF (explicit + inherited), never fund
   RBF-signaling txs, fee floor ≥ ~80% of estimate, per-pair 0-conf amount caps. (0-conf is only ever for
   the on-chain HTLC *funding*, never the cross-leg settlement, which waits for anchor depth.)

## 4. Reuse vs net-new

Reuse (already in SeqDEX): the Elements asset HTLC script + `LockSEQLeg`/`ClaimSEQ`/refund; the `pkg/xchain`
orchestrator and its `VerifySeqLegSafe` anchor-ordering check; the relay's opaque swap-session courier; the
order-book intent/`oneof settlement` plumbing; the same-preimage atomicity model.

Net-new for Phase 2:
- **`SubmarineTerms` settlement variant** in the offer schema (the reserved `=22` "Lightning" slot, sibling
  of `SameChainTerms=20` / `CrossChainTerms=21`): fields ~ `bytes payment_hash`, `bytes maker_refund_pub`,
  `uint32 onchain_cltv` (Sequentia HTLC refund height), `uint32 ln_cltv_delta`, `uint64 min_anchor_depth`
  (default > 1, NOT 1), `uint64 max_0conf_amount`, `Direction direction` (normal/reverse), `string ln_hrp`.
- **The BTC-LN leg driver:** create/pay the BOLT11 (normal) or issue a **hold invoice** and settle/cancel it
  on `P` (reverse). CLN provides hold invoices (the `holdinvoice`/`hodl` mechanism or the plugin); the maker
  runs a SeqLN (or any CLN) node on Bitcoin — this is where **SeqLN "same binary runs real BTC" is used for
  the first time** (`--network=testnet4`).
- **The stitching state machine** binding the LN hold invoice to the Sequentia HTLC by the shared `P`, with
  the anchor-depth gate before settle, and the refund/timeout path on both legs.

## 5. Build order (incremental, each verifiable)

1. **SeqLN on Bitcoin testnet4** — verify the same binary runs `--network=testnet4` against a Bitcoin node
   (dual-chain claim). Foundation for the maker's LN leg. (First step; concrete + testable now.)
2. **Hold invoice on the Bitcoin SeqLN node** — issue a hold invoice on a chosen `H`, confirm it stays
   pending until settle/cancel. (Needs a funded BTC channel with inbound liquidity for the receive role.)
3. **Sequentia asset HTLC round-trip** — lock a testnet asset to `H`+CLTV, claim with `P`, and separately
   exercise the CLTV refund. Reuse SeqDEX `pkg/xchain` primitives; assert on-chain.
4. **`SubmarineTerms` schema + relay courier** — add the =22 variant + opaque submarine-session messages.
5. **Maker stitching + anchor-depth gate** — the state machine; the maker settles the held BTC-LN invoice
   only after the taker's asset-claim reaches `min_anchor_depth` Bitcoin-anchor blocks.
6. **End-to-end + refund** — a non-custodial asset↔BTC-LN swap on testnets, and the refund path exercised.

## 5b. Implementation seam (mapped against the live seqdex code)

The cross-chain maker already exists in `~/seqdex/daemon` (branch `main`; SHARED with another session —
coordinate). Phase 2 plugs into it; do NOT rebuild the SEQ leg or the anchor gate.

- `pkg/xchain/orchestrator.go` — the 5-step swap: (1) Alice locks the BTC leg (longer CLTV), (2) Bob locks
  the SEQ leg (shorter CLTV), (3) **`VerifySeqLegSafe`** = the anchor-depth gate (SEQ leg's block
  `anchorheight >= Hp` AND `getanchorstatus == ok` AND quorum-certified; commit `444d26a` added the
  certification requirement), (4) Alice redeems SEQ with the preimage (reveals it on-chain), (5) Bob reads
  the preimage and redeems the BTC leg. The BTC leg is **pluggable via the `btcBackend` interface**
  (`pkg/xchain/btc_backend.go:26`): `LockBTCLeg` / `VerifyBTCLeg` / `ClaimBTCLeg` / `RefundBTCLeg`
  (`elementsBTCBackend`, and `NewSwapBitcoin` for real testnet4).
- **The catch:** that interface assumes an ON-CHAIN funded HTLC — `LockBTCLeg` returns a funded P2SH +
  block height, `ClaimBTCLeg`/`RefundBTCLeg` return txids. A Lightning leg has none of that: it's a hold
  invoice + an off-chain HTLC inside a channel, settled/cancelled by preimage. So a Lightning backend does
  NOT fit `btcBackend` cleanly.
- **Recommended approach:** generalise the parent leg to a `swapLeg` interface with two implementations —
  the existing on-chain-HTLC leg, and a new `lnLeg` (hold invoice). `lnLeg.Lock` = issue/observe a hold
  invoice on `H` (reverse) or prepare to pay a BOLT11 (normal); `lnLeg.Claim` = settle the hold invoice with
  the preimage; `lnLeg.Refund` = cancel/let it time out. The orchestrator's step order and the SEQ-leg
  anchor gate (`VerifySeqLegSafe`) stay IDENTICAL — the only Sequentia-safety rule is unchanged: the maker
  settles the BTC-LN hold invoice ONLY after Alice's SEQ redeem is anchor-deep (step 3 before step 5's
  LN settle). The `lnLeg` talks to a SeqLN/CLN node on Bitcoin (step 1 of §5, done) via its RPC.
- **Hold invoices:** core CLN has the primitives (`createinvoice`, the `htlc_accepted` hook,
  `preapproveinvoice`) but no turnkey hold command — the `lnLeg`/maker implements the hold via the
  `htlc_accepted` hook (accept-and-hold until preimage known, then resolve), à la Boltz. This is the main
  net-new LN plumbing.
- **Infra to test end-to-end:** a funded BTC(testnet4) channel with inbound liquidity for the receive role
  (hold-invoice payee). Two local SeqLN-on-Bitcoin nodes with a channel between them is the simplest
  self-contained harness once one has testnet4 coins.

## 5c. Progress (live on testnet)

- **Step 1 done:** the same SeqLN binary runs `--network=testnet4` on real Bitcoin (bcli -> box testnet4
  bitcoind via tunnel, `/usr/local/bin/bitcoin-cli`), fully synced, "Server started" — dual-chain validated.
- **BTC-LN channel + bidirectional payments done** (the maker's LN-leg foundation): two SeqLN-on-Bitcoin
  nodes, funded node 1 with 0.0008 tBTC from the `w` wallet (left the DEX `seqdex-mm-btc` untouched),
  opened a 40k-sat channel (`fundchannel ... push_msat=10000000msat`) -> CHANNELD_NORMAL after one
  testnet4 block, and routed payments BOTH ways (3000 sat n1->n2 and 2000 sat n2->n1, both complete;
  `lntb` invoices). So SeqLN does genuine Bitcoin Lightning end to end, both send and receive.
- Two fixes were needed and are general (committed to `sequentia-stable`): (a) `--force-feerates` now
  satisfies `unknown_feerates()` (`chaintopology.c`) so a node whose backend does no fee estimation
  (Sequentia, or a sparse testnet4 node) can open channels with `--force-feerates`; (b) operational
  gotcha: CLN reserves `min-emergency-msat` (25k sat default, anchor force-close fees) on the Bitcoin
  path, so leave headroom above channel + funding-fee + 25k when sizing a small funded node. Also: keep
  lightningd + all subdaemons + plugins at the SAME build (version-string check `bad version` kills the
  node if you rebuild only lightningd).
- **LN leg + stitching state machine IMPLEMENTED (compiles, vet-clean) in the seqdex maker daemon**
  (`pkg/xchain`, branch `phase2-submarine-ln`):
  - `leg_lightning.go` — the `LNLeg` interface + `clnLNLeg`, a minimal CLN `lightning-rpc` unix-socket
    JSON-RPC client. `NORMAL`-direction `Pay(bolt11, wantHash, amountMsat)` uses CLN core (`decode` +
    `pay`) and works against a STOCK SeqLN/CLN node; it refuses to pay unless the invoice's `payment_hash`
    equals the swap `H` and double-checks the revealed preimage hashes to `H`. `REVERSE`-direction
    `CreateHoldInvoice`/`WaitHeld`/`SettleHold`/`CancelHold` drive the hold-invoice plugin (see §5d).
    (Three live-CLN bugs were found + fixed here: the decoder command is `decode` not `decodepay`; `pay`
    takes `invstring` not `bolt11`; and the request encoder must set `SetEscapeHTML(false)` — Go's default
    turns `<>&` into `\uXXXX`, which CLN's JSON parser rejects, e.g. a description containing `->`.)
  - `submarine.go` — `SubmarineSwap` EMBEDS `*Swap` purely to reuse the SEQ leg unchanged
    (`VerifySEQLeg`/`LockSEQLeg`/`ClaimSEQLeg`/`RefundSEQLeg`/`WatchSEQClaim`/`InjectSecret`); the embedded
    `btcBackend` is nil and never touched (the BTC leg is the `LNLeg`). `RunNormal` and `RunReverse` are the
    two Case-A flows, each with its refund/cancel path on error.
  - **Anchor-depth gate implemented as `VerifySeqAnchorBuried`** (NOT `VerifySeqLegSafe`): it requires the
    relevant Sequentia block's Bitcoin anchor to be BURIED by `min_anchor_depth` Bitcoin blocks
    (`node anchor tip − block anchorheight >= min_anchor_depth`), plus quorum-certified + `anchorstatus==ok`.
    `min_anchor_depth` is enforced `>= 2` (1 is unsafe, §3.2). `NORMAL` gates the SEQ *funding* before
    `Pay`; `REVERSE` gates the taker's SEQ *claim* (which revealed `P`) before `SettleHold`. This is a
    deliberate WAIT for real-time anchoring to bury the tx — consistent with anchoring supremacy (it does
    not block a reorg; it declines the irreversible LN action until a reorg is implausible).
  - Helpers added: `hexEq`/`hashEqualsPreimage` (`util.go`), errors `ErrLNLegInvalid`/`ErrLNLegTimeout`.
- **NORMAL direction PROVEN END TO END, LIVE** (`TestSubmarineRunNormalLive`, env-gated; passing run
  2026-07-03): the SEQ asset leg on the anchored two-chain regtest, the BTC leg on REAL testnet4 Lightning
  (the two SeqLN-on-Bitcoin nodes + the 40k channel). The run: taker mints a BOLT11 on a chosen preimage `P`
  (payment_hash `H`) and funds the SEQ HTLC (claim=maker); the maker verifies it, the anchor gate REFUSES
  while shallow (depth 0 < 3), the parent (Bitcoin-stand-in) chain is advanced to bury the anchor to depth 3,
  then `RunNormal` pays the invoice over testnet4 (learning `P`), and claims the SEQ asset with `P` — the
  same `P` settles both legs, SEQ claim confirmed with the preimage on-chain. This is the NORMAL half of the
  §6 exit criterion WITH the anchor-depth secret-reveal gate enforced live. The LN-leg primitive alone is
  also covered by `TestLNLegPayLive`. (The anchor gate is demonstrable deterministically because the regtest
  SEQ chain anchors to a parent chain we control — no waiting on real Bitcoin blocks.)
- **REVERSE direction PROVEN END TO END, LIVE — plugin-free (maker-secret mode)** (`TestSubmarine
  ReverseMakerSecretLive`, env-gated; passing run 2026-07-03). See §5e for why there are two REVERSE modes.
  The run: the maker generates `P`, locks the asset HTLC (claim=taker) and issues a PLAIN invoice on `H`; the
  taker verifies the HTLC and its anchor-depth gate REFUSES to pay while shallow (depth 0 < 3); the anchor is
  buried to depth 3; the taker pays the invoice over REAL testnet4 Lightning and LEARNS `P` from the
  settlement; the maker receives the sats; the taker independently claims the asset with `P`. So BOTH
  directions of Case A now complete live with the anchor-depth secret-reveal gate enforced (maker-side
  pre-pay in NORMAL; taker-side pre-pay in this REVERSE mode).
- **Optional enhancement (not required for the exit criterion): the hold-invoice REVERSE** (`RunReverse` +
  the hold methods) is fully IMPLEMENTED but its live proof needs a hold-invoice plugin on the maker's
  `--network=testnet4` SeqLN node (§5d). It buys the FULLY-maker-non-custodial property (§5e). A correct hold
  invoice must construct a BOLT11 the node routes to but does NOT auto-settle (the node must not know `P`),
  then hold the `htlc_accepted` hook and resolve it with the `P` learned from the taker's on-chain SEQ claim
  — the tree's `tests/plugins/hold_htlcs.py` shows the hook-hold but not the invoice construction, so use/port
  the daywalker90 `holdinvoice` plugin (the tree has in-tree `cln-plugin`/`cln-rpc` crates to build against,
  avoiding crates.io version drift). Deploying a plugin on the box's live node is a step to confirm with
  Andreas first. (The SEQ-leg CLTV refund used by both modes' `RefundReverseSEQ` is already proven by
  `TestCrossChainSwap`.)

## 5d. Hold invoices: plugin over RPC (decision)

The original plan (§5b) anticipated implementing the hold inside the Go maker via CLN's `htlc_accepted`
hook. That would make the Go maker itself a CLN plugin (an in-process subdaemon subscribed to the hook),
which is invasive. Instead the maker stays a plain RPC CLIENT of its node and the hold is provided by the
mature CLN **`holdinvoice` plugin** (daywalker90; Rust), which exposes exactly the RPC methods
`clnLNLeg` calls — `holdinvoice`, `holdinvoicelookup` (state `accepted`/`settled`/`cancelled`),
`holdinvoicesettle`, `holdinvoicecancel` — all backed by the `htlc_accepted` hook internally. This keeps the
"maker runs a SeqLN/CLN node and talks to it over RPC" architecture intact and avoids reimplementing a
hold-invoice state machine. Deploy step: build/load that plugin on the maker's `--network=testnet4` SeqLN
node; if the deployed plugin's method/param names differ, they are localised to `clnLNLeg` (leg_lightning.go).
The NORMAL direction needs NO plugin (core `pay` only).

## 5e. Two REVERSE modes (who generates P, where the anchor gate lives)

Both are non-custodial (worst case a CLTV refund on each leg) and both enforce the same anchor-depth rule;
they differ in WHO generates `P` and therefore WHERE the gate sits and what a stock node supports.

- **maker-secret / taker-gated (SHIPPED, plugin-free — `OfferReverseMakerSecret`).** The MAKER generates
  `P`, locks the asset (claim=taker) and issues a PLAIN invoice on `H`. Paying the invoice settles the
  BTC-LN irreversibly and reveals `P`; the taker then claims the asset. The gate is the TAKER's, BEFORE
  paying: it must verify the asset HTLC (`VerifySEQLeg`) and that it is anchor-buried
  (`VerifySeqAnchorBuried >= min_anchor_depth`) first, because a plain invoice cannot be refunded once paid.
  Runs against a stock SeqLN/CLN node. This is the mode proven live.
- **hold-invoice / maker-gated (IMPLEMENTED, needs the plugin — `RunReverse`).** The TAKER generates `P`;
  the maker issues a HOLD invoice on `H` and settles it only AFTER the taker's on-chain asset claim (which
  reveals `P`) is anchor-buried. The gate is the MAKER's, before settling. This is strictly more
  maker-protective (the taker's LN payment auto-refunds if the maker never settles), which is why it is worth
  keeping for a well-capitalized public maker — but it needs the hold-invoice plugin.

Pick maker-secret for a wallet/DEX that controls (or trusts) its taker client to gate; pick hold-invoice for
a public maker serving arbitrary takers. `clnLNLeg` implements the LN primitives for both.

## 6. Exit criterion

A non-custodial Sequentia-asset ↔ BTC-over-LN swap completed on testnets (both directions of Case A), with
the timeout/refund path exercised, and the anchor-depth secret-reveal gate enforced (the party taking the
irreversible LN action provably waits until the asset side is anchor-deep).

**STATUS: MET (2026-07-03).** Both directions complete live end to end — the SEQ asset leg on the anchored
two-chain regtest, the BTC leg on real testnet4 Lightning:
- NORMAL: `TestSubmarineRunNormalLive` (maker gates the SEQ funding, pays, learns `P`, claims the asset).
- REVERSE: `TestSubmarineReverseMakerSecretLive` (maker-secret mode; taker gates before paying, learns `P`,
  claims the asset).
Both enforce `VerifySeqAnchorBuried >= min_anchor_depth` (each shown REFUSING a shallow anchor, then
proceeding once buried). The refund path (`RefundReverseSEQ` → SEQ-leg CLTV) is covered by
`TestCrossChainSwap`. Remaining as an OPTIONAL enhancement (§5e): the hold-invoice REVERSE (`RunReverse`,
fully-maker-non-custodial), which is coded but awaits a hold-invoice plugin on the node.
