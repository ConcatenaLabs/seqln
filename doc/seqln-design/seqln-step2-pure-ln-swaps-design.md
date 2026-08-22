# SeqLN Step 2 — Pure-LN asset↔BTC swaps (the "assets at the edges" reach layer) — design

STATUS: design/scoping pass (2026-07-04). Step 1 (asset-aware channels + routing + `pay asset=`) is DONE and
proven (doc `seqln-asset-channels-build-plan.md`). This scopes Step 2, the next phase:
"pure-LN swaps working" before wallet/DEX integration.

Grounding docs: `seqdex/docs/seqdex-lightning-feasibility.md` (§4 the pure-LN mechanism, §3 the anchoring↔LN safety
result, §8 phasing — this is that doc's **Phase 3**), `seqdex/docs/seqln-dex-instant-swap-latency.md` (§"endgame" — this
is the instant-both-ways path), `seqln-phase2-submarine-swaps.md` (§5b/§5c/§5d — the live code seam we reuse).

---

## 0. Where this sits, in one paragraph

Step 1 put issued assets (GOLD, USDX, …) into Sequentia Lightning channels and made SeqLN route them
correctly. Step 2 uses those channels as the **edge** of a Taproot-Assets-style "assets at the edges"
network: BTC is the universal medium in the middle (the global Bitcoin Lightning Network), a Sequentia asset
lives only at the edges, and a **translating node** converts asset-LN ↔ BTC-LN per payment. The result: a
Sequentia GOLD holder can pay/receive over the entire Bitcoin LN with the FX invisible at the edge, and the
swap is **instant and trustless** — no on-chain transaction in the happy path, so the anchor-depth wait that
gates today's submarine swaps disappears.

In the feasibility doc's phasing this is **Phase 3**, which explicitly *depends on* Phase 2 (asset channels)
— now delivered.

---

## 1. Why this, why now (the payoff)

- **Instant.** Both legs are off-chain LN payments settling in hundreds of ms. There is **no on-chain tx in
  the success path**, so no 0-conf risk and — crucially — **no `min_anchor_depth` wait**. Submarine swaps
  (live today) are gated by burying the on-chain asset claim to Bitcoin-anchor depth (~20–30 min); the
  pure-LN swap removes the on-chain leg entirely, so that gate is gone. This is the whole point of
  `seqdex/docs/seqln-dex-instant-swap-latency.md`: *"the 'instant' lives entirely in the pure-LN leg."*
- **Trustless (custody), both directions.** One shared secret reused across two LN payments, stitched at the
  translating node; the node can never take one leg without settling the other. Worst case is a timelock
  refund. Non-custodial exactly like Boltz.
- **Reach.** The medium leg is plain BTC over the *global* Bitcoin LN, so a Sequentia asset can be spent to /
  received from any Bitcoin-LN counterparty in the world — not just a Sequentia-local peer.
- **It composes with what we already shipped.** The asset leg is Step-1 `pay asset=`; the BTC leg + the
  stitching state machine already exist (submarine swaps); the only structural change is *upgrading the asset
  leg from on-chain to LN*, which mostly *deletes* code (the on-chain HTLC + the anchor gate) from the happy
  path.

Honest residual (Principle 1): anchoring is irrelevant to the happy path (nothing touches chain), but the
**dispute/refund path** falls back to on-chain HTLC timeouts, where timelock sizing (below) and anchoring
still matter. "Instant and final" is honest for the pure-LN happy path; the refund path is the rare exception.

---

## 2. Mechanism (both directions)

Shared secret `P`, `H = SHA256(P)`. Two **independently routed** LN payments on two **separate** networks
(SeqLN-on-Sequentia for the asset, the global Bitcoin LN for BTC), stitched at the translating node by `P`.
This is NOT one onion across both networks (the networks are disjoint routing graphs / different chains); it
is two payments glued by the shared secret, exactly the submarine-swap pattern with both legs now off-chain.
The maker's **incoming** (held) leg must carry the **longer** CLTV than the **outgoing** leg it settles.

**Buy GOLD with BTC** (taker holds BTC-LN, wants GOLD in a Sequentia asset channel):
1. Taker generates `P`, `H`. Taker issues (or is quoted) a GOLD invoice on `H` on the Sequentia network.
2. Maker issues a BTC **hold** invoice on `H`. Taker pays it → BTC HTLC held (unsettled) at the maker.
3. Maker pays the taker's GOLD invoice over Sequentia asset-LN (`pay asset=GOLD`) → taker claims GOLD,
   revealing `P`.
4. Maker reads `P` (off its own asset payment's success) and **settles** the held BTC invoice.
Atomicity: the maker only learns `P` by paying GOLD; settling BTC needs `P`. Ladder: BTC (incoming/held) CLTV
> GOLD (outgoing) CLTV.

**Sell GOLD for BTC** (taker holds GOLD in an asset channel, wants BTC-LN): symmetric, hold invoice on the
**asset** leg. Maker issues a GOLD **hold** invoice on `H`; taker pays it in GOLD (held); maker pays the
taker's BTC invoice over Bitcoin LN → taker claims BTC revealing `P`; maker settles the held GOLD invoice.
Ladder: GOLD (incoming/held) CLTV > BTC (outgoing) CLTV.

Either direction needs a **hold invoice on exactly one leg** (the maker's incoming). HTLC (SHA256 reuse) is
the v1 primitive; **PTLC** (point-based, no hash reuse, no wormhole/correlation, scriptless) is the better
long-term target but needs Taproot/Schnorr adaptor work and is not required for v1.

---

## 3. Architecture — the translating node (a.k.a. the edge / interchain router)

The translating node is the **seqob maker in the LP role**, running two Lightning daemons:
- a **SeqLN-on-Sequentia** node — holds the asset channels (Step 1: GOLD/USDX/tSEQ), asset-aware routing;
- a **SeqLN-on-Bitcoin** node — a real Bitcoin-LN node (SeqLN runs `--network=testnet4`/bitcoin unchanged;
  proven live in `seqln-phase2-submarine-swaps.md` §5c: genuine BTC channels + bidirectional payments).

A single Go coordinator (the existing swap orchestrator) stitches the two by the shared `P`. The taker needs
LN liquidity only on the side they start from (asset-LN to buy-with-nothing… no: to *buy GOLD* the taker pays
BTC, so needs BTC-LN outbound; to *sell GOLD* the taker pays GOLD, so needs an asset channel). Receiving a leg
needs inbound liquidity on that network — the usual LN constraint.

"Assets at the edges" mapping: the **middle** is BTC over the global LN (any hop count, asset-blind); the
**edges** are Sequentia asset channels; the **edge node** = this translating node. The FX (GOLD↔BTC rate) is
applied once, at the edge, per an RFQ quote (§5.3).

---

## 4. Reuse map (grounded in the live code — the elegant part)

Everything below already exists in seqdex's `pkg/xchain` (branch `phase2-submarine-ln`). Step 2 is mostly *reuse + delete*, not new construction.

- **`LNLeg` interface + `clnLNLeg`** (`leg_lightning.go`) — a minimal CLN unix-socket JSON-RPC client. Already
  has `Pay(bolt11, wantHash, amountMsat)` (verifies `payment_hash == H` and the revealed preimage) and the
  hold methods `CreateHoldInvoice`/`WaitHeld`/`SettleHold`/`CancelHold`. **This is the whole asset leg** — I
  instantiate a *second* `clnLNLeg` pointed at the Sequentia SeqLN node's rpc socket. Delta: teach `Pay` to
  pass `asset=<id>` to CLN `pay` (Step-1 param) so it routes in the asset. (~small.)
- **The preimage/HTLC primitive** `pkg/xchain/primitive.go` — `HashLock` (`:99`) behind a `LockPrimitive`
  interface (`:76`), so a PTLC/adaptor can drop in later (§5.4). Shared `H` across both legs, unchanged.
- **seqob order book = the quote source** — `api-spec/protobuf/seqob/v1/offer.proto`: `Offer` (`:27`) uses an
  integer `offer_amount`/`want_amount` ratio (no float price) with a **mandatory `expires_at_unix` (`:43`)`;
  `LightningTerms` (`:92`) already carries `ln_direction` (`ASSET_ONCHAIN_FOR_BTC_LN`/`BTC_LN_FOR_ASSET_ONCHAIN`),
  `maker_issues_hold_invoice` (`:97`), `max_0conf_amount` (`:98`). Whole-oneof signing in
  `internal/seqob/offer/offer.go`. **There is NO interactive RFQ today — the resting signed offer IS the quote,
  `expires_at_unix` is its expiry** (§5.3).
- **Opaque courier / relay** — `relay.proto` `SwapMsg{session_id,ciphertext}` (`:71`, relay never decrypts);
  router `internal/seqob/session/router.go` (has a `ReorgWatcher` reopen hook `:38`); sealed handshake atoms
  `internal/seqob/client/xcourier_submarine.go` (`XcSubTermsRequest`/`XcSubTerms`/`XcSubAssetFunded`/
  `XcSubAssetLocked`/`XcSubSettled` `:31–37`) — pure-LN renames the "asset funded" atom to "asset invoice/held".
- **Binaries** — `cmd/seqob-maker` (`-mode lightning -side buy|sell -ln-socket`; `serveSubmarine` dispatches on
  `ln_direction`); taker `cmd/seqob-cli` `xsublift` (sell asset for BTC-LN) / `xsubbuy` (buy asset with BTC-LN).
- **Step 1** — `pay asset=<id>` is the asset-leg payment primitive; the asset channels are the LP inventory.

**The one asymmetry to fix (the crux of the work).** The **BTC leg is cleanly abstracted** (`LNLeg` interface
`leg_lightning.go:40`; on-chain `btcBackend` interface `orchestrator.go:56`), but the **asset (Sequentia) leg is NOT
— it is hardcoded**: `SubmarineSwap` embeds a concrete `*Swap` (`submarine.go:32`) whose Sequentia-leg ops
(`LockSEQLeg`/`ClaimSEQLeg`/`RefundSEQLeg`/`VerifySEQLeg`/`WatchSEQClaim`, `orchestrator.go:113–251`,
`maker.go:112`) call a concrete `*ElementsLeg` (`leg_elements.go`) + `*Chain` (`chain.go`). There is **no
`AssetLeg` interface**, so "add a second `LNLeg`" needs a small refactor. Two options:
  - **(minimal, do first)** implement asset-LN backends at the **`Sub*Ops` seam** — the per-role settlement
    interfaces the drivers run against (`internal/seqob/client/xdriver_submarine.go:26` `SubMakerOps`/`SubTakerOps`,
    `..._reverse.go:34`), today satisfied by `LiveSub*Ops` wrapping `*SubmarineSwap`. The drivers
    (`RunMaker/TakerSubmarine*`) are written purely against these interfaces + the courier and never touch
    `ElementsLeg`, so blast radius is contained. The seam atoms (`NormalParams`/`ReverseMakerSecretParams`,
    `submarine.go:133,:382`) carry on-chain outpoint fields (`SeqRedeemScript`, `SeqTxID/Vout`, `SeqLocktime`)
    that an asset-LN leg replaces with channel/invoice identifiers.
  - **(deeper, cleaner end-state)** introduce an `AssetLeg` interface mirroring `LNLeg`; give a new `PureLNSwap`
    **two LN-style legs** (asset + BTC), on-chain leg gone. Preferred once M2 proves the seam.

- **Anchor gate `VerifySeqAnchorBuried`** (`submarine.go:73,:108`) — waits for the on-chain asset claim to bury
  to `min_anchor_depth`. Pure-LN happy path has **no on-chain claim → the gate is removed** (kept only on the
  on-chain refund/timeout fallback). This deletion *is* the latency win.
- **Hold invoices — net-new wiring, not just a plugin deploy.** `clnLNLeg` already *calls* the daywalker90
  `holdinvoice` methods (`leg_lightning.go:165–217`), BUT the scout confirmed the **hold-invoice REVERSE engine
  is implemented yet NOT wired into any binary** — only the **plain-invoice / taker-gated maker-secret reverse**
  (`OfferReverseMakerSecret` `submarine.go:411`, driven by `xsubbuy`) is reachable end-to-end;
  `maker_issues_hold_invoice`/`max_0conf_amount` are declared but unused. So Step 2 must (a) deploy the plugin
  on the **Sequentia** SeqLN node for the asset hold invoice (§5.1, confirm it holds an *asset* HTLC), and
  (b) actually wire a hold-invoice flow through the drivers/binaries.

Net-new is contained: an asset-aware `Pay` on `clnLNLeg`; asset-LN `Sub*Ops` (or an `AssetLeg` interface); a
`PureLNSwap` orchestration (the submarine flow minus the anchor gate); the holdinvoice plugin on the Sequentia
node + hold-flow wiring; and the seqob pure-LN direction + quote reuse.

---

## 5. Hard problems / design decisions

### 5.1 Hold invoices on the ASSET leg (prerequisite)
The sell direction needs a **GOLD hold invoice** on the Sequentia SeqLN node. A Sequentia "asset invoice" is
today just a normal BOLT11 whose msat amount is interpreted as asset-atom-msat and paid via `pay asset=GOLD`
(Step 1). The `holdinvoice` plugin holds via the `htlc_accepted` hook, which is asset-agnostic (it holds
*any* HTLC), so it *should* hold an asset HTLC — but this must be **verified on a Sequentia (elements) SeqLN
node**, since the plugin was validated on the Bitcoin node. This is M0. (Relates to task #20.)

### 5.2 Timelock laddering across TWO LN networks (get the units right)
Feasibility §3 is load-bearing here. The two legs live on chains with different block cadence (~6–7× ratio,
Sequentia faster). Rules:
- Size every timelock in **wall-clock**, converting each leg's CLTV by its own chain's block time.
- The maker's **incoming/held** leg CLTV must exceed the **outgoing** leg's by a safe margin (standard hop
  laddering), computed in wall-clock, not raw block counts.
- Per-hop CLTV delta ≈ Bitcoin's ~40 blocks (≈6.7 h) ⇒ ~270 Sequentia blocks; `to_self_delay` ~1000–2000
  Sequentia blocks (~1–2 days) for the asset channels.
- Do **not** add a cross-chain reorg buffer for the happy path (no chain touched); the refund path uses each
  leg's native HTLC timeout, and anchoring makes the Sequentia side's finality Bitcoin-bounded (a plus).

### 5.3 RFQ / quote (the two legs have different amounts)
GOLD amount ≠ BTC amount; they are bound by a rate. Decision: the **rate comes from the seqob order book**
(the maker rests a priced GOLD↔BTC offer), and the taker gets a **short-lived quote** (RFQ) before initiating,
so both invoices' amounts are consistent and the maker's spread is locked for the session. Design the quote as
a signed, expiring courier message referencing the resting offer; the maker honors it for the session or the
swap aborts (refund). This mirrors Taproot-Assets' RFQ. Reuse the existing seqob price-server / offer signing;
do not invent a second pricing path (Principle 4: the any-asset fee/rate math is already correct — don't
re-derive it).

### 5.4 HTLC vs PTLC
v1 = HTLC (SHA256 `H` reused on both legs) — reuses all existing machinery, matches submarine swaps. Known
cost: hash reuse is correlatable across the two networks and carries the classic wormhole risk at multi-hop.
PTLC (point `T = P·G`, adaptor signatures) fixes both and is scriptless, but needs Taproot/Schnorr adaptor
work on both legs and is not production-ready in CLN. **Recommend HTLC for v1**, PTLC as a later hardening.

### 5.5 Liquidity (structural, not custody)
The LP must be capitalized on **both** networks (asset channels on Sequentia + BTC channels on Bitcoin). This
is liquidity provision, not custody — the LP can refuse a quote but can never abscond (worst case: timelock
refund). Non-custodial by construction; a capitalized, reputable maker dominates for *liveness*, not trust.
Cannot be removed (you cannot conjure cross-network liquidity). Honest and documented.

### 5.6 Intra-Sequentia cross-asset (GOLD↔USDX) — deliberately OUT of scope for v1
A same-network asset↔asset swap (both legs on SeqLN-on-Sequentia) could in principle be a **single-onion edge
forward** (one payment, the edge node converting GOLD→USDX mid-route per the RFQ quote) — true Taproot-Assets
edge forwarding, and the direct inverse of Step-1's cross-asset *guard*. But it requires the harder work of a
unit-changing forward (in-amount and out-amount are different assets, so `check_fwd_amount` must apply the
quoted rate, and the onion must carry the quote reference). The cross-chain asset↔BTC swap above is
higher-value (reaches the global BTC LN, kills the anchor wait) and reuses far more. **Defer intra-Sequentia
single-onion conversion to a Step-2b**; it is not needed for "pure-LN swaps working."

---

## 6. Milestone breakdown (incremental, each independently verifiable)

> **Load-bearing fact that shapes the order:** the wired submarine flows never use a hold invoice — they lean
> on the on-chain **anchor-depth gate** to make a plain-invoice irreversibility safe. Pure-LN has **no on-chain
> leg → no anchor gate**, so the maker's incoming leg **must** be a hold invoice (held until the maker learns
> `P` by paying the outgoing leg). Hold invoices are therefore *mandatory*, not optional, and are the main
> net-new wiring. Which node holds depends on direction: **buy GOLD → hold on the BTC (Bitcoin) node; sell GOLD
> → hold on the asset (Sequentia) node.** M0 (below) built the hold plugin and proved it holds even an *asset*
> HTLC by an externally-supplied hash with no invoice — so the hold primitive is settled for BOTH legs, and
> buy-first is now preferred just for its shorter cross-chain harness, not for any remaining hold risk.

- **M0 — hold primitive. DONE (2026-07-04).** Built a minimal CLN hold plugin
  (`seqln/contrib/holdinvoice-seq/holdinvoice.py`) exposing exactly `clnLNLeg`'s RPC contract
  (`holdinvoice`/`holdinvoicelookup`/`holdinvoicesettle`/`holdinvoicecancel`) via an async `htlc_accepted`
  hook + `Request.set_result`. **Proven live on a GOLD (asset) HTLC:** hold→settle(P)→`complete`,
  hold→cancel→`failed`, and unregistered payments pass through untouched. **Two findings that shrink M1/M2:**
  (a) it holds fine on an *asset* (elements) HTLC, so §5.1's "does it hold an asset HTLC?" risk is already
  retired; (b) the maker can hold an **externally-supplied hash with NO local invoice and NO knowledge of
  `P`** — the taker generates `P`, the maker only sees `H`, and the taker pays the *bare hash* via `sendpay`
  (as in Step-1 testing), so **create-by-hash BOLT11 / HSM `sign_invoice` is NOT needed** (the anticipated
  hardest dependency, and the daywalker90 Rust plugin, are both eliminated). TODO before production: file-
  backed hold state (survive plugin restart) + amount/cltv validation.
- **M1 — asset `LNLeg` primitives. DONE (2026-07-04, seqdex branch `phase3-pure-ln`, commit `7e7fe94`).**
  `clnLNLeg` gained an `assetID` (+ `NewCLNAssetLNLeg`); `Pay` now passes `asset=` so the maker's asset leg
  routes in its issued asset; new `PayHash` pays a BARE hash (no BOLT11) via `getroute(asset=)`+`sendpay`+
  `waitsendpay` and returns the preimage on settle (the taker's hold-pay primitive); `SettleHold` now passes
  the preimage (matching holdinvoice-seq). **Both proven live** on GOLD channels: `TestLNLegAssetPayLive`
  (asset Pay recovers P) and `TestLNLegPayHashLive` (PayHash of a held bare hash recovers P on settle).
  **Seam simplification:** because `clnLNLeg` now serves both policy and asset, the "two-LN-leg seam" needs
  **no new `AssetLeg` interface** — a pure-LN swap just holds two `LNLeg`s (one `NewCLNAssetLNLeg`, one
  `NewCLNLNLeg`). The `Sub*Ops`-refactor option from §4 is unnecessary for pure-LN; that orchestration is M2.
- **M2 — pure-LN buy-with-BTC, happy path. DONE (2026-07-04, seqdex `phase3-pure-ln` commit `d0d70b9`).**
  `PureLNSwap{assetLeg, btcLeg LNLeg}` (both `*clnLNLeg`, no new interface): `PrepareTakerBuy` (taker issues
  the asset invoice on P) → `MakerRegisterHold` (maker holds incoming BTC on H, no P) → `MakerFulfill` (wait
  held → pay asset leg, learning P → settle BTC; cancels on failure = refund) + `RunTakerBuy` (taker pays the
  BTC hold by bare hash, blocks until settle). **Proven live end to end** (`TestPureLNBuyLive`, ln1 taker /
  ln2 maker; GOLD asset leg + a 2nd Sequentia asset as the BTC stand-in since the mechanism is
  network-agnostic): **settled in ~2.1s, both sides on one shared preimage, NO on-chain tx / NO anchor wait**
  — the headline win over anchor-gated submarine swaps. (Real global-BTC-LN leg = M5.)
- **M3 — sell direction + refund. DONE (2026-07-04, seqdex `phase3-pure-ln` commit `6b4dbab`).** Refactored
  `PureLNSwap` into direction-agnostic incoming/outgoing helpers with thin BUY/SELL wrappers. **SELL** (taker
  sells the asset for BTC = the mirror: maker holds the *asset* leg, pays BTC) settles ~2.1s live. **Atomic
  refund** proven: when the maker's outgoing pay fails (unroutable), `MakerFulfill` cancels the hold and the
  taker's incoming HTLC is failed back — neither leg completes, no partial. (`TestPureLNSellLive`,
  `TestPureLNRefundLive`.) NOTE the on-chain CLTV-timeout path for an *offline* party (§5.2, wall-clock ladder)
  relies on LN's native HTLC timeout + force-close and is not exercised here — a deeper follow-up, not on the
  happy/adversarial-app path proven so far. Also: the refund test is slow (~72s) only because CLN `pay`
  retries an unroutable amount until `retry_for`; a maker would cap retries.
- **M4 — seqob integration. DONE — DRIVER + BINARIES + LIVE E2E, BOTH DIRECTIONS (2026-07-04, seqdex
  `phase3-pure-ln` commits `d499194`+`3216996`+`f22da9d`+`e347291`).** The pure-LN `ln_direction` values (`LnAssetLNForBTCLN`/`LnBTCLNForAssetLN`,
  `IsPureLN`; commit `efc9434`) + the opaque courier atoms (`xcourier_pureln.go`:
  `XcPln{TermsRequest,Terms,AssetInvoice,HoldReady,Settled}`, and `XcMsg.MakerLNNodeID`) + the **driver** over
  the relay (`xdriver_pureln.go`). Handshake: taker→`TermsRequest`; maker→`Terms{maker_ln_node_id,btc_amount,
  seq_amount}`; taker→`AssetInvoice{H,bolt11}` (invoice on a fresh P for its INCOMING leg); maker→`HoldReady`
  (hold registered on H); taker pays the maker's hold by bare hash and blocks; maker pays the taker's invoice
  (learns P), settles the hold, →`Settled`. Taker verifies the revealed preimage is its own P. No on-chain leg
  → no anchor watcher on the happy path. **The driver is direction-parameterized** (`PlnDirection`,
  `holdPayAmts`) because BUY/SELL are genuinely symmetric — the taker always originates P, invoices its incoming
  leg, and pays the maker's hold on its outgoing leg. Neutral seams `PlnMakerOps{HoldNodeID,RegisterHold,
  Fulfill}` / `PlnTakerOps{PrepareInvoice,PayHold}`, with `LivePln{Maker,Taker}{Buy,Sell}Ops` over the M3
  engine's BUY vs `*Sell` wrappers; SELL is the mirror (maker holds the *asset* leg, taker mints a *BTC*
  invoice). Pinned by in-process fake-ops handshake tests for BUY + SELL (one direction-agnostic fake serves
  both) + a bad-terms rejection test; full client suite + daemon build green. **WIRED THROUGH THE BINARIES
  (2026-07-04, commit `f22da9d`):** `seqob-maker -mode pureln` posts a pure-LN offer and serves each swap with
  `RunMakerPureLN` (no Sequentia RPC, no bitcoind — only two lightning-rpc sockets: `-asset-ln-socket`
  SeqLN-on-Sequentia + `-ln-socket` SeqLN-on-Bitcoin; `-side` picks direction, `servePureLN` mirrors
  `serveSubmarine`'s one-in-flight/cancel-after-fill discipline but with no anchor gate). `seqob-cli xpln -side
  buy|sell` is the taker — no on-chain leg means no asset HTLC to fund and no refund state file (a stall unwinds
  via the LN hold timeout); it finds+verifies the matching pure-LN offer by `ln_direction` and drives
  `RunTakerPureLN` over the WS courier. Amounts are msat on both legs (atoms/sats ×1000). **LIVE E2E PROVEN
  (2026-07-04, commit `e347291`):** on the laptop SeqLN regtest (ln2 maker w/ holdinvoice-seq, ln1 taker; GOLD
  `83053bb2…` asset leg + `cbe3b48f…` as the BTC stand-in — the mechanism is network-agnostic, same as the M2/M3
  engine proof), BOTH directions settled end-to-end through the real `seqobd` relay + encrypted courier in
  seconds, both legs off-chain, no anchor wait: BUY (`xpln -side buy`, maker `-side sell`) and SELL (mirror),
  each with maker+taker converging on one preimage. Two fixes fell out: (a) the seqobd **validator** capped
  `ln_direction` at 1 (rejected every pure-LN offer) → widened to 2/3 + require `maker_ln_node_pubkey` for
  pure-LN; (b) added **`-btc-asset`** to maker+cli so the BTC leg can route over a 2nd issued asset (regtest
  stand-in; empty = real BTC-LN). An RFQ quote (§5.3) off the order book is still a fixed-amount offer today
  (whole-swap), same as the submarine wiring — dynamic per-lift pricing is a later refinement, not a blocker.
  **M4 DONE.** CAVEAT (found 2026-07-04 during the Tier-2 capstone): the M4 same-network stand-in ran BOTH legs
  over the SAME node pair (ln1↔ln2) carrying two assets, and verified settle/preimage but NOT per-asset
  movement. The `pay` plugin's route selection does not constrain to the asset channel when a peer is reachable
  via multiple channels, so the GOLD leg could misroute over the cbe3b48f channel — the swap still settles on
  the shared preimage but the wrong asset moves. So the M4 e2e proves the courier + driver handshake but its
  per-asset correctness needs re-verification with the legs on separate peers (as the capstone did). **M5 below
  is unaffected** (its legs are on separate networks). PRIORITY FIX: constrain `pay`'s route selection to the
  payment asset (pay.c / libplugin-pay.c).
- **M5 — real Bitcoin-LN BTC leg (testnet4). DONE, BOTH DIRECTIONS (2026-07-04).** Replaced M4's same-network
  2nd-asset "BTC" stand-in with a GENUINE Bitcoin **testnet4** Lightning leg: a policy-asset HTLC on a
  `bitcoind(testnet4)`-backed SeqLN node (`--network=testnet4`, `-btc-asset` omitted → `NewCLNLNLeg`). **ZERO
  code change** — the `-btc-asset`/validator work from M4 already covered it. Topology (all on the laptop, unix
  sockets local): asset leg on the Sequentia SeqLN pair (ln2 maker / ln1 taker, GOLD `83053bb2…`), BTC leg on a
  real testnet4 SeqLN pair (`seqln-btc2` maker-side w/ holdinvoice / `seqln-btc` taker-side, a 40k-sat testnet4
  channel), backed by the box's fully-synced testnet4 bitcoind over an auto-reconnecting SSH tunnel
  (`-L 48332`). BUY (taker buys GOLD for 5000 real testnet4 sats, preimage `cd39c6a9…`) and SELL (mirror,
  preimage `68194e6a…`) both settled off-chain in seconds through the `seqobd` relay + courier, no anchor wait;
  5000 real testnet4 sats moved each way over the real channel. Ops lessons: (i) the M0 holdinvoice-seq plugin
  is asset-agnostic and works unchanged on a bitcoind-backed (policy-asset) node — verified; (ii) CLN won't
  route while `warning_lightningd_sync` ("Still loading latest blocks") is set, so the testnet4 nodes must be
  fully caught up to the tip before a swap; (iii) DB migrates `282→285` needed `--database-upgrade=true` after
  the `-12→-33` lightningd bump. **"Assets at the edges" now reaches real Bitcoin Lightning.** Remaining reach
  polish (not a blocker): route to a THIRD-PARTY public testnet4 invoice over multiple hops (here the two BTC
  nodes are directly channeled), and a larger BTC channel for bigger amounts.

Then Step 3 (wallet + DEX integration) surfaces this in the wallets (Phoenix-like UX; the instant-swap-latency
doc's action items).

---

## 7. Open questions (as posed before M0; all resolved by the M0-M5 log above)

1. **Direction first?** Buy-GOLD-with-BTC (hold invoice on the BTC/Bitcoin leg — a plain CLN HTLC, lower risk)
   vs Sell-GOLD-for-BTC (hold invoice on the *asset*/Sequentia leg — must first confirm the plugin holds an
   asset HTLC). Neither hold-invoice flow is wired today (the shipped submarine reverses use the on-chain
   anchor gate instead), so both need wiring — but buy-first avoids the asset-hold-invoice risk. Recommend
   **buy-first** to get the headline "instant, no anchor wait" result soonest, then sell.
2. **HTLC now, PTLC later?** Recommend yes (HTLC v1 reuses everything; PTLC is a later hardening).
3. **Scope of "pure-LN swaps" for this step:** just cross-chain asset-LN ↔ BTC-LN (recommended — it's the
   "assets at the edges" reach and the instant path), or also the intra-Sequentia GOLD↔USDX single-onion
   edge-forward (§5.6, harder, deferrable)?
4. **Where the LP/translating node runs:** the box (alongside the existing seqob maker + the SeqLN-on-Bitcoin
   nodes), a deployment decision taken separately. Regtest+testnet4 harness
   for development, as with submarine swaps.
