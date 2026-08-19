# Sequentia Lightning: a Core Lightning fork. Design and development plan

A plan for forking Core Lightning (CLN, formerly c-lightning) to run Lightning on Sequentia, with the
same client also able to run on real Bitcoin. "Sequentia" means the Sequentia testnet today and the
Sequentia mainnet after launch; "Bitcoin" means testnet4 today and mainnet later. This document is the
handover spec for the implementing session/team. It builds on the safety analysis in
`seqdex/docs/seqdex-lightning-feasibility.md` (anchoring and LN, timelock sizing, swap designs) and on fresh
research into the CLN codebase (master `066056d915`, v26.06.2) and assets-on-Lightning prior art.

Terminology guard: "anchor outputs" is a Lightning commitment-format feature (CPFP anchors);
"Bitcoin anchoring" is Sequentia's consensus mechanism. This document always writes "LN anchor
outputs" for the former and "Bitcoin anchoring / anchor depth" for the latter.

## 0. Summary of the design

1. Fork current CLN (not the 2019 Liquid branch; its content was upstreamed and is maintained in
   master, CI-enforced under `liquid-regtest` against Elements Core 23.2.1, one minor version behind
   Sequentia's 23.3.3 base). One binary, all networks: the fork adds `sequentia`,
   `sequentia-testnet`, `sequentia-regtest` rows to CLN's single chainparams table while the Bitcoin
   networks remain untouched and upstream-compatible.
2. "Same client on both chains" v1 = one `lightningd` binary, one daemon instance per chain (the
   universal pattern; CLN is strictly single-network per daemon), plus a supervisor/swap plugin that
   coordinates the pair. Single-daemon dual-chain is spec-legal (one node_id may announce channels on
   several chains; BOLT 7 node_announcement is chain-agnostic) and is kept as a v2 differentiator,
   not a v1 requirement.
3. Phase A ships Sequentia support at parity with CLN-on-Liquid: channels denominated in the chain's
   policy asset, explicit fee outputs, PSET, transparent addresses. Two Sequentia-specific patches:
   the block-header parser (Sequentia inserts anchor height + anchor hash into the header) and the
   finality/depth policy (below).
4. Phase B is the genuinely novel deliverable: asset-denominated channels. Nobody has ever shipped or
   even publicly specced asset channels for an Elements chain (Blockstream announced them in 2019 and
   never built them; CLN treats non-policy assets as zero value). Sequentia is structurally the right
   chain to be first: native asset outputs remove the entire client-side overlay apparatus Taproot
   Assets needs on Bitcoin, any-asset fees remove Liquid's two-asset problem (needing L-BTC to run a
   USDT channel), and transparent-by-default matches CLN's no-CT channel machinery exactly.
5. Finality design: a certified Sequentia block is final except under a Bitcoin-anchor reorg (tail
   truncation only). Channels become usable at minimum_depth 1 on a certified block; public
   announcement waits for the anchor to be k Bitcoin blocks deep (SCID stability). Timelocks are
   sized in wall-clock, not copied block counts. A Sequentia-aware backend plugin (`seq-bcli`) feeds
   lightningd only certified blocks and sources feerates from the any-asset fee system.
6. Cross-chain: submarine swaps between the two instances first (PeerSwap is the reusable base; it is
   already a CLN plugin and already Elements-aware), integrated with the SeqOB order book via the
   already-reserved `LightningTerms = 22` settlement variant. Cross-asset anything is never free:
   signed RFQ quotes with seconds-scale expiry (the free-option rule).

## 1. Goals and non-goals

Goals
- G1: `lightningd --network=sequentia-testnet` runs against a Sequentia node over Elements RPC;
  BOLT-compliant channels and payments between Sequentia LN nodes.
- G2: the same binary runs `--network=testnet4|bitcoin` unchanged (upstream parity preserved; the
  fork stays rebase-able on upstream CLN).
- G3: asset-denominated channels (one asset per channel, explicit amounts), with on-chain fees for
  commitment/closing/penalty transactions payable in the channel's own asset.
- G4: correctness under Bitcoin anchoring: reorg (tail-truncation) handling, anchor-aware depth
  policy, wall-clock timelocks, watchtower guidance.
- G5: BTC-over-LN <-> Sequentia-asset swaps (submarine swaps) between a user's two instances or
  against a maker, pluggable into the SeqOB order book.
- G6: mainnet-ready parameterization: everything Sequentia-specific keyed off chainparams so mainnet
  is a new table row (genesis hash, HRP, ports), not new code.

Non-goals (v1)
- Confidential (blinded) amounts inside channels. Deferred permanently unless a strong need appears;
  transparent channels are the design, matching the chain's default.
- Multi-asset inside ONE channel (the dead BOLT PR #72 model). One asset per channel is the settled
  consensus across tapd, RGB, and this design.
- Free-floating cross-asset routing in gossip. Cross-asset conversion happens only at explicit
  RFQ-quoting boundary nodes.
- Single-daemon dual-chain operation (v2 candidate).
- LN anchor-output commitments and taproot channels on Sequentia at parity with Bitcoin: inherited
  as OFF on Elements-family networks from upstream (static-remotekey commitments today). Track
  upstream draft PR #8097 (enables LN anchors + taproot channels on liquid) and adopt when it lands
  rather than maintaining our own variant.

## 2. Baseline assessment (what the fork inherits)

Verified state of CLN master relevant to us:
- Chainparams: one table in `bitcoin/chainparams.c` with 7 networks including `liquid` and
  `liquid-regtest`; per-network fields include `onchain_hrp`, `lightning_hrp`, `bip70_name` (must
  equal the node's `getblockchaininfo.chain`; checked at startup), genesis hash (= BOLT chain_hash),
  `is_elements`, and `fee_asset_tag` (33 bytes: 0x01 explicit prefix + policy asset id in internal
  byte order). These are the only hardcoded asset ids in the tree.
- Elements machinery: explicit fee output added automatically in tx construction
  (`elements_tx_add_fee_output`), elements weights, PSET (PSBT v2 + `WALLY_PSBT_INIT_PSET`),
  elements sighash, ~25 files with `is_elements` paths. libwally elements support is compiled in by
  default and is chain-agnostic (asset ids and genesis are runtime parameters).
- Wallet and watch paths skip any output whose asset is not `fee_asset_tag`
  (`amount_asset_is_main`); "sat" in CLN means 1 unit of the chain's fee asset. This is the single
  deep assumption Phase B must break.
- Addresses: bech32 only, unblinded, using the chain's `onchain_hrp`; no blech32 anywhere; P2TR
  refused on elements. Matches Sequentia transparent-by-default; blech32 (`tsqb`/`sqb`) is simply
  out of scope for LN.
- Anchors/taproot/splicing: disabled on elements (`options.c` strips the anchors feature; splicing
  tests skipped: "sequentiad doesnt yet support PSBT features we need").
- Backend seam: `plugins/bcli.c` implements exactly 5 documented methods (getchaininfo,
  getrawblockbyheight, estimatefees, sendrawtransaction, getutxout) against `sequentia-cli`; a
  replacement backend plugin is a first-class, documented substitution point
  (`--disable-plugin bcli`).
- minimum_depth: chosen by the fundee in accept_channel; CLN's default `funding_confirms` is already
  1 on testnet-class networks (3 on mainnet), per-open overridable.
- CI: the full integration suite runs under `TEST_NETWORK=liquid-regtest` as a dedicated matrix job,
  against Elements Core 23.2.1. Our fork adds an equivalent `sequentia-regtest` job.
- History: the 2019 "Lightning on Liquid" branch (`cdecker/lightning#lightning-elements`, invoice
  prefix `lnex`) was upstreamed in v0.8.0; L-BTC only; issued-asset channels were announced but no
  code or spec was ever published. Starting from that branch would be archaeology; starting from
  master inherits the same work, maintained.

## 3. Phase A: Sequentia network support (parity with CLN-on-Liquid)

### 3.1 Chainparams rows

Add three rows (mainnet values fixed at re-genesis/launch):

| field | sequentia-testnet | sequentia (mainnet) | sequentia-regtest |
| --- | --- | --- | --- |
| onchain_hrp | `tb` (shared with Bitcoin testnet by design) | `bc` (shared) | `ert`-style local hrp per our regtest chainparams |
| lightning_hrp | `tsq` (invoices `lntsq...`) | `sq` (invoices `lnsq...`) | `rsq` (invoices `lnrsq...`) |
| bip70_name | the EXACT string a live node returns from `getblockchaininfo.chain` (verify at implementation; current testnet datadirs suggest a legacy name, see Open question Q3) | set at launch | ditto |
| genesis_blockhash (chain_hash) | Sequentia testnet genesis | mainnet genesis | regtest genesis |
| cli | `sequentia-cli` (our binary name) with the right `-chain=` arg | ditto | ditto |
| is_elements | true | true | true |
| fee_asset_tag | 0x01 + tSEQ asset id (internal byte order) | 0x01 + SEQ asset id | 0x01 + regtest policy asset |
| new: has_bitcoin_anchor | true | true | per regtest config (likely false) |

Notes:
- The shared `tb`/`bc` on-chain HRP is deliberate (the dual-chain shared-address invariant). The
  BOLT11 prefix must NOT collide, hence fresh `lightning_hrp` strings; signet (`tb` on-chain, `tbs`
  invoices) is the in-tree precedent for onchain_hrp differing from lightning_hrp. Unknown-prefix
  invoices are safely unpayable by stock wallets (BOLT 11: reader MUST fail an unknown prefix).
- chain_hash: CLN never verifies the genesis bytes against the node (it verifies only bip70_name),
  and liquid's entry uses display order while bitcoin entries use internal order. Pick internal byte
  order for consistency with the bitcoin rows and document it.
- Equal-standing note: Phase A denominates in tSEQ only because upstream CLN hardwires one fee asset
  per chain. This is engineering scaffolding on the way to Phase B, not a statement that the
  Sequence token is privileged; the design goal remains any asset as a first-class channel unit.

### 3.2 The block-header parser patch (the one consensus-format change)

Sequentia inserts `m_anchor_height` (u32 LE) + `m_anchor_hash` (32 bytes) into the block header
after `block_height` and before the dynafed/legacy-proof fields, in both serialization branches,
committed under hashing (`src/primitives/block.h:226-249, 262-307`; `g_con_bitcoin_anchor=true` +
`g_con_blockheightinheader=true` on Sequentia networks). Sequentia forces dynafed OFF and uses the
legacy signed-blocks CProof, which maps to CLN's already-implemented legacy path (challenge hashed,
solution excluded).

Change: in `bitcoin/block.c` (`bitcoin_block_from_hex` and the header hashing), parse and hash the
extra 36 bytes at that position, gated on the new chainparams bool `has_bitcoin_anchor`. Verify the
PoS proof serializes as the expected two var-length fields. Everything else (txs, PSET, fee outputs)
is stock Elements and needs no change.

### 3.3 BOLT profile for Sequentia

- chain_hash: Sequentia genesis in every open_channel/open_channel2, channel_announcement,
  channel_update, gossip query, and the init `networks` TLV. Unknown-chain messages are ignored per
  BOLT; Bitcoin peers and Sequentia peers can share TCP connections or be kept separate; both work.
- BOLT 12: `offer_chains` MUST always be set on Sequentia offers (an absent chains field implies
  Bitcoin mainnet by spec).
- Feature bits: none needed for Phase A. Phase B introduces one (section 5).
- Gossip: standard, scoped by chain_hash. Sequentia gossip never leaks into Bitcoin gossip stores
  and vice versa (upstream behavior).

### 3.4 The `seq-bcli` backend plugin and finality policy

Replace/wrap bcli on Sequentia networks with `seq-bcli` (same 5 methods plus internal extras):

- getrawblockbyheight serves a block only once it is quorum-certified (getblockheader
  `poscertified == true`, the RPC shipped 2026-07-02) AND the chain's anchor status is ok
  (getanchorstatus). lightningd therefore sees only the certified chain view; an uncertified tip is
  invisible to LN. Consequence: CLN's depth 1 == "certified block", and the default
  `funding_confirms = 1` (testnet-class default already) is correct and fast (one Sequentia block
  interval).
- Tail truncation (a Bitcoin reorg orphaning Sequentia anchors) reaches lightningd as a normal
  reorg: CLN already re-org-handles by unwatching/rewatching and rebroadcasting; truncation can only
  shorten the tail, never substitute a conflicting history, so funding/commitment/justice txs
  re-enter the mempool and reconfirm. Per the feasibility analysis this is strictly safer than
  Bitcoin reorgs (causal order preserved; CSV clocks reset in the defender's favor; no
