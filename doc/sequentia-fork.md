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

Three Elements-family network entries are added, plus two fields on `struct chainparams`:
`has_anchor_header`, which gates every Sequentia-specific code path, and
`has_tapscript_introspection`, which marks a chain whose tapscript has Elements' introspection
opcodes as one this fork's covenant channel types are offered on, and gates the
taproot-covenant channel type (section 5b). Such a feature keys on that flag and never on
`is_elements`, which the Liquid entries share; they leave the flag unset, since this fork does
not develop against Liquid:

| network_name | onchain HRP | lightning HRP | bip70 (chain) | is_elements | has_anchor_header | has_tapscript_introspection |
| --- | --- | --- | --- | --- | --- | --- |
| `sequentia-testnet` (live) | `tb` | `tsqt` | `test` | yes | yes | yes |
| `sequentia-regtest` (local tests) | `bcrt` | `sqrt` | `sequentia-regtest` | yes | yes | yes |
| `sequentia` (placeholder) | `bc` | `sqt` | `sequentia` | yes | yes | yes |

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
  (~2 weeks). These are defaults; operators and per-open flags can still override. `pay`,
  `keysend`, `crossassetpay` and askrene's `getroutes` default `maxdelay`, the longest a payer
  lets its payment be locked, to the same 20160 (`chainparams_max_htlc_cltv()`; `getroutes`
  also takes it as its limit), so a payer accepts an invoice
  with a final lock time of several thousand blocks, such as an Arca receive invoice's; a
  Bitcoin payer keeps BOLT #4's 2016.
- **The sweep of a node's own delayed output** (`lightningd/onchain_control.c`
  `handle_onchaind_spend_to_us()`): onchaind prices it toward a deadline at most 300 blocks ahead,
  set when the output first appears. A `to_self_delay` of 1440 puts that deadline long before the
  output can be spent, so the sweep would bid the feerate for the next block from its first
  attempt. When the deadline falls within 12 blocks of the block the output can first be mined in,
  the window is measured from that block instead: the first attempt, once the delay has run, is at
  the floor, and the feerate rises from there as the deadline nears. Bitcoin's default delay of
  144 blocks leaves the deadline where it was.
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
- A channel's dust limit and the node's minimum channel capacity (`--min-capacity-sat`) are
  reference amounts too: a count of atoms would be dust in a cheap asset and a large sum in a dear
  one. openingd sets the channel's `dust_limit_satoshis` at what the reference dust limit (546) is
  worth in the channel asset at the node's rate, rounded up as the node rounds its own relay dust
  threshold, and judges the capacity the same way (`value_limits_in_asset()` in
  `openingd/openingd.c`; lightningd stores the dust limit openingd negotiated). HTLCs are therefore
  trimmed at the same value in every asset, and the channel reserve, 1% of the funding and at least
  the dust limit, is worth the same in every asset too. Both are fixed at funding, as BOLT 2 fixes
  the dust limit: a later change of rate leaves an open channel's dust limit and reserve where they
  were, and a node without a rate for the asset opens no channel in it. A fundee whose dust limit is
  above the reserve the opener asks of it (BOLT 2 forbids that) lowers it to that reserve when the
  reserve is worth at least four fifths of it, the margin by which the reference dust limit stands
  above the node's relay dust threshold for a channel output, and refuses the channel otherwise.
- `hsmd_setup_channel` carries the channel's dust limits and reserves to a validating signer in a
  TLV stream (`hsmd/hsmd_wire.csv`; a signer that predates it ignores it, and a node that predates
  it sends none). The device signer holds a mutual close's dust and the peer's reserve to them
  (`contrib/seqln-signer/README.md`).

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
  display hex) for every channel, the policy asset's included, as `listfunds` names each
  channel's and output's `asset`: no asset is the one a missing value stands for.
- `wallet/wallet.c`, `wallet/reservation.c`, `wallet/walletrpc.c`: the on-chain wallet records
  UTXOs of any issued asset (the output a peer's commitment pays this node, which onchaind hands
  to the wallet, in the channel's asset), selects coins per-asset, funds single-asset
  transactions (change and fee in the funding asset, fee sized per section 4), and `listfunds`
  shows an `asset` field on issued-asset UTXOs (amounts are that asset's atoms). The per-asset
  selection, including the fee-bump coins of anchor spends and HTLC transactions, applies on
  Sequentia networks only; a Bitcoin node selects from all its UTXOs, as upstream does.
- `fundpsbt`, `utxopsbt`, `addpsbtoutput`, `txprepare` and `withdraw` (`wallet/reservation.c`,
  `plugins/txprepare.c`) take the `asset` being moved (32-byte display-hex id) and pay the fee in
  it, at the node's rate for it. Without it they move the asset of their inputs: `utxopsbt`
  the one asset its `utxos` hold (coins of two assets are refused), `fundpsbt` and the commands
  built on it the policy asset. `migrate_fill_close_output_asset` (`wallet/db.c`) gives a close
  output recorded without an asset its channel's.
- `plugins/spender/fundchannel.c`, `plugins/spender/multifundchannel.{c,h}`: the `asset` parameter
  (32-byte display-hex id); all channels in one funding tx must share one asset.
- `onchaind/onchaind.c` + `onchaind/onchaind_wire.csv`, `lightningd/onchain_control.c`,
  `lightningd/anchorspend.c`: force-close resolution and anchor CPFP in the channel asset
  (single-asset CPFP; no privileged coin is assumed for fee-bumping).

## 5b. Taproot-covenant channels (`option_seq_taproot_covenant`)

A channel type for chains whose tapscript has Elements' introspection opcodes
(`has_tapscript_introspection`, section 1). Its commitments spend the same 2-of-2 P2WSH funding
output as every other type, so opening and funding are unchanged, and pay taproot outputs. Each
HTLC output claims itself: the leaf that lets its holder take it requires the claim's output at
the same index to carry the HTLC's whole value, in the channel's asset, to the holder's own
delayed output. The holder needs no signature from the peer for that, so `commitment_signed`
carries no HTLC signatures, there are no second-stage HTLC transactions, and every claim
attaches its fee from another input when it is made, in any asset the node accepts for fees.

**Enabling it.** Start both peers with `--taproot-covenant-channels` (lightningd-config(5)). The
node then offers feature bit 172/173 and prefers the channel type `[12, 172]`
(`option_static_remotekey` with this type) whenever its peer offers it too; `fundchannel
channel_type=[12,172]` asks for it explicitly, and a peer that does not offer it gets an
ordinary channel. `listpeerchannels` names it `seq_taproot_covenant/even`. The option offers
nothing on a chain without the flag (the Liquid entries included) and nothing when the signer cannot sign the
type's spends: lightningd withdraws the feature unless hsmd lists the four messages below among
its capabilities.

**Scripts** (`common/tcov_scripts.{c,h}`, `bitcoin/tapscript.{c,h}`). On the commitment held by
one side ("self", the peer "other"), every taproot output has self's revocation key as its
internal key and two leaves, and every key in a leaf is in the script, x-only:

| Output | Leaf 0 | Leaf 1 |
| --- | --- | --- |
| `to_local`, and D | DELAY: `<self delayed key> CHECKSIGVERIFY <to_self_delay> CSV` | REVOKE: `<per-commitment point> <G> ROT ECMULSCALARVERIFY KEEP(S)` |
| HTLC self offered | TIMEOUT: `<self htlc key> CHECKSIGVERIFY <cltv_expiry> CLTV DROP COV(A,X,D)` | SUCCESS: `SIZE 32 EQUALVERIFY HASH160 <RIPEMD160(payment_hash)> EQUALVERIFY <other htlc key> CHECKSIG` |
| HTLC self received | SUCCESS: the same hash lock, then `<self htlc key> CHECKSIGVERIFY COV(A,X,D)` | TIMEOUT: `<other htlc key> CHECKSIGVERIFY <cltv_expiry> CLTV` |

- `to_remote` is the P2WPKH of other's payment basepoint, as under `option_static_remotekey`.
- `COV(A,X,D)`: the output at this input's index carries the explicit asset A (the channel's), an
  explicit value of at least X (the HTLC output's own value) and pays the witness v1 program D,
  the `to_local` of the same commitment. The output a claim creates is therefore spendable
  only as `to_local` is: by self after the delay, or by other once self has revoked the
  commitment.
- `KEEP(S)`: the output at this input's index carries this input's explicit asset, at least its
  explicit value, and pays S, other's `to_remote` script. REVOKE needs no signature, only the
  per-commitment secret that other learns when self revokes the commitment, so anyone holding
  that secret can return a revoked `to_local`, and every D of that commitment, whole to other.
- Leaves use the Elements leaf version 0xc4 and the `TapLeaf/elements`, `TapBranch/elements` and
  `TapTweak/elements` tags; signatures use the Elements taproot signature hash, which commits to
  the chain's genesis hash and to every input's asset and value (section 9).
- Locks are block heights and block counts, as BOLT 2 and 4 give them. Fees, trimming and output
  order are those of an `option_static_remotekey` channel without anchors: a P2TR output weighs
  what a P2WSH one does, so both sides compute the same commitment fee.

**A force-close on the chain.** The commitment has the funding output as its one input and pays,
in the channel's asset, a taproot `to_local`, a P2WPKH `to_remote`, one taproot output per HTLC
above the dust limit, and the explicit fee output. onchaind (`onchaind/onchaind.c`) resolves each
output by asking lightningd for a spend (`onchaind_spend_tcov`), and lightningd
(`lightningd/onchain_control.c`) builds it, has hsmd sign it, and rebuilds it at each block at the
feerate its deadline needs, replacing the one in the mempool when the new fee is higher:

- An HTLC the closing side offered, once its CLTV has passed, and one it received, once it has
  the preimage: a claim whose input 0 is the HTLC output, spent by its covenant leaf (witness:
  the preimage for a success, the signature, the leaf, the control block), whose output 0 is D
  with the HTLC's whole value, and whose fee comes from the node's wallet coins: in the
  channel's asset if the node accepts it for fees and holds enough of it, otherwise in the
  accepted asset whose coins are worth most to it, with change back to the wallet. With one fee
  coin such a claim is about 380 vB. After the closing side's delay it sweeps D to its wallet
  with the DELAY leaf.
- `to_local`: swept to the wallet by the DELAY leaf after the delay.
- The other side takes an HTLC on that commitment with the SUCCESS leaf of one the closer
  offered (with the preimage) or the TIMEOUT leaf of one the closer received (after its CLTV),
  paying its own wallet; that claim takes its fee from the output when the node accepts the
  channel's asset for fees, and from a wallet coin otherwise.
- A revoked commitment: the victim's onchaind spends its `to_local` and HTLC outputs, and any
  D the cheater's claims create, by the key path, signed with the revocation key. When a tower got there first
  with REVOKE, onchaind adds the output it paid the victim to the wallet.
- No coin in an accepted asset covers a claim's fee: lightningd logs it and tries again.
- The output a spend is for is spent on chain, by that spend or another: lightningd stops
  rebuilding it and releases its fee coins. onchaind hears of a spend after lightningd does, so a
  node back from being away can be asked to spend an output the peer already took, in the
  commitment's own block, say. lightningd remembers the outputs it saw spent with no spend of its
  own under way and builds no spend of one, so a spend that can never be mined holds no fee coin.

**Signers.** hsmd signs the spends with four messages (`hsmd/hsmd_wire.csv`):
`hsmd_sign_tcov_delayed_to_us` (DELAY), `hsmd_sign_tcov_local_htlc` (a covenant leaf),
`hsmd_sign_tcov_remote_htlc_to_us` (the other side's HTLC leaf) and `hsmd_sign_tcov_penalty`
(the key path), each answered by `hsmd_sign_tcov_reply` with a BIP340 signature. lightningd sends
the whole transaction and every input's previous output, since the signature commits to all of
them, and signs the fee coins with `hsmd_sign_htlc_tx_mingle`. The device signer
(`contrib/seqln-signer`) computes the same signature hash itself, validates the type's
commitments against these trees before signing them, and, in enforce mode, signs a spend only
when every output pays one of its own scripts, or, for a covenant leaf, D at the input's index,
with the fee within its payment limit; it signs a claim's fee coins once it has approved the
claim.

**Watchtower** (section 7b). At each revocation channeld stores, instead of a signed justice
transaction, a template of kind `WT_TMPL_TCOV_REVOKE` (`common/presign_templates.h`): the
REVOKE leaf's witness (the revoked secret, the leaf, its control block) and the output S it
pays. It needs no signature, so the device signs nothing for the tower on this type. `speculad`
finds the revoked commitment's `to_local` and every D (the same script) with `scantxoutset`
once the commitment confirms, and spends each to S with its fee input, as it does for the other
templates.

Files: `bitcoin/chainparams.{c,h}`, `bitcoin/tapscript.{c,h}`, `common/tcov_scripts.{c,h}`,
`common/tcov_commit_tx.{c,h}`, `common/features.{c,h}`, `common/channel_type.{c,h}`,
`common/initial_channel.c`, `channeld/tcov_channel.{c,h}`, `channeld/full_channel.c`,
`channeld/channeld.c`, `hsmd/hsmd_wire.csv`, `hsmd/libhsmd.c`, `lightningd/options.c`,
`lightningd/hsm_control.c`, `lightningd/channel.c`, `lightningd/onchain_control.c`,
`lightningd/onchain_presign.c`, `onchaind/onchaind.c`, `onchaind/onchaind_wire.csv`,
`speculad/speculad.c`. Tests: `common/test/run-tcov_scripts.c` (the trees, control blocks,
signature hashes and signatures against vectors from the Sequentia node's test framework) and
`tests/sequentia/test_taproot_covenant.py` (section 10).

## 5c. Point-locked HTLCs (`option_seq_point_locks`)

On a taproot-covenant channel (section 5b) an HTLC can be locked to a point L rather than to a
hash: its SUCCESS leaf opens with the 32-byte scalar t where t*G equals L, checked by
`OP_ECMULSCALARVERIFY`, where a hash-locked one takes a preimage. Nothing else about the
channel changes: commitments are signed as before and there are no adaptor signatures. A
payment locked this way is decorrelated: every hop sees a different point, unrelated to the
payee's invoice. Point locks are for payments that never leave Sequentia. A payment between
SeqLN and Bitcoin Lightning, and a cross-chain swap, stay hash-locked end to end under one
hash, because no hop can derive a point from a hash a Bitcoin payee chose.

**Enabling it.** Start the node with `--point-locks` beside `--taproot-covenant-channels`
(lightningd-config(5)). It then offers feature bit 174/175 in `init`, its node announcement
and its invoices, and every invoice carries, in the field `t`, the payment point T = p*G of
its preimage p (`decode` shows it as `payment_point`). lightningd withdraws the feature when
`hsmd` does not list `hsmd_tcov_htlc_locks`: the device signer (`contrib/seqln-signer`) does
not, so a keyless node takes no point locks and its payments stay hash-locked.

**The leaves** (`common/tcov_scripts.h`). The hash lock of the SUCCESS leaf,
`SIZE 32 EQUALVERIFY HASH160 <RIPEMD160(payment_hash)> EQUALVERIFY` (27 bytes), becomes the
point lock `<L> <G> ROT ECMULSCALARVERIFY` (70 bytes; L compressed, its parity included).
The rest of each tree is unchanged: the offered HTLC's SUCCESS leaf is
`<L> <G> ROT ECMULSCALARVERIFY <other htlc key> CHECKSIG` (104 bytes), the received HTLC's
is the point lock, `<self htlc key> CHECKSIGVERIFY` and `COV(A,X,D)`.

**On the wire.** A point-locked `update_add_htlc` carries the TLV `seq_point_lock` (type
174174, the 33-byte point), and its `payment_hash` is the point's x coordinate, so every
place that keys an HTLC on its hash keeps working; `update_fulfill_htlc` carries the scalar
where it would carry the preimage. channeld refuses the TLV on a channel that is not of the
taproot-covenant type or from a peer it did not offer point locks to, and a fulfil whose
scalar does not open the point. The onion payload of each hop carries `seq_point_tweak`
(174174, 32 bytes), and the payee's also `seq_point_payment_hash` (174176): the invoice's
payment hash. Each hop's onion layer commits, as its associated data, to the payment_hash
that hop sees.

**A payment.** The payer picks a scalar c and locks the first HTLC to L0 = T + c*G (`pay`
does this; `sendonion` takes `lock_point`, and `createonion` an `assocdata` per hop). Each
forwarding hop is told d in its onion and offers the next HTLC locked to L + d*G; the payee
is told r = c + the sum of the d's and the invoice's payment hash, and opens its HTLC with
p + r. Going back, each hop takes its d off the scalar it learns, so the payer receives
p + c and keeps p: the invoice's preimage, the proof of payment. `pay` locks a payment to the
point when the invoice has one and offers the feature, the paying node offers it too and has a
channel of the taproot-covenant type, and a route exists whose every node announces the
feature; it then routes only through such nodes, leaves only by one of its own taproot-covenant
channels (it reads their types from `listpeerchannels`), and sends in one part. Gossip does not
say a channel's type, so a channel further along may still be of an older type: a node that
announces point locks fails a point-locked HTLC it would forward on such a channel with
`required_channel_feature_missing` ("Attempt to send a point-locked HTLC on a channel that takes
none"), and `pay` then routes point locks around that channel without disabling it ("Channel
<scid>/<dir> took no point lock"), trying the invoice's other route hints first. When no route
is left whose every node and channel takes point locks, and no point-locked attempt is still
out (each one that went out has failed back, so nothing is locked to the point and an HTLC
under the hash cannot pay the payee twice), it pays by the invoice's hash over any route
(logging "Paying by hash lock, not point lock"). So a payment from a node with no
taproot-covenant channel never sends a point-locked HTLC, and one whose older channel lies
further along sends one attempt that fails back before the hash-locked one.

**State.** `channel_htlcs` holds each HTLC's `lock_point`, and for an incoming one
`point_add`: what the node adds to the scalar it learns to open that HTLC (the payee's r,
or minus a forwarder's d), so a restart in the middle of a payment loses nothing.
`listpeerchannels` shows an HTLC's `lock_point`; the `htlc_accepted` hook shows it and, for
the payee, `invoice_payment_hash`, and a plugin that resolves such an HTLC may give the
invoice's preimage or the scalar itself.

**On the chain.** onchaind (`onchaind/onchaind.c`) builds a point-locked HTLC's tree from the
lock in its HTLC stub, claims it with the scalar exactly as it claims a hash-locked one with
the preimage, and reads the scalar out of the peer's SUCCESS witness, checking it opens the
point, for lightningd to settle the HTLC it was forwarded from.

**Signers.** channeld sends `hsmd_tcov_htlc_locks` (the payment hashes and points of a
commitment's point-locked HTLCs) before `hsmd_validate_commitment_tx` and
`hsmd_sign_remote_commitment_tx`, for a signer that rebuilds commitments; libhsmd, which
does not, acknowledges it.

Files: `common/point_lock.{c,h}`, `common/tcov_scripts.{c,h}`, `common/tcov_commit_tx.{c,h}`,
`common/bolt11.{c,h}`, `common/sphinx.{c,h}`, `common/htlc_wire.{c,h}`,
`wire/peer_wire.csv`, `wire/onion_wire.csv`, `channeld/channeld.c`,
`channeld/full_channel.c`, `channeld/tcov_channel.c`, `hsmd/hsmd_wire.csv`,
`hsmd/libhsmd.c`, `lightningd/peer_htlcs.c`, `lightningd/pay.c`, `lightningd/invoice.c`,
`lightningd/hsm_control.c`, `lightningd/options.c`, `wallet/wallet.c`,
`wallet/migrations.c`, `onchaind/onchaind.c`, `plugins/libplugin-pay.c`, `plugins/pay.c`.
Tests: `tests/sequentia/test_point_locks.py` (section 10).

## 5d. Provider-signed credit (`option_seq_credit`)

A hosted user's channel moves only when the user's device signs, so while the device is away
the user cannot be paid over it. A credit channel lets the side that opened it, the
**provider**, credit the other side, the **holder**, without a channel update: the provider
signs a **credit note**, "the holder is owed c atoms of the channel's asset in all",
conditional on the preimage of the payment the note was issued for. Credit is cumulative: each
note states the whole amount owed, so the latest supersedes every earlier one. The holder
claims it on chain from either commitment, or the channel's mutual close pays it.

**What a note binds the provider to.** Once a note and its payment's preimage are out,
the provider cannot take that credit back:

- every commitment of the channel, the provider's and the holder's, pays the provider's
  balance to a script whose CLAIM leaf pays the holder what the latest note still owes, out of
  that output, with no signature from the holder and none from the provider beyond the note.
  Anyone holding the note and the preimage can make the claim; it pays only the holder's
  static payment script;
- the provider's balance cannot drop below the latest note: the holder's channeld, and the
  holder's device signer, refuse a commitment whose provider output could not pay it, an HTLC
  or a fee change included, and the provider's own node refuses to offer an HTLC that would;
- a mutual close pays the holder its balance and the latest note, out of the provider's side.
  A close that leaves the note out is not signed by the holder, its node or its device.

What the provider can still do: before a note reaches the holder, the holder has the provider's
word only, because the payment was made to the provider. The provider decides whether and when
to issue a note, and the holder sees a payment it expected go uncredited. The provider can close
the channel at any time; the credit is then paid by the close or claimed from the commitment.
After a claim, what remains of the provider's output is the provider's after its delay, counted
again from the claim. Credit is never folded into the holder's channel balance: it stays a
separate claim on the provider's output until the channel closes.

**Enabling it.** Start both nodes with `--credit-channels` beside
`--taproot-covenant-channels` (lightningd-config(5)). They offer feature bit 176/177; the
channel type is `[12, 172, 176]` (`seq_credit/even` in `channel_type.names`). A node opens such
a channel, as provider, only when its `hsmd` lists `hsmd_sign_credit_note` and
`hsmd_sign_tcov_payment_to_us`: libhsmd does, the device signer does not, so a keyless node never
provides. It accepts one, as holder, only when its `hsmd` lists `hsmd_credit_note`: libhsmd and
the device signer both do.

**The scripts** (`common/credit_scripts.h`). The CLAIM leaf (172 bytes) takes the witness
`<sig> <c> <x>`:

    SIZE 32 EQUALVERIFY SHA256 OVER <Dtag> SWAP CAT SWAP CAT ROT SWAP <Pc> CHECKSIGFROMSTACKVERIFY
    <B> PUSHCURRENTINPUTINDEX INSPECTINPUTVALUE 1 EQUALVERIFY SUB64 VERIFY        (paid = B - input)
    2DUP GREATERTHAN64 VERIFY OVER SWAP SUB64 VERIFY                              (c > paid; c - paid)
    output i+1: that value, the holder's program U, this input's asset
    <B> SWAP SUB64 VERIFY; output i: B - c, this input's own script and asset

The note is a BIP340 signature by the credit key Pc over the 72 bytes
`Dtag || c (8 bytes, little-endian) || SHA256(x)`. Dtag = tagged_hash("SeqLN/credit",
channel_id), BOLT 2's channel id from the funding outpoint, binds a note to its channel; Pc is the
provider's funding key plus tagged_hash("SeqLN/credit-key", funding key)*G, a key that signs
nothing but notes. B is the output's value in its commitment, so paid is what earlier claims on
that output took; U is P2WPKH of the holder's payment basepoint.

| Output | Internal key | Leaves |
| --- | --- | --- |
| The provider's `to_local` on its own commitment | revocation key | CLAIM at depth 1; DELAY and REVOKE (section 5b) at depth 2 |
| The provider's output on the holder's commitment | BIP341's NUMS point (no key path) | CLAIM; PROVIDER: `<provider payment key> CHECKSIGVERIFY <holder's to_self_delay> CSV` |

D, the output the provider's own HTLC claims pay, keeps the two-leaf `to_local` tree: a smaller
output under the CLAIM script would let one note pay a second time.

**Notes on the wire.** The provider sends each note to the holder in the custom peer message
48033 (odd, so a peer that does not know it ignores it): `[channel_id][u64 credit]
[sha256 payment_hash][64 signature][u8 has_preimage][32 preimage]`, again whenever the channel
reconnects. The holder's node checks the note against the channel's credit key and the preimage
against its hash, keeps it (`credit_notes` table), and hands its latest to channeld, which tells
the signer (`hsmd_credit_note`, with the preimage) before it signs anything more on the
channel, and to onchaind.

**Commands.** `issuecredit id amount_msat payment_hash [preimage] [channel_id]` (provider):
add `amount_msat` to the credit of the channel with peer `id`, sign the cumulative note and
send it; refused when the provider's spendable balance less its dust limit cannot pay the new
total. `addcreditnote id credit payment_hash signature [preimage] [channel_id]` (holder):
keep a note received another way, refused unless the channel's credit key signed it.
`listcreditnotes [id]`: every note of every credit channel, each with `peer_id`,
`channel_id`, `role` (`provider` or `holder`), `credit`, `payment_hash`, `signature` and,
once known, `preimage`. The plugin `contrib/credit-seq` issues notes from paid invoices:
`creditinvoice id amount_msat` makes an invoice of the provider whose payment credits peer `id`,
and its `invoice_payment` hook calls `issuecredit` before accepting the payment, refusing the
payment when no note can be issued.

**On the chain.** When a commitment of the channel confirms, the holder's onchaind claims its
latest note from the provider's output by CLAIM, with a fee coin from its wallet in any asset
the node accepts, and watches what remains for a later note; the provider's onchaind sweeps
what remains after its delay. A claim on the holder's commitment with a fee coin in another
asset is 464 vB.

**Mutual close.** closingd's close pays the holder the latest note out of the provider's side
(lightningd logs "Closing pays the holder ... of credit"). Each side computes the close from
the latest note it holds; if they disagree, neither signature checks and the channel goes to
chain, where the holder claims its note.

**Signers.** libhsmd signs notes with the credit key (`hsmd_sign_credit_note`), the
provider's PROVIDER leaf spends (`hsmd_sign_tcov_payment_to_us`), and acknowledges
`hsmd_credit_note`. The device signer (`contrib/seqln-signer`) holds credit: it checks each
note it is told of (the channel's id, the credit key's signature, the preimage), keeps the
latest with its preimage in its channel store, validates the channel's commitments against
the credit trees, refuses a commitment whose provider output cannot pay that note and a close
that does not pay it, and signs a credit claim's fee coins. Its WASM build and SDK give a wallet
the notes it holds (`creditNotes()`, and the SDK's `onCredit` when a new one arrives), with
everything a claim needs.

Files: `common/credit_scripts.{c,h}`, `bitcoin/tapscript.{c,h}`, `common/tcov_commit_tx.{c,h}`,
`common/initial_channel.{c,h}`, `common/features.{c,h}`, `channeld/channeld.c`,
`channeld/full_channel.c`, `closingd` (via `lightningd/closing_control.c`),
`lightningd/credit.{c,h}`, `lightningd/peer_htlcs.c`, `lightningd/onchain_control.c`,
`lightningd/opening_control.c`, `lightningd/hsm_control.c`, `lightningd/options.c`,
`onchaind/onchaind.c`, `hsmd/hsmd_wire.csv`, `hsmd/libhsmd.c`, `hsmd/hsmd_proxy.c`,
`wallet/wallet.c`, `wallet/migrations.c`, `contrib/credit-seq/`, `contrib/seqln-signer/`.
Tests: `tests/sequentia/test_credit.py`, `common/test/run-credit_scripts.c` and the signer's
`cargo test` (section 10).

## 5e. Symmetric channels (`option_seq_symmetric`)

A channel type in which an old state is replaced by a newer one rather than punished, so a
node keeps only the latest states and a stale state costs its publisher only fees. Offered on
chains with `has_tapscript_introspection` (section 1), like the taproot-covenant type, and kept
out of the other types' code paths: their commitments, signatures and on-chain resolution are
unchanged.

**Enabling it.** Start both peers with `--symmetric-channels` (lightningd-config(5)). The node
then offers feature bit 178/179 and prefers the channel type `[12, 178]` whenever its peer
offers it too (a credit provider's channel to a credit holder stays a credit channel);
`fundchannel channel_type=[12,178]` asks for it explicitly. `listpeerchannels` names it
`seq_symmetric/even`. lightningd withdraws the feature unless hsmd lists the three messages
below among its capabilities.

**Transactions** (`common/sym_scripts.h`, which carries every script). The funding output is
the usual 2-of-2 P2WSH, so opening, gossip and the mutual close are those of every other type.
A unilateral close takes three transactions, and each pays its fee from an input attached when
it is broadcast, in any asset the node accepts:

- the **kickoff** spends the funding output into KO, a taproot output with one leaf, UPD(-1).
  Both funding keys sign it once, at open, `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY`, so anyone can
  add a fee input and its change, and it is the same transaction whatever the state. Those
  signatures bind the funding input to the output at the same index, KO, at whatever index;
- an **update** spends KO, or the output of any older state k, by UPD(k), into the output of
  state n > k, of the same value and asset;
- the **settle** spends state n's output by SETTLE(n) once the shared delay has passed; its
  first outputs are the settlement: each side's balance to P2WPKH of its payment basepoint and
  each HTLC to a taproot output with a SUCCESS leaf (preimage and the receiver's key) and a
  TIMEOUT leaf (the offerer's key after the expiry). Keys are basepoints, untweaked: there is
  no revocation.

A state output is `tr(H, {UPD(n), R(n)})` with H the NUMS point, where R(n) is the SETTLE leaf,
or a branch over SETTLE and a Simplicity leaf: the state output is a mixed tree, so another
leaf can join it without changing UPD, its signatures or the watcher. UPD(k) takes two BIP340
signatures through `OP_CHECKSIGFROMSTACK` over `SHA256(tag || n || P || R)`: the new state
number (8 bytes, in the witness), the program P of the output at the input's own index, and R,
which the witness publishes. The tag folds in the chain's genesis hash and the funding
outpoint, so a signature replays neither to another chain nor to another channel whose keys
are the same. One signature from each side therefore covers the update and, through P, the
settlement; it spends any older state output of the channel whatever its txid, and leaves
every other input and output free for the fee. SETTLE needs no signature: it hashes the asset,
value and script hash of each of its outputs and compares the digest. The settlement's values
add up to the state output's value. An HTLC below the dust limit (the larger of the two
sides') stays with the side that offered it, a balance below it goes to the other side, what
msat rounding leaves goes to the opener, and the outputs are sorted so that both sides build
the same list. Every key in a leaf is a 32-byte script constant.

**States and signatures.** Each commitment is a state: commitment i of the opener is state 2i,
of the accepter 2i + 1, so each side's own states only ever grow. Each side's update key is its
delayed payment basepoint, which this type uses for nothing else. On the wire, in TLV 48041
(`wire/peer_wire.csv`):

- `funding_created` and `funding_signed` carry the kickoff signature in `signature` and the
  sender's update signature on the receiver's first state in `sym_sig`;
- `commitment_signed` carries the kickoff signature again, no HTLC signatures, and the
  sender's update signature on the receiver's new state;
- `revoke_and_ack` carries the sender's update signature on its own state that replaces the
  one it revokes. Whoever revokes a state thus hands the other a newer one whole, so a node
  cheated with any state it saw revoked always holds one numbered above it.

lightningd keeps three states of each channel (`lightningd/symmetric.h`, table `channel_sym`):
its own latest and the peer's latest, each with both signatures, and the peer's newest, which
it signed and the peer has not countersigned yet: the peer can broadcast that one, so its
settlement is kept. The shared delay is the larger of the two `to_self_delay`s: a node asks
`--symmetric-delay` (72 blocks on the Sequentia networks) and refuses a peer that asks more.

**On chain.** A unilateral close broadcasts the kickoff with a fee coin. onchaind
(`handle_symmetric_close`) then publishes over KO the best state the node holds whole, and over
any older state that reaches the chain, whoever published it; once a state the node knows has
stood for the delay, it publishes its settlement. lightningd builds each of these with a fee coin
in the channel's asset if the node accepts it for fees and holds enough, else in the accepted
asset whose coins are worth most to it, rebuilds it each block at a rising fee until its input
is spent, and releases the coins of a spend that lost to another. The settlement's own balance
output goes to the wallet; an HTLC the node offered is taken back by its TIMEOUT leaf after its
expiry, one it received by its SUCCESS leaf once the preimage is known, and the preimage of one
the peer claims is passed upstream. The update and the settle need no key, so a node that keeps
the watchtower store has `speculad` replace a stale state and settle while it is down (section
7b).

**Delays.** Every output waits for the settlement, HTLCs included, and a peer that withheld its
last acknowledgement can publish the state it holds just before the delay runs out, restarting
it once. So an HTLC on a symmetric channel must outlive twice the shared delay and 12 blocks
more: lightningd refuses to offer or accept one that would not, and goes on chain that long
before an HTLC expires (`sym_htlc_margin()`). Forwarding over a symmetric channel therefore
needs that doubled delay inside the route's lock times.

**Signers.** hsmd signs the type with three messages (`hsmd/hsmd_wire.csv`):
`hsmd_sign_sym_kickoff` (the funding key, `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY`, answered by
`hsmd_sign_tx_reply`), `hsmd_sign_sym_state` (the update key over a state's message, with the
state's settlement and every HTLC it carries, so a signer that holds a balance can check what
the state pays it) and `hsmd_sign_sym_htlc` (the HTLC basepoint over a settlement HTLC's
claim). The fee coins of every stage are signed with `hsmd_sign_htlc_tx_mingle`.

**Developers.** `dev-sym-snapshot id` freezes the best state a node holds; its next unilateral
close then publishes that one as though it held nothing newer, which is how the tests make a
stale state.

Files: `common/sym_scripts.{c,h}`, `common/sym_state.{c,h}`, `common/sym_channel.{c,h}`,
`channeld/sym_channeld.{c,h}`, `lightningd/symmetric.{c,h}`, and the symmetric branches of
`openingd/openingd.c`, `channeld/channeld.c`, `channeld/full_channel.c`,
`common/initial_channel.c`, `onchaind/onchaind.c`, `lightningd/onchain_control.c`,
`lightningd/opening_control.c`, `lightningd/peer_htlcs.c`, `lightningd/peer_control.c`,
`hsmd/libhsmd.c` and `wallet/wallet.c`. Tests: `common/test/run-sym_scripts.c` checks the
scripts, trees, messages, signatures and the kickoff's signature hash against vectors from the
Sequentia node's test framework, whose builders were spent on a Sequentia chain with each
negative case (an older update over a newer one, a settle before its delay, a settlement moved
by one atom, a 33-byte key) forced into a block; `tests/sequentia/test_symmetric.py` (section
10).

## 6. Asset-aware gossip, routing, payments

- How route finding learns a channel's asset. The channel announcement and the channel update are
  BOLT 7's messages unchanged, with no asset field: a node learns the asset of an announced
  channel from its funding output on chain, which it already reads to check the announcement. An
  asset field in gossip would add nothing a node could trust without that same check, and would
  make Sequentia's gossip differ from Bitcoin's on the wire. Files:
  - `gossipd/gossipd.c`, `gossipd/gossmap_manage.{c,h}`, `gossipd/gossipd_wire.csv`,
    `lightningd/gossip_control.c`: `gossipd_get_txout_reply` carries the funding output's asset,
    and the asset is written to the gossip store.
  - `common/gossip_store_wire.csv`: `gossip_store_channel_asset` (4108) records it, immediately
    after the channel's amount record.
  - `common/gossmap.{c,h}`: `gossmap_chan_get_asset()` reads it back. For this node's own
    channels, announced or not, `gossmods_from_listpeerchannels()`
    (`common/gossmods_listpeerchannels.c`) records each one's asset from `listpeerchannels` in
    the local modifications (`gossmap_local_setasset()`), so an unannounced first hop carries its
    asset too.
  - `listchannels` shows each channel's `asset`.
- `plugins/topology.c`: `getroute` routes in one asset. It is the one in `asset=`, else the asset
  of this node's channels when they all hold one; a node with channels in several assets, or a
  route from another node (`fromid`), must name it.
- `plugins/pay.c`, `plugins/libplugin-pay.{c,h}`: `pay` routes in the asset the BOLT11 invoice
  names. `asset=` may repeat it, and a different one is refused ("The invoice is to be paid in
  asset X, not Y"). A BOLT12 invoice names no asset, so for one of those it is `asset=`, else the
  asset of this node's channels when they all hold one. A payment in an asset this node has no open
  channel in (`CHANNELD_NORMAL` or `CHANNELD_AWAITING_SPLICE`) is refused before any HTLC is
  offered, with `PAY_INSUFFICIENT_FUNDS` and a message naming the asset and every channel looked
  at (`payment_asset_unsendable()`). A channel in the asset whose peer is offline, or whose
  balance is still settling, is left to the payment's own attempts, which never use a channel
  in another asset.
  - `payment_route_check()`, the single choke point for every routing variant, MPP splits
    included, skips any channel in another asset.
  - The direct-channel shortcut (`directpay`) uses only a channel to the payee in the payment's
    asset.
  - A routehint through a channel the gossip records in another asset is dropped.
  - On Sequentia networks xpay does not take over `pay` (`plugins/xpay/xpay.c`): xpay, askrene
    and renepay route over channels of any asset.
- `plugins/keysend.c`: `keysend ... asset=<id>` pays in that asset, else in the asset of this
  node's channels when they all hold one; a node with channels in several assets must name it.
  The payment routes only over channels in the asset, so no route mixes assets, and an asset this
  node cannot send is refused before any HTLC is offered, as for `pay`. The final CLTV delta it
  asks of the payee is 420 blocks, the margin over Sequentia's 180-block default that upstream's
  42 keeps over Bitcoin's 18; a Sequentia payee refuses 42 as expiring too soon. Upstream
  deprecates `keysend` for xpay's `xkeysend`, which knows no asset; here it is not deprecated.
- `lightningd/peer_htlcs.c` `best_channel()`: a forwarding node may move an HTLC to another
  channel with the same peer, but only one in the same asset.
- `lightningd/pay.c`: an all-zero first hop ("any channel to this peer") in `sendpay`, and a first
  hop by node in `injectpaymentonion`, are refused when the peer's channels hold several assets.
- `lightningd/peer_htlcs.c` `forward_htlc()`: the backstop. A node refuses to forward an HTLC
  across an asset boundary (incoming and outgoing `channel_asset` must match), failing with
  `unknown_next_peer`, so a hand-crafted or buggy cross-asset route can never swap one asset for
  another at par. A conversion at a quoted rate is the plugin `contrib/crossasset-seq`, which
  takes a quoted HTLC on the `htlc_accepted` hook before it reaches this check and sends the next
  hop itself; without the plugin the check refuses the same route.
- `lightningd/htlc_end.c` `new_htlc_out()`: a payment whose first hop carries less than it
  delivers is what a payment converted across assets on the way looks like (the two amounts are
  in different assets). The payer records no routing fee for it; upstream treats the negative
  fee as a corrupt HTLC and aborts the daemon, from the payer's own `sendpay` or `sendonion`.
- `common/bolt11.{c,h}`, `common/bolt11_json.c`, `lightningd/invoice.c`, `lightningd/routehint.c`,
  `wallet/invoices.c` (column `invoices.asset`): an invoice names the asset it is paid in, in the
  BOLT11 field `a` described below, and the payee records it. `invoice ... asset=<id>` sets it;
  without `asset=` it is the asset of this node's channels when they all hold one, and a node
  with channels in several assets, or none, refuses until the caller names one. An invoice in an
  asset the node holds no channel in (an opening one counts) is refused unless
  `allow_unfunded=true`, since nothing could pay it. Route hints name only channels in the
  invoice's asset. `createinvoice` records the asset its `a` field names, and the backfilled
  invoice of an incoming keysend names the asset the HTLC arrived in. `invoice_check_payment()`
  refuses an HTLC arriving on a channel in any other asset (`incorrect_or_unknown_payment_details`,
  logged as "paid in asset X, invoice wants Y"). `decode`, `listinvoices` and the `wait*invoice`
  results show the asset.
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

Invoices: standard BOLT11 with the network's Lightning HRP (`tsqt` on the testnet, so invoices
read `lntsqt...`) and one more tagged field, which carries the asset:

- `a` (29): `data_length` 52. The 32-byte id of the asset the invoice is to be paid in, in the
  order its hex is displayed (the order RPC results and explorers print it; the reverse of its
  serialization in a transaction). Like every field it is covered by the invoice's signature.
- On a Sequentia network a reader requires it: an invoice without `a` fails to decode ("a:
  missing: an invoice on <network> must name the asset it is paid in"), whatever it is for. The
  Sequence token is one asset among equals, so no asset is implied by the field's absence, and
  an invoice for the token names it like any other. A field of another length also fails the
  invoice ("a: expected 52 characters"), as BOLT 11 requires for its fixed-length fields.
- On any other chain `a` is an unknown field, which BOLT 11 readers skip, so a Bitcoin or
  Liquid invoice means what it always did.
- An invoice for another network is not valid where either network is a Sequentia one: `decode`
  shows its fields with `valid: false` and `warning_network` naming both networks ("the invoice
  is for regtest (lnbcrt), and this node runs sequentia-regtest (lnsqrt)"), and `pay` refuses
  it. Between two Bitcoin networks `decode` reads an invoice as upstream does.

Invoice amounts are numeric msat fields read as thousandths of the asset's atoms.

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
  which `pay` and `keysend` call) within a per-asset limit (an invoice against the asset its `a`
  field names, a keysend against every asset it has channels in), refuses a commitment that adds an
  HTLC this node offers for a payment it did not approve, and refuses one that leaves this side
  less than the balance it tracks: value leaves this side only through an HTLC it offered and
  the next commitment settles. For that, channeld lists every HTLC a commitment carries in the
  signing request (`collect_htlcs`, `channeld/channeld.c`), those trimmed as dust included,
  whose value is in the fee. Every output of a commitment or a close must be in the channel's one
  asset, with no issuance on the funding input. The native signer never runs without its store:
  one it cannot restore, or a missing one once it has made one, stops it at start. See
  [its README](../contrib/seqln-signer/README.md).
- A device that refuses a request on lightningd's own connection is dropped and the request is
  sent again when a device reconnects (a device that was missing state is re-primed then); a
  request refused three times ends the node, with the request named in its log, rather than
  holding the node unanswering.
- The one exception is the signature of the node's own closing transaction. lightningd asks
  for it (`SIGN_COMMITMENT_TX`, for its commitment and for a mutual close alike) when a channel
  closes, and again at every start for each channel in `CLOSINGD_COMPLETE` or
  `AWAITING_UNILATERAL`. A device whose store does not record that transaction (a store an
  older device wrote, or a lost one) refuses it. The proxy then answers
  `hsmd_sign_commitment_tx_refused` (`hsmd/hsmd_wire.csv`, `hsmd/hsmd_proxy.c`), and lightningd
  (`lightningd/peer_control.c`) logs the refusal with the channel and the transaction, sends
  nothing, and goes on starting. The channel stays in its state; once its funding is spent,
  onchaind resolves it from the chain. A `close` waiting on that transaction fails with the
  refusal (`lightningd/closing_control.c`). A node with its own keys is never refused, and signs
  and sends the transaction as before.
- For the same reason a keyless node takes the peer's signed closing transaction as the one to
  broadcast only once its device agrees to sign it (`device_signs_close` in
  `lightningd/peer_control.c`, called from `peer_received_closing_signature` in
  `lightningd/closing_control.c`): lightningd asks the device for that signature as each proposal
  arrives. A device refuses a close that pays this side's balance anywhere but its own scripts or
  one its wallet named, or at a fee over its limit; the commitment then stays the transaction to
  broadcast, and `close` falls back to it after its `unilateraltimeout` instead of leaving the
  channel in `AWAITING_UNILATERAL` with nothing it can broadcast. A node with its own keys is not
  asked.
- The device speaks hsmd version 6 only and refuses an INIT whose highest version is below
  it, at any time (lightningd offers 5 to 6). Below version 6 a commitment point comes with the
  secret of the commitment two before it, so a host that lowered the version could read the
  secret of a commitment the device has not revoked; at 6 a secret leaves the device only
  through a revocation it validated.
- A device moved onto a store older than version 6 (written by a device that validated
  nothing) marks every channel in it as predating validation and signs no commitment step for
  it: no commitment of either side, no revocation, no close. The channel moves no more and its
  peer closes it (the cutover closes them from the hubs). The device reports these channels to the
  wallet (`predatingChannels`).
- A keyless node's device signs a spend of the node's wallet (a withdrawal, a channel funding,
  an anchor fee bump, and what a channel close paid it) only when every output but the fee pays
  one of its own wallet scripts or is the funding output of a channel this side is opening, with
  the fee, and anything the channel's first commitment gives the peer, within its payment limit
  for the asset (the signer README, "Withdrawals"). A spend to any other address waits for a way
  to approve an address on the device. A withdrawal it declines comes back unsigned, so the node
  cannot finalize it and sends nothing. The fee of every other transaction it signs that this
  side pays (a commitment or a close of a channel it opened, a sweep, a penalty, an HTLC claim) is
  at most that limit.

- The device signs the spends of a taproot-covenant channel's outputs (section 5b) with the
  Elements taproot signature hash, which it computes itself, and validates that type's
  commitments against its trees. In enforce mode a spend may pay only the device's own scripts,
  or, through a covenant leaf, the D the covenant names, with its fee within the payment limit;
  the claim's fee coins (`hsmd_sign_htlc_tx_mingle`) are held to the withdrawal rule, D allowed
  once the device has approved the claim.

## 7b. Specula keyless watchtower

Built on the signer split: the device pre-signs the transactions a watchtower would need, so a
host can defend the channel while the device is offline, without ever holding a key.

- `channeld/watchtower.{c,h}`, `common/penalty_base.{c,h}`, `common/presign_templates.{c,h}`: at
  every commitment advance channeld has the signer pre-sign the justice (penalty) set for the
  newly revoked commitment: one transaction for the peer's `to_local` output, one for each
  non-dust HTLC output, and one for the output of the peer's second-stage transaction for each
  of those HTLCs (its HTLC-timeout or HTLC-success, which the peer can race the HTLC justice
  with), all in the channel asset. Channels here have no anchors, so that second-stage
  transaction is fixed by the signature we gave the peer for the commitment: channeld records
  its txid and output value in the penalty base when it signs (`penalty_htlcs.stage2_txid`,
  `stage2_amount`), and the justice binds its output before the peer could broadcast it. A
  commitment that carries HTLC outputs but no `to_local` (a peer with no balance of its own)
  gets a justice set too. The templates are
  `SIGHASH_SINGLE|ANYONECANPAY`, so output 0 carries the swept value and a fee input can be
  attached later without the device.
- The penalty transaction channeld builds for each revoked commitment and hands to lightningd
  for the `commitment_revocation` hook (`penalty_tx_create`, upstream) is in the channel asset
  too.
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
  justice set as one transaction, every blob whose input is in the confirmed UTXO set: the
  revoked commitment's outputs until they are spent, and the output of the peer's second-stage
  transaction once that has confirmed. It never loads a secret. It pays the fee from a box-owned
  node wallet (`--fee-wallet`): it appends one fee input and its change, and pays the fee in that
  coin's asset at the node's exchange rate for it (`getfeeexchangerates`; `--fee-base-perkw` and
  `--fee-max-perkw` are in reference atoms), raising it by replacement each round until the
  justice confirms. The fee coin is chosen as a wallet chooses the fee coin of an exit: in the
  channel's asset when the node accepts that for fees and the wallet holds it; otherwise in the
  accepted asset whose largest coin covers the most fees (its value over the fee of a kilo-vbyte
  in it), with no asset preferred for what it is. The swept outputs stay in the channel asset, so
  a justice transaction may carry two assets. The tower logs the asset and amount of each fee it
  pays and why it is not the channel asset; a tower holding no coin in an accepted asset says so
  once and tries again every round. A round costs a few CLI calls
  per channel; the stored revoked commitments are polled only once a channel's funding output is
  spent. It needs the node to run with `txindex=1`.

On a taproot-covenant channel (section 5b) the tower's template for a revoked commitment is the
REVOKE leaf's witness, which needs no signature; `speculad` finds that commitment's `to_local`
and every claim output of it by their script and returns each to the victim.

On a symmetric channel (section 5e) nothing is punished, so the store holds one record per
channel, `sym`, rewritten before channeld goes on whenever the best state the node holds whole,
or the peer's newest, changes: the channel's constants and those two states, with their update
signatures. `speculad` follows the spends from the funding output through the blocks, the kickoff
to KO and each update to its state output. Over the state output that stands it publishes an
update into the stored best state when that is newer; once the stored state, or the peer's
newest, stands and the delay has passed, it publishes its settlement. Each pays its fee from the
fee wallet as a justice transaction does and is raised by replacement at each new block until
its input is spent. Any older state output is rebuilt from the number and R its update
published, so the record does not grow with the states. A reorg below what it scanned restarts
the walk from the funding output. The settlement's HTLC outputs are left to the node, whose key
claims them.

The Specula design note is not yet published in this repository; the header comment of
`speculad/speculad.c` is the fullest description of the model.

## 8. Plugins and daemons affected (summary)

| Component | Change |
| --- | --- |
| `plugins/bcli.c` | Certified-frontier clamp, fixed feerates on Sequentia, `getfeeexchangerates` passthrough |
| `plugins/pay.c`, `plugins/libplugin-pay.{c,h}` | The invoice's asset, per-asset route filter, refusal of an asset this node cannot send |
| `plugins/topology.c` | `getroute` in one asset, `listchannels` `asset` |
| `plugins/spender/*` | `fundchannel`/`multifundchannel` `asset` parameter, single-asset funding txs |
| `channeld`, `openingd`, `closingd`, `onchaind` | Channel asset threading (section 5) |
| `gossipd` | On-chain asset learning + gossip store records (section 6) |
| `hsmd` | Proxy/signer split (section 7); stock in-process `hsmd` is unchanged and remains the default |
| `channeld`, `lightningd/onchain_presign.c`, `speculad` | Specula watchtower: pre-signed justice/sweep sets and their offline broadcaster (section 7b) |
| `lightningd/plugin.c` | Startup fix: skip the `plugins_config` wait loop when every plugin is already `INIT_COMPLETE` (a hang reachable with a minimal plugin set, not Sequentia-specific) |
| `contrib/holdinvoice-seq/` | New plugin: hold-invoice primitive for pure-Lightning swaps |
| `contrib/crossasset-seq/` | New plugin: quoted cross-asset forwarding (signed quotes, one forward per quote, settle or fail both HTLCs together) |
| `contrib/seqln-signer/` | New crate: Rust device signer (native + WASM) |
| `channeld`, `onchaind`, `lightningd/onchain_control.c`, `hsmd`, `speculad` | Taproot-covenant channel type: taproot commitments, covenant HTLC claims with the fee attached at claim time, keyless tower template (section 5b) |
| `channeld`, `onchaind`, `lightningd/peer_htlcs.c`, `plugins/pay.c` | Point-locked HTLCs: the lock in the SUCCESS leaves, forwarding with a per-hop tweak, the payee's invoice point, `pay`'s choice of lock (section 5c) |
| `channeld`, `closingd`, `onchaind`, `lightningd/credit.c`, `hsmd`, `contrib/credit-seq/`, `contrib/seqln-signer/` | Provider-signed credit: the CLAIM leaf on the provider's balance output, notes issued and held, the floor, the close and the claim (section 5d) |
| `openingd`, `channeld`, `onchaind`, `lightningd/symmetric.c`, `hsmd` | Symmetric channels: the kickoff, update signatures per state, the replacement of older states and the settlement on chain, each with a fee coin (section 5e) |

## 9. libwally dependency

`.gitmodules` pins `external/libwally-core` to
https://github.com/ConcatenaLabs/libwally-core, branch
`sequentia-issuance-denomination`, which carries two patches over upstream libwally:

- **The issuance denomination byte.** Sequentia extends the Elements `CAssetIssuance`
  serialization with a 1-byte `nDenomination` (asset decimal precision) after `nInflationKeys`.
  Stock libwally under-reads every issuance input by one byte, so `wally_tx_from_bytes` fails on
  any issuance transaction and a node syncing an issuance block crashes. The patch (libwally
  `src/transaction.c`) consumes and preserves the byte so issuance transactions round-trip
  byte-exact; non-issuance inputs are untouched.
- **The Elements leaf version in signature hashes.** A script-path signature hash commits to
  the hash of the leaf being spent, which Elements chains compute with leaf version 0xc4. Stock
  libwally hashes it with Bitcoin's 0xc0 even for an Elements transaction, so every script-path
  signature it makes there fails on the chain. The patch (libwally `src/tx_io.c`) uses 0xc4 on
  Elements. SeqLN's taproot scripts (`common/tcov_scripts.h`) are spent by script path, and
  `common/test/run-tcov_scripts` fails against an unpatched libwally.

Build with `git submodule update --init --recursive` (or clone with `--recurse-submodules`); no
manual patching is needed. A build tree from before the submodule moved keeps its old library,
since `make` rebuilds libwally only when its headers change: run `make external-clean` once
before `make`.

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
the network defaults, the output a peer's commitment pays this node listed and spent in the
channel's asset (`test_close_output_asset.py`), and moved by `withdraw`, `txprepare` and
`utxopsbt` in that asset at a rate other than par, and given its asset by the upgrade of a
database that recorded it without one (`test_asset_withdraw.py`), a keyless node spending each kind of close
output only to its own address and within its device's payment limit
(`test_close_output_spend.py`, on Bitcoin regtest too, with the redirected spend forced into a
block there; `SEQLN_DEVICE=wasm` runs the keyless tests on the browser build), a keyless node
whose device moves what a close paid it to the node's own address and funds a channel from it,
and refuses that coin's spend to any other address (`test_withdrawal_rule.py`, on Bitcoin
regtest too, with the redirected spend and the redirected funding forced into a block there), a
keyless node
started on a version-1 store, whose device signs no step of the channels in it while the hub
closes them, moves what the closes paid it to its own address, and pays both ways over a channel
opened afterwards (`test_predating_store.py`), a breach of an asset channel with a pending HTLC
answered by `speculad` while the victim is offline, also once the node has delisted the channel's
asset, with the fee paid from another asset the tower holds, and one the cheater races with its
HTLC-success or HTLC-timeout transaction, whose output the tower takes (`test_watchtower.py`), a keyless node, as
either side of a channel, closing it and restarting with it closing, closing cooperatively to an address
of its wallet outside the node that the device was given, and falling back to a unilateral close
when the device refuses the address (`test_keyless_close.py`), a
keyless node whose device approves an invoice against the limit of the asset it names, paying
in one asset while another's limit is spent (`test_keyless_invoice_asset.py`), a
keyless node paying and receiving payments trimmed as dust with nothing refused, and one whose
host misstates its balance in its own database, which has its device refuse the next commitment,
and which closes unilaterally on the balance the device tracked
(`test_keyless_balance.py`), a
keyless node whose device, moved onto an older store, refuses its closing transaction, at start
in each closing state and after `close` times out, and one with an HTLC on chain
(`test_keyless_start.py`, which runs on Bitcoin regtest too, with `TEST_NETWORK=regtest`), the
fees of channels in assets of any value and between peers that value an asset differently
(`test_fee_market.py`), a channel in the Sequence token naming its asset in
`listpeerchannels` like any other, and a hold in it (`test_channel_asset.py`),
the asset plugins see on an HTLC, with `holdinvoice-seq` holding only the asset it was
registered in, across a restart, and accepted only once the parts it holds reach its amount,
a part short of it failed back with `mpp_timeout` at the hold's timeout (`test_hold_asset.py`), and the asset an invoice names in its
`a` field: under its signature, required on decode, refused at creation without a channel in it,
and the only asset its route hints are in (`test_invoice_asset.py`; `common/test/run-bolt11.c`
covers the field's encoding and its meaning on Bitcoin), an invoice for another network decoded
`valid: false` with both networks named, on Bitcoin regtest too (`test_decode_network.py`), and
route finding in that asset: a payer
with channels in two assets paying each invoice in its own, to a direct peer as well as over two
hops, `getroute` in one asset, an unannounced first hop, and an invoice in an asset the payer
cannot send refused with no HTLC offered anywhere, and a route whose first hop carries less than
it delivers sent by the payer and refused at the asset boundary by the next hop
(`test_asset_routing.py`), and a multi-part
payment split over two channels in its asset beside a larger one in another, a payment beyond what
the payer can spend in the asset failing with every part it offered in that asset, and keysend in
an asset, one hop and two, refused when the payer must name the asset or no route in it exists
(`test_asset_mpp_keysend.py`), and a payment converted through one quoting node: both HTLCs
settled on one preimage with the three nodes' books equal to the quote, an HTLC one atom off the
quote, a quote past its expiry and a quote used twice refused with nothing sent on, a payee that
fails the payment failing both HTLCs, the cap on open forwards per asset, the Sequence token as
one leg like any other, a restart of the quoting node mid-forward, lightningd refusing the
same route without the plugin, and a payment locked for 5,000 blocks paid under
`crossassetpay`'s default `maxdelay` (`test_crossasset_forward.py`), and a payer's default
`maxdelay`, the network's own cap: an invoice with a final lock time of 5,000 blocks paid by
a default `pay`, and returned by `getroute` and askrene's `getroutes`, on Sequentia and
refused on Bitcoin regtest (`test_pay_maxdelay.py`, on Bitcoin regtest too), and a channel in the
Sequence token or in an issued asset funded by one transaction from a wallet outside the node:
`fundchannel_complete` given it blinded and unsigned, its txid unchanged by the signatures the
wallet adds after the peer has signed the first commitment, and the channel paid over and closed
to the node, which held nothing; with `fundchannel_complete` accepting a funding output worth less
than the channel, which the funder must therefore check itself (`test_external_funding.py`), and
the taproot-covenant channel type (section 5b): chosen only when both peers offer it, paid over
both ways, an HTLC in flight at a force-close claimed by its covenant past its CLTV with the fee
from a coin in another asset and claimed with its preimage, the peer's claims on the closer's
commitment by either leaf, a revoked commitment punished by the victim and, while the victim is
offline, by `speculad`, a node back from being away that builds no claim of an HTLC output the
peer took in the commitment's own block, and a keyless node whose device signs the commitments, the claim and its
fee coin, and the sweeps, refusing nothing (`test_taproot_covenant.py`), and point-locked HTLCs
(section 5c): a payment over two hops whose every HTLC is locked to its own point, none of them
the invoice's point or hash, settled after the forwarder restarts mid-payment, with a
hash-locked payment beside it to a payee that takes no point locks; a point invoice paid by its
hash through a hop that takes none; a point invoice paid by its hash, by `pay` and by `xpay`,
over a channel of an older type between two nodes that both take point locks, with nothing
point-locked sent; a point-locked payment that takes the dearer route over taproot-covenant
channels rather than the cheaper one whose first channel is older; a route whose second channel
is older, refused there and paid by hash over the same channels; and a point-locked HTLC claimed
on chain with its scalar,
which the forwarder reads from the witness to settle the payment upstream
(`test_point_locks.py`), and the provider-signed credit (section 5d): two invoices of the
provider paid for the holder, a cumulative note for each, a forged note refused, the provider's
node refusing to pay its balance below the note, the holder's commitment dropped and the latest
note claimed from it with the fee in another asset, the rest swept by the provider after its
delay; a mutual close paying the holder the note; a provider that forgets its notes, whose close
without them the holder will not sign, and whose own commitment the holder claims from; the same
provider's HTLC below the note refused by the holder's channeld; and a keyless holder whose device
is stopped while it is paid twice, then returns, learns the latest note and signs the claim's fee
coin, refusing nothing (`test_credit.py`), and the symmetric channel type (section 5e): chosen
only when both peers offer it, paid over both ways; a unilateral close while the peer is away
whose kickoff, update and settlement each take their fee from a coin in another asset, and pay
each side its balance; a stale state, published and mined by a peer that kept it while the
other was away, replaced by the latest one when that side returns within the delay, and the
latest split settled; HTLCs in flight claimed from the settlement by their SUCCESS leaf with the
preimage, and by their TIMEOUT leaf after the expiry; a mutual close; and, with the victim
offline, `speculad` holding only its store replacing the stale state by the latest and settling
it after the delay, each with a fee coin from its own wallet in another asset
(`test_symmetric.py`). They need `sequentiad`, `sequentia-cli`
and a Bitcoin Core `bitcoind` on `PATH`, and the keyless tests need the device signer built
(`cargo build --release` in `contrib/seqln-signer`, or `SEQLN_SIGNER=/path/to/seqln-signer`).
The test plugins run under the `python3` on `PATH`, which needs the `pyln` packages, so the
`uv` environment's `bin` goes first:

```sh
PATH=$PWD/.venv/bin:/path/to/bitcoin/bin:/path/to/Sequentia/src:$PATH TEST_NETWORK=sequentia-regtest \
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
2. **Payment paths other than `pay` and `keysend` are asset-blind.** xpay, askrene and renepay
   know no asset. Use `pay`, which pays in the asset the invoice names, or `keysend asset=`. A plugin that settles
   HTLCs itself must check the `asset` the `htlc_accepted` hook names, as
   `contrib/holdinvoice-seq` and `contrib/crossasset-seq` do.
3. **Mainnet chainparams are placeholders.** All-zero genesis, NULL fee asset; the `sequentia`
   network entry must not be used.
4. **Committee-stall fail-open.** If the certified frontier is more than 144 blocks behind the tip
   (a stalled committee), the bcli clamp fails open with a warning rather than halting; operators
   should monitor for that log message.
5. **Penalty across an induced anchor reorg is untested.** Open, payment and mutual close of an
   issued-asset channel, and a breach of one answered by `speculad`, run in `tests/sequentia/`,
   and force-close resolution has been exercised on the testnet, but no test covers a penalty
   across a Bitcoin-anchor tail truncation.
6. **`speculad` needs a fee coin in an asset the node accepts.** Its fee wallet must hold at
   least one P2WPKH coin in an accepted asset, large enough for the fee of every output of one
   breach; while it holds none, a breach goes unanswered (the tower logs it and retries each
   round), and the cheater's delayed outputs become spendable after the channel's delay.
