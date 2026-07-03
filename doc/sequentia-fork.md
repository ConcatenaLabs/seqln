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

Done (Phase 0, network + parser):
- `chainparams.h`: `has_anchor_header` field.
- `chainparams.c`: sequentia-testnet (accurate) + sequentia mainnet (placeholder) entries + testnet
  fee-asset constant.
- `block.c`: anchored-header parse.

Next:
- Test-harness duplicates (`contrib/pyln-testing/.../{utils,fixtures}.py`, `tests/utils.py`,
  `devtools/gossipwith.c`) need Sequentia entries before the pytest suite runs.
- A proper `bitcoin/test/run-*.c` unit test asserting the block-1000 hash (the Python file is the
  interim regression check).
- sequentia-regtest: needs a custom-params node (con_bitcoin_anchor + a local bitcoind mainchain) to
  exercise the anchor path locally.
- Phase 0 exit criterion: `lightningd --network=sequentia-testnet` syncs a Sequentia node and its
  computed block hashes match. Confirm build against Elements Core 23.3.3 (CI pins 23.2.1).
- Then Phase 1 (policy-asset channels) per the spec.

## Decisions still provisional (worth Alberto's sign-off before Phase 3)

- Lightning HRPs (`sqt`/`tsqt`/`sqrt`).
- Asset invoice encoding: standard BOLT11 for the Sequence token and BTC; issued-asset invoices add
  `asset_id` (32-byte, internal order) + `asset_amount` (integer atoms) tagged fields and omit the HRP
  amount (BOLT11's msat/multiplier encoding is BTC-specific). Field type numbers are SeqLN-local until
  standardized.
