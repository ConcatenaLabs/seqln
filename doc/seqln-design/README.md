# SeqLN design documents

The design specs for **this fork**. They describe SeqLN's own code, so they live
here rather than in the Sequentia node repository, which owns the protocol
specification (anchoring, proof of stake, the fee market) and nothing about how
Lightning is implemented on top of it.

| Document | Status |
|---|---|
| [`seqln-core-lightning-fork-spec.md`](seqln-core-lightning-fork-spec.md) | The design spec as written before implementation: networks, chain abstraction, asset channels, anchoring and timelock policy. Start here, but where it differs from [`../sequentia-fork.md`](../sequentia-fork.md) (HRPs `sqt`/`tsqt`, no regtest entry, the asset TLV on v1 `open_channel`, announced asset channels, certified-depth confirmations with anchor burial gating only the announcement), the fork doc and the code win. |
| [`seqln-asset-channels-build-plan.md`](seqln-asset-channels-build-plan.md) | Build plan for asset-aware channels. Implemented. |
| [`seqln-phase2-submarine-swaps.md`](seqln-phase2-submarine-swaps.md) | Submarine-swap primitives, both directions. Historical: implemented in [`seqdex`](https://github.com/ConcatenaLabs/seqdex) (`pkg/xchain`); the §5d plan to use the daywalker90 plugin was replaced by `contrib/holdinvoice-seq`. |
| [`seqln-step2-pure-ln-swaps-design.md`](seqln-step2-pure-ln-swaps-design.md) | Pure-Lightning asset↔BTC swaps. Historical milestone log: implemented in `seqdex` (`pkg/xchain`) plus `contrib/holdinvoice-seq` here; its §7 questions predate milestones M0-M5 and are resolved by them. |
| [`seqln-tier2-hosted-channels-design.md`](seqln-tier2-hosted-channels-design.md) | The hosted-channel signer split (thin-wallet non-custodial Lightning). Daemon-layer milestones implemented, including the Noise_XK transport; wallet integration is in [Fulmen](https://github.com/ConcatenaLabs/fulmen); hosted-LSP liquidity (JIT/pay-to-open) is not in this repo. |
| [`sequentia-lightning-cln-spec.md`](sequentia-lightning-cln-spec.md) | The earlier fork plan, superseded by `seqln-core-lightning-fork-spec.md`. Kept as the record of what was decided against. |

[`../sequentia-fork.md`](../sequentia-fork.md) is the file-level delta and hazard
list against upstream Core Lightning — what this fork changes, rather than why.

Two neighbours own the documents that are about *them*, not about SeqLN: the
Sequentia protocol spec is in
[`Sequentia`](https://github.com/ConcatenaLabs/Sequentia) under
`doc/sequentia/`, and the DEX design notes these specs cite as
`seqdex/docs/...` are in
[`seqdex`](https://github.com/ConcatenaLabs/seqdex).
