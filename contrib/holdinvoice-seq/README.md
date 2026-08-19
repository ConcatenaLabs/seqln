# holdinvoice-seq: SeqLN hold-invoice plugin

A minimal CLN plugin that holds incoming HTLCs by `payment_hash` in the
`accepted` state until told to settle (revealing the preimage) or cancel. It is
the safety primitive for pure-Lightning swaps
([doc/seqln-design/seqln-step2-pure-ln-swaps-design.md](../../doc/seqln-design/seqln-step2-pure-ln-swaps-design.md)): a swap maker's *incoming* leg is held until the
maker learns the preimage by paying the *outgoing* leg.

Crucially it holds an **externally-supplied hash with no local invoice and no
knowledge of the preimage**: the taker generates `P`, the maker only ever sees
`H = SHA256(P)`, registers it here, and the taker pays the bare hash via
`sendpay` (so no create-by-hash BOLT11 / HSM invoice signing is needed).

## RPC methods (match seqdex's `clnLNLeg`)
- `holdinvoice payment_hash [amount_msat] [label] [description] [cltv]`: register `H` to be held.
- `holdinvoicelookup payment_hash`: `{state: waiting|accepted|settled|cancelled|unknown, amount_msat}`.
- `holdinvoicesettle payment_hash preimage`: resolve held HTLC(s) with the preimage (must hash to `H`).
- `holdinvoicecancel payment_hash`: fail held HTLC(s) back to the payer.

## Load
    lightning-cli plugin start /path/to/seqln/contrib/holdinvoice-seq/holdinvoice.py
or `plugin=.../holdinvoice-seq/holdinvoice.py` in the node config.

Uses the in-tree `contrib/pyln-client` (located tree-relative, no external deps;
it deliberately avoids pyln's gossmap import chain which pulls in `coincurve`).

## Status / TODO
- Proven live (2026-07-04) on GOLD (asset) HTLCs: hold->settle->complete,
  hold->cancel->failed, and unregistered payments pass through untouched.
- M0: in-memory state (no persistence across plugin restart); add file-backed
  persistence of held (hash -> state/preimage) before production use, so a crash
  mid-hold re-holds re-delivered HTLCs correctly.
- Optional: amount/cltv validation against the registered expectation; a
  create-by-hash BOLT11 path (HSM `sign_invoice`) if a payable invoice is wanted
  instead of `sendpay`-to-hash.
