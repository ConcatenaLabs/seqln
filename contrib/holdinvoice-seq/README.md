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

## One asset per hold

On a Sequentia network a node can hold channels in several assets, and an
HTLC's amount is in the asset of the channel it arrived on. A hold is registered
in one asset, and only HTLCs that arrive in it are held and counted in
`received_msat`. An HTLC in any other asset is failed back at once with
`incorrect_or_unknown_payment_details`, and logged as "refused an htlc for H in
asset X". The hold stays `waiting`, so a holder that settles only an `accepted`
hold never reveals the preimage for a payment in the wrong asset. The plugin
reads the asset from the `htlc_accepted` hook's `htlc.asset`, which names every
asset, the Sequence token (the policy asset) like any other. A hold an older
version of the plugin recorded as `"policy"` is read back as the network's
policy asset. On other networks there are no assets and every HTLC counts.

## The full amount

A hold registered with `amount_msat` is `accepted` only once the HTLCs it holds
in its asset add up to that amount: a payment may come in several parts, and
`received_msat` counts them. While they fall short the hold stays `waiting`,
`holdinvoicewait` does not return, and `holdinvoicesettle` is refused, so the
holder never gives the preimage away for part of a payment. When the rest does
not arrive within `mpp_timeout` seconds of the first part (60 by default, as
BOLT 4 asks of a payee), the parts are failed back with `mpp_timeout` (0x17),
`received_msat` returns to 0, and the hold waits for a payment again. A hold
registered with no amount is accepted at its first part.

## Restarts

Each registration, settle and cancel is written to lightningd's datastore
(key `holdinvoice-seq`, then the payment hash) before the call returns. On
start the plugin reads them back. lightningd replays the HTLCs it still holds
to the `htlc_accepted` hook: a registered hold holds them again (each HTLC
counted once), and a settled hold resolves them with its preimage.

## RPC methods (match seqdex's `clnLNLeg`)
- `holdinvoice payment_hash [amount_msat] [label] [description] [cltv] [asset] [mpp_timeout]`: register `H` to be held until the parts received reach `amount_msat`, failing them back after `mpp_timeout` seconds (default 60) if they do not. On a Sequentia network `asset` is the 32-byte hex id of the asset to hold the payment in; without it the hold is in the asset of this node's channels when they all hold one, and the call is refused when they hold several or none.
- `holdinvoicelookup payment_hash`: `{state: waiting|accepted|settled|cancelled|unknown, amount_msat, received_msat, cltv_expiry, blockheight, asset}`. `received_msat` sums the held HTLCs in the hold's asset; `accepted` means it has reached `amount_msat`. `asset` is the hold's asset, the Sequence token's included (absent on other networks). `cltv_expiry` is the earliest absolute expiry among the held HTLCs (the payer chose it); the holder caps any outgoing payment it makes against the hold so it resolves before that height. `blockheight` is the node's tip, the height that expiry is measured against.
- `holdinvoicewait payment_hash [timeout=60]`: blocks until the hold leaves `waiting` (the whole amount is held, or the hold was settled or cancelled) or `timeout` seconds pass, then answers exactly as `holdinvoicelookup` would. A holder waiting on this acts the moment the HTLC lands instead of a poll interval later.
- `holdinvoicesettle payment_hash preimage`: resolve held HTLC(s) with the preimage (must hash to `H`). Refused while the hold holds parts short of its amount. The answer carries `received_msat`.
- `holdinvoicecancel payment_hash`: fail held HTLC(s) back to the payer. The answer carries `received_msat`.

## Load
    lightning-cli plugin start /path/to/seqln/contrib/holdinvoice-seq/holdinvoice.py
or `plugin=.../holdinvoice-seq/holdinvoice.py` in the node config.

Uses the in-tree `contrib/pyln-client` (located tree-relative, no external deps;
it deliberately avoids pyln's gossmap import chain which pulls in `coincurve`).

## Limits
- The registered `cltv` is reported, not enforced: the holder compares
  `cltv_expiry` with what it needs before it settles.
- A hold settled before any HTLC arrives resolves each HTLC that arrives for it
  at once, whatever its amount.
- There is no create-by-hash BOLT11 path (HSM `sign_invoice`): the payer pays
  the bare hash with `sendpay`.

`tests/sequentia/test_hold_asset.py` exercises the asset rule, the full amount
and the restart.
