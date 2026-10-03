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
reads the asset from the `htlc_accepted` hook's `htlc.asset`; for a hold in the
Sequence token (the policy asset) it checks the HTLC's channel in
`listpeerchannels`. On other networks there are no assets and every HTLC counts.

## Restarts

Each registration, settle and cancel is written to lightningd's datastore
(key `holdinvoice-seq`, then the payment hash) before the call returns. On
start the plugin reads them back. lightningd replays the HTLCs it still holds
to the `htlc_accepted` hook: a registered hold holds them again (each HTLC
counted once), and a settled hold resolves them with its preimage.

## RPC methods (match seqdex's `clnLNLeg`)
- `holdinvoice payment_hash [amount_msat] [label] [description] [cltv] [asset]`: register `H` to be held. On a Sequentia network `asset` is the 32-byte hex id of the asset to hold the payment in; without it the hold is in the asset of this node's channels when they all hold one, and the call is refused when they hold several or none.
- `holdinvoicelookup payment_hash`: `{state: waiting|accepted|settled|cancelled|unknown, amount_msat, received_msat, cltv_expiry, blockheight, asset}`. `received_msat` sums the held HTLCs in the hold's asset. `asset` is the hold's asset (absent for the Sequence token, as `listpeerchannels` has it, and on other networks). `cltv_expiry` is the earliest absolute expiry among the held HTLCs (the payer chose it); the holder caps any outgoing payment it makes against the hold so it resolves before that height. `blockheight` is the node's tip, the height that expiry is measured against.
- `holdinvoicewait payment_hash [timeout=60]`: blocks until the hold leaves `waiting` (the HTLC is held, or the hold was settled or cancelled) or `timeout` seconds pass, then answers exactly as `holdinvoicelookup` would. A holder waiting on this acts the moment the HTLC lands instead of a poll interval later.
- `holdinvoicesettle payment_hash preimage`: resolve held HTLC(s) with the preimage (must hash to `H`).
- `holdinvoicecancel payment_hash`: fail held HTLC(s) back to the payer.

## Load
    lightning-cli plugin start /path/to/seqln/contrib/holdinvoice-seq/holdinvoice.py
or `plugin=.../holdinvoice-seq/holdinvoice.py` in the node config.

Uses the in-tree `contrib/pyln-client` (located tree-relative, no external deps;
it deliberately avoids pyln's gossmap import chain which pulls in `coincurve`).

## Limits
- The registered `amount_msat` and `cltv` are reported, not enforced: the holder
  compares `received_msat` and `cltv_expiry` with what it expects before it
  settles.
- There is no create-by-hash BOLT11 path (HSM `sign_invoice`): the payer pays
  the bare hash with `sendpay`.

`tests/sequentia/test_hold_asset.py` exercises the asset rule and the restart.
