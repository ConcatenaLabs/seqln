# crossasset-seq: quoted cross-asset forwarding

A Core Lightning plugin that lets a SeqLN node convert a payment between two
assets it holds channels in. A payer holding asset A pays an invoice in asset
B through the converting node (the quoting node): the incoming HTLC arrives
in A, the outgoing HTLC leaves in B, under one payment hash, at amounts the
quoting node quoted and signed before anything was sent. The payee sees an
ordinary payment in B.

lightningd itself never converts. `forward_htlc()` refuses any forward whose
incoming and outgoing channels hold different assets, and that stays. The
plugin takes a quoted HTLC on the `htlc_accepted` hook before lightningd
would forward it, sends the onion's next hop itself with `sendonion` over the
channel the onion names, and resolves the incoming HTLC with the preimage the
outgoing one returns, or fails it back with the outgoing one's error.

The same plugin serves both roles: the quoting node publishes rates and
answers quote requests; the payer requests, checks and pays.

## The quote

A quote binds one payment to fixed terms:

| Field | Meaning |
| --- | --- |
| `network` | The quoting node's network (`getinfo`) |
| `node_id` | The quoting node |
| `quote_id` | 16 random bytes, hex |
| `payment_hash` | The one payment the quote is for |
| `asset_in`, `amount_in_msat` | What the quoting node takes: exactly this, in this asset |
| `asset_out`, `amount_out_msat` | What it forwards: exactly this, in this asset |
| `rate` | Atoms of `asset_out` given per atom of `asset_in`, a decimal, as the quoting node publishes it |
| `fee_base_msat`, `fee_ppm` | Its fee, in `asset_in` |
| `expiry` | Unix time after which an HTLC for the quote is refused |
| `cltv_delta` | Blocks the incoming HTLC must outlive the outgoing one by (the node's `cltv-delta`) |
| `max_out_cltv` | Most blocks above the tip the outgoing HTLC may expire at |
| `signature` | `signmessage` by the quoting node's key over the text below |

`amount_in_msat` is `ceil(amount_out_msat / rate)`, plus `ceil` of `fee_ppm`
millionths of that, plus `fee_base_msat`. On Sequentia an amount in msat is
thousandths of the asset's atoms.

The signature covers the text `seqln-crossasset-quote-v1:` followed by every
field above except `signature`, as JSON with sorted keys and no spaces.
`crossassetquotemessage quote` prints that text. The tag keeps a quote
signature apart from any other message the node signs. The signature is a
promise by the quoting node, not a spending authorisation. It names one
payment hash and both amounts, so it cannot be taken as a quote for another
payment, another amount or another node.

The rate is the quoting node's own. The plugin never takes it from the
chain's fee exchange rates. No pair is quoted until the operator publishes
one, and no asset is a default leg: the Sequence token is quoted only when
its pair is published, like any other asset.

## Quoting node

    lightning-cli crossassetsetrate asset_in asset_out rate [fee_base_msat] [fee_ppm] [max_out_msat]
    lightning-cli crossassetrates
    lightning-cli crossassetforwards

- `crossassetsetrate` publishes a pair, or with `rate=0` withdraws it. The
  pair is kept in the datastore. Fees and caps cannot be negative. `max_out_msat` caps one quote's outgoing
  amount (0: no cap beyond the channel).
- `crossassetrates` lists the published pairs, the limits below and the open
  forwards per outgoing asset.
- `crossassetforwards` lists every quote an HTLC has used and what became of
  it (`forwarding`, `settled`, `failed`).
- `crossassetquote payment_hash asset_in asset_out amount_out_msat [seconds]`
  signs a quote locally. Payers ask over the wire (below).

A quote is refused when the pair is not published, when the node holds no
open channel in `asset_in`, when no channel in `asset_out` can send the
amount, when the hash has a quote that an HTLC used and whose forward did
not fail, or when the node already
has as many forwards open in `asset_out` as its cap allows.

The quoting node forwards an HTLC under a quote only if all of these hold:

- the quote has not expired;
- the HTLC arrived in `asset_in` with exactly `amount_in_msat`;
- the onion forwards over a channel of this node in `asset_out`, exactly
  `amount_out_msat`;
- the outgoing expiry is above the tip and at most `max_out_cltv` blocks
  out, and the incoming expiry is at least `cltv_delta` blocks later;
- fewer than `crossasset-max-open` forwards are open in `asset_out`.

Otherwise the HTLC fails back with `incorrect_or_unknown_payment_details`,
and the reason goes to the log as `crossasset: refused the htlc for <hash>:
<reason>`. A refusal does not spend the quote. The cap refusal fails with
`temporary_node_failure`, and the quote stays usable once a forward closes.

An HTLC that uses the quote spends it. The record is written to the
datastore before the outgoing HTLC is sent, so a quote is used once only,
across restarts too: a second HTLC for the same hash is refused (`quote <id>
has already been used`). After a restart lightningd replays the incoming
HTLC; the plugin sends nothing again and resolves the HTLC from the outgoing
payment's outcome. Once a forward has failed, the payer may ask for a new
quote for the same payment; that is a new grant, and the spent quote stays
spent.

The plugin acts only on an HTLC that would leave in another asset than it
arrived in. A payment to this node, or a forward in one asset that shares a
quoted hash, goes to lightningd untouched. An unannounced channel is
forwarded over only by its alias, as lightningd forwards. The real scid of
a private channel is unknown to the plugin.

Unused quotes live in memory only (at most 1,000 at a time; expired ones
are dropped). After a restart they are gone, and an HTLC for one is refused
by lightningd's own asset check.

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| `crossasset-quote-seconds` | 30 | Longest life of a quote, in seconds. A payer may ask for a shorter one |
| `crossasset-max-open` | 4 | Most forwards open at once in one outgoing asset |
| `crossasset-max-out-cltv` | 432 | Most blocks an outgoing HTLC may lock the node's funds for |

### Loading

    important-plugin=/path/to/seqln/contrib/crossasset-seq/crossasset.py

While a forward is open, only this plugin holds the incoming HTLC. Without
it, lightningd would treat the replayed HTLC as an ordinary forward, refuse
it at the asset boundary and fail it back while the outgoing HTLC was still
out: the quoting node would pay out B and not collect A. So the plugin is
not dynamic and cannot be stopped while lightningd runs. Load it as an
`important-plugin`, so that lightningd stops too if the plugin dies. Do not
remove it from the configuration while `crossassetforwards` shows a forward
in `forwarding`.

The quoting node signs with its node key, so it must hold its own key: on a
keyless node every quote would wait for the device.

It uses the in-tree `contrib/pyln-client` (found tree-relative, standard
library only).

## Payer

    lightning-cli crossassetpay bolt11 node_id maxamount_in_msat [asset_in] [maxdelay] [retry_for]
    lightning-cli crossassetrequestquote node_id payment_hash asset_in asset_out amount_out_msat [seconds] [timeout]
    lightning-cli crossassetcheckquote quote node_id payment_hash asset_in asset_out amount_out_msat

`crossassetpay` pays an invoice in one asset with another, converted by
`node_id`, a peer the payer has a channel with in `asset_in` (by default the
one asset its channels to that peer hold). `maxamount_in_msat` is required:
it is the most of `asset_in` the payer will give. The payer can check that a
quote is what the quoting node signed, but not that the quoting node's rate
is a fair one, so only the payer can set that bound. It:

1. decodes the invoice, which names `asset_out`, the amount, the payee and
   the hash;
2. finds the path from the quoting node to the payee in `asset_out`: a route
   hint of the invoice that starts at the quoting node, else `getroute`
   from it;
3. asks the quoting node for a quote for the amount that path needs;
4. checks the quote (below); refuses it if it asks more than
   `maxamount_in_msat` of `asset_in`, or if its `cltv_delta` would lock the
   payer's HTLC for more than `maxdelay` blocks (default 1008);
5. sends one HTLC with `sendpay`: its first hop pays the quoting node
   `amount_in_msat` in `asset_in`, and its onion has the quoting node
   forward `amount_out_msat` toward the payee, which gets the invoice's
   payment secret and amount;
6. waits, and returns the preimage, the quote and both amounts.

The payer relies on nothing it cannot check. Before sending, it requires
that the quote names the node, hash, assets and amount it asked for, on its
network; that the signature verifies against the quoting node's key; that
`amount_in_msat` follows from the signed rate and fees; and that the quote
has not expired. After sending, the HTLC it offered can be claimed only with
the preimage, which the quoting node learns only when the payee is paid. If
anything fails, the HTLC fails back.

The payer's `listsendpays` shows the payment with `amount_sent_msat` in
`asset_in` and `amount_msat` in `asset_out`. The two are in different units,
and their difference is not a fee.

## Wire

Quotes travel as custom messages between peers (odd types, which a node
without the plugin ignores):

- `0xc0a1` request: the type, then JSON `{request_id, payment_hash, asset_in,
  asset_out, amount_out_msat[, seconds]}`;
- `0xc0a3` reply: the type, then JSON `{request_id, quote}` or
  `{request_id, error}`.

The payer must be connected to the quoting node, which holding a channel to
it ensures.

## Limits

- **The quoting node writes an option.** Between the incoming HTLC and the
  outgoing one's resolution, whoever holds the preimage can settle or fail
  depending on how the rate has moved. The quote's expiry bounds when a
  forward may start, `crossasset-max-out-cltv` bounds how long it may stay
  open, `crossasset-max-open` bounds how many are open per asset, and the
  rate's spread prices the rest. No premium is collected for an option that
  is not exercised.
- One HTLC per quote. A multi-part payment cannot be converted.
- The quoting node must be the payer's direct peer, and the conversion
  happens at that first hop.
- Quote requests are not rate-limited beyond the 1,000 unused quotes held at
  once.
- Forward records stay in the datastore.

`tests/sequentia/test_crossasset_forward.py` runs every rule above on an
anchored Sequentia test network.
