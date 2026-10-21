# credit-seq: invoices that credit a holder

A plugin for the provider of a credit channel
([doc/sequentia-fork.md](../../doc/sequentia-fork.md), section 5d). On such a channel the
provider, the side that opened it, can credit the other side, the holder, while the holder
cannot sign a channel update: a hosted user whose device is away. The provider is paid
instead of the holder, and signs a cumulative credit note, enforceable from its balance output
on either commitment, for what it owes the holder in all.

Run it on the provider's node, started with `--taproot-covenant-channels` and
`--credit-channels`:

    lightningd ... --plugin=/path/to/seqln/contrib/credit-seq/credit.py

## Commands

    creditinvoice id amount_msat [label] [description]

An invoice of this node whose payment credits peer `id`. It is in the asset of this node's
credit channel with `id`, where this node provides; the call fails unless there is exactly one
such channel. The reply is `invoice`'s, with `credited` (the peer) and `channel_id` added.
Hand the invoice to whoever pays the holder.

## When the invoice is paid

The `invoice_payment` hook asks lightningd to issue a note for the amount (`issuecredit`),
conditional on the invoice's payment hash and carrying its preimage, before the payment is
accepted: this node collects a payment only once the holder is owed it. lightningd signs the
note, keeps it and sends it to the holder's node, which keeps it too and hands it to its signer.
If no note can be issued (this node's balance in the channel, less its dust limit, cannot pay
the new total), the payment is refused and fails back to the payer.

A note binds this node from the moment it is out: the holder, or anyone holding the note and
the payment's preimage, claims it from this node's balance output of either commitment, and a
mutual close pays it. This node cannot move its balance below the latest note. Until a note
reaches the holder, the holder has only this node's word, since the payment was made to it.

`listcreditnotes` lists the notes issued and held; see section 5d for the commands and what the
holder's node and signer do with a note.
