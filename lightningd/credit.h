#ifndef LIGHTNING_LIGHTNINGD_CREDIT_H
#define LIGHTNING_LIGHTNINGD_CREDIT_H
/* SEQUENTIA: the provider-signed credit (common/credit_scripts.h,
 * doc/sequentia-fork.md section 5d).
 *
 * On a credit channel the opener is the provider: while the holder cannot
 * sign a channel update (its device is away), the provider can credit it by
 * signing a note, "the holder is owed c atoms in all", conditional on the
 * preimage of the payment it was paid for.  The note is enforceable from the
 * provider's balance output of either commitment by its CLAIM leaf; anyone
 * holding the note and the preimage can move what it owes to the holder's
 * script.  A later note supersedes every earlier one.
 *
 * The provider issues notes (issuecredit, which a plugin calls when a
 * payment for the holder arrives) and sends each to the holder's node in
 * the custom peer message SEQ_CREDIT_NOTE_MSG, again whenever the channel
 * reconnects.  The holder's node checks a note against the channel's credit
 * key, keeps it, and hands its latest to channeld (which tells the signer,
 * and refuses an update that leaves the provider's balance unable to pay it)
 * and to onchaind (which claims it once a commitment is on chain). */
#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/signature.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>

struct channel;
struct lightningd;
struct node_id;

/* The custom peer message carrying a note: odd, so a peer that does not
 * know it ignores it.
 * [channel_id][u64 credit][sha256 payment_hash][64 sig][u8 has_preimage]
 * [32 preimage, if has_preimage] */
#define SEQ_CREDIT_NOTE_MSG 48033

struct credit_note {
	/* Cumulative credit, atoms of the channel's asset. */
	u64 credit;
	struct sha256 payment_hash;
	struct bip340sig sig;
	/* The payment's preimage, once known (a note is enforceable only
	 * with it). */
	struct preimage *preimage;
};

/* Is @channel a credit channel? */
bool channel_has_credit(const struct channel *channel);

/* The channel's latest note: for the holder, the highest it can enforce
 * (with its preimage); for the provider, the highest it issued.  NULL if
 * none. */
struct credit_note *channel_credit_latest(const tal_t *ctx,
					  struct channel *channel);

/* What a mutual close of @channel moves from the provider's side to the
 * holder's: the latest note's credit (for the holder, the highest it can
 * enforce; for the provider, the highest it issued).  0 if none. */
u64 channel_credit_owed(struct channel *channel);

/* channeld for @channel was just started: the provider sends its latest
 * note to the holder, the holder hands its latest to channeld. */
void credit_channel_started(struct channel *channel);

/* onchaind for @channel was just started: hand it the latest note. */
void credit_onchaind_started(struct channel *channel);

/* A SEQ_CREDIT_NOTE_MSG from @peer_id.  Returns false if @msg is not one. */
bool credit_handle_peer_msg(struct lightningd *ld,
			    const struct node_id *peer_id,
			    const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_CREDIT_H */
