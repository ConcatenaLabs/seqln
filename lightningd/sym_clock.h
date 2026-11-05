#ifndef LIGHTNING_LIGHTNINGD_SYM_CLOCK_H
#define LIGHTNING_LIGHTNINGD_SYM_CLOCK_H
/* SEQUENTIA: lightningd's side of a symmetric channel's settle clock
 * (option_seq_symmetric_clock, common/sym_scripts.h).
 *
 * The funding transaction issues one atom of a fresh asset, the marker, into
 * a seed output beside the 2-of-2; the marker's id derives from the funding
 * input that issues it, which the opener names in open_channel.  The opener's
 * fundchannel_complete refuses a funding that does not issue exactly that.
 * The accepter, which puts nothing into the channel, checks the funding once
 * it is mined, before the channel locks in, and forgets the channel if it is
 * wrong.  The channel keeps the issuer and, once checked, the seed's output
 * in the funding (wallet table channel_sym_clock). */
#include "config.h"
#include <bitcoin/tx.h>

struct channel;

struct sym_clock_funding {
	/* The funding input whose issuance makes the marker. */
	struct bitcoin_outpoint issuer;
	/* The seed's output number in the funding, once checked. */
	bool seed_known;
	u32 seed_outnum;
};

/* Attach the clock to a channel just opened, before its funding is watched:
 * @seed_outnum once the opener checked its funding, else NULL. */
void sym_clock_attach(struct channel *channel,
		      const struct bitcoin_outpoint *issuer,
		      const u32 *seed_outnum);

/* The seed script of @channel's funding. */
u8 *sym_clock_seed_of(const tal_t *ctx, const struct channel *channel);

/* @channel's funding @tx is mined: check it, if not checked yet.  False if
 * it does not issue the marker into the seed as it must: the channel must
 * not lock in, and is forgotten once the caller returns. */
bool sym_clock_funding_found(struct channel *channel,
			     const struct bitcoin_tx *tx);

/* Show the signer a settle-clock channel's funding transaction @tx, whose
 * input @issuer issues its marker: a signer that holds a balance checks it
 * before it signs a state that pays this side.  False if it refuses. */
bool sym_clock_show_signer(struct lightningd *ld, const struct node_id *peer,
			   u64 dbid, const struct bitcoin_tx *tx,
			   const struct bitcoin_outpoint *funding,
			   const struct bitcoin_outpoint *issuer);

/* The marker of @channel, as an output asset (0x01 || id). */
void sym_clock_marker_of(const struct channel *channel, u8 asset[33]);

/* The clock @clock of @channel's kickoff, as a settle's input after the
 * state output: the capacity in the channel asset, the clock's leaf as its
 * witness, the shared delay as its sequence. */
struct sym_spend_in;
void sym_clock_input(const tal_t *ctx, const struct channel *channel,
		     const struct bitcoin_outpoint *clock,
		     struct sym_spend_in *in);

/* The seed, as the kickoff's input after the funding: its one atom of the
 * marker, and the KICK leaf as its witness.  False if the seed's output in
 * the funding is not known yet. */
bool sym_clock_seed_input(const tal_t *ctx, const struct channel *channel,
			  struct sym_spend_in *in);

#endif /* LIGHTNING_LIGHTNINGD_SYM_CLOCK_H */
