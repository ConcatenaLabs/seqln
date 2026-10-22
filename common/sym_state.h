#ifndef LIGHTNING_COMMON_SYM_STATE_H
#define LIGHTNING_COMMON_SYM_STATE_H
/* One state of a symmetric channel (common/sym_scripts.h) as the daemons pass
 * it and the database keeps it: which commitment it is, its state number,
 * its settlement outputs and the update signatures held for it. */
#include "config.h"
#include <bitcoin/signature.h>
#include <common/amount.h>
#include <common/htlc.h>

struct sym_channel;
struct sym_output;
struct sym_tree;

struct sym_state_out {
	struct amount_sat amount;
	u8 *spk;
	/* Its asset (0x01 || 32-byte id), or NULL: the channel's.  Only a
	 * channel that holds several assets names one. */
	u8 *asset;
};

struct sym_state {
	/* Whose commitment this is, from the holder's side, and its index. */
	enum side owner;
	u64 commit_num;
	s64 num;
	/* The settlement, in order. */
	struct sym_state_out *outs;
	/* The update signatures held: [LOCAL] the holder's own. */
	bool has_sig[NUM_SIDES];
	struct bip340sig sig[NUM_SIDES];
};

/* A state from a settlement list. */
struct sym_state *sym_state_new(const tal_t *ctx, enum side owner,
				u64 commit_num, s64 num,
				const struct sym_output *outs);

/* Its outputs as the script builders take them. */
struct sym_output *sym_state_outputs(const tal_t *ctx,
				     const struct sym_state *st);

/* Its state output's tree (no Simplicity leaf). */
void sym_state_tree_of(const tal_t *ctx, const struct sym_channel *sc,
		       const struct sym_state *st, struct sym_tree *tree);

/* Both signatures held, in UPD's order. */
bool sym_state_signed(const struct sym_state *st, enum side opener,
		      const struct bip340sig **sig_opener,
		      const struct bip340sig **sig_accepter);

/* The total its settlement pays. */
struct amount_sat sym_state_total(const struct sym_state *st);

/* A state whose outputs all leave their asset to the channel encodes as it
 * always has; one that names an asset sets 0x80 in the owner byte and
 * follows each output with whether it names one, and the 33 bytes. */
void towire_sym_state(u8 **pptr, const struct sym_state *st);
struct sym_state *fromwire_sym_state(const tal_t *ctx,
				     const u8 **pptr, size_t *max);

#endif /* LIGHTNING_COMMON_SYM_STATE_H */
