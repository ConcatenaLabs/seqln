#ifndef LIGHTNING_CHANNELD_SYM_CHANNELD_H
#define LIGHTNING_CHANNELD_SYM_CHANNELD_H
/* SEQUENTIA: channeld's side of the symmetric channel type
 * (common/sym_scripts.h): each commitment is a state, signed by an update
 * signature from each side over a message that commits to its settlement. */
#include "config.h"
#include <bitcoin/signature.h>
#include <common/sym_state.h>

struct channel;
struct hsm_htlc;

/* The state @side's commitment @commit_num carries now. */
struct sym_state *sym_channeld_state(const tal_t *ctx,
				     const struct channel *channel,
				     enum side side, u64 commit_num);

/* Our update signature on @st (into st->sig[LOCAL]), from hsmd; @htlcs as
 * for hsmd_sign_remote_commitment_tx, so a validating signer can check what
 * the state pays it. */
void sym_channeld_sign(const struct channel *channel, struct sym_state *st,
		       const struct hsm_htlc *htlcs);

/* Our funding key's kickoff signature, from hsmd. */
void sym_channeld_kickoff_sig(const struct channel *channel,
			      struct bitcoin_signature *sig);

#endif /* LIGHTNING_CHANNELD_SYM_CHANNELD_H */
