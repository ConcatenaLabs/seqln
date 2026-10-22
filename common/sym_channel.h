#ifndef LIGHTNING_COMMON_SYM_CHANNEL_H
#define LIGHTNING_COMMON_SYM_CHANNEL_H
/* A symmetric channel's scripts (common/sym_scripts.h) from the state the
 * daemons keep of it (common/initial_channel.h): the kickoff, each side's
 * states and the checks of the update signatures. */
#include "config.h"
#include <common/sym_scripts.h>
#include <common/sym_state.h>

struct channel;

/* The channel's constants: tag, update keys (each side's delayed payment
 * basepoint, which this type uses for nothing else), asset, delay. */
void sym_channel_of(const struct channel *channel, struct sym_channel *sc);

/* The shared delay: the larger of the two to_self_delays. */
u16 sym_shared_delay(const struct channel *channel);

/* The dust limit of every settlement: the larger of the two. */
struct amount_sat sym_dust_limit(const struct channel *channel);

/* The state @side's commitment @commit_num carries: its view's balances and
 * @htlcs (every committed HTLC, trimmed ones included).  NULL and *err set if
 * it cannot be paid out of the funding. */
struct sym_state *sym_channel_state(const tal_t *ctx,
				    const struct channel *channel,
				    enum side side, u64 commit_num,
				    const struct sym_htlc *htlcs,
				    const char **err);

/* The message both sides sign for @st. */
void sym_channel_msg(const struct channel *channel, const struct sym_state *st,
		     struct sha256 *msg);

/* Is @sig @signer's update signature on @st? */
bool sym_channel_check_sig(const struct channel *channel,
			   const struct sym_state *st, enum side signer,
			   const struct bip340sig *sig);

/* The kickoff, unsigned, and the funding script it spends. */
struct bitcoin_tx *sym_channel_kickoff(const tal_t *ctx,
				       const struct channel *channel,
				       const u8 **wscript);

#endif /* LIGHTNING_COMMON_SYM_CHANNEL_H */
