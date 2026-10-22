#ifndef LIGHTNING_LIGHTNINGD_SYMMETRIC_H
#define LIGHTNING_LIGHTNINGD_SYMMETRIC_H
/* SEQUENTIA: lightningd's side of the symmetric channel type
 * (common/sym_scripts.h).
 *
 * The node keeps three states of each such channel: its own latest and the
 * peer's latest, each with both update signatures, and the peer's newest,
 * which it signed and the peer has not countersigned yet (the peer can
 * broadcast that one, so its settlement is kept).  The kickoff's two
 * signatures are kept from the open: the peer's is last_sig on last_tx.
 *
 * A unilateral close broadcasts the kickoff, then the best state the node
 * holds whole (onchaind), then its settlement after the shared delay; each
 * pays its fee from a wallet coin attached when it is built, in any asset
 * the node accepts for fees, and is rebuilt each block until its input is
 * spent. */
#include "config.h"
#include <common/sym_scripts.h>
#include <common/sym_state.h>

struct bitcoin_outpoint;
struct channel;
struct lightningd;

/* The channel's script constants. */
void sym_channel_from(const struct channel *channel, struct sym_channel *sc);
u16 sym_channel_delay(const struct channel *channel);

/* How many blocks before an HTLC's expiry the channel must start to close:
 * the kickoff and the update confirm, the shared delay passes, possibly a
 * second time (a peer that withheld its last acknowledgement publishes the
 * state it holds just before the first runs out), the settlement and the
 * claim confirm. */
u32 sym_htlc_margin(const struct channel *channel);

/* The states openingd and channeld report: each takes the state (it becomes
 * the channel's) and is saved at once. */
void sym_record_opened(struct channel *channel,
		       const struct bitcoin_signature *kickoff_sig,
		       struct sym_state *local,
		       struct sym_state *remote_pending);
void sym_record_sent(struct channel *channel,
		     struct sym_state *remote_pending);
void sym_record_local(struct channel *channel, struct sym_state *local);
void sym_record_revoked(struct channel *channel,
			struct sym_state *remote);

/* The highest-numbered state this node holds with both signatures. */
const struct sym_state *sym_best_state(const struct channel *channel);

/* Is @tx this channel's kickoff (output 0 KO)? */
bool sym_is_kickoff(const struct channel *channel, const struct bitcoin_tx *tx);

/* Broadcast the kickoff with a fee coin.  False if the channel has no
 * kickoff signatures. */
bool sym_broadcast_kickoff(struct lightningd *ld, struct channel *channel,
			   const char *cmd_id);

/* A spend of a channel output whose input 0 carries @witness and needs no
 * signature of ours (an update, a settle): outputs 0 .. m-1 are @outs, in
 * the channel's asset; a fee coin, its change and the fee follow.  It is
 * rebuilt each block, its fee raised by replacement, until the output is
 * spent on chain. */
void sym_spend_start(struct channel *channel,
		     const struct bitcoin_outpoint *out,
		     struct amount_sat amount, const u8 *spent_spk,
		     u8 **witness TAKES,
		     const struct sym_state_out *outs,
		     u32 sequence, u32 minblock, u32 deadline);

/* An output of the channel is spent on chain: a spend of ours of it stops
 * and frees its fee coins, and one onchaind proposes later never starts. */
void sym_note_spent(struct channel *channel,
		    const struct bitcoin_outpoint *out);

#endif /* LIGHTNING_LIGHTNINGD_SYMMETRIC_H */
