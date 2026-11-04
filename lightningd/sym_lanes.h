#ifndef LIGHTNING_LIGHTNINGD_SYM_LANES_H
#define LIGHTNING_LIGHTNINGD_SYM_LANES_H
/* SEQUENTIA: lightningd's side of a channel of several assets
 * (`option_seq_symmetric_lanes`, common/sym_lanes.h).
 *
 * Lane 0 is the channel's own: its asset, funding output and our balance in
 * it are the channel's.  Every other lane keeps its own here, beside the
 * peer's signature on its kickoff.  An HTLC names its lane, and its amount
 * is in that lane's asset: a payment stays in one asset end to end.
 *
 * A swap moves two lanes' balances in opposite directions in one state.
 * Whoever wants one asks with `symswap` (SEQ_SWAP_REQUEST_MSG), which this
 * node saves before it is sent; the peer's `sym_swap` hook takes it or not
 * (no plugin: not), and a peer that takes it sends it in its next
 * commitment_signed, which channeld accepts only as asked.  A request
 * expires: after its block, and a few blocks' grace, a swap for it is
 * refused. */
#include "config.h"
#include <bitcoin/signature.h>
#include <common/amount.h>
#include <common/sym_lanes.h>

struct channel;
struct command;
struct json_stream;
struct lightningd;
struct node_id;

/* Blocks after a request's expiry before we refuse a swap for it: the
 * peer's commitment may be on its way. */
#define SYM_SWAP_GRACE 3

struct sym_lanes_info {
	/* Lanes 1 .. n. */
	struct sym_lane *lanes;
	/* Our balance in each, as channel->our_msat is in lane 0. */
	struct amount_msat *our_msat;
	/* The peer's signature on each one's kickoff, and ours. */
	struct bitcoin_signature *kickoff_sigs, *local_kickoff_sigs;
	/* The swap in flight, and the one we asked for, as the peer will
	 * send it, with the block it expires at; NULL if none. */
	struct sym_swap *swap, *req;
	u32 req_expiry;
	/* The symswap command waiting for req, never saved. */
	struct command *cmd;
	/* Every spend of another lane's funding output seen: onchaind takes
	 * each, whenever it starts, until the channel is forgotten. */
	struct sym_lane_spend {
		struct bitcoin_tx *tx;
		u32 input;
		u32 height;
	} *spends;
	/* The spend of lane 0's funding onchaind started on, and whether
	 * this process has broadcast the other lanes' kickoffs; never
	 * saved. */
	struct bitcoin_txid *onchaind_txid;
	bool kicked;
};

bool channel_is_sym_lanes(const struct channel *channel);

/* The lanes of a channel just opened, all the opener's, and the kickoff
 * signatures, the peer's and ours; saved at once. */
void sym_lanes_attach(struct channel *channel, const struct sym_lane *lanes,
		      const struct bitcoin_signature *sigs,
		      const struct bitcoin_signature *local_sigs);

/* Is every other lane's output in the funding transaction, to the funding
 * script, in its asset, for its amount, all explicit?  NULL if so. */
const char *sym_lanes_check_funding(const tal_t *ctx,
				    const struct channel *channel,
				    const struct bitcoin_tx *tx);

/* Watch every other lane's funding output: a spend of one, whoever made it,
 * takes the channel to chain. */
void sym_lanes_watch(struct lightningd *ld, struct channel *channel);

/* Broadcast every other lane's kickoff, a fee coin attached to each (lane
 * 0's is the channel's, sym_broadcast_kickoff). */
void sym_lanes_kickoffs(struct lightningd *ld, struct channel *channel);

/* Save the channel's lanes, balances and swaps. */
void sym_lanes_save(struct channel *channel);

/* How many lanes, lane 0 included; lane @lane's asset, funding output
 * (in the channel's funding transaction) and amount; our balance in it. */
size_t channel_num_lanes(const struct channel *channel);
const u8 *channel_lane_asset(const struct channel *channel, u16 lane);
void channel_lane_funding(const struct channel *channel, u16 lane,
			  struct bitcoin_outpoint *out,
			  struct amount_sat *amount);
struct amount_msat channel_lane_our_msat(const struct channel *channel,
					 u16 lane);

/* What lane @lane (not 0) can still bring us: the peer's balance in it. */
struct amount_msat channel_lane_receivable(const struct channel *channel,
					   u16 lane);

/* The lane that holds @asset, or -1. */
int channel_lane_of_asset(const struct channel *channel, const u8 asset[33]);

/* An HTLC in lane @lane (not 0) was fulfilled: @amount moves to us, or from
 * us.  False on overflow. */
bool sym_lanes_credit(struct channel *channel, u16 lane,
		      struct amount_msat amount, bool to_us);

/* channeld's report of the swap in flight, as a commitment step leaves it
 * (NULL: none).  A swap that reached its last state moves our balances. */
void sym_lanes_swap_step(struct channel *channel, const struct sym_swap *swap);

/* What channeld_init takes. */
void sym_lanes_init_args(const tal_t *ctx, const struct channel *channel,
			 struct sym_lane **lanes, struct amount_msat **ours,
			 struct sym_swap **swap, struct sym_swap **req);

/* A SEQ_SWAP_REQUEST_MSG or SEQ_SWAP_REFUSE_MSG from @peer_id; false if
 * @msg is neither. */
bool sym_lanes_handle_peer_msg(struct lightningd *ld,
			       const struct node_id *peer_id, const u8 *msg);

/* A new block: requests past their expiry and grace are dropped. */
void sym_lanes_notify_new_block(struct lightningd *ld);

/* onchaind just started on @tx, a spend of lane 0's funding: it takes every
 * other lane's spend seen so far. */
void sym_lanes_onchaind_started(struct channel *channel,
				const struct bitcoin_tx *tx);

/* The asset of a settlement output paying @spk, in a state we hold, or NULL
 * (the channel's own). */
const u8 *sym_lanes_output_asset(const tal_t *ctx,
				 const struct channel *channel, const u8 *spk);

/* listpeerchannels: seq_lanes and seq_swap. */
void json_add_sym_lanes(struct json_stream *js, const struct channel *channel);

#endif /* LIGHTNING_LIGHTNINGD_SYM_LANES_H */
