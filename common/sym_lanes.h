#ifndef LIGHTNING_COMMON_SYM_LANES_H
#define LIGHTNING_COMMON_SYM_LANES_H
/* A symmetric channel of several assets (`option_seq_symmetric_lanes`): one
 * lane per asset, over the base type's scripts (common/sym_scripts.h).
 *
 *   funding  lane 0 is the channel's own funding output, in the channel's
 *            asset; lane i > 0 is another output of the same transaction,
 *            to the same 2-of-2 script, in lane i's asset.
 *   kickoff  each lane's funding output moves to KO at the same index: the
 *            same program for every lane, signed SIGHASH_SINGLE|
 *            SIGHASH_ANYONECANPAY by both funding keys over that pair alone.
 *            That sighash does not commit to the input's index, so lane i's
 *            signatures are those of a kickoff of its output alone, and hold
 *            at index i of one kickoff of every lane.
 *   state n  every lane's state output is the same program P(n): its
 *            SETTLE(n) fixes the whole settlement, lane 0's outputs, then
 *            lane 1's, and so on, each in its lane's asset.  One update
 *            signature per side covers every lane, so no lane's balance moves
 *            without both.
 *   update   each lane's output moves to P(n) by UPD, with the same witness;
 *            UPD reads only the output at its input's index.
 *   settle   one transaction spends every lane's output by SETTLE(n): each
 *            asset's outputs balance only against its own lane's input.
 *
 * An HTLC belongs to one lane and settles in its asset.  A swap moves two
 * lanes' balances in opposite directions in one state, so it is applied
 * whole or not at all. */
#include "config.h"
#include <bitcoin/signature.h>
#include <bitcoin/tx.h>
#include <common/amount.h>
#include <common/htlc.h>

struct channel;
struct sym_htlc;
struct sym_output;

/* The most lanes beside lane 0. */
#define SYM_MAX_LANES 8

/* Lane i > 0 (lane 0 is the channel's own funding). */
struct sym_lane {
	/* Its asset: 0x01 || 32-byte id, never the channel's. */
	u8 asset[33];
	/* Its funding output, in the channel's funding transaction. */
	u32 outnum;
	struct amount_sat funding_sats;
};

/* What each view owes each side in one lane: [view][side], as
 * channel->view[view].owed[side] for lane 0. */
struct sym_lane_balance {
	struct amount_msat owed[NUM_SIDES][NUM_SIDES];
};

/* A swap between two lanes, as one change to the channel: whoever sent it
 * (htlc_state_owner(state)) gives @give in lane @give_lane and takes @take
 * in lane @take_lane. */
struct sym_swap {
	u64 id;
	enum htlc_state state;
	u16 give_lane, take_lane;
	struct amount_msat give, take;
};

/* The custom peer messages that ask for a swap and refuse one, each after
 * its type: channel_id, id (u64); a request then gives give_msat (u64) in
 * lane give_lane (u16), takes take_msat in take_lane, as its sender sees
 * them, until block expiry (u32); a refusal its reason (u16 length, bytes).
 * The swap itself rides in the accepter's next commitment_signed. */
#define SEQ_SWAP_REQUEST_MSG 48045
#define SEQ_SWAP_REFUSE_MSG 48047

struct channel_id;
u8 *towire_seq_swap_request(const tal_t *ctx, const struct channel_id *cid,
			    u64 id, u16 give_lane, struct amount_msat give,
			    u16 take_lane, struct amount_msat take, u32 expiry);
bool fromwire_seq_swap_request(const u8 *msg, struct channel_id *cid,
			       u64 *id, u16 *give_lane,
			       struct amount_msat *give, u16 *take_lane,
			       struct amount_msat *take, u32 *expiry);
u8 *towire_seq_swap_refuse(const tal_t *ctx, const struct channel_id *cid,
			   u64 id, const char *reason);
bool fromwire_seq_swap_refuse(const tal_t *ctx, const u8 *msg,
			      struct channel_id *cid, u64 *id, char **reason);

/* The lanes TLVs of open_channel, funding_created and funding_signed
 * (wire/peer_wire.csv).  The parsers return false on a malformed blob. */
u8 *sym_lanes_open_blob(const tal_t *ctx, const struct sym_lane *lanes);
bool sym_lanes_from_open_blob(const tal_t *ctx, const u8 *blob,
			      struct sym_lane **lanes);
u8 *sym_lanes_created_blob(const tal_t *ctx, const struct sym_lane *lanes,
			   const secp256k1_ecdsa_signature *sigs);
bool sym_lanes_from_created_blob(const tal_t *ctx, const u8 *blob,
				 size_t nlanes, u32 **outnums,
				 secp256k1_ecdsa_signature **sigs);
u8 *sym_lanes_signed_blob(const tal_t *ctx,
			  const secp256k1_ecdsa_signature *sigs);
bool sym_lanes_from_signed_blob(const tal_t *ctx, const u8 *blob,
				size_t nlanes,
				secp256k1_ecdsa_signature **sigs);

void towire_sym_lane(u8 **pptr, const struct sym_lane *lane);
void fromwire_sym_lane(const u8 **cursor, size_t *max, struct sym_lane *lane);
void towire_sym_swap(u8 **pptr, const struct sym_swap *swap);
void fromwire_sym_swap(const u8 **cursor, size_t *max, struct sym_swap *swap);

/* What every side checks of a channel's lanes: at most SYM_MAX_LANES, each
 * an explicit asset other than the channel's and every other lane's, with
 * funds.  NULL if sound, else why not. */
const char *sym_lanes_check(const tal_t *ctx, const struct sym_lane *lanes,
			    const u8 channel_asset[33]);

/* How many lanes the channel has, lane 0 included. */
size_t sym_num_lanes(const struct channel *channel);

/* Lane @lane's asset (lane 0: the channel's). */
const u8 *sym_lane_asset(const struct channel *channel, size_t lane);

/* The lane that holds @asset, or -1. */
int sym_lane_of_asset(const struct channel *channel, const u8 asset[33]);

/* Lane @lane's funding: its outpoint and amount. */
void sym_lane_funding(const struct channel *channel, size_t lane,
		      struct bitcoin_outpoint *outpoint,
		      struct amount_sat *amount);

/* What @view owes @side in lane @lane. */
struct amount_msat sym_lane_owed(const struct channel *channel, size_t lane,
				 enum side view, enum side side);

/* The settlement of @side's view: each lane's (common/sym_scripts.h's
 * sym_settlement) in lane order, each output in its lane's asset (lane 0's
 * naming none).  @htlc_lanes[i] is @htlcs[i]'s lane (NULL: all lane 0).
 * NULL and *err set if a lane cannot be paid out of its funding. */
struct sym_output *sym_lanes_settlement(const tal_t *ctx,
					const struct channel *channel,
					enum side side,
					const struct sym_htlc *htlcs,
					const u16 *htlc_lanes,
					const char **err);

/* Lane @lane's kickoff, unsigned: its funding output alone to KO, in its
 * asset.  @wscript is set to the 2-of-2 it spends. */
struct bitcoin_tx *sym_lane_kickoff_tx(const tal_t *ctx,
				       const struct channel *channel,
				       size_t lane, const u8 **wscript);

/* Apply @swap's change to one view's balances: @owed0 is lane 0's
 * (channel->view[view].owed), @lanes every other lane's.  False, changing
 * nothing, if a side cannot pay its leg. */
bool sym_swap_apply(const struct sym_swap *swap,
		    struct amount_msat owed0[NUM_SIDES],
		    struct sym_lane_balance *lanes, enum side view);

#endif /* LIGHTNING_COMMON_SYM_LANES_H */
