#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/tapscript.h>
#include <bitcoin/varint.h>
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/htlc_tx.h>
#include <common/memleak.h>
#include <common/psbt_keypath.h>
#include <common/tcov_scripts.h>
#include <common/timeout.h>
#include <common/utxo.h>
#include <db/exec.h>
#include <errno.h>
#include <hsmd/hsm_utxo.h>
#include <hsmd/hsmd_wiregen.h>
#include <hsmd/permissions.h>
#include <inttypes.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/hsm_control.h>
#include <lightningd/onchain_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/subd.h>
#include <onchaind/onchaind_wiregen.h>
#include <wallet/txfilter.h>
#include <wallet/wallet.h>
#include <wally_psbt.h>
#include <wally_transaction.h>

/* If we're restarting, we keep a per-channel copy of watches, and replay */
struct replay_tx {
	u32 blockheight;
	struct bitcoin_txid txid;
	struct bitcoin_tx *tx;
};

static const struct bitcoin_txid *replay_tx_keyof(const struct replay_tx *rtx)
{
	return &rtx->txid;
}

static bool replay_tx_eq_txid(const struct replay_tx *rtx,
			      const struct bitcoin_txid *txid)
{
	return bitcoin_txid_eq(&rtx->txid, txid);
}

HTABLE_DEFINE_NODUPS_TYPE(struct replay_tx, replay_tx_keyof, txid_hash, replay_tx_eq_txid,
			  replay_tx_hash);

/* We dump all the known preimages when onchaind starts up. */
static void onchaind_tell_fulfill(struct channel *channel)
{
	struct htlc_in_map_iter ini;
	struct htlc_in *hin;
	u8 *msg;
	struct lightningd *ld = channel->peer->ld;

	for (hin = htlc_in_map_first(ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;

		/* BOLT #5:
		 *
		 * A local node:

		 *  - if it receives (or already possesses) a payment preimage
		 *  for an unresolved HTLC output that it has been offered AND
		 *  for which it has committed to an outgoing HTLC:
		 *    - MUST *resolve* the output by spending it, using the
		 *      HTLC-success transaction.
		 *    - MUST NOT reveal its own preimage when it's not the final recipient...
		 *    - MUST resolve the output of that HTLC-success transaction.
		 *  - otherwise:
		 *      - if the *remote node* is NOT irrevocably committed to
		 *        the HTLC:
		 *        - MUST NOT *resolve* the output by spending it.
		 */

		/* We only set preimage once it's irrevocably committed, and
		 * we spend even if we don't have an outgoing HTLC (eg. local
		 * payment complete) */
		if (!hin->preimage)
			continue;

		msg = towire_onchaind_known_preimage(channel, hin->preimage);
		subd_send_msg(channel->owner, take(msg));
	}
}

/* If we want to know if this HTLC is missing, return depth. */
static bool tell_if_missing(const struct channel *channel,
			    struct htlc_stub *stub,
			    bool *tell_immediate)
{
	struct htlc_out *hout;

	/* Keep valgrind happy. */
	*tell_immediate = false;

	/* Don't care about incoming HTLCs, just ones we offered. */
	if (stub->owner == REMOTE)
		return false;

	/* Might not be a current HTLC. */
	hout = find_htlc_out(channel->peer->ld->htlcs_out, channel, stub->id);
	if (!hout)
		return false;

	/* BOLT #5:
	 *
	 *   - for any committed HTLC that does NOT have an output in this
	 *     commitment transaction:
	 *     - if the payment preimage is known:
	 *       - MUST fulfill the corresponding incoming HTLC (if any).
	 *     - otherwise:
	 *       - once the commitment transaction has reached reasonable depth:
	 *         - MUST fail the corresponding incoming HTLC (if any).
	 *       - if no *valid* commitment transaction contains an output
	 *         corresponding to the HTLC:
	 *         - MAY fail the corresponding incoming HTLC sooner.
	 */
	if (hout->hstate >= RCVD_ADD_REVOCATION
	    && hout->hstate < SENT_REMOVE_REVOCATION)
		*tell_immediate = true;

	log_debug(channel->log,
		  "We want to know if htlc %"PRIu64" is missing (%s)",
		  hout->key.id, *tell_immediate ? "immediate" : "later");
	return true;
}

static void handle_onchain_init_reply(struct channel *channel, const u8 *msg)
{
	struct htlc_stub *stubs;
	u64 commit_num;
	bool *tell, *tell_immediate;

	if (!fromwire_onchaind_init_reply(msg, &commit_num)) {
		channel_internal_error(channel, "Invalid onchaind_init_reply %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* FIXME: We may already be ONCHAIN state when we implement restart! */
	channel_set_state(channel,
			  FUNDING_SPEND_SEEN,
			  ONCHAIN,
			  REASON_UNKNOWN,
			  "Onchain init reply");

	/* Tell it about any relevant HTLCs */
	/* FIXME: Filter by commitnum! */
	stubs = wallet_htlc_stubs(tmpctx, channel->peer->ld->wallet, channel,
				  commit_num);
	tell = tal_arr(stubs, bool, tal_count(stubs));
	tell_immediate = tal_arr(stubs, bool, tal_count(stubs));

	for (size_t i = 0; i < tal_count(stubs); i++) {
		tell[i] = tell_if_missing(channel, &stubs[i],
					  &tell_immediate[i]);
	}
	msg = towire_onchaind_htlcs(channel, stubs, tell, tell_immediate);
	subd_send_msg(channel->owner, take(msg));

	/* Tell it about any preimages we know. */
	onchaind_tell_fulfill(channel);
}

/**
 * Notify onchaind about the depth change of the watched tx.
 */
static void onchain_tx_depth(struct channel *channel,
			     const struct bitcoin_txid *txid,
			     unsigned int depth)
{
	u8 *msg;
	msg = towire_onchaind_depth(channel, txid, depth);
	subd_send_msg(channel->owner, take(msg));
}

/**
 * Entrypoint for the txwatch callback, calls onchain_tx_depth.
 */
static enum watch_result onchain_tx_watched(struct lightningd *ld,
					    const struct bitcoin_txid *txid,
					    const struct bitcoin_tx *tx,
					    unsigned int depth,
					    struct channel *channel)
{
	u32 blockheight = get_block_height(ld->topology);

	if (tx != NULL) {
		struct bitcoin_txid txid2;

		bitcoin_txid(tx, &txid2);
		if (!bitcoin_txid_eq(txid, &txid2)) {
			channel_internal_error(channel, "Txid for %s is not %s",
					       fmt_bitcoin_tx(tmpctx, tx),
					       fmt_bitcoin_txid(tmpctx, txid));
			return DELETE_WATCH;
		}
	}

	if (depth == 0) {
		log_unusual(channel->log, "Chain reorganization!");
		channel_set_owner(channel, NULL);

		/* We will most likely be freed, so this is a noop */
		return KEEP_WATCHING;
	}

	/* Store so we remember if we crash, and can replay later */
	wallet_insert_funding_spend(ld->wallet, channel, txid, 0, blockheight);

	onchain_tx_depth(channel, txid, depth);
	return KEEP_WATCHING;
}

static void watch_tx_and_outputs(struct channel *channel,
				 const struct bitcoin_tx *tx);
static void onchaind_replay(struct channel *channel);

static void replay_unwatch_txid(struct channel *channel,
				const struct bitcoin_txid *txid)
{
	replay_tx_hash_delkey(channel->onchaind_replay_watches, txid);
}

static void onchaind_spent_reply(struct subd *onchaind, const u8 *msg,
				 const int *fds,
				 struct bitcoin_txid *txid)
{
	bool interested;
	struct txwatch *txw;
	struct channel *channel = onchaind->channel;

	if (!fromwire_onchaind_spent_reply(msg, &interested))
		channel_internal_error(channel, "Invalid onchaind_spent_reply %s",
				       tal_hex(tmpctx, msg));

	channel->num_onchain_spent_calls--;

	/* Only delete watch if it says it doesn't care */
	if (interested)
		goto out;

	/* If we're doing replay: */
	if (channel->onchaind_replay_watches) {
		replay_unwatch_txid(channel, txid);
		goto out;
	}

	/* Frees the txo watches, too: see watch_tx_and_outputs() */
	txw = find_txwatch(channel->peer->ld->topology, txid,
			   onchain_tx_watched, channel);
	if (!txw)
		log_unusual(channel->log, "Can't unwatch txid %s",
			    fmt_bitcoin_txid(tmpctx, txid));
	tal_free(txw);

out:
	/* If that's the last request, continue asking for blocks */
	if (channel->onchaind_replay_watches
	    && channel->num_onchain_spent_calls == 0) {
		onchaind_replay(channel);
	}
}

static void tcov_note_spent(const struct channel *channel,
			    const struct bitcoin_outpoint *out);

/**
 * Notify onchaind that an output was spent and register new watches.
 */
static void onchain_txo_spent(struct channel *channel, const struct bitcoin_tx *tx, size_t input_num, u32 blockheight)
{
	u8 *msg;
	struct bitcoin_txid *txid;
	struct bitcoin_outpoint spent;
	/* Onchaind needs all inputs, since it uses those to compare
	 * with existing spends (which can vary, with feerate changes). */
	struct tx_parts *parts = tx_parts_from_wally_tx(tmpctx, tx->wtx,
							-1, -1);

	watch_tx_and_outputs(channel, tx);

	bitcoin_tx_input_get_outpoint(tx, input_num, &spent);
	tcov_note_spent(channel, &spent);

	/* Reply will need this if we want to unwatch */
	txid = tal(NULL, struct bitcoin_txid);
	bitcoin_txid(tx, txid);

	msg = towire_onchaind_spent(channel, parts, input_num, blockheight);
	subd_req(channel->owner, channel->owner, take(msg), -1, 0,
		 onchaind_spent_reply, take(txid));
	channel->num_onchain_spent_calls++;
}

/**
 * Entrypoint for the txowatch callback, stores tx and calls onchain_txo_spent.
 */
static enum watch_result onchain_txo_watched(struct channel *channel,
					     const struct bitcoin_tx *tx,
					     size_t input_num,
					     const struct block *block)
{
	onchain_txo_spent(channel, tx, input_num, block->height);

	/* We don't need to keep watching: If this output is double-spent
	 * (reorg), we'll get a zero depth cb to onchain_tx_watched, and
	 * restart onchaind. */
	return DELETE_WATCH;
}

/* To avoid races, we watch the tx and all outputs. */
static void watch_tx_and_outputs(struct channel *channel,
				 const struct bitcoin_tx *tx)
{
	struct bitcoin_outpoint outpoint;
	struct txwatch *txw;
	struct lightningd *ld = channel->peer->ld;

	bitcoin_txid(tx, &outpoint.txid);

	/* Make txwatch a parent of txo watches, so we can unwatch together. */
	txw = watch_txid(channel->owner, ld->topology,
			 &outpoint.txid,
			 onchain_tx_watched, channel);

	for (outpoint.n = 0; outpoint.n < tx->wtx->num_outputs; outpoint.n++)
		watch_txo(txw, ld->topology, channel, &outpoint,
			  onchain_txo_watched);
}

static void handle_onchain_log_coin_move(struct channel *channel, const u8 *msg)
{
	struct chain_coin_mvt *mvt = tal(NULL, struct chain_coin_mvt);

	if (!fromwire_onchaind_notify_coin_mvt(msg, mvt)) {
		channel_internal_error(channel, "Invalid onchain notify_coin_mvt");
		return;
	}

	/* onchaind uses an empty string to mean "this channel" */
	if (streq(mvt->account.alt_account, "")) {
		tal_free(mvt->account.alt_account);
		set_mvt_account_id(&mvt->account, channel, NULL);
	} else {
		mvt->originating_acct = new_mvt_account_id(mvt, channel, NULL);
	}

	wallet_save_chain_mvt(channel->peer->ld, take(mvt));
}

static void handle_onchain_log_penalty_adj(struct channel *channel, const u8 *msg)
{
	struct amount_msat msat;
	struct channel_coin_mvt *mvt;

	if (!fromwire_onchaind_notify_penalty_adj(msg, &msat)) {
		channel_internal_error(channel, "Invalid onchain notify_penalty_adj");
		return;
	}

	mvt = new_channel_mvt_penalty_adj(tmpctx, channel, msat, COIN_CREDIT);
	wallet_save_channel_mvt(channel->peer->ld, mvt);
	mvt = new_channel_mvt_penalty_adj(tmpctx, channel, msat, COIN_DEBIT);
	wallet_save_channel_mvt(channel->peer->ld, mvt);
}

static void replay_watch_tx(struct channel *channel,
			    u32 blockheight,
			    const struct bitcoin_tx *tx TAKES)
{
	struct replay_tx *rtx = tal(channel->onchaind_replay_watches, struct replay_tx);
	bitcoin_txid(tx, &rtx->txid);
	rtx->blockheight = blockheight;
	rtx->tx = clone_bitcoin_tx(rtx, tx);

	/* We might already be watching, in which case don't re-add! */
	if (replay_tx_hash_get(channel->onchaind_replay_watches, &rtx->txid))
		tal_free(rtx);
	else
		replay_tx_hash_add(channel->onchaind_replay_watches, rtx);
}

/* We've finished replaying, turn any txs left into live watches */
static void convert_replay_txs(struct channel *channel)
{
	struct replay_tx *rtx;
	struct replay_tx_hash_iter rit;
	struct replay_tx_hash *watches;

	/* Set to NULL so these are queued as real watches */
	watches = tal_steal(tmpctx, channel->onchaind_replay_watches);
	channel->onchaind_replay_watches = NULL;
	replay_tx_hash_lock(watches);
	for (rtx = replay_tx_hash_first(watches, &rit);
	     rtx;
	     rtx = replay_tx_hash_next(watches, &rit)) {
		watch_tx_and_outputs(channel, rtx->tx);
	}
	replay_tx_hash_unlock(watches);
}

static void replay_block(struct bitcoind *bitcoind,
			 u32 height,
			 struct bitcoin_blkid *blkid,
			 struct bitcoin_block *blk,
			 struct channel *channel)
{
	struct replay_tx *rtx;
	struct replay_tx_hash_iter rit;

	/* If we're shutting down, this can happen! */
	if (!channel->owner)
		return;

	/* Tell onchaind that all existing txs have reached a new depth */
	replay_tx_hash_lock(channel->onchaind_replay_watches);
	for (rtx = replay_tx_hash_first(channel->onchaind_replay_watches, &rit);
	     rtx;
	     rtx = replay_tx_hash_next(channel->onchaind_replay_watches, &rit)) {
		/* Note: if you're in this block, that's depth 1! */
		onchain_tx_depth(channel, &rtx->txid, height - rtx->blockheight + 1);
	}
	replay_tx_hash_unlock(channel->onchaind_replay_watches);

	/* See if we add any new txs which spend a watched one */
	for (size_t i = 0; i < tal_count(blk->tx); i++) {
		for (size_t j = 0; j < blk->tx[i]->wtx->num_inputs; j++) {
			struct bitcoin_txid spent;
			bitcoin_tx_input_get_txid(blk->tx[i], j, &spent);
			rtx = replay_tx_hash_get(channel->onchaind_replay_watches, &spent);
			if (rtx) {
				/* Note: for efficiency, blk->tx's don't have
				 * PSBTs, so add one now */
				if (!blk->tx[i]->psbt)
					blk->tx[i]->psbt = new_psbt(blk->tx[i], blk->tx[i]->wtx);
				onchain_txo_spent(channel, blk->tx[i], j, height);
				/* Watch this and all the children too. */
				replay_watch_tx(channel, height, blk->tx[i]);
			}
		}
	}

	/* Replay finished?  Now we'll get fed real blocks */
	if (height == get_block_height(bitcoind->ld->topology)) {
		convert_replay_txs(channel);
		return;
	}

	/* Ready for next block */
	channel->onchaind_replay_height = height + 1;

	/* Otherwise, wait for those to be resolved (in case onchaind is slow,
	 * e.g. waiting for HSM). */
	if (channel->num_onchain_spent_calls == 0)
		onchaind_replay(channel);
}

static void onchaind_replay(struct channel *channel)
{
	assert(channel->onchaind_replay_watches);
	assert(channel->num_onchain_spent_calls == 0);

	bitcoind_getrawblockbyheight(channel,
				     channel->peer->ld->topology->bitcoind,
				     channel->onchaind_replay_height,
				     replay_block, channel);
}

static void handle_extracted_preimage(struct channel *channel, const u8 *msg)
{
	struct preimage preimage;

	if (!fromwire_onchaind_extracted_preimage(msg, &preimage)) {
		channel_internal_error(channel, "Invalid extracted_preimage");
		return;
	}

	onchain_fulfilled_htlc(channel, &preimage);
}

static void handle_missing_htlc_output(struct channel *channel, const u8 *msg)
{
	struct htlc_stub htlc;

	if (!fromwire_onchaind_missing_htlc_output(msg, &htlc)) {
		channel_internal_error(channel, "Invalid missing_htlc_output");
		return;
	}

	/* We only set tell_if_missing on LOCAL htlcs */
	if (htlc.owner != LOCAL) {
		channel_internal_error(channel,
				       "onchaind_missing_htlc_output: htlc %"PRIu64" is not local!",
				       htlc.id);
		return;
	}

	/* BOLT #5:
	 *
	 *   - for any committed HTLC that does NOT have an output in this
	 *     commitment transaction:
	 *     - if the payment preimage is known:
	 *       - MUST fulfill the corresponding incoming HTLC (if any).
	 *     - otherwise:
	 *       - once the commitment transaction has reached reasonable depth:
	 *         - MUST fail the corresponding incoming HTLC (if any).
	 *       - if no *valid* commitment transaction contains an output
	 *         corresponding to the HTLC:
	 *         - MAY fail the corresponding incoming HTLC sooner.
	 */
	/* Note: we already succeeded any incoming which we preimage for */
	onchain_failed_our_htlc(channel, &htlc, "missing in commitment tx", false);
}

static void handle_onchain_htlc_timeout(struct channel *channel, const u8 *msg)
{
	struct htlc_stub htlc;

	if (!fromwire_onchaind_htlc_timeout(msg, &htlc)) {
		channel_internal_error(channel, "Invalid onchain_htlc_timeout");
		return;
	}

	/* It should tell us about timeouts on our LOCAL htlcs */
	if (htlc.owner != LOCAL) {
		channel_internal_error(channel,
				       "onchaind_htlc_timeout: htlc %"PRIu64" is not local!",
				       htlc.id);
		return;
	}

	/* BOLT #5:
	 *
	 *   - if the commitment transaction HTLC output has *timed out* and
	 *     hasn't been *resolved*:
	 *     - MUST *resolve* the output by spending it using the HTLC-timeout
	 *     transaction.
	 */
	onchain_failed_our_htlc(channel, &htlc, "timed out", true);
}

static void handle_irrevocably_resolved(struct channel *channel, const u8 *msg UNUSED)
{
	/* FIXME: Implement check_htlcs to ensure no dangling hout->in ptrs! */
	free_htlcs(channel->peer->ld, channel);

	log_info(channel->log, "onchaind complete, forgetting peer");

	/* This will also free onchaind. */
	delete_channel(channel, false);
}


/**
 * onchain_add_utxo -- onchaind is telling us about an UTXO we own
 */
static void onchain_add_utxo(struct channel *channel, const u8 *msg)
{
	struct chain_coin_mvt *mvt;
	u32 blockheight;
	struct bitcoin_outpoint outpoint;
	u32 csv_lock;
	struct amount_sat amount;
	struct pubkey *commitment_point;
	u8 *scriptPubkey;

	if (!fromwire_onchaind_add_utxo(
		tmpctx, msg, &outpoint, &commitment_point,
		&amount, &blockheight, &scriptPubkey,
		&csv_lock)) {
		log_broken(channel->log,
			   "onchaind gave invalid add_utxo message: %s",
			   tal_hex(msg, msg));
		return;
	}

	assert(blockheight);
	outpointfilter_add(channel->peer->ld->wallet->owned_outpoints,
			   &outpoint);
	log_debug(channel->log, "adding utxo to watch %s, csv %u",
		  fmt_bitcoin_outpoint(tmpctx, &outpoint),
		  csv_lock);

	wallet_add_onchaind_utxo(channel->peer->ld->wallet,
				 &outpoint, scriptPubkey,
				 blockheight, amount, channel,
				 commitment_point,
				 csv_lock);

	mvt = new_coin_wallet_deposit(msg, &outpoint, blockheight,
			              amount, mk_mvt_tags(MVT_DEPOSIT));
	mvt->originating_acct = new_mvt_account_id(mvt, channel, NULL);

	wallet_save_chain_mvt(channel->peer->ld, mvt);
}

static void onchain_annotate_txout(struct channel *channel, const u8 *msg)
{
	struct bitcoin_outpoint outpoint;
	enum wallet_tx_type type;
	if (!fromwire_onchaind_annotate_txout(msg, &outpoint, &type))
		fatal("onchaind gave invalid onchain_annotate_txout "
		      "message: %s",
		      tal_hex(msg, msg));
	wallet_annotate_txout(channel->peer->ld->wallet, &outpoint, type,
			      channel->dbid);
}

static void onchain_annotate_txin(struct channel *channel, const u8 *msg)
{
	struct bitcoin_txid txid;
	enum wallet_tx_type type;
	u32 innum;
	if (!fromwire_onchaind_annotate_txin(msg, &txid, &innum, &type))
		fatal("onchaind gave invalid onchain_annotate_txin "
		      "message: %s",
		      tal_hex(msg, msg));
	wallet_annotate_txin(channel->peer->ld->wallet, &txid, innum, type,
				    channel->dbid);
}

/* All onchaind-produced txs are actually of the same form: */
struct onchain_signing_info {
	/* Fields common to every callback: */
	struct channel *channel;

	/* Minimum block */
	u32 minblock;

	/* Block we want this mined by */
	u32 deadline_block;

	/* Witness script for tx */
	u8 *wscript;
	/* Trailing element for witness stack */
	const tal_t *stack_elem;

	/* Information for consider_onchain_rebroadcast */
	struct amount_sat fee;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	u32 to_self_delay;
	u32 locktime;
	u8 *(*sign)(const tal_t *ctx,
		    const struct bitcoin_tx *tx,
		    const struct onchain_signing_info *info);

	/* Information for consider_onchain_htlc_tx_rebroadcast */
	struct bitcoin_tx *raw_htlc_tx;

	/* Tagged union (for sanity checking!) */
	enum onchaind_wire msgtype;
	union {
		/* WIRE_ONCHAIND_SPEND_HTLC_TIMEDOUT */
		struct {
			u64 commit_num;
		} htlc_timedout;
		/* WIRE_ONCHAIND_SPEND_PENALTY */
		struct {
			struct secret remote_per_commitment_secret;
		} spend_penalty;
		/* WIRE_ONCHAIND_SPEND_HTLC_SUCCESS */
		struct {
			u64 commit_num;
			struct bitcoin_signature remote_htlc_sig;
			struct preimage preimage;
		} htlc_success;
		/* WIRE_ONCHAIND_SPEND_HTLC_TIMEOUT */
		struct {
			u64 commit_num;
			struct bitcoin_signature remote_htlc_sig;
		} htlc_timeout;
		/* WIRE_ONCHAIND_SPEND_FULFILL */
		struct {
			struct pubkey remote_per_commitment_point;
			struct preimage preimage;
		} fulfill;
		/* WIRE_ONCHAIND_SPEND_HTLC_EXPIRED */
		struct {
			struct pubkey remote_per_commitment_point;
		} htlc_expired;
	} u;
};

/* If we don't care / don't know */
static u32 infinite_block_deadline(const struct chain_topology *topo)
{
	return get_block_height(topo) + 300;
}

/**
 * slow_sweep_dealine -- A smart(-ish) way of estimating sweep fees.
 *
 * We use the `close_blockheight` as the basis for the target. We then
 * target to have the funds back at most 2 weeks after the close,
 * linearly increasing the confirmation target until we get
 * close. However, we also don't want to panic and set a target that
 * is too close, in order not to waste too many funds on the sweep
 * fees.  `from` is the height the window is measured from: the current
 * one, or the one at which the output can first be spent.
 */
static u32 slow_sweep_deadline(const struct chain_topology *topo,
			       const struct channel *c, u32 from)
{
	u32 closeheight, deadline, height = from;

	if (c->close_blockheight) {
		closeheight = *c->close_blockheight;
	} else {
		log_unusual(c->log,
			    "Missing close_blockheight?  Using current height "
			    "+ 300 = %d",
			    height + 300);
		return height + 300;
	}

	/* A two week deadline seems like a not too bad default. We
	 * should likely tweak this to hit the desired cost vs. idle
	 * time tradeoff. */
	deadline = closeheight + 2016;

	/* If we missed the deadline, don't panic, let's continue with
	 * a somewhat reasonable target, and hope for the best. No
	 * need to ramp up to confirmation target 1, we're supposed to
	 * be slow. */
	if (deadline < height + 12)
		return height + 12;

	/* At the same time don't be too lenient, we want this to
	 * confirm and not just idle around forever. */
	if (deadline > height + 300)
		return height + 300;

	return deadline;
}

static struct onchain_signing_info *new_signing_info(const tal_t *ctx,
						     struct channel *channel,
						     enum onchaind_wire msgtype)
{
	struct onchain_signing_info *info = tal(ctx, struct onchain_signing_info);
	info->channel = channel;
	info->msgtype = msgtype;
	return info;
}

static u8 *sign_tx_to_us(const tal_t *ctx,
			 const struct bitcoin_tx *tx,
			 const struct onchain_signing_info *info)
{
	assert(info->msgtype == WIRE_ONCHAIND_SPEND_TO_US);
	return towire_hsmd_sign_any_delayed_payment_to_us(ctx,
							  info->u.htlc_timedout.commit_num,
							  tx, info->wscript,
							  0,
							  &info->channel->peer->id,
							  info->channel->dbid);
}

static u8 *sign_penalty(const tal_t *ctx,
			const struct bitcoin_tx *tx,
			const struct onchain_signing_info *info)
{
	assert(info->msgtype == WIRE_ONCHAIND_SPEND_PENALTY);
	return towire_hsmd_sign_any_penalty_to_us(ctx,
						  &info->u.spend_penalty.remote_per_commitment_secret,
						  tx, info->wscript,
						  0,
						  &info->channel->peer->id,
						  info->channel->dbid);
}

static u8 *sign_htlc_success(const tal_t *ctx,
			     const struct bitcoin_tx *tx,
			     const struct onchain_signing_info *info)
{
	const bool anchor_outputs = channel_type_has_anchors(info->channel->type);

	assert(info->msgtype == WIRE_ONCHAIND_SPEND_HTLC_SUCCESS);
	return towire_hsmd_sign_any_local_htlc_tx(ctx,
						  info->u.htlc_success.commit_num,
						  tx, info->wscript,
						  anchor_outputs,
						  0,
						  &info->channel->peer->id,
						  info->channel->dbid);
}

static u8 *sign_htlc_timeout(const tal_t *ctx,
			     const struct bitcoin_tx *tx,
			     const struct onchain_signing_info *info)
{
	const bool anchor_outputs = channel_type_has_anchors(info->channel->type);

	assert(info->msgtype == WIRE_ONCHAIND_SPEND_HTLC_TIMEOUT);
	return towire_hsmd_sign_any_local_htlc_tx(ctx,
						  info->u.htlc_timeout.commit_num,
						  tx, info->wscript,
						  anchor_outputs,
						  0,
						  &info->channel->peer->id,
						  info->channel->dbid);
}

static u8 *sign_fulfill(const tal_t *ctx,
			const struct bitcoin_tx *tx,
			const struct onchain_signing_info *info)
{
	const bool anchor_outputs = channel_type_has_anchors(info->channel->type);

	assert(info->msgtype == WIRE_ONCHAIND_SPEND_FULFILL);
	return towire_hsmd_sign_any_remote_htlc_to_us(ctx,
						      &info->u.fulfill.remote_per_commitment_point,
						      tx, info->wscript,
						      anchor_outputs,
						      0,
						      &info->channel->peer->id,
						      info->channel->dbid);
}

static u8 *sign_htlc_expired(const tal_t *ctx,
			     const struct bitcoin_tx *tx,
			     const struct onchain_signing_info *info)
{
	const bool anchor_outputs = channel_type_has_anchors(info->channel->type);

	assert(info->msgtype == WIRE_ONCHAIND_SPEND_HTLC_EXPIRED);
	return towire_hsmd_sign_any_remote_htlc_to_us(ctx,
						      &info->u.htlc_expired.remote_per_commitment_point,
						      tx, info->wscript,
						      anchor_outputs,
						      0,
						      &info->channel->peer->id,
						      info->channel->dbid);
}

/* Matches bitcoin_witness_sig_and_element! */
static const struct onchain_witness_element **
onchain_witness_sig_and_element(const tal_t *ctx, u8 **witness)
{
	struct onchain_witness_element **welements;
	welements = tal_arr(ctx, struct onchain_witness_element *,
			    tal_count(witness));

	for (size_t i = 0; i < tal_count(welements); i++) {
		welements[i] = tal(welements, struct onchain_witness_element);
		/* See bitcoin_witness_sig_and_element */
		welements[i]->is_signature = (i == 0);
		welements[i]->witness = tal_dup_talarr(welements[i], u8,
						       witness[i]);
	}
	return cast_const2(const struct onchain_witness_element **, welements);
}

/* Matches bitcoin_witness_htlc_success_tx & bitcoin_witness_htlc_timeout_tx! */
static const struct onchain_witness_element **
onchain_witness_htlc_tx(const tal_t *ctx, u8 **witness)
{
	struct onchain_witness_element **welements;
	welements = tal_arr(ctx, struct onchain_witness_element *,
			    tal_count(witness));

	for (size_t i = 0; i < tal_count(welements); i++) {
		welements[i] = tal(welements, struct onchain_witness_element);
		/* See bitcoin_witness_htlc_success_tx / bitcoin_witness_htlc_timeout_tx */
		welements[i]->is_signature = (i == 1 || i == 2);
		welements[i]->witness = tal_dup_talarr(welements[i], u8,
						       witness[i]);
	}
	return cast_const2(const struct onchain_witness_element **, welements);
}

/* Make normal 1-input-1-output tx to us, but don't sign it yet.
 *
 * If worthwhile is not NULL, we set it to true normally, or false if
 * we had to lower fees so much it's unlikely to get mined
 * (i.e. "don't wait up!").
*/
static struct bitcoin_tx *onchaind_tx_unsigned(const tal_t *ctx,
					       struct channel *channel,
					       const struct onchain_signing_info *info,
					       struct amount_sat *fee,
					       bool *worthwhile)
{
	struct bitcoin_tx *tx;
	struct amount_sat amt;
	size_t weight;
	struct pubkey final_key;
	struct ext_key final_wallet_ext_key;
	u64 block_target;
	struct lightningd *ld = channel->peer->ld;
	bool keypath_ok;

	/* Use BIP86 derivation for P2TR if available, otherwise BIP32 */
	if (ld->bip86_base) {
		bip86_pubkey(ld, &final_key, channel->final_key_idx);
		if (bip32_key_from_parent(ld->bip86_base,
					  channel->final_key_idx,
					  BIP32_FLAG_KEY_PUBLIC,
					  &final_wallet_ext_key) != WALLY_OK) {
			channel_internal_error(channel,
					       "Could not derive final_wallet_ext_key (bip86) %"PRIu64,
					       channel->final_key_idx);
			return NULL;
		}
	} else {
		bip32_pubkey(ld, &final_key, channel->final_key_idx);
		if (bip32_key_from_parent(ld->bip32_base,
					  channel->final_key_idx,
					  BIP32_FLAG_KEY_PUBLIC,
					  &final_wallet_ext_key) != WALLY_OK) {
			channel_internal_error(channel,
					       "Could not derive final_wallet_ext_key %"PRIu64,
					       channel->final_key_idx);
			return NULL;
		}
	}

	tx = bitcoin_tx(ctx, chainparams, 1, 1, info->locktime);
	/* Asset-aware channels: this sweeps a commitment/HTLC output (in the
	 * channel asset) to our wallet, so the sweep output + elements fee must
	 * be in that asset too.  Must precede the input/output adds.  NULL ==
	 * policy asset. */
	bitcoin_tx_set_output_asset(tx, channel->channel_asset);
	bitcoin_tx_add_input(tx, &info->out, info->to_self_delay,
			     NULL, info->out_sats, NULL, info->wscript);

	if (chainparams->is_elements) {
		bitcoin_tx_add_output(
			tx, scriptpubkey_p2wpkh(tmpctx, &final_key), NULL, info->out_sats);
		keypath_ok = psbt_add_keypath_to_last_output(tx, channel->final_key_idx, &final_wallet_ext_key, false /* is_taproot */);
	} else {
		bitcoin_tx_add_output(
			tx, scriptpubkey_p2tr(tmpctx, &final_key), NULL, info->out_sats);
		keypath_ok = psbt_add_keypath_to_last_output(tx, channel->final_key_idx, &final_wallet_ext_key, true /* is_taproot */);
	}
	if (!keypath_ok) {
 		channel_internal_error(channel, "Could not add keypath?");
		return tal_free(tx);
	}
	/* Worst-case sig is 73 bytes */
	weight = bitcoin_tx_weight(tx) + 1 + 3 + 73 + 0 + tal_count(info->wscript);
	weight += elements_tx_overhead(chainparams, 1, 1);

	/* BOLT #5:
	 * A node which broadcasts an HTLC-success or HTLC-timeout transaction for a
	 * commitment transaction:
	 *   - if `option_anchors` applies:
	 *     - MUST combine it with inputs contributing sufficient fee to ensure timely
	 *       inclusion in a block.
	 *     - MAY combine it with other transactions.
	 */
	/* FIXME: We don't combine! */
	block_target = info->deadline_block;
	for (;;) {
		u32 feerate, asset_feerate;

		feerate = feerate_for_target(ld->topology, block_target);
		/* The sweep pays its fee in the channel asset: in that
		 * asset's atoms, at this node's rate.  With no rate for the
		 * asset there is nothing better than the reference feerate. */
		asset_feerate = channel_asset_feerate(ld->topology,
						      channel->channel_asset,
						      feerate);
		if (!asset_feerate)
			asset_feerate = feerate;
		*fee = amount_tx_fee(asset_feerate, weight);

		log_debug(channel->log,
			  "Feerate for target %"PRIu64" (%+"PRId64" blocks) is %u (%u in the channel asset), fee %s of %s",
			  block_target,
			  block_target - get_block_height(ld->topology),
			  feerate, asset_feerate,
			  fmt_amount_sat(tmpctx, *fee),
			  fmt_amount_sat(tmpctx, info->out_sats));

		/* If we can afford fee and it's not dust, we're done */
		if (amount_sat_sub(&amt, info->out_sats, *fee)
		    && amount_sat_greater_eq(amt, channel->our_config.dust_limit))
			break;

		/* Hmm, can't afford with recommended fee.  Try increasing deadline! */
		block_target++;

		/* If we can't even afford at FEERATE_FLOOR, something is wrong! */
		if (feerate == FEERATE_FLOOR) {
			amt = channel->our_config.dust_limit;
			/* Not quite true, but Never Happens */
			*fee = AMOUNT_SAT(0);
			log_broken(channel->log, "TX can't afford minimal feerate"
				   "; setting output to %s",
				   fmt_amount_sat(tmpctx, amt));
			break;
		}
	}

	/* If we anticipate waiting a long time (say, 20 blocks past
	 * the deadline), tell onchaind not to wait */
	if (worthwhile) {
		*worthwhile = (block_target < info->deadline_block + (u64)20);
		if (!*worthwhile) {
			log_unusual(channel->log,
				    "Lowballing feerate for %s sats from %u to %u (deadline %u->%"PRIu64"):"
				    " won't count on it being spent!",
				    fmt_amount_sat(tmpctx, info->out_sats),
				    feerate_for_target(ld->topology, info->deadline_block),
				    feerate_for_target(ld->topology, block_target),
				    info->deadline_block, block_target);
		}
	}

	/* If we came close to target, it's worthwhile to wait for. */
	if (block_target != info->deadline_block)
		log_debug(channel->log, "Had to adjust deadline from %u to %"PRIu64" for %s",
			  info->deadline_block, block_target,
			  fmt_amount_sat(tmpctx, info->out_sats));
	bitcoin_tx_output_set_amount(tx, 0, amt);
	bitcoin_tx_finalize(tx);

	return tx;
}

static u8 **sign_and_get_witness(const tal_t *ctx,
				 const struct channel *channel,
				 struct bitcoin_tx *tx,
				 const struct onchain_signing_info *info)
{
	const u8 *msg;
	struct bitcoin_signature sig;
	struct lightningd *ld = channel->peer->ld;

	msg = hsm_sync_req(tmpctx, ld, take(info->sign(NULL, tx, info)));
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		fatal("Reading sign_tx_reply: %s", tal_hex(tmpctx, msg));

	return bitcoin_witness_sig_and_element(ctx, &sig, info->stack_elem,
					       tal_bytelen(info->stack_elem),
					       info->wscript);
}

/* Always sets *welements, returns tx.  Sets *worthwhile to false if
 * it wasn't worthwhile at the given feerate (and it had to drop feerate).
 * Returns NULL iff it called channel_internal_error().
 */
static struct bitcoin_tx *onchaind_tx(const tal_t *ctx,
				      struct channel *channel,
				      const struct onchain_signing_info *info,
				      struct amount_sat *fee,
				      bool *worthwhile,
				      const struct onchain_witness_element ***welements)
{
	struct bitcoin_tx *tx;
	u8 **witness;

	tx = onchaind_tx_unsigned(ctx, channel, info, fee, worthwhile);
	if (!tx)
		return NULL;

	/* Now sign, and set witness */
	witness = sign_and_get_witness(NULL, channel, tx, info);
	*welements = onchain_witness_sig_and_element(ctx, witness);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));

	return tx;
}

static bool consider_onchain_rebroadcast(struct channel *channel,
					 const struct bitcoin_tx **tx,
					 struct onchain_signing_info *info)
{
	struct bitcoin_tx *newtx;
	struct amount_sat newfee;
	struct bitcoin_txid oldtxid, newtxid;
	u8 **witness;

	newtx = onchaind_tx_unsigned(tmpctx, channel, info, &newfee, NULL);
	if (!newtx)
		return true;

	/* FIXME: Don't RBF if fee is not sufficiently increased? */

	/* OK!  RBF time! */
	witness = sign_and_get_witness(NULL, channel, newtx, info);
	bitcoin_tx_input_set_witness(newtx, 0, take(witness));

	bitcoin_txid(newtx, &newtxid);
	bitcoin_txid(*tx, &oldtxid);

	/* Don't spam the logs! */
	log_(channel->log,
	     amount_sat_less_eq(newfee, info->fee) ? LOG_DBG : LOG_INFORM,
	     NULL, false,
	     "RBF onchain txid %s (fee %s) with txid %s (fee %s)",
	     fmt_bitcoin_txid(tmpctx, &oldtxid),
	     fmt_amount_sat(tmpctx, info->fee),
	     fmt_bitcoin_txid(tmpctx, &newtxid),
	     fmt_amount_sat(tmpctx, newfee));

	log_debug(channel->log,
		  "RBF %s->%s",
		  fmt_bitcoin_tx(tmpctx, *tx),
		  fmt_bitcoin_tx(tmpctx, newtx));

	/* FIXME: This is ugly, but we want the same parent as old tx. */
	tal_steal(tal_parent(*tx), newtx);
	tal_free(*tx);
	*tx = newtx;
	info->fee = newfee;
	return true;
}

static bool consider_onchain_htlc_tx_rebroadcast(struct channel *channel,
						 const struct bitcoin_tx **tx,
						 struct onchain_signing_info *info)
{
	struct amount_sat change, excess;
	struct utxo **utxos;
	const struct hsm_utxo **hsm_utxos;
	u32 feerate;
	size_t weight;
	struct bitcoin_tx *newtx;
	size_t locktime;
	struct bitcoin_txid oldtxid, newtxid;
	struct wally_psbt *psbt;
	const u8 *msg;
	struct amount_sat oldfee, newfee;
	struct lightningd *ld = channel->peer->ld;

	/* We can't do much without anchor outputs (we could CPFP?) */
	if (!channel_type_has_anchors(channel->type))
		return true;

	/* Note that we can have UTXOs taken from us if there are a lot of
	 * closes going on, so we re-fetch them every time.  This is messy,
	 * but since that bitcoind will take the highest feerate ones, it will
	 * priority order them for us. */

	feerate = feerate_for_target(ld->topology, info->deadline_block);

	/* Make a copy to play with */
	newtx = clone_bitcoin_tx(tmpctx, info->raw_htlc_tx);
	weight = bitcoin_tx_weight(newtx);

	/* We'll need this to regenerate PSBT */
	if (wally_psbt_get_locktime(newtx->psbt, &locktime) != WALLY_OK) {
		log_broken(channel->log, "Cannot get psbt locktime?!");
		return true;
	}

	utxos = wallet_utxo_boost(tmpctx,
				  ld->wallet,
				  get_block_height(ld->topology),
				  AMOUNT_SAT(0),
				  bitcoin_tx_compute_fee(newtx),
				  feerate,
				  &weight, NULL,
				  /* Asset-aware: bump a GOLD HTLC-tx with GOLD utxos. */
				  channel->channel_asset);

	/* Add those to create a new PSBT */
	psbt = psbt_using_utxos(tmpctx, ld->wallet, utxos, locktime,
				BITCOIN_TX_RBF_SEQUENCE, newtx->psbt);

	/* Subtract how much we pay in fees for this tx, to calc excess. */
	if (!amount_sat_sub(&excess,
			    psbt_compute_fee(psbt),
			    amount_tx_fee(feerate, weight))) {
		/* We didn't make the feerate.  Did we get nothing at all? */
		if (tal_count(utxos) == 0) {
			log_unusual(channel->log,
				    "We want to bump HTLC fee, but no funds!");
			return true;
		}
		/* At least we got something! */
		log_unusual(channel->log,
			    "We want to bump HTLC fee more, but ran out of funds!");
		excess = AMOUNT_SAT(0);
	}

	/* We were happy with feerate already (can't happen with zero-fee
	 * anchors!)? */
	if (tal_count(utxos) == 0)
		return true;

	/* Maybe add change */
	change = change_amount(excess, feerate, weight);
	if (!amount_sat_eq(change, AMOUNT_SAT(0))) {
		/* Append change output. */
		struct pubkey final_key;
		/* Use BIP86 derivation for P2TR if available, otherwise BIP32 */
		if (ld->bip86_base) {
			bip86_pubkey(ld, &final_key, channel->final_key_idx);
		} else {
			bip32_pubkey(ld, &final_key, channel->final_key_idx);
		}
		psbt_append_output(psbt,
				   scriptpubkey_p2tr(tmpctx, &final_key),
				   change);
	}

	/* Sanity check: are we paying more in fees than HTLC is worth? */
	if (amount_sat_greater(psbt_compute_fee(psbt), info->out_sats)) {
		log_unusual(channel->log,
			    "Not spending %s in fees to get an HTLC worth %s!",
			    fmt_amount_sat(tmpctx, psbt_compute_fee(psbt)),
			    fmt_amount_sat(tmpctx, info->out_sats));
		return true;
	}

	/* Now, get HSM to sign off. */
	hsm_utxos = utxos_to_hsm_utxos(tmpctx, utxos);
	msg = towire_hsmd_sign_htlc_tx_mingle(NULL,
					      &channel->peer->id,
					      channel->dbid,
					      hsm_utxos,
					      psbt);
	msg = hsm_sync_req(tmpctx, ld, take(msg));
	if (!fromwire_hsmd_sign_htlc_tx_mingle_reply(tmpctx, msg, &psbt))
		fatal("Reading sign_htlc_tx_mingle_reply: %s",
		      tal_hex(tmpctx, msg));

	if (!psbt_finalize(psbt))
		fatal("Non-final PSBT from hsm: %s",
		      fmt_wally_psbt(tmpctx, psbt));

	newtx = tal(tal_parent(*tx), struct bitcoin_tx);
	newtx->chainparams = chainparams;
	newtx->wtx = psbt_final_tx(newtx, psbt);
	assert(newtx->wtx);
	newtx->psbt = tal_steal(newtx, psbt);

	bitcoin_txid(*tx, &oldtxid);
	bitcoin_txid(newtx, &newtxid);

	oldfee = bitcoin_tx_compute_fee(*tx);
	newfee = bitcoin_tx_compute_fee(newtx);

	/* Don't spam the logs! */
	log_(channel->log,
	     amount_sat_less_eq(newfee, oldfee) ? LOG_DBG : LOG_INFORM,
	     NULL, false,
	     "RBF HTLC txid %s (fee %s) with txid %s (fee %s)",
	     fmt_bitcoin_txid(tmpctx, &oldtxid),
	     fmt_amount_sat(tmpctx, oldfee),
	     fmt_bitcoin_txid(tmpctx, &newtxid),
	     fmt_amount_sat(tmpctx, newfee));

	tal_free(*tx);
	*tx = newtx;
	return true;
}

/* We want to mine a success tx before they can timeout */
static u32 htlc_incoming_deadline(const struct channel *channel, u64 htlc_id)
{
	struct htlc_in *hin;

	hin = find_htlc_in(channel->peer->ld->htlcs_in, channel, htlc_id);
	if (!hin) {
		log_broken(channel->log, "No htlc IN %"PRIu64", using infinite deadline",
			   htlc_id);
		return infinite_block_deadline(channel->peer->ld->topology);
	}

	return hin->cltv_expiry - 1;
}

/* If there's a corresponding incoming HTLC, we want this mined in time so
 * we can fail incoming before incoming peer closes on us! */
static u32 htlc_outgoing_incoming_deadline(const struct channel *channel, u64 htlc_id)
{
	struct htlc_out *hout;

	hout = find_htlc_out(channel->peer->ld->htlcs_out, channel, htlc_id);
	if (!hout) {
		log_broken(channel->log, "No htlc OUT %"PRIu64", using infinite deadline",
			   htlc_id);
		return infinite_block_deadline(channel->peer->ld->topology);
	}

	/* If it's ours, no real pressure, but let's avoid leaking
	 * that information by using our standard setting. */
	if (!hout->in)
		return hout->cltv_expiry;

	/* Give us at least six blocks to redeem! */
	return hout->in->cltv_expiry - 6;
}

/* Create the onchain tx and tell onchaind about it */
static void create_onchain_tx(struct channel *channel,
			      const struct bitcoin_outpoint *out,
			      struct amount_sat out_sats,
			      u32 to_self_delay,
			      u32 locktime,
			      u8 *(*sign)(const tal_t *ctx,
					  const struct bitcoin_tx *tx,
					  const struct onchain_signing_info *info),
			      struct onchain_signing_info *info STEALS,
			      const char *caller)
{
	struct bitcoin_tx *tx;
	const struct onchain_witness_element **welements;
	bool worthwhile;
	struct lightningd *ld = channel->peer->ld;

	/* Save these in case we need to RBF.  We could extract from
	 * tx, but this is clearer and simpler. */
	info->out = *out;
	info->out_sats = out_sats;
	info->to_self_delay = to_self_delay;
	info->locktime = locktime;
	info->sign = sign;

	tx = onchaind_tx(tmpctx, channel, info, &info->fee, &worthwhile, &welements);
	if (!tx) {
		tal_free(info);
		return;
	}

	log_debug(channel->log, "Broadcast for onchaind tx %s%s",
		  fmt_bitcoin_tx(tmpctx, tx),
		  worthwhile ? "" : "(NOT WORTHWHILE, LOWBALL FEE!)");

	/* We allow "excessive" fees, as we may be fighting with censors and
	 * we'd rather spend fees than have our adversary win. */
	broadcast_tx(channel, ld->topology,
		     channel, take(tx), NULL, true, info->minblock,
		     NULL, consider_onchain_rebroadcast, take(info));

	subd_send_msg(channel->owner,
		      take(towire_onchaind_spend_created(NULL,
							 worthwhile,
							 welements)));
}

/* BOLT #5:
 *
 *  - if `option_anchors` applies:
 *    - MAY use a single transaction to *resolve* all the outputs.
 *    - if confirmation doesn't happen before reaching `security_delay` blocks from
 *  expiry:
 *      - SHOULD *resolve* revoked outputs in their own, separate penalty transactions. A previous
 *  penalty transaction claiming multiple revoked outputs at once may be blocked from confirming
 *  because of a transaction pinning attack.
 *  - otherwise:
 *    - MAY use a single transaction to *resolve* all the outputs.
 *  - MUST handle its transactions being invalidated by HTLC transactions.
 */
/* FIXME: we always use one transaction per HTLC, even when we have
 * plenty of time and could combine them. */
static void handle_onchaind_spend_to_us(struct channel *channel,
					const u8 *msg)
{
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	u32 sequence;

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_TO_US);

	/* BOLT #3:
	 * #### `to_local` Output
	 *...
	 * The output is spent by an input with `nSequence` field set to `to_self_delay` (which can only be valid after that duration has passed) and witness:
 	 *
	 *    <local_delayedsig> <>
	 */

	/* BOLT #3:
	 * ## HTLC-Timeout and HTLC-Success Transactions
	 *
	 * These HTLC transactions are almost identical, except the HTLC-timeout transaction is timelocked.
	 *...
	 * To spend this via penalty, the remote node uses a witness stack
	 * `<revocationsig> 1`, and to collect the output, the local node uses
	 * an input with nSequence `to_self_delay` and a witness stack
	 * `<local_delayedsig> 0`.
	 */
	info->stack_elem = NULL;

	if (!fromwire_onchaind_spend_to_us(info, msg,
					   &out, &out_sats,
					   &sequence,
					   &info->minblock,
					   &info->u.htlc_timedout.commit_num,
					   &info->wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_to_us %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* No real deadline on this, it's just returning to our wallet.  But
	 * it cannot be spent before `minblock`, when its delay has run
	 * (`to_self_delay`, about a day of blocks on a Sequentia network):
	 * a deadline that falls before that, or within the slow sweep's
	 * shortest window (12 blocks) after it, would have the sweep bid
	 * the feerate for the next block from its first attempt.  Then the
	 * window is measured from the block it can first be mined in. */
	info->deadline_block =
	    slow_sweep_deadline(channel->peer->ld->topology, channel,
				get_block_height(channel->peer->ld->topology));
	if (info->deadline_block < info->minblock + 12) {
		log_debug(channel->log,
			  "Sweep deadline %u falls before its output can be"
			  " spent (block %u): measuring from there",
			  info->deadline_block, info->minblock);
		info->deadline_block =
		    slow_sweep_deadline(channel->peer->ld->topology, channel,
					info->minblock);
	}

	/* sequence is usually channel->channel_info.their_config.to_self_delay,
	 * but for leases it can be greater. */
	create_onchain_tx(channel, &out, out_sats,
			  sequence, 0,
			  sign_tx_to_us, info,
			  __func__);
}

static void handle_onchaind_spend_penalty(struct channel *channel,
					  const u8 *msg)
{
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	u8 *stack_elem;

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_PENALTY);
	/* We can always spend penalty txs immediately */
	info->minblock = 0;
	if (!fromwire_onchaind_spend_penalty(info, msg,
					     &out, &out_sats,
					     &info->u.spend_penalty.remote_per_commitment_secret,
					     &stack_elem,
					     &info->wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_penalty %s",
				       tal_hex(tmpctx, msg));
		return;
	}
	/* info->stack_elem is const void * */
	info->stack_elem = stack_elem;

	/* FIXME: deadline for HTLCs is actually a bit longer, but for
	 * their output it's channel->our_config.to_self_delay after
	 * the commitment tx is mined. */
	info->deadline_block = *channel->close_blockheight
		+ channel->our_config.to_self_delay;
	create_onchain_tx(channel, &out, out_sats,
			  0, 0,
			  sign_penalty, info,
			  __func__);
}

static void handle_onchaind_spend_fulfill(struct channel *channel,
					  const u8 *msg)
{
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	struct preimage preimage;
	u64 htlc_id;
	const bool anchor_outputs = channel_type_has_anchors(channel->type);

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_FULFILL);
	info->minblock = 0;

	if (!fromwire_onchaind_spend_fulfill(info, msg,
					     &out, &out_sats,
					     &htlc_id,
					     &info->u.fulfill.remote_per_commitment_point,
					     &preimage,
					     &info->wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_fulfill %s",
				       tal_hex(tmpctx, msg));
		return;
	}
	info->stack_elem = tal_dup(info, struct preimage, &preimage);

	info->deadline_block = htlc_incoming_deadline(channel, htlc_id);
	/* BOLT #3:
	 *
	 * Note that if `option_anchors` applies, the nSequence field of
	 * the spending input must be `1`.
	 */
	create_onchain_tx(channel, &out, out_sats,
			  anchor_outputs ? 1 : 0,
			  0,
			  sign_fulfill, info,
			  __func__);
}

static void handle_onchaind_spend_htlc_success(struct channel *channel,
					       const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats, fee;
	u64 htlc_id;
	u8 *htlc_wscript;
	struct bitcoin_tx *tx;
	u8 **witness;
	struct bitcoin_signature sig;
	const struct onchain_witness_element **welements;
	const bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS_DEPRECATED);
	const bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_HTLC_SUCCESS);
	info->minblock = 0;

	if (!fromwire_onchaind_spend_htlc_success(info, msg,
						  &out, &out_sats, &fee,
						  &htlc_id,
						  &info->u.htlc_success.commit_num,
						  &info->u.htlc_success.remote_htlc_sig,
						  &info->u.htlc_success.preimage,
						  &info->wscript,
						  &htlc_wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_htlc_success %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* BOLT #3:
	 * * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
	 */
	tx = htlc_tx(NULL, chainparams, &out, info->wscript, out_sats, htlc_wscript, fee,
		     0, option_anchor_outputs, option_anchors_zero_fee_htlc_tx,
		     info->channel->channel_asset);
	tal_free(htlc_wscript);
	if (!tx) {
		/* Can only happen if fee > out_sats */
		channel_internal_error(channel, "Invalid onchaind_spend_htlc_success %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* FIXME: tell onchaind if HTLC is too small for current
	 * feerate! */
	info->deadline_block = htlc_incoming_deadline(channel, htlc_id);

	/* Now sign, and set witness */
	msg = hsm_sync_req(tmpctx, ld, take(sign_htlc_success(NULL, tx, info)));
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		fatal("Reading sign_tx_reply: %s", tal_hex(tmpctx, msg));

	witness = bitcoin_witness_htlc_success_tx(NULL, &sig,
						  &info->u.htlc_success.remote_htlc_sig,
						  &info->u.htlc_success.preimage,
						  info->wscript);
	welements = onchain_witness_htlc_tx(tmpctx, witness);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));

	info->raw_htlc_tx = clone_bitcoin_tx(info, tx);
	info->out_sats = out_sats;

	/* Immediately consider RBF. */
	consider_onchain_htlc_tx_rebroadcast(channel,
					     cast_const2(const struct bitcoin_tx **, &tx),
					     info);

	log_debug(channel->log, "Broadcast for onchaind tx %s",
		  fmt_bitcoin_tx(tmpctx, tx));
	broadcast_tx(channel, channel->peer->ld->topology,
		     channel, take(tx), NULL, false,
		     info->minblock, NULL,
		     consider_onchain_htlc_tx_rebroadcast, take(info));

	msg = towire_onchaind_spend_created(NULL, true, welements);
	subd_send_msg(channel->owner, take(msg));
}

static void handle_onchaind_spend_htlc_timeout(struct channel *channel,
					       const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats, fee;
	u64 htlc_id;
	u32 cltv_expiry;
	u8 *htlc_wscript;
	struct bitcoin_tx *tx;
	u8 **witness;
	struct bitcoin_signature sig;
	const struct onchain_witness_element **welements;
	const bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS_DEPRECATED);
	const bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_HTLC_TIMEOUT);

	if (!fromwire_onchaind_spend_htlc_timeout(info, msg,
						  &out, &out_sats, &fee,
						  &htlc_id,
						  &cltv_expiry,
						  &info->u.htlc_timeout.commit_num,
						  &info->u.htlc_timeout.remote_htlc_sig,
						  &info->wscript,
						  &htlc_wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_htlc_timeout %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* BOLT #3:
	 * * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
	 */
	tx = htlc_tx(NULL, chainparams, &out, info->wscript, out_sats, htlc_wscript, fee,
		     cltv_expiry, option_anchor_outputs, option_anchors_zero_fee_htlc_tx,
		     info->channel->channel_asset);
	tal_free(htlc_wscript);
	if (!tx) {
		/* Can only happen if fee > out_sats */
		channel_internal_error(channel, "Invalid onchaind_spend_htlc_timeout %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* FIXME: tell onchaind if HTLC is too small for current
	 * feerate! */
	info->deadline_block = htlc_outgoing_incoming_deadline(channel, htlc_id);

	/* nLocktime: we have to be *after* that block! */
	info->minblock = cltv_expiry + 1;

	/* Now sign, and set witness */
	msg = hsm_sync_req(tmpctx, ld, take(sign_htlc_timeout(NULL, tx, info)));
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		fatal("Reading sign_tx_reply: %s", tal_hex(tmpctx, msg));

	witness = bitcoin_witness_htlc_timeout_tx(NULL, &sig,
						  &info->u.htlc_timeout.remote_htlc_sig,
						  info->wscript);
	welements = onchain_witness_htlc_tx(tmpctx, witness);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));

	info->raw_htlc_tx = clone_bitcoin_tx(info, tx);
	info->out_sats = out_sats;

	/* Immediately consider RBF. */
	consider_onchain_htlc_tx_rebroadcast(channel,
					     cast_const2(const struct bitcoin_tx **, &tx),
					     info);

	log_debug(channel->log, "Broadcast for onchaind tx %s",
		  fmt_bitcoin_tx(tmpctx, tx));
	broadcast_tx(channel, channel->peer->ld->topology,
		     channel, take(tx), NULL, false,
		     info->minblock, NULL,
		     consider_onchain_htlc_tx_rebroadcast, take(info));

	msg = towire_onchaind_spend_created(NULL, true, welements);
	subd_send_msg(channel->owner, take(msg));
}

static void handle_onchaind_spend_htlc_expired(struct channel *channel,
					       const u8 *msg)
{
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	u64 htlc_id;
	u32 cltv_expiry;
	const bool anchor_outputs = channel_type_has_anchors(channel->type);

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_HTLC_EXPIRED);

	/* BOLT #5:
	 *
	 * A local node:
	 * ...
	 *   - if the commitment transaction HTLC output has *timed out* AND NOT
	 *     been *resolved*:
	 *     - MUST *resolve* the output, by spending it to a convenient
	 *       address.
	 */
	info->stack_elem = NULL;

	if (!fromwire_onchaind_spend_htlc_expired(info, msg,
						  &out, &out_sats,
						  &htlc_id,
						  &cltv_expiry,
						  &info->u.htlc_expired.remote_per_commitment_point,
						  &info->wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_htlc_expired %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* nLocktime: we have to be *after* that block! */
	info->minblock = cltv_expiry + 1;

	/* We have to spend it before we can close incoming */
	info->deadline_block = htlc_outgoing_incoming_deadline(channel, htlc_id);
	create_onchain_tx(channel, &out, out_sats,
			  anchor_outputs ? 1 : 0,
			  cltv_expiry,
			  sign_htlc_expired, info,
			  __func__);
}

/*~ SEQUENTIA: spends of a taproot-covenant channel's outputs
 * (common/tcov_scripts.h), which onchaind asks for with onchaind_spend_tcov.
 *
 * Input 0 spends the channel's output by one leaf or by the key path.  A
 * covenant leaf (our HTLC claims from our own commitment) demands that the
 * output at the input's index carry the output's whole value to our delayed
 * output D: the fee must come from another input, from our wallet, in any
 * asset this node accepts for fees, the channel's own first.  Any other
 * spend pays our wallet; its fee comes out of the output itself while the
 * node accepts the channel's asset for fees, and from another input when it
 * does not.  Every spend is rebuilt and signed again at each block until
 * mined, at the feerate its deadline then calls for. */
struct tcov_spend {
	struct channel *channel;
	enum tcov_spend_signer signer;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	u8 *spent_spk;
	u64 commit_num;
	struct pubkey *remote_point;
	struct secret *revocation_secret;
	u8 *leaf, *cb;
	struct sha256 merkle_root;
	struct preimage *preimage;
	/* The covenant's destination, or NULL: our wallet. */
	u8 *cov_program;
	u32 locktime, sequence, minblock, deadline_block;
	/* What the last broadcast paid, in its fee asset, and the wallet
	 * coins it spent (which it reserved, and may spend again). */
	struct amount_sat fee;
	u8 fee_asset[33];
	struct bitcoin_outpoint *coins;
	/* The output is spent on chain, by this spend or by the peer. */
	bool spent;
};

/* The spends in progress.  Once the output one spends is spent on chain it
 * stops: the broadcast follows the txid it first sent, so a replacement
 * that confirmed, or the peer's spend, would otherwise have it rebuilt,
 * signed again and its fee coins reserved again at every block until the
 * channel is forgotten. */
static struct tcov_spend **tcov_spends;

static void destroy_tcov_spend(struct tcov_spend *ts)
{
	for (size_t i = 0; i < tal_count(tcov_spends); i++) {
		if (tcov_spends[i] == ts) {
			tal_arr_remove(&tcov_spends, i);
			return;
		}
	}
}

static void tcov_spend_track(struct tcov_spend *ts)
{
	if (!tcov_spends)
		tcov_spends = notleak(tal_arr(NULL, struct tcov_spend *, 0));
	ts->spent = false;
	tal_arr_expand(&tcov_spends, ts);
	tal_add_destructor(ts, destroy_tcov_spend);
}

static void tcov_note_spent(const struct channel *channel,
			    const struct bitcoin_outpoint *out)
{
	for (size_t i = 0; i < tal_count(tcov_spends); i++) {
		if (tcov_spends[i]->channel == channel
		    && bitcoin_outpoint_eq(&tcov_spends[i]->out, out))
			tcov_spends[i]->spent = true;
	}
}

/* The input 0 signature, from hsmd. */
static bool tcov_sign_input0(const struct tcov_spend *ts,
			     struct bitcoin_tx *tx,
			     struct bip340sig *sig)
{
	struct lightningd *ld = ts->channel->peer->ld;
	const struct node_id *id = &ts->channel->peer->id;
	u64 dbid = ts->channel->dbid;
	const u8 *msg;

	switch (ts->signer) {
	case TCOV_SIGN_DELAYED:
		msg = towire_hsmd_sign_tcov_delayed_to_us(NULL, ts->commit_num,
							  tx, 0, ts->leaf,
							  id, dbid);
		break;
	case TCOV_SIGN_LOCAL_HTLC:
		msg = towire_hsmd_sign_tcov_local_htlc(NULL, ts->commit_num,
						       tx, 0, ts->leaf,
						       id, dbid);
		break;
	case TCOV_SIGN_REMOTE_HTLC:
		msg = towire_hsmd_sign_tcov_remote_htlc_to_us(NULL,
							      ts->remote_point,
							      tx, 0, ts->leaf,
							      id, dbid);
		break;
	case TCOV_SIGN_PENALTY:
		msg = towire_hsmd_sign_tcov_penalty(NULL, ts->revocation_secret,
						    tx, 0, &ts->merkle_root,
						    id, dbid);
		break;
	default:
		return false;
	}
	msg = hsm_sync_req(tmpctx, ld, take(msg));
	return fromwire_hsmd_sign_tcov_reply(msg, sig);
}

/* Input 0's witness: <sig> [<preimage>] <leaf> <control block>, or <sig>. */
static u8 **tcov_witness(const tal_t *ctx, const struct tcov_spend *ts,
			 const struct bip340sig *sig)
{
	u8 **w = tal_arr(ctx, u8 *, 0);

	tal_arr_expand(&w, tap_sig_to_witness(w, sig, TAP_SIGHASH_DEFAULT));
	if (tal_bytelen(ts->leaf) == 0)
		return w;
	if (ts->preimage)
		tal_arr_expand(&w, tal_dup_arr(w, u8, ts->preimage->r,
					       sizeof(ts->preimage->r), 0));
	tal_arr_expand(&w, tal_dup_talarr(w, u8, ts->leaf));
	tal_arr_expand(&w, tal_dup_talarr(w, u8, ts->cb));
	return w;
}

static size_t tcov_input0_witness_weight(const struct tcov_spend *ts)
{
	/* count, the 64-byte signature, then the optional elements. */
	size_t w = 1 + 1 + 64;

	if (tal_bytelen(ts->leaf)) {
		if (ts->preimage)
			w += 1 + 32;
		w += varint_size(tal_bytelen(ts->leaf)) + tal_bytelen(ts->leaf);
		w += 1 + tal_bytelen(ts->cb);
	}
	return w;
}

/* Our wallet's script for what this spend pays us. */
static u8 *tcov_wallet_spk(const tal_t *ctx, struct channel *channel,
			   struct ext_key *ext)
{
	struct lightningd *ld = channel->peer->ld;
	struct pubkey final_key;

	if (ld->bip86_base) {
		bip86_pubkey(ld, &final_key, channel->final_key_idx);
		if (bip32_key_from_parent(ld->bip86_base, channel->final_key_idx,
					  BIP32_FLAG_KEY_PUBLIC, ext) != WALLY_OK)
			return NULL;
	} else {
		bip32_pubkey(ld, &final_key, channel->final_key_idx);
		if (bip32_key_from_parent(ld->bip32_base, channel->final_key_idx,
					  BIP32_FLAG_KEY_PUBLIC, ext) != WALLY_OK)
			return NULL;
	}
	return scriptpubkey_p2wpkh(ctx, &final_key);
}

/* Mark @psbt's output @outnum as our wallet key's. */
static void tcov_set_keypath(struct wally_psbt *psbt, size_t outnum,
			     struct channel *channel, const struct ext_key *ext)
{
	tal_wally_start();
	/* Only a hint for the wallet's bookkeeping: the output pays our
	 * script whether or not it carries one. */
	if (!psbt_output_set_keypath(channel->final_key_idx, ext, false,
				     &psbt->outputs[outnum]))
		log_unusual(channel->log, "tcov spend: no keypath on output %zu",
			    outnum);
	tal_wally_end(psbt);
}

/* Spendable wallet coins of @asset. */
static bool tcov_own_coin(const struct tcov_spend *ts,
			  const struct bitcoin_outpoint *op)
{
	for (size_t i = 0; i < tal_count(ts->coins); i++)
		if (bitcoin_outpoint_eq(&ts->coins[i], op))
			return true;
	return false;
}

/* Spendable wallet coins of @asset: unreserved, or reserved by this very
 * spend's last broadcast. */
static struct utxo **tcov_coins(const tal_t *ctx, const struct tcov_spend *ts,
				const u8 *asset, struct amount_sat *total)
{
	struct lightningd *ld = ts->channel->peer->ld;
	struct utxo **all = wallet_get_unspent_utxos(tmpctx, ld->wallet);
	struct utxo **coins = tal_arr(ctx, struct utxo *, 0);
	u32 height = get_block_height(ld->topology);

	*total = AMOUNT_SAT(0);
	for (size_t i = 0; i < tal_count(all); i++) {
		if (memcmp(all[i]->asset, asset, sizeof(all[i]->asset)) != 0)
			continue;
		if ((utxo_is_reserved(all[i], height)
		     && !tcov_own_coin(ts, &all[i]->outpoint))
		    || utxo_is_csv_locked(all[i], height)
		    || !all[i]->blockheight
		    || all[i]->close_info)
			continue;
		if (!amount_sat_add(total, *total, all[i]->amount))
			continue;
		tal_arr_expand(&coins, tal_steal(coins, all[i]));
	}
	return coins;
}

/* The weight of the spend paying @dest_spk, with @coins (none: the fee out
 * of the output), a change output if @change, and the fee output. */
static size_t tcov_weight(const struct tcov_spend *ts, const u8 *dest_spk,
			  struct utxo **coins, bool change)
{
	struct wally_psbt *psbt = create_psbt(tmpctx, 0, 0, ts->locktime);
	struct bitcoin_tx *tx;
	size_t weight;
	u8 dummy[33];

	memset(dummy, 1, sizeof(dummy));
	psbt_append_input(psbt, &ts->out, ts->sequence, NULL, NULL, NULL);
	psbt_append_output_asset(psbt, dest_spk, ts->out_sats, dummy);
	for (size_t i = 0; i < tal_count(coins); i++)
		psbt_append_input(psbt, &coins[i]->outpoint, 0, NULL, NULL, NULL);
	if (change)
		psbt_append_output_asset(psbt, dest_spk, ts->out_sats, dummy);
	psbt_append_output_asset(psbt, NULL, ts->out_sats, dummy);
	tx = bitcoin_tx_with_psbt(tmpctx, psbt);
	/* The inputs are counted; add their witnesses. */
	weight = bitcoin_tx_weight(tx) + tcov_input0_witness_weight(ts);
	for (size_t i = 0; i < tal_count(coins); i++)
		weight += 1 + bitcoin_tx_input_witness_weight(coins[i]->utxotype);
	return weight;
}

static int cmp_utxo_amount_desc(struct utxo *const *a, struct utxo *const *b,
				void *unused)
{
	if (amount_sat_greater((*a)->amount, (*b)->amount))
		return -1;
	if (amount_sat_less((*a)->amount, (*b)->amount))
		return 1;
	return 0;
}

/* Build and sign the spend at @feerate (reference atoms per kw).  NULL if
 * it cannot be paid for now. */
static struct bitcoin_tx *tcov_build(const tal_t *ctx,
				     struct tcov_spend *ts,
				     u32 feerate)
{
	struct channel *channel = ts->channel;
	struct lightningd *ld = channel->peer->ld;
	const u8 *chan_asset = channel->channel_asset;
	struct ext_key ext;
	u8 *wallet_spk, *dest_spk;
	struct wally_psbt *psbt;
	struct utxo **coins = NULL;
	const u8 *fee_asset = NULL;
	struct amount_sat fee, change = AMOUNT_SAT(0), sum = AMOUNT_SAT(0);
	struct bitcoin_tx *tx;
	struct bip340sig sig;
	const struct hsm_utxo **hsm_utxos;
	const u8 *msg;
	u64 chan_rate = topo_asset_fee_rate(ld->topology, chan_asset);

	wallet_spk = tcov_wallet_spk(tmpctx, channel, &ext);
	if (!wallet_spk) {
		log_broken(channel->log, "tcov spend: no wallet key");
		return NULL;
	}
	if (ts->cov_program) {
		dest_spk = tal_arr(tmpctx, u8, 2 + 32);
		dest_spk[0] = 0x51;
		dest_spk[1] = 32;
		memcpy(dest_spk + 2, ts->cov_program, 32);
	} else
		dest_spk = wallet_spk;

	/* Not a covenant, and the channel's asset pays fees here: out of
	 * the output itself, as for any other channel type. */
	if (!ts->cov_program && chan_rate) {
		size_t weight = tcov_weight(ts, dest_spk, NULL, false);
		struct amount_sat left;

		fee = amount_tx_fee(feerate_in_asset(feerate, chan_rate), weight);
		if (!amount_sat_sub(&left, ts->out_sats, fee)
		    || amount_sat_less(left, channel->our_config.dust_limit)) {
			log_unusual(channel->log, "tcov spend of %s: %s cannot pay"
				    " its own fee %s; looking for a fee coin",
				    fmt_bitcoin_outpoint(tmpctx, &ts->out),
				    fmt_amount_sat(tmpctx, ts->out_sats),
				    fmt_amount_sat(tmpctx, fee));
		} else {
			psbt = create_psbt(tmpctx, 0, 0, ts->locktime);
			psbt_append_input(psbt, &ts->out, ts->sequence, NULL,
					  NULL, NULL);
			psbt_input_set_wit_utxo_asset(psbt, 0, ts->spent_spk,
						      ts->out_sats, chan_asset);
			psbt_append_output_asset(psbt, dest_spk, left,
						 chan_asset);
			tcov_set_keypath(psbt, 0, channel, &ext);
			psbt_append_output_asset(psbt, NULL, fee, chan_asset);
			memcpy(ts->fee_asset, chan_asset, sizeof(ts->fee_asset));
			goto sign;
		}
	}

	/* A fee coin: the channel's asset if it pays fees here and we hold
	 * enough of it, else the accepted asset whose coins are worth the
	 * most to this node.  The Sequence token is one asset among them. */
	for (size_t i = 0; i < tal_count(ld->topology->asset_fee_rates) + 1; i++) {
		const u8 *asset;
		u64 rate;
		struct amount_sat total, need;
		struct utxo **c;

		if (i == 0) {
			asset = chan_asset;
			rate = chan_rate;
		} else {
			asset = ld->topology->asset_fee_rates[i-1].asset;
			rate = ld->topology->asset_fee_rates[i-1].scaled_value;
		}
		if (!rate)
			continue;
		c = tcov_coins(tmpctx, ts, asset, &total);
		if (tal_count(c) == 0)
			continue;
		need = amount_tx_fee(feerate_in_asset(feerate, rate),
				     tcov_weight(ts, dest_spk, c, true));
		if (amount_sat_less(total, need))
			continue;
		if (i == 0) {
			coins = c;
			fee_asset = asset;
			break;
		}
		/* Their value to this node: atoms times its rate for them. */
		double worth = (double)total.satoshis * rate; /* Raw: ranking */
		double best = (double)sum.satoshis /* Raw: ranking */
			* topo_asset_fee_rate(ld->topology, fee_asset ? fee_asset : asset);
		if (!fee_asset || worth > best) {
			coins = c;
			fee_asset = asset;
			sum = total;
		}
	}
	if (!fee_asset) {
		log_unusual(channel->log, "tcov spend of %s: no coin in an asset"
			    " this node accepts for fees covers it; trying"
			    " again",
			    fmt_bitcoin_outpoint(tmpctx, &ts->out));
		return NULL;
	}

	/* Fewest coins: largest first, until the fee and a change output
	 * are covered. */
	asort(coins, tal_count(coins), cmp_utxo_amount_desc, NULL);
	{
		u64 rate = topo_asset_fee_rate(ld->topology, fee_asset);
		struct utxo **use = tal_arr(tmpctx, struct utxo *, 0);

		sum = AMOUNT_SAT(0);
		for (size_t i = 0; i < tal_count(coins); i++) {
			tal_arr_expand(&use, coins[i]);
			if (!amount_sat_add(&sum, sum, coins[i]->amount))
				return NULL;
			fee = amount_tx_fee(feerate_in_asset(feerate, rate),
					    tcov_weight(ts, dest_spk, use, true));
			if (amount_sat_greater_eq(sum, fee))
				break;
		}
		coins = use;
		if (!amount_sat_sub(&change, sum, fee))
			return NULL;
		/* Change below the chain's dust goes to the fee. */
		if (amount_sat_less(change, chainparams->dust_limit)) {
			fee = sum;
			change = AMOUNT_SAT(0);
		}
	}

	psbt = create_psbt(tmpctx, 0, 0, ts->locktime);
	psbt_append_input(psbt, &ts->out, ts->sequence, NULL, NULL, NULL);
	psbt_input_set_wit_utxo_asset(psbt, 0, ts->spent_spk, ts->out_sats,
				      chan_asset);
	psbt_append_output_asset(psbt, dest_spk, ts->out_sats, chan_asset);
	if (!ts->cov_program)
		tcov_set_keypath(psbt, 0, channel, &ext);
	psbt = psbt_using_utxos(tmpctx, ld->wallet, coins, ts->locktime,
				BITCOIN_TX_RBF_SEQUENCE, psbt);
	if (amount_sat_greater(change, AMOUNT_SAT(0))) {
		psbt_append_output_asset(psbt, wallet_spk, change, fee_asset);
		tcov_set_keypath(psbt, psbt->num_outputs - 1, channel, &ext);
	}
	psbt_append_output_asset(psbt, NULL, fee, fee_asset);
	memcpy(ts->fee_asset, fee_asset, sizeof(ts->fee_asset));

sign:
	tx = bitcoin_tx_with_psbt(tmpctx, psbt);
	if (!tcov_sign_input0(ts, tx, &sig)) {
		log_broken(channel->log, "tcov spend: hsmd did not sign %s",
			   fmt_bitcoin_outpoint(tmpctx, &ts->out));
		return NULL;
	}
	tal_wally_start();
	{
		u8 **wit = tcov_witness(tmpctx, ts, &sig);
		struct wally_tx_witness_stack *stack;

		wally_tx_witness_stack_init_alloc(tal_count(wit), &stack);
		for (size_t i = 0; i < tal_count(wit); i++)
			wally_tx_witness_stack_add(stack, wit[i],
						   tal_bytelen(wit[i]));
		wally_psbt_input_set_final_witness(&psbt->inputs[0], stack);
		wally_tx_witness_stack_free(stack);
	}
	tal_wally_end(psbt);

	if (tal_count(coins)) {
		hsm_utxos = utxos_to_hsm_utxos(tmpctx, coins);
		msg = towire_hsmd_sign_htlc_tx_mingle(NULL, &channel->peer->id,
						      channel->dbid, hsm_utxos,
						      psbt);
		msg = hsm_sync_req(tmpctx, ld, take(msg));
		if (!fromwire_hsmd_sign_htlc_tx_mingle_reply(tmpctx, msg, &psbt))
			fatal("Reading sign_htlc_tx_mingle_reply: %s",
			      tal_hex(tmpctx, msg));
		/* Keep other spends off these coins until this one can
		 * be mined, and a few blocks more. */
		for (size_t i = 0; i < tal_count(coins); i++)
			wallet_reserve_utxo(ld->wallet, coins[i],
					    get_block_height(ld->topology),
					    (ts->minblock > get_block_height(ld->topology)
					     ? ts->minblock - get_block_height(ld->topology)
					     : 0) + 12);
	}
	if (!psbt_finalize(psbt)) {
		log_broken(channel->log, "tcov spend: cannot finalize %s",
			   fmt_wally_psbt(tmpctx, psbt));
		return NULL;
	}
	tx = tal(ctx, struct bitcoin_tx);
	tx->chainparams = chainparams;
	tx->wtx = psbt_final_tx(tx, psbt);
	if (!tx->wtx)
		return tal_free(tx);
	tx->psbt = tal_steal(tx, psbt);
	ts->fee = fee;
	tal_free(ts->coins);
	ts->coins = tal_arr(ts, struct bitcoin_outpoint, tal_count(coins));
	for (size_t i = 0; i < tal_count(coins); i++)
		ts->coins[i] = coins[i]->outpoint;
	log_debug(channel->log, "tcov spend of %s (%s): fee %s of asset %s at"
		  " %u/kw, %zu fee coin(s)",
		  fmt_bitcoin_outpoint(tmpctx, &ts->out),
		  ts->cov_program ? "by covenant" : "to our wallet",
		  fmt_amount_sat(tmpctx, fee), fmt_asset_id(tmpctx, ts->fee_asset),
		  feerate, tal_count(coins));
	return tx;
}

static u32 tcov_feerate(const struct tcov_spend *ts)
{
	return feerate_for_target(ts->channel->peer->ld->topology,
				  ts->deadline_block);
}

/* Each block: rebuild at the deadline's feerate, and replace the one out
 * there if the new one pays more. */
static bool tcov_rebroadcast(struct channel *channel,
			     const struct bitcoin_tx **tx,
			     struct tcov_spend *ts)
{
	struct amount_sat oldfee = ts->fee;
	u8 oldasset[33];
	struct bitcoin_tx *newtx;
	struct bitcoin_txid oldtxid, newtxid;

	if (ts->spent) {
		log_debug(channel->log, "tcov spend of %s: output spent, done",
			  fmt_bitcoin_outpoint(tmpctx, &ts->out));
		return false;
	}
	memcpy(oldasset, ts->fee_asset, sizeof(oldasset));
	newtx = tcov_build(tal_parent(*tx), ts, tcov_feerate(ts));
	if (!newtx)
		return true;
	/* A replacement must pay more than what it replaces. */
	if (memcmp(oldasset, ts->fee_asset, sizeof(oldasset)) == 0
	    && amount_sat_less_eq(ts->fee, oldfee)) {
		ts->fee = oldfee;
		tal_free(newtx);
		return true;
	}
	bitcoin_txid(*tx, &oldtxid);
	bitcoin_txid(newtx, &newtxid);
	log_(channel->log,
	     LOG_INFORM, NULL, false,
	     "RBF tcov spend %s (fee %s) with %s (fee %s of %s)",
	     fmt_bitcoin_txid(tmpctx, &oldtxid),
	     fmt_amount_sat(tmpctx, oldfee),
	     fmt_bitcoin_txid(tmpctx, &newtxid),
	     fmt_amount_sat(tmpctx, ts->fee),
	     fmt_asset_id(tmpctx, ts->fee_asset));
	tal_free(*tx);
	*tx = newtx;
	return true;
}

static void tcov_retry(struct tcov_spend *ts)
{
	/* broadcast_tx's macro names a type "struct channel": pass a plain
	 * variable of that name. */
	struct channel *channel = ts->channel;
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_tx *tx;

	if (ts->spent) {
		tal_free(ts);
		return;
	}
	tx = tcov_build(ts, ts, tcov_feerate(ts));
	if (!tx) {
		notleak(new_reltimer(ld->timers, ts, time_from_sec(10),
				     tcov_retry, ts));
		return;
	}
	log_debug(channel->log, "Broadcast for onchaind tx %s",
		  fmt_bitcoin_tx(tmpctx, tx));
	/* The outgoing tx owns the spend from here, and frees it. */
	broadcast_tx(channel, ld->topology, channel, take(tx), NULL,
		     false, ts->minblock, NULL, tcov_rebroadcast, take(ts));
}

static void handle_onchaind_spend_tcov(struct channel *channel,
				       const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct tcov_spend *ts = tal(channel, struct tcov_spend);
	u8 signer, deadline;
	u64 htlc_id;
	struct bitcoin_tx *tx;
	struct onchain_witness_element **welements;
	u8 **wit;

	ts->coins = NULL;
	ts->channel = channel;
	tcov_spend_track(ts);
	if (!fromwire_onchaind_spend_tcov(ts, msg, &ts->out, &ts->out_sats,
					  &ts->spent_spk, &signer,
					  &ts->commit_num, &ts->remote_point,
					  &ts->revocation_secret,
					  &ts->leaf, &ts->cb,
					  &ts->merkle_root, &ts->preimage,
					  &ts->cov_program,
					  &ts->locktime, &ts->sequence,
					  &ts->minblock, &deadline,
					  &htlc_id)) {
		channel_internal_error(channel, "Invalid onchaind_spend_tcov %s",
				       tal_hex(tmpctx, msg));
		tal_free(ts);
		return;
	}
	ts->signer = signer;
	if (tal_bytelen(ts->cov_program) == 0)
		ts->cov_program = tal_free(ts->cov_program);
	else if (tal_bytelen(ts->cov_program) != 32) {
		channel_internal_error(channel, "onchaind_spend_tcov: bad program");
		tal_free(ts);
		return;
	}

	switch ((enum tcov_spend_deadline)deadline) {
	case TCOV_DEADLINE_HTLC_IN:
		ts->deadline_block = htlc_incoming_deadline(channel, htlc_id);
		break;
	case TCOV_DEADLINE_HTLC_OUT:
		ts->deadline_block = htlc_outgoing_incoming_deadline(channel,
								     htlc_id);
		break;
	case TCOV_DEADLINE_NOW:
		ts->deadline_block = get_block_height(ld->topology) + 2;
		break;
	case TCOV_DEADLINE_SWEEP:
	default:
		ts->deadline_block = slow_sweep_deadline(ld->topology, channel,
							 max_unsigned(get_block_height(ld->topology),
								      ts->minblock));
		break;
	}

	tx = tcov_build(ts, ts, tcov_feerate(ts));

	/* Elements to recognise our spend by: the signature changes with
	 * every rebuild, the rest does not. */
	{
		struct bip340sig dummy;
		memset(&dummy, 0, sizeof(dummy));
		wit = tcov_witness(tmpctx, ts, &dummy);
	}
	welements = tal_arr(tmpctx, struct onchain_witness_element *,
			    tal_count(wit));
	for (size_t i = 0; i < tal_count(wit); i++) {
		welements[i] = tal(welements, struct onchain_witness_element);
		welements[i]->is_signature = (i == 0);
		welements[i]->witness = tal_dup_talarr(welements[i], u8, wit[i]);
	}

	/* onchaind recognises our spend by these whether or not it is
	 * built yet. */
	subd_send_msg(channel->owner,
		      take(towire_onchaind_spend_created(NULL, true,
				cast_const2(const struct onchain_witness_element **,
					    welements))));

	if (!tx) {
		/* Nothing to pay its fee with yet: try again later. */
		notleak(new_reltimer(ld->timers, ts, time_from_sec(10),
				     tcov_retry, ts));
		return;
	}

	log_debug(channel->log, "Broadcast for onchaind tx %s",
		  fmt_bitcoin_tx(tmpctx, tx));
	broadcast_tx(channel, ld->topology, channel, take(tx), NULL, false,
		     ts->minblock, NULL, tcov_rebroadcast, take(ts));
}

static unsigned int onchain_msg(struct subd *sd, const u8 *msg, const int *fds UNUSED)
{
	enum onchaind_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_ONCHAIND_INIT_REPLY:
		handle_onchain_init_reply(sd->channel, msg);
		break;

 	case WIRE_ONCHAIND_EXTRACTED_PREIMAGE:
		handle_extracted_preimage(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_MISSING_HTLC_OUTPUT:
		handle_missing_htlc_output(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_HTLC_TIMEOUT:
		handle_onchain_htlc_timeout(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_ALL_IRREVOCABLY_RESOLVED:
		handle_irrevocably_resolved(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_ADD_UTXO:
		onchain_add_utxo(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_ANNOTATE_TXIN:
		onchain_annotate_txin(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_ANNOTATE_TXOUT:
		onchain_annotate_txout(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_NOTIFY_COIN_MVT:
		handle_onchain_log_coin_move(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_NOTIFY_PENALTY_ADJ:
		handle_onchain_log_penalty_adj(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_TO_US:
		handle_onchaind_spend_to_us(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_PENALTY:
		handle_onchaind_spend_penalty(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_HTLC_SUCCESS:
		handle_onchaind_spend_htlc_success(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_HTLC_TIMEOUT:
		handle_onchaind_spend_htlc_timeout(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_FULFILL:
		handle_onchaind_spend_fulfill(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_HTLC_EXPIRED:
		handle_onchaind_spend_htlc_expired(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_TCOV:
		handle_onchaind_spend_tcov(sd->channel, msg);
		break;

	/* We send these, not receive them */
	case WIRE_ONCHAIND_INIT:
	case WIRE_ONCHAIND_SPENT:
	case WIRE_ONCHAIND_DEPTH:
	case WIRE_ONCHAIND_HTLCS:
	case WIRE_ONCHAIND_KNOWN_PREIMAGE:
	case WIRE_ONCHAIND_SPEND_CREATED:
	case WIRE_ONCHAIND_DEV_MEMLEAK:
	case WIRE_ONCHAIND_DEV_MEMLEAK_REPLY:
	case WIRE_ONCHAIND_SPENT_REPLY:
		break;
	}

	return 0;
}

/* Only error onchaind can get is if it dies. */
static void onchain_error(struct channel *channel,
			  struct peer_fd *pps UNUSED,
			  const char *desc,
			  const u8 *err_for_them UNUSED,
			  bool disconnect UNUSED,
			  bool warning UNUSED)
{
	channel_set_owner(channel, NULL);

	/* This happens on shutdown: fine */
	if (channel->peer->ld->state == LD_STATE_SHUTDOWN)
		return;

	/* FIXME: re-launch? */
	log_broken(channel->log, "%s", desc);
	channel_set_billboard(channel, true, desc);
}

/* With a reorg, this can get called multiple times; each time we'll kill
 * onchaind (like any other owner), and restart */
enum watch_result onchaind_funding_spent(struct channel *channel,
					 const struct bitcoin_tx *tx,
					 u32 blockheight)
{
	u8 *msg;
	struct bitcoin_txid our_last_txid;
	struct lightningd *ld = channel->peer->ld;
	int hsmfd;
	enum state_change reason;

	/* use REASON_ONCHAIN or closer's reason, if known */
	reason = REASON_ONCHAIN;
	if (channel->closer != NUM_SIDES)
		reason = REASON_UNKNOWN;  /* will use last cause as reason */

	channel_fail_saw_onchain(channel, reason,
				 tx,
				 "Funding transaction spent");

	/* If we haven't posted the open event yet, post an open */
	if (!channel->scid || !channel->remote_channel_ready) {
		u32 blkh;
		/* Blockheight will be zero if it's not in chain */
		blkh = wallet_transaction_height(channel->peer->ld->wallet,
						 &channel->funding.txid);
		channel_record_open(channel, blkh, true);
	}

	tal_free(channel->close_blockheight);
	channel->close_blockheight = tal_dup(channel, u32, &blockheight);

	/* We could come from almost any state. */
	/* NOTE(mschmoock) above comment is wrong, since we failed above! */
	channel_set_state(channel,
			  channel->state,
			  FUNDING_SPEND_SEEN,
			  reason,
			  tal_fmt(tmpctx, "Onchain funding spend"));

	hsmfd = hsm_get_client_fd(ld, &channel->peer->id,
				  channel->dbid,
				  HSM_PERM_SIGN_ONCHAIN_TX
				  | HSM_PERM_COMMITMENT_POINT);
	if (hsmfd < 0) {
		log_broken(channel->log, "Could not get hsm fd for onchaind: %s",
			   strerror(errno));
		return KEEP_WATCHING;
	}

	channel_set_owner(channel, new_channel_subd(channel, ld,
						    "lightning_onchaind",
						    channel,
						    &channel->peer->id,
						    channel->log, false,
						    onchaind_wire_name,
						    onchain_msg,
						    onchain_error,
						    channel_set_billboard,
						    take(&hsmfd),
						    NULL));

	if (!channel->owner) {
		log_broken(channel->log, "Could not subdaemon onchain: %s",
			   strerror(errno));
		return KEEP_WATCHING;
	}

	struct ext_key final_wallet_ext_key;
	if (bip32_key_from_parent(
		    ld->bip32_base,
		    channel->final_key_idx,
		    BIP32_FLAG_KEY_PUBLIC,
		    &final_wallet_ext_key) != WALLY_OK) {
		log_broken(channel->log, "Could not derive final_wallet_ext_key %"PRIu64,
			   channel->final_key_idx);
		return KEEP_WATCHING;
	}

	/* This could be a mutual close, but it doesn't matter.
	 * We don't need this for stub channels as well */
	if (!channel->scid || !is_stub_scid(*channel->scid))
		bitcoin_txid(channel->last_tx, &our_last_txid);
	else
	/* Dummy txid for stub channel to make valgrind happy. */
		bitcoin_txid_from_hex("80cea306607b708a03a1854520729d"
				"a884e4317b7b51f3d4a622f88176f5e034",
				64,
				&our_last_txid);

	log_debug(channel->log, "channel->static_remotekey_start[LOCAL] %"PRIu64,
		  channel->static_remotekey_start[LOCAL]);

	msg = towire_onchaind_init(channel,
				  &channel->their_shachain.chain,
				  chainparams,
				  channel->funding_sats,
				  channel->channel_asset,
				  channel->our_msat,
				  &channel->channel_info.old_remote_per_commit,
				  &channel->channel_info.remote_per_commit,
				   /* BOLT #2:
				    * `to_self_delay` is the number of blocks
				    * that the other node's to-self outputs
				    * must be delayed */
				   /* So, these are reversed: they specify ours,
				    * we specify theirs. */
				  channel->channel_info.their_config.to_self_delay,
				  channel->our_config.to_self_delay,
				  channel->our_config.dust_limit,
				  &our_last_txid,
				  channel->shutdown_scriptpubkey[LOCAL],
				  channel->shutdown_scriptpubkey[REMOTE],
				  channel->opener,
				  &channel->local_basepoints,
				  &channel->channel_info.theirbase,
				  tx_parts_from_wally_tx(tmpctx, tx->wtx, -1, -1),
				  tx->wtx->locktime,
				  blockheight,
				  /* FIXME: config for 'reasonable depth' */
				  3,
				  channel->last_htlc_sigs,
				  channel->min_possible_feerate,
				  channel->max_possible_feerate,
				  &channel->local_funding_pubkey,
				  &channel->channel_info.remote_fundingkey,
				  channel->static_remotekey_start[LOCAL],
				  channel->static_remotekey_start[REMOTE],
				   channel_has(channel, OPT_ANCHOR_OUTPUTS_DEPRECATED),
				   channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX),
				   channel_has(channel, OPT_SEQ_TAPROOT_COVENANT),
				  feerate_min(ld, NULL));
	subd_send_msg(channel->owner, take(msg));

	/* If we're replaying, we just watch this */
	if (channel->onchaind_replay_watches) {
		replay_watch_tx(channel, blockheight, tx);
	} else {
		watch_tx_and_outputs(channel, tx);
	}

	/* We keep watching until peer finally deleted, for reorgs. */
	return KEEP_WATCHING;
}

void onchaind_replay_channels(struct lightningd *ld)
{
	struct peer *peer;
	struct peer_node_id_map_iter it;

	/* We don't hold a db tx for all of init */
	db_begin_transaction(ld->wallet->db);

	/* For each channel, if we've recorded a spend, it's onchaind time! */
	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		struct channel *channel;

		list_for_each(&peer->channels, channel, list) {
			struct bitcoin_tx *tx;
			u32 blockheight;

			if (channel_state_uncommitted(channel->state))
				continue;

			tx = wallet_get_funding_spend(tmpctx, ld->wallet, channel->dbid,
						      &blockheight);
			if (!tx)
				continue;

			log_info(channel->log,
				 "Restarting onchaind (%s): closed in block %u",
				 channel_state_name(channel), blockheight);

			/* We're in replay mode */
			channel->onchaind_replay_watches = new_htable(channel, replay_tx_hash);
			channel->onchaind_replay_height = blockheight;

			onchaind_funding_spent(channel, tx, blockheight);
			onchaind_replay(channel);
		}
	}
	db_commit_transaction(ld->wallet->db);
}
