#include "config.h"
#include <bitcoin/script.h>
#include <ccan/mem/mem.h>
#include <common/channel_type.h>
#include <common/memleak.h>
#include <common/sym_factory.h>
#include <common/sym_scripts.h>
#include <common/sym_state.h>
#include <inttypes.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/onchain_control.h>
#include <lightningd/peer_control.h>
#include <lightningd/sym_factory.h>
#include <lightningd/symmetric.h>
#include <lightningd/watch.h>
#include <wallet/wallet.h>

bool channel_is_sym_factory(const struct channel *channel)
{
	return channel->sym_factory
		&& channel_type_has(channel->type, OPT_SEQ_SYMMETRIC_FACTORY);
}

const struct bitcoin_outpoint *sym_factory_anchor(const struct channel *channel)
{
	if (channel->sym_factory_ko)
		return channel->sym_factory_ko;
	return &channel->sym_factory->out;
}

void sym_factory_attach(struct channel *channel, struct sym_factory *f TAKES)
{
	tal_free(channel->sym_factory);
	if (taken(f))
		channel->sym_factory = tal_steal(channel, f);
	else {
		u8 *b = tal_arr(tmpctx, u8, 0);
		const u8 *cursor;
		size_t max;

		towire_sym_factory(&b, f);
		cursor = b;
		max = tal_bytelen(b);
		channel->sym_factory = fromwire_sym_factory(channel, &cursor,
							    &max);
	}
	wallet_sym_factory_save(channel->peer->ld->wallet, channel);
}

/*~ One watch on F per node, held by one of the node's channels in that
 * factory: a txo watch fires its callbacks while it walks the watches of
 * that output, and a callback that adds a watch (as ours must, on the KOs)
 * can grow the table under that walk and lose the rest of them.  The
 * holder's callback moves every channel of the factory on, and when the
 * holder goes away another channel takes the watch up.
 *
 * The watch stays while any channel of the factory does: a reorganization
 * that takes the split out of the chain can put another split there (a
 * split's txid depends on its fee coin), and every channel then moves to
 * the KO of that one.  Bitcoin anchoring reorganizes this chain whenever
 * Bitcoin does, so this is not a corner case. */
struct factory_watch {
	struct lightningd *ld;
	struct bitcoin_outpoint out;
	struct channel *holder;
	struct txowatch *w;
};

static struct factory_watch **factory_watches;

static struct factory_watch *find_factory_watch(const struct bitcoin_outpoint *out)
{
	for (size_t i = 0; i < tal_count(factory_watches); i++)
		if (bitcoin_outpoint_eq(&factory_watches[i]->out, out))
			return factory_watches[i];
	return NULL;
}

static void forget_factory_watch(struct factory_watch *fw)
{
	for (size_t i = 0; i < tal_count(factory_watches); i++) {
		if (factory_watches[i] == fw) {
			tal_arr_remove(&factory_watches, i);
			break;
		}
	}
	tal_free(fw);
}

/* The node's channels in the factory at @out. */
static struct channel **factory_channels(const tal_t *ctx,
					 struct lightningd *ld,
					 const struct bitcoin_outpoint *out)
{
	struct channel **chans = tal_arr(ctx, struct channel *, 0);
	struct peer_node_id_map_iter it;
	struct peer *peer;
	struct channel *c;

	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		list_for_each(&peer->channels, c, list) {
			if (!channel_is_sym_factory(c))
				continue;
			if (!bitcoin_outpoint_eq(&c->sym_factory->out, out))
				continue;
			tal_arr_expand(&chans, c);
		}
	}
	return chans;
}

static enum watch_result factory_spent(struct channel *holder,
				       const struct bitcoin_tx *tx,
				       size_t input_num,
				       const struct block *block);
static enum watch_result ko_spent(struct channel *channel,
				  const struct bitcoin_tx *tx,
				  size_t input_num,
				  const struct block *block);

static void hold_factory_watch(struct factory_watch *fw, struct channel *holder);

/* The holder is going away: another channel of the factory takes the watch
 * up, if one is left. */
static void destroy_holder(struct channel *holder, struct factory_watch *fw)
{
	struct channel **chans = factory_channels(tmpctx, fw->ld, &fw->out);

	fw->w = NULL;
	fw->holder = NULL;
	for (size_t i = 0; i < tal_count(chans); i++) {
		if (chans[i] == holder)
			continue;
		hold_factory_watch(fw, chans[i]);
		return;
	}
	forget_factory_watch(fw);
}

static void hold_factory_watch(struct factory_watch *fw, struct channel *holder)
{
	fw->holder = holder;
	fw->w = watch_txo(holder, fw->ld->topology, holder, &fw->out,
			  factory_spent);
	tal_add_destructor2(holder, destroy_holder, fw);
}

/* Slot @slot's KO on @tx, which spent F: SPLIT pays it at output @slot, in
 * the factory's asset, for its amount.  False if it does not. */
static bool ko_of(const struct channel *channel, const struct bitcoin_tx *tx,
		  struct bitcoin_outpoint *ko)
{
	const struct sym_factory *f = channel->sym_factory;
	u8 *spk = sym_factory_ko_spk(tmpctx, f, f->slot);
	struct amount_asset amt;
	const struct wally_tx_output *o;

	if (f->slot >= tx->wtx->num_outputs)
		return false;
	o = &tx->wtx->outputs[f->slot];
	if (!memeq(o->script, o->script_len, spk, tal_bytelen(spk)))
		return false;
	amt = bitcoin_tx_output_get_amount(tx, f->slot);
	if (!amount_asset_is(&amt, f->asset)
	    || amt.value != f->slots[f->slot].amount.satoshis) /* Raw: check */
		return false;
	bitcoin_txid(tx, &ko->txid);
	ko->n = f->slot;
	return true;
}

/* Our best state, over the KO, with a fee coin: what a unilateral close
 * of a split factory channel publishes, and what onchaind replaces if it
 * finds an older state there. */
static bool publish_update(struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;
	const struct sym_state *best = channel->sym_dev_stale
		? channel->sym_dev_stale : sym_best_state(channel);
	const struct bip340sig *sig_op, *sig_acc;
	struct sym_channel sc;
	struct sym_tree ko, tree;
	struct sym_state_out *outs;
	u8 **witness;

	if (!best || !sym_state_signed(best, channel->opener, &sig_op,
				       &sig_acc)) {
		log_broken(channel->log, "Factory channel without a state"
			   " both sides signed: cannot close it unilaterally");
		return false;
	}
	if (channel->sym_dev_stale)
		log_unusual(channel->log, "dev-sym-snapshot: publishing state"
			    " %"PRId64" as if it were our latest", best->num);
	sym_channel_from(channel, &sc);
	sym_kickoff_tree(tmpctx, &sc, &ko);
	sym_state_tree_of(tmpctx, &sc, best, &tree);
	witness = sym_update_witness(NULL, sig_op, sig_acc, &tree, ko.upd,
				     sym_tree_control_block(tmpctx, &ko,
							    SYM_LEAF_UPD));
	outs = tal_arr(tmpctx, struct sym_state_out, 1);
	outs[0].amount = channel->funding_sats;
	outs[0].spk = sym_tree_spk(outs, &tree);
	log_info(channel->log, "Publishing state %"PRId64" over this factory"
		 " channel's KO %s, a fee coin attached", best->num,
		 fmt_bitcoin_outpoint(tmpctx, channel->sym_factory_ko));
	sym_spend_start(channel, channel->sym_factory_ko, channel->funding_sats,
			sym_tree_spk(tmpctx, &ko), take(witness), outs,
			SYM_SEQUENCE, 0, get_block_height(ld->topology) + 6);
	return true;
}

static void watch_ko(struct lightningd *ld, struct channel *channel)
{
	channel->funding_spend_watch = watch_txo(channel, ld->topology, channel,
						 channel->sym_factory_ko,
						 ko_spent);
}

/* F is spent: by the split, the only way it can be.  Every channel of
 * ours in the factory takes its KO as its output and goes on, and one
 * that is closing publishes its best state over it.  Seen again (a replay,
 * a restart), it changes nothing; a different split, after a
 * reorganization, moves every channel to its KO in that one. */
static enum watch_result factory_spent(struct channel *holder,
				       const struct bitcoin_tx *tx,
				       size_t input_num UNUSED,
				       const struct block *block)
{
	struct lightningd *ld = holder->peer->ld;
	struct bitcoin_outpoint out = holder->sym_factory->out;
	struct channel **chans = factory_channels(tmpctx, ld, &out);

	for (size_t i = 0; i < tal_count(chans); i++) {
		struct channel *c = chans[i];
		struct bitcoin_outpoint ko;

		/* Its split spend, if it made one, stops. */
		sym_note_spent(c, &out);
		if (!ko_of(c, tx, &ko)) {
			struct bitcoin_txid txid;

			bitcoin_txid(tx, &txid);
			log_broken(c->log, "Factory output %s spent by %s, which"
				   " does not pay this channel's KO at output %u",
				   fmt_bitcoin_outpoint(tmpctx, &out),
				   fmt_bitcoin_txid(tmpctx, &txid),
				   c->sym_factory->slot);
			continue;
		}
		if (c->sym_factory_ko) {
			if (bitcoin_outpoint_eq(c->sym_factory_ko, &ko))
				continue;
			/* Another split took the first one's place: the
			 * spend over the old KO, if any, stops too. */
			log_unusual(c->log, "Factory %s split again by %s: the"
				    " split that paid %s left the chain",
				    fmt_bitcoin_outpoint(tmpctx, &out),
				    fmt_bitcoin_txid(tmpctx, &ko.txid),
				    fmt_bitcoin_outpoint(tmpctx,
							 c->sym_factory_ko));
			sym_note_spent(c, c->sym_factory_ko);
			c->funding_spend_watch = tal_free(c->funding_spend_watch);
			c->sym_factory_ko = tal_free(c->sym_factory_ko);
		}
		c->sym_factory_ko = tal_dup(c, struct bitcoin_outpoint, &ko);
		wallet_sym_factory_save(ld->wallet, c);
		log_info(c->log, "Factory %s split at block %u: this channel's"
			 " output is now %s", fmt_bitcoin_outpoint(tmpctx, &out),
			 block->height, fmt_bitcoin_outpoint(tmpctx, &ko));
		watch_ko(ld, c);
		if (c->state == AWAITING_UNILATERAL)
			publish_update(c);
	}
	return KEEP_WATCHING;
}

/* The channel's KO is spent, by an update (UPD(-1) is its only leaf): the
 * channel is closing, and onchaind takes it from that update. */
static enum watch_result ko_spent(struct channel *channel,
				  const struct bitcoin_tx *tx,
				  size_t input_num UNUSED,
				  const struct block *block)
{
	struct bitcoin_txid txid;

	bitcoin_txid(tx, &txid);
	sym_note_spent(channel, channel->sym_factory_ko);
	wallet_insert_funding_spend(channel->peer->ld->wallet, channel, &txid,
				    0, block->height);
	return onchaind_funding_spent(channel, tx, block->height);
}

/* F seen in a block: the channel's short id names F's block and
 * transaction, and 0x8000 + slot where an output number goes, which no real
 * output can have, so a hub's channels in one factory never share one. */
static void factory_found(struct lightningd *ld,
			  const struct bitcoin_tx *tx,
			  u32 outnum,
			  const struct txlocator *loc,
			  struct channel *channel)
{
	struct amount_asset amt = bitcoin_tx_output_get_amount(tx, outnum);
	struct bitcoin_outpoint scid_out;

	if (!amount_asset_is(&amt, channel->sym_factory->asset)) {
		channel_fail_permanent(channel, REASON_LOCAL,
				       "Factory output %s is not in the"
				       " channel's asset",
				       fmt_bitcoin_outpoint(tmpctx,
							    &channel->sym_factory->out));
		return;
	}
	scid_out.txid = channel->sym_factory->out.txid;
	scid_out.n = 0x8000 + channel->sym_factory->slot;
	if (depthcb_update_scid(channel, &scid_out, loc))
		channel_watch_depth(ld, loc->blkheight, channel);
}

bool sym_factory_watching(const struct channel *channel)
{
	if (channel->sym_factory_ko && !channel->funding_spend_watch)
		return false;
	return find_factory_watch(&channel->sym_factory->out) != NULL;
}

void sym_factory_watch(struct lightningd *ld, struct channel *channel)
{
	const struct sym_factory *f = channel->sym_factory;
	struct amount_sat total;
	struct factory_watch *fw;

	if (channel->sym_factory_ko && !channel->funding_spend_watch)
		watch_ko(ld, channel);

	if (!sym_factory_value(f->slots, &total))
		abort();
	watch_scriptpubkey(channel, ld->topology,
			   take(sym_factory_spk(NULL, f->asset, f->slots)),
			   &f->out, total, factory_found, channel);

	fw = find_factory_watch(&f->out);
	if (!fw) {
		fw = tal(NULL, struct factory_watch);
		fw->ld = ld;
		fw->out = f->out;
		if (!factory_watches)
			factory_watches = notleak(tal_arr(NULL,
							  struct factory_watch *,
							  0));
		tal_arr_expand(&factory_watches, notleak(fw));
		hold_factory_watch(fw, channel);
	}
	/* The channel's funding_spend_watch is its KO's: the watch on F is
	 * the factory's, not this channel's. */
}

bool sym_factory_close(struct lightningd *ld, struct channel *channel)
{
	const struct sym_factory *f = channel->sym_factory;
	struct sym_state_out *outs;
	struct amount_sat total;

	if (channel->sym_factory_ko)
		return publish_update(channel);

	/* The split first: no signature, every slot's KO, a fee coin. */
	if (!sym_factory_value(f->slots, &total))
		abort();
	outs = tal_arr(tmpctx, struct sym_state_out, tal_count(f->slots));
	for (size_t i = 0; i < tal_count(f->slots); i++) {
		outs[i].amount = f->slots[i].amount;
		outs[i].spk = sym_factory_ko_spk(outs, f, i);
	}
	log_info(channel->log, "Splitting factory %s to close slot %u, a fee"
		 " coin attached", fmt_bitcoin_outpoint(tmpctx, &f->out),
		 f->slot);
	sym_spend_start(channel, &f->out, total,
			sym_factory_spk(tmpctx, f->asset, f->slots),
			take(sym_split_witness(NULL, f->asset, f->slots)), outs,
			SYM_SEQUENCE, 0, get_block_height(ld->topology) + 6);
	return true;
}
