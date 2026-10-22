#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/bip32.h>
#include <common/memleak.h>
#include <common/sym_scripts.h>
#include <common/sym_state.h>
#include <common/timeout.h>
#include <hsmd/hsm_utxo.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/symmetric.h>
#include <lightningd/watchtower_store.h>
#include <wallet/wallet.h>
#include <wally_psbt.h>

/* Blocks for the kickoff, the update, the settlement and a claim to
 * confirm, beside the delays (sym_htlc_margin). */
#define SYM_SLACK 12

u16 sym_channel_delay(const struct channel *channel)
{
	u16 ours = channel->our_config.to_self_delay;
	u16 theirs = channel->channel_info.their_config.to_self_delay;
	return ours > theirs ? ours : theirs;
}

void sym_channel_from(const struct channel *channel, struct sym_channel *sc)
{
	const struct pubkey *ours = &channel->local_basepoints.delayed_payment;
	const struct pubkey *theirs = &channel->channel_info.theirbase.delayed_payment;

	sym_channel_init(sc, &chainparams->genesis_blockhash, &channel->funding,
			 channel->opener == LOCAL ? ours : theirs,
			 channel->opener == LOCAL ? theirs : ours,
			 channel->channel_asset, sym_channel_delay(channel));
}

u32 sym_htlc_margin(const struct channel *channel)
{
	return 2 * (u32)sym_channel_delay(channel) + SYM_SLACK;
}

/* The database, and the watchtower store when the node keeps one: both
 * before channeld goes on, so a keyless watcher always holds the best state
 * this node holds. */
static void sym_save(struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;

	wallet_sym_save(ld->wallet, channel);
	if (wt_store_enabled(ld) && !wt_store_put_sym(ld, channel))
		log_broken(channel->log, "watchtower: failed storing the"
			   " symmetric channel's record");
}

void sym_record_opened(struct channel *channel,
		       const struct bitcoin_signature *kickoff_sig,
		       struct sym_state *local,
		       struct sym_state *remote_pending)
{
	tal_free(channel->sym_kickoff_sig);
	channel->sym_kickoff_sig = tal_dup(channel, struct bitcoin_signature,
					   kickoff_sig);
	tal_free(channel->sym_local);
	channel->sym_local = tal_steal(channel, local);
	tal_free(channel->sym_remote_pending);
	channel->sym_remote_pending = tal_steal(channel, remote_pending);
	sym_save(channel);
}

void sym_record_sent(struct channel *channel,
		     struct sym_state *remote_pending)
{
	tal_free(channel->sym_remote_pending);
	channel->sym_remote_pending = tal_steal(channel, remote_pending);
	sym_save(channel);
}

void sym_record_local(struct channel *channel, struct sym_state *local)
{
	tal_free(channel->sym_local);
	channel->sym_local = tal_steal(channel, local);
	sym_save(channel);
}

void sym_record_revoked(struct channel *channel, struct sym_state *remote)
{
	tal_free(channel->sym_remote);
	channel->sym_remote = tal_steal(channel, remote);
	/* The pending one is now this one, whole. */
	if (channel->sym_remote_pending
	    && channel->sym_remote_pending->num == channel->sym_remote->num)
		channel->sym_remote_pending = tal_free(channel->sym_remote_pending);
	sym_save(channel);
}

const struct sym_state *sym_best_state(const struct channel *channel)
{
	const struct sym_state *best = NULL;
	const struct sym_state *cands[] = { channel->sym_local,
					    channel->sym_remote };

	for (size_t i = 0; i < ARRAY_SIZE(cands); i++) {
		const struct sym_state *st = cands[i];
		if (!st || !st->has_sig[LOCAL] || !st->has_sig[REMOTE])
			continue;
		if (!best || st->num > best->num)
			best = st;
	}
	return best;
}

bool sym_is_kickoff(const struct channel *channel, const struct bitcoin_tx *tx)
{
	struct sym_channel sc;
	struct sym_tree ko;
	u8 *spk;

	if (tx->wtx->num_outputs < 1)
		return false;
	sym_channel_from(channel, &sc);
	sym_kickoff_tree(tmpctx, &sc, &ko);
	spk = sym_tree_spk(tmpctx, &ko);
	return memeq(tx->wtx->outputs[0].script, tx->wtx->outputs[0].script_len,
		     spk, tal_bytelen(spk));
}

/*~ A spend whose input 0 needs nothing from hsmd: the kickoff (both funding
 * signatures, from the open), an update (both update signatures), a settle
 * (no signature at all).  Only the fee coins are signed, by hsmd, as an
 * HTLC transaction's are. */
struct sym_spend {
	struct channel *channel;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	u8 *spent_spk;
	u8 **witness;
	struct sym_state_out *outs;
	u32 sequence, minblock, deadline_block;
	/* What the last broadcast paid, in its fee asset, and the wallet
	 * coins it spent (which it reserved, and may spend again). */
	struct amount_sat fee;
	u8 fee_asset[33];
	struct bitcoin_outpoint *coins;
	/* The output is spent on chain, by this spend or another. */
	bool spent;
};

static struct sym_spend **sym_spends;

static void destroy_sym_spend(struct sym_spend *ss)
{
	for (size_t i = 0; i < tal_count(sym_spends); i++) {
		if (sym_spends[i] == ss) {
			tal_arr_remove(&sym_spends, i);
			return;
		}
	}
}

/* The output @ss spends is spent: if not by @ss, its fee coins are free
 * again (a spend that lost a race must not keep them from the next). */
static void sym_unreserve(const struct sym_spend *ss,
			  const struct bitcoin_outpoint *op)
{
	struct lightningd *ld = ss->channel->peer->ld;
	struct utxo *u = wallet_utxo_get(tmpctx, ld->wallet, op);

	if (u && u->status == OUTPUT_STATE_RESERVED)
		wallet_unreserve_utxo(ld->wallet, u,
				      get_block_height(ld->topology),
				      u->reserved_til);
}

static void sym_release_coins(struct sym_spend *ss)
{
	for (size_t i = 0; i < tal_count(ss->coins); i++)
		sym_unreserve(ss, &ss->coins[i]);
	ss->coins = tal_free(ss->coins);
}

static bool sym_seen_spent(const struct channel *channel,
			   const struct bitcoin_outpoint *out)
{
	for (size_t i = 0; i < tal_count(channel->sym_spent_seen); i++)
		if (bitcoin_outpoint_eq(&channel->sym_spent_seen[i], out))
			return true;
	return false;
}

void sym_note_spent(struct channel *channel,
		    const struct bitcoin_outpoint *out)
{
	bool ours = false;

	for (size_t i = 0; i < tal_count(sym_spends); i++) {
		if (sym_spends[i]->channel == channel
		    && bitcoin_outpoint_eq(&sym_spends[i]->out, out)) {
			ours = true;
			if (!sym_spends[i]->spent) {
				sym_spends[i]->spent = true;
				sym_release_coins(sym_spends[i]);
			}
		}
	}
	/* No spend of ours under way: onchaind, which hears of this spend
	 * after us, may yet propose one (over KO, say, when the peer's update
	 * spent it first), and it must not hold a fee coin forever. */
	if (!ours && channel_type_has(channel->type, OPT_SEQ_SYMMETRIC)
	    && !sym_seen_spent(channel, out)) {
		if (!channel->sym_spent_seen)
			channel->sym_spent_seen
				= tal_arr(channel, struct bitcoin_outpoint, 0);
		tal_arr_expand(&channel->sym_spent_seen, *out);
	}
}

static u8 *sym_wallet_spk(const tal_t *ctx, struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;
	struct pubkey key;

	if (ld->bip86_base)
		bip86_pubkey(ld, &key, channel->final_key_idx);
	else
		bip32_pubkey(ld, &key, channel->final_key_idx);
	return scriptpubkey_p2wpkh(ctx, &key);
}

static bool sym_own_coin(const struct sym_spend *ss,
			 const struct bitcoin_outpoint *op)
{
	for (size_t i = 0; i < tal_count(ss->coins); i++)
		if (bitcoin_outpoint_eq(&ss->coins[i], op))
			return true;
	return false;
}

/* Spendable wallet coins of @asset: unreserved, or reserved by this very
 * spend's last broadcast. */
static struct utxo **sym_coins(const tal_t *ctx, const struct sym_spend *ss,
			       const u8 *asset, struct amount_sat *total)
{
	struct lightningd *ld = ss->channel->peer->ld;
	struct utxo **all = wallet_get_unspent_utxos(tmpctx, ld->wallet);
	struct utxo **coins = tal_arr(ctx, struct utxo *, 0);
	u32 height = get_block_height(ld->topology);

	*total = AMOUNT_SAT(0);
	for (size_t i = 0; i < tal_count(all); i++) {
		if (memcmp(all[i]->asset, asset, sizeof(all[i]->asset)) != 0)
			continue;
		if ((utxo_is_reserved(all[i], height)
		     && !sym_own_coin(ss, &all[i]->outpoint))
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

static size_t sym_witness_weight(u8 **witness)
{
	size_t w = varint_size(tal_count(witness));
	for (size_t i = 0; i < tal_count(witness); i++)
		w += varint_size(tal_bytelen(witness[i]))
			+ tal_bytelen(witness[i]);
	return w;
}

static struct wally_psbt *sym_psbt_base(const tal_t *ctx,
					const struct sym_spend *ss)
{
	const u8 *asset = ss->channel->channel_asset;
	struct wally_psbt *psbt = create_psbt(ctx, 0, 0, 0);

	psbt_append_input(psbt, &ss->out, ss->sequence, NULL, NULL, NULL);
	psbt_input_set_wit_utxo_asset(psbt, 0, ss->spent_spk, ss->out_sats,
				      asset);
	for (size_t i = 0; i < tal_count(ss->outs); i++)
		psbt_append_output_asset(psbt, ss->outs[i].spk,
					 ss->outs[i].amount, asset);
	return psbt;
}

static size_t sym_weight(const struct sym_spend *ss, struct utxo **coins,
			 const u8 *change_spk)
{
	struct wally_psbt *psbt = sym_psbt_base(tmpctx, ss);
	struct bitcoin_tx *tx;
	size_t weight;
	u8 dummy[33];

	memset(dummy, 1, sizeof(dummy));
	for (size_t i = 0; i < tal_count(coins); i++)
		psbt_append_input(psbt, &coins[i]->outpoint, 0, NULL, NULL, NULL);
	psbt_append_output_asset(psbt, change_spk, ss->out_sats, dummy);
	psbt_append_output_asset(psbt, NULL, ss->out_sats, dummy);
	tx = bitcoin_tx_with_psbt(tmpctx, psbt);
	weight = bitcoin_tx_weight(tx) + sym_witness_weight(ss->witness);
	for (size_t i = 0; i < tal_count(coins); i++)
		weight += 1 + bitcoin_tx_input_witness_weight(coins[i]->utxotype);
	return weight;
}

static int cmp_coin_desc(struct utxo *const *a, struct utxo *const *b,
			 void *unused)
{
	if (amount_sat_greater((*a)->amount, (*b)->amount))
		return -1;
	if (amount_sat_less((*a)->amount, (*b)->amount))
		return 1;
	return 0;
}

/* Build and sign at @feerate (reference atoms per kw); NULL if no coin in an
 * asset this node accepts for fees covers it now.  The fee coin is in the
 * channel's asset if the node accepts it for fees and holds enough of it,
 * else in the accepted asset whose coins are worth the most to it. */
static struct bitcoin_tx *sym_build(const tal_t *ctx, struct sym_spend *ss,
				    u32 feerate)
{
	struct channel *channel = ss->channel;
	struct lightningd *ld = channel->peer->ld;
	const u8 *chan_asset = channel->channel_asset;
	u8 *change_spk = sym_wallet_spk(tmpctx, channel);
	struct utxo **coins = NULL;
	const u8 *fee_asset = NULL;
	struct amount_sat fee, change, sum = AMOUNT_SAT(0);
	struct wally_psbt *psbt;
	struct bitcoin_tx *tx;
	const u8 *msg;

	for (size_t i = 0; i < tal_count(ld->topology->asset_fee_rates) + 1; i++) {
		const u8 *asset;
		u64 rate;
		struct amount_sat total, need;
		struct utxo **c;

		if (i == 0) {
			asset = chan_asset;
			rate = topo_asset_fee_rate(ld->topology, chan_asset);
		} else {
			asset = ld->topology->asset_fee_rates[i-1].asset;
			rate = ld->topology->asset_fee_rates[i-1].scaled_value;
		}
		if (!rate)
			continue;
		c = sym_coins(tmpctx, ss, asset, &total);
		if (tal_count(c) == 0)
			continue;
		need = amount_tx_fee(feerate_in_asset(feerate, rate),
				     sym_weight(ss, c, change_spk));
		if (amount_sat_less(total, need))
			continue;
		if (i == 0) {
			coins = c;
			fee_asset = asset;
			break;
		}
		double worth = (double)total.satoshis * rate; /* Raw: ranking */
		double best = (double)sum.satoshis /* Raw: ranking */
			* topo_asset_fee_rate(ld->topology,
					      fee_asset ? fee_asset : asset);
		if (!fee_asset || worth > best) {
			coins = c;
			fee_asset = asset;
			sum = total;
		}
	}
	if (!fee_asset) {
		log_unusual(channel->log, "symmetric spend of %s: no coin in an"
			    " asset this node accepts for fees covers it;"
			    " trying again",
			    fmt_bitcoin_outpoint(tmpctx, &ss->out));
		return NULL;
	}

	/* Fewest coins: largest first, until the fee is covered. */
	asort(coins, tal_count(coins), cmp_coin_desc, NULL);
	{
		u64 rate = topo_asset_fee_rate(ld->topology, fee_asset);
		struct utxo **use = tal_arr(tmpctx, struct utxo *, 0);

		sum = AMOUNT_SAT(0);
		for (size_t i = 0; i < tal_count(coins); i++) {
			tal_arr_expand(&use, coins[i]);
			if (!amount_sat_add(&sum, sum, coins[i]->amount))
				return NULL;
			fee = amount_tx_fee(feerate_in_asset(feerate, rate),
					    sym_weight(ss, use, change_spk));
			if (amount_sat_greater_eq(sum, fee))
				break;
		}
		coins = use;
		if (!amount_sat_sub(&change, sum, fee))
			return NULL;
		if (amount_sat_less(change, chainparams->dust_limit)) {
			fee = sum;
			change = AMOUNT_SAT(0);
		}
	}

	psbt = sym_psbt_base(tmpctx, ss);
	psbt = psbt_using_utxos(tmpctx, ld->wallet, coins, 0,
				BITCOIN_TX_RBF_SEQUENCE, psbt);
	if (amount_sat_greater(change, AMOUNT_SAT(0)))
		psbt_append_output_asset(psbt, change_spk, change, fee_asset);
	psbt_append_output_asset(psbt, NULL, fee, fee_asset);
	memcpy(ss->fee_asset, fee_asset, sizeof(ss->fee_asset));

	tal_wally_start();
	{
		struct wally_tx_witness_stack *stack;

		wally_tx_witness_stack_init_alloc(tal_count(ss->witness), &stack);
		for (size_t i = 0; i < tal_count(ss->witness); i++)
			wally_tx_witness_stack_add(stack, ss->witness[i],
						   tal_bytelen(ss->witness[i]));
		wally_psbt_input_set_final_witness(&psbt->inputs[0], stack);
		wally_tx_witness_stack_free(stack);
	}
	tal_wally_end(psbt);

	msg = towire_hsmd_sign_htlc_tx_mingle(NULL, &channel->peer->id,
					      channel->dbid,
					      utxos_to_hsm_utxos(tmpctx, coins),
					      psbt);
	msg = hsm_sync_req(tmpctx, ld, take(msg));
	if (!fromwire_hsmd_sign_htlc_tx_mingle_reply(tmpctx, msg, &psbt))
		fatal("Reading sign_htlc_tx_mingle_reply: %s",
		      tal_hex(tmpctx, msg));
	for (size_t i = 0; i < tal_count(coins); i++)
		wallet_reserve_utxo(ld->wallet, coins[i],
				    get_block_height(ld->topology),
				    (ss->minblock > get_block_height(ld->topology)
				     ? ss->minblock - get_block_height(ld->topology)
				     : 0) + 12);
	if (!psbt_finalize(psbt)) {
		log_broken(channel->log, "symmetric spend: cannot finalize %s",
			   fmt_wally_psbt(tmpctx, psbt));
		return NULL;
	}
	tx = tal(ctx, struct bitcoin_tx);
	tx->chainparams = chainparams;
	tx->wtx = psbt_final_tx(tx, psbt);
	if (!tx->wtx)
		return tal_free(tx);
	tx->psbt = tal_steal(tx, psbt);
	ss->fee = fee;
	tal_free(ss->coins);
	ss->coins = tal_arr(ss, struct bitcoin_outpoint, tal_count(coins));
	for (size_t i = 0; i < tal_count(coins); i++)
		ss->coins[i] = coins[i]->outpoint;
	log_debug(channel->log, "symmetric spend of %s: fee %s of asset %s at"
		  " %u/kw, %zu fee coin(s)",
		  fmt_bitcoin_outpoint(tmpctx, &ss->out),
		  fmt_amount_sat(tmpctx, fee), fmt_asset_id(tmpctx, ss->fee_asset),
		  feerate, tal_count(coins));
	return tx;
}

static u32 sym_feerate(const struct sym_spend *ss)
{
	return feerate_for_target(ss->channel->peer->ld->topology,
				  ss->deadline_block);
}

/* Each block: rebuild at the deadline's feerate, and replace the one out
 * there if the new one pays more. */
static bool sym_rebroadcast(struct channel *channel,
			    const struct bitcoin_tx **tx,
			    struct sym_spend *ss)
{
	struct amount_sat oldfee = ss->fee;
	u8 oldasset[33];
	struct bitcoin_outpoint *oldcoins;
	struct bitcoin_tx *newtx;

	if (ss->spent)
		return false;
	memcpy(oldasset, ss->fee_asset, sizeof(oldasset));
	oldcoins = tal_steal(tmpctx, ss->coins);
	ss->coins = tal_dup_talarr(ss, struct bitcoin_outpoint, oldcoins);
	newtx = sym_build(tal_parent(*tx), ss, sym_feerate(ss));
	if (!newtx)
		return true;
	if (memcmp(oldasset, ss->fee_asset, sizeof(oldasset)) == 0
	    && amount_sat_less_eq(ss->fee, oldfee)) {
		/* The one out there stays: so do its coins, and those the
		 * rebuild reserved besides are free again. */
		struct bitcoin_outpoint *newcoins = ss->coins;

		ss->coins = tal_steal(ss, oldcoins);
		for (size_t i = 0; i < tal_count(newcoins); i++)
			if (!sym_own_coin(ss, &newcoins[i]))
				sym_unreserve(ss, &newcoins[i]);
		tal_free(newcoins);
		ss->fee = oldfee;
		memcpy(ss->fee_asset, oldasset, sizeof(oldasset));
		tal_free(newtx);
		return true;
	}
	tal_free(*tx);
	*tx = newtx;
	return true;
}

static void sym_retry(struct sym_spend *ss)
{
	struct channel *channel = ss->channel;
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_tx *tx;

	if (ss->spent) {
		tal_free(ss);
		return;
	}
	tx = sym_build(ss, ss, sym_feerate(ss));
	if (!tx) {
		notleak(new_reltimer(ld->timers, ss, time_from_sec(10),
				     sym_retry, ss));
		return;
	}
	broadcast_tx(channel, ld->topology, channel, take(tx), NULL,
		     false, ss->minblock, NULL, sym_rebroadcast, take(ss));
}

void sym_spend_start(struct channel *channel,
		     const struct bitcoin_outpoint *out,
		     struct amount_sat amount, const u8 *spent_spk,
		     u8 **witness TAKES,
		     const struct sym_state_out *outs,
		     u32 sequence, u32 minblock, u32 deadline)
{
	struct sym_spend *ss;

	/* Already spent on chain: onchaind proposed it before it heard. */
	if (sym_seen_spent(channel, out)) {
		log_debug(channel->log, "symmetric spend of %s: already spent"
			  " on chain, not attempted",
			  fmt_bitcoin_outpoint(tmpctx, out));
		if (taken(witness))
			tal_free(witness);
		return;
	}
	ss = tal(channel, struct sym_spend);
	ss->channel = channel;
	ss->out = *out;
	ss->out_sats = amount;
	ss->spent_spk = tal_dup_talarr(ss, u8, spent_spk);
	if (taken(witness))
		ss->witness = tal_steal(ss, witness);
	else {
		ss->witness = tal_arr(ss, u8 *, tal_count(witness));
		for (size_t i = 0; i < tal_count(witness); i++)
			ss->witness[i] = tal_dup_talarr(ss->witness, u8,
							witness[i]);
	}
	ss->outs = tal_arr(ss, struct sym_state_out, tal_count(outs));
	for (size_t i = 0; i < tal_count(outs); i++) {
		ss->outs[i].amount = outs[i].amount;
		ss->outs[i].spk = tal_dup_talarr(ss->outs, u8, outs[i].spk);
	}
	ss->sequence = sequence;
	ss->minblock = minblock;
	ss->deadline_block = deadline;
	ss->fee = AMOUNT_SAT(0);
	memset(ss->fee_asset, 0, sizeof(ss->fee_asset));
	ss->coins = NULL;
	ss->spent = false;
	if (!sym_spends)
		sym_spends = notleak(tal_arr(NULL, struct sym_spend *, 0));
	tal_arr_expand(&sym_spends, ss);
	tal_add_destructor(ss, destroy_sym_spend);
	sym_retry(ss);
}

bool sym_broadcast_kickoff(struct lightningd *ld, struct channel *channel,
			   const char *cmd_id)
{
	struct sym_channel sc;
	struct sym_tree ko;
	struct sym_state_out *outs;
	const u8 *wscript;
	u8 **witness;

	if (!channel->sym_kickoff_sig || !sym_is_kickoff(channel,
							 channel->last_tx)) {
		log_broken(channel->log, "Symmetric channel without its"
			   " kickoff signatures: cannot close it unilaterally");
		return false;
	}
	sym_channel_from(channel, &sc);
	sym_kickoff_tree(tmpctx, &sc, &ko);
	outs = tal_arr(tmpctx, struct sym_state_out, 1);
	outs[0].amount = channel->funding_sats;
	outs[0].spk = sym_tree_spk(outs, &ko);
	wscript = bitcoin_redeem_2of2(tmpctx, &channel->local_funding_pubkey,
				      &channel->channel_info.remote_fundingkey);
	witness = bitcoin_witness_2of2(NULL, channel->sym_kickoff_sig,
				       &channel->last_sig,
				       &channel->local_funding_pubkey,
				       &channel->channel_info.remote_fundingkey);
	log_info(channel->log, "Broadcasting the kickoff of symmetric channel"
		 " %s, a fee coin attached",
		 fmt_bitcoin_outpoint(tmpctx, &channel->funding));
	sym_spend_start(channel, &channel->funding, channel->funding_sats,
			scriptpubkey_p2wsh(tmpctx, wscript), take(witness), outs,
			SYM_SEQUENCE, 0, get_block_height(ld->topology) + 6);
	return true;
}
