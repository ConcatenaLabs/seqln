#include "config.h"
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/channeld_wiregen.h>
#include <common/channel_type.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/pseudorand.h>
#include <common/sym_lanes.h>
#include <common/sym_scripts.h>
#include <connectd/connectd_wiregen.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/onchain_control.h>
#include <lightningd/opening_control.h>
#include <lightningd/peer_control.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
#include <lightningd/sym_lanes.h>
#include <lightningd/symmetric.h>
#include <lightningd/watch.h>
#include <wallet/wallet.h>
#include <wire/wire.h>

bool channel_is_sym_lanes(const struct channel *channel)
{
	return channel->sym_lanes != NULL;
}

void sym_lanes_save(struct channel *channel)
{
	wallet_sym_lanes_save(channel->peer->ld->wallet, channel);
}

void sym_lanes_attach(struct channel *channel, const struct sym_lane *lanes,
		      const struct bitcoin_signature *sigs,
		      const struct bitcoin_signature *local_sigs)
{
	struct sym_lanes_info *info = tal(channel, struct sym_lanes_info);
	size_t n = tal_count(lanes);

	assert(tal_count(sigs) == n && tal_count(local_sigs) == n);
	info->lanes = tal_dup_talarr(info, struct sym_lane, lanes);
	info->kickoff_sigs = tal_dup_talarr(info, struct bitcoin_signature,
					    sigs);
	info->local_kickoff_sigs = tal_dup_talarr(info,
						  struct bitcoin_signature,
						  local_sigs);
	info->our_msat = tal_arrz(info, struct amount_msat, n);
	if (channel->opener == LOCAL)
		for (size_t l = 0; l < n; l++)
			if (!amount_sat_to_msat(&info->our_msat[l],
						lanes[l].funding_sats))
				abort();
	info->swap = info->req = NULL;
	info->req_expiry = 0;
	info->cmd = NULL;
	info->spends = NULL;
	info->onchaind_txid = NULL;
	info->kicked = false;
	tal_free(channel->sym_lanes);
	channel->sym_lanes = info;
	sym_lanes_save(channel);
}

size_t channel_num_lanes(const struct channel *channel)
{
	return 1 + (channel->sym_lanes ? tal_count(channel->sym_lanes->lanes) : 0);
}

const u8 *channel_lane_asset(const struct channel *channel, u16 lane)
{
	if (lane == 0)
		return channel->channel_asset;
	assert(lane < channel_num_lanes(channel));
	return channel->sym_lanes->lanes[lane - 1].asset;
}

void channel_lane_funding(const struct channel *channel, u16 lane,
			  struct bitcoin_outpoint *out,
			  struct amount_sat *amount)
{
	*out = channel->funding;
	if (lane == 0) {
		*amount = channel->funding_sats;
		return;
	}
	assert(lane < channel_num_lanes(channel));
	out->n = channel->sym_lanes->lanes[lane - 1].outnum;
	*amount = channel->sym_lanes->lanes[lane - 1].funding_sats;
}

struct amount_msat channel_lane_our_msat(const struct channel *channel,
					 u16 lane)
{
	if (lane == 0)
		return channel->our_msat;
	assert(lane < channel_num_lanes(channel));
	return channel->sym_lanes->our_msat[lane - 1];
}

struct amount_msat channel_lane_receivable(const struct channel *channel,
					   u16 lane)
{
	struct amount_msat total, theirs;
	struct bitcoin_outpoint out;
	struct amount_sat amount;

	channel_lane_funding(channel, lane, &out, &amount);
	if (!amount_sat_to_msat(&total, amount)
	    || !amount_msat_sub(&theirs, total,
				channel_lane_our_msat(channel, lane)))
		return AMOUNT_MSAT(0);
	return theirs;
}

int channel_lane_of_asset(const struct channel *channel, const u8 asset[33])
{
	for (size_t l = 0; l < channel_num_lanes(channel); l++)
		if (memeq(channel_lane_asset(channel, l), 33, asset, 33))
			return l;
	return -1;
}

/* Move @amount of lane @lane to us or from us. */
static bool lane_move(struct channel *channel, u16 lane,
		      struct amount_msat amount, bool to_us)
{
	struct amount_msat *ours = lane ? &channel->sym_lanes->our_msat[lane - 1]
		: &channel->our_msat;

	if (to_us)
		return amount_msat_accumulate(ours, amount);
	return amount_msat_deduct(ours, amount);
}

static const u8 *lane_funding_spk(const tal_t *ctx,
				  const struct channel *channel)
{
	return scriptpubkey_p2wsh(ctx,
				  bitcoin_redeem_2of2(tmpctx,
						      &channel->local_funding_pubkey,
						      &channel->channel_info.remote_fundingkey));
}

const char *sym_lanes_check_funding(const tal_t *ctx,
				    const struct channel *channel,
				    const struct bitcoin_tx *tx)
{
	const u8 *spk = lane_funding_spk(tmpctx, channel);

	for (size_t l = 1; l < channel_num_lanes(channel); l++) {
		const struct sym_lane *lane = &channel->sym_lanes->lanes[l - 1];
		const struct wally_tx_output *o;
		struct amount_asset a;

		if (lane->outnum >= tx->wtx->num_outputs)
			return tal_fmt(ctx, "no output %u for lane %zu",
				       lane->outnum, l);
		o = &tx->wtx->outputs[lane->outnum];
		if (!memeq(o->script, o->script_len, spk, tal_bytelen(spk)))
			return tal_fmt(ctx, "output %u, lane %zu's, does not"
				       " pay the channel", lane->outnum, l);
		a = wally_tx_output_get_amount(o);
		if (!amount_asset_is(&a, lane->asset)
		    || !amount_asset_extract_value(tmpctx, &a)
		    || !amount_sat_eq(amount_sat(a.value), lane->funding_sats))
			return tal_fmt(ctx, "output %u, lane %zu's, does not"
				       " hold %s of %s explicitly",
				       lane->outnum, l,
				       fmt_amount_sat(tmpctx, lane->funding_sats),
				       fmt_asset_id(tmpctx, lane->asset));
	}
	return NULL;
}

/* A lane's funding output is spent: if the channel is not on chain yet,
 * the peer kicked a lane off, and every lane goes. */
static bool onchaind_runs(const struct channel *channel)
{
	return channel->owner && streq(channel->owner->name, "onchaind");
}

/* Whether @tx is the channel's mutual close (common/close_tx.h): it spends
 * every lane's funding output, and every output but the fee pays one of the
 * two shutdown scripts.  Spending several lanes is not enough: the kickoff
 * signatures are SIGHASH_SINGLE|ANYONECANPAY, so either side can kick off
 * several lanes in one transaction, which pays KO, not a shutdown script,
 * and leaves the other lanes to kick off. */
static bool is_lanes_mutual_close(const struct channel *channel,
				  const struct bitcoin_tx *tx)
{
	const u8 *ours = channel->shutdown_scriptpubkey[LOCAL];
	const u8 *theirs = channel->shutdown_scriptpubkey[REMOTE];

	if (!ours || !theirs
	    || tx->wtx->num_inputs != channel_num_lanes(channel))
		return false;
	for (size_t l = 0; l < channel_num_lanes(channel); l++) {
		struct bitcoin_outpoint out;
		struct amount_sat amount;
		bool spent = false;

		channel_lane_funding(channel, l, &out, &amount);
		for (size_t i = 0; i < tx->wtx->num_inputs; i++) {
			struct bitcoin_outpoint in;

			bitcoin_tx_input_get_outpoint(tx, i, &in);
			if (bitcoin_outpoint_eq(&in, &out))
				spent = true;
		}
		if (!spent)
			return false;
	}
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		const struct wally_tx_output *o = &tx->wtx->outputs[i];

		if (!o->script_len)
			continue;
		if (!memeq(o->script, o->script_len, ours, tal_bytelen(ours))
		    && !memeq(o->script, o->script_len, theirs,
			      tal_bytelen(theirs)))
			return false;
	}
	return true;
}

static enum watch_result lane_funding_spent(struct channel *channel,
					    const struct bitcoin_tx *tx,
					    size_t inputnum,
					    const struct block *block)
{
	struct sym_lanes_info *info = channel->sym_lanes;
	struct bitcoin_outpoint out;
	struct bitcoin_txid txid;
	struct sym_lane_spend s;

	bitcoin_tx_input_get_outpoint(tx, inputnum, &out);
	bitcoin_txid(tx, &txid);
	sym_note_spent(channel, &out);
	/* The mutual close spends every lane: lane 0's spend takes the channel
	 * on, as for any close. */
	if (is_lanes_mutual_close(channel, tx))
		return KEEP_WATCHING;
	for (size_t i = 0; i < tal_count(info->spends); i++) {
		struct bitcoin_txid t;
		bitcoin_txid(info->spends[i].tx, &t);
		if (bitcoin_txid_eq(&t, &txid) && info->spends[i].input == inputnum)
			return KEEP_WATCHING;
	}
	/* Kept until the channel is forgotten: onchaind takes it whenever it
	 * starts. */
	{
		/* A block's transaction carries no PSBT: copy it whole. */
		const u8 *raw = linearize_tx(tmpctx, tx);
		size_t len = tal_bytelen(raw);

		s.tx = pull_bitcoin_tx(info, &raw, &len);
		if (!s.tx)
			return KEEP_WATCHING;
	}
	s.input = inputnum;
	s.height = block->height;
	if (!info->spends)
		info->spends = tal_arr(info, struct sym_lane_spend, 0);
	tal_arr_expand(&info->spends, s);
	sym_lanes_save(channel);

	if (onchaind_runs(channel)) {
		if (!info->onchaind_txid
		    || !bitcoin_txid_eq(info->onchaind_txid, &txid))
			onchaind_lane_spent(channel, tx, inputnum,
					    block->height);
	} else if (channel_state_wants_onchain_fail(channel->state)) {
		log_unusual(channel->log, "Lane funding %s spent: going to"
			    " chain", fmt_bitcoin_outpoint(tmpctx, &out));
		channel_fail_permanent(channel, REASON_ONCHAIN,
				       "A lane's funding was spent");
	}
	/* Kept for a reorganization, which may take the spend away. */
	return KEEP_WATCHING;
}

void sym_lanes_onchaind_started(struct channel *channel,
				const struct bitcoin_tx *tx)
{
	struct sym_lanes_info *info = channel->sym_lanes;
	struct bitcoin_txid txid;

	bitcoin_txid(tx, &txid);
	tal_free(info->onchaind_txid);
	info->onchaind_txid = tal_dup(info, struct bitcoin_txid, &txid);
	/* The mutual close pays every lane out: nothing to kick off. */
	if (is_lanes_mutual_close(channel, tx))
		return;
	for (size_t i = 0; i < tal_count(info->spends); i++) {
		struct bitcoin_txid t;

		bitcoin_txid(info->spends[i].tx, &t);
		/* onchaind read that one already. */
		if (bitcoin_txid_eq(&t, &txid))
			continue;
		onchaind_lane_spent(channel, info->spends[i].tx,
				    info->spends[i].input,
				    info->spends[i].height);
	}
	/* Every lane goes to chain: the ones not kicked off yet, we do. */
	sym_lanes_kickoffs(channel->peer->ld, channel);
}

const u8 *sym_lanes_output_asset(const tal_t *ctx,
				 const struct channel *channel, const u8 *spk)
{
	const struct sym_state *states[] = { channel->sym_local,
					     channel->sym_remote,
					     channel->sym_remote_pending,
					     channel->sym_dev_stale };

	for (size_t s = 0; s < ARRAY_SIZE(states); s++) {
		if (!states[s])
			continue;
		for (size_t i = 0; i < tal_count(states[s]->outs); i++) {
			const struct sym_state_out *o = &states[s]->outs[i];
			if (o->asset && memeq(o->spk, tal_bytelen(o->spk),
					      spk, tal_bytelen(spk)))
				return tal_dup_arr(ctx, u8, o->asset, 33, 0);
		}
	}
	return NULL;
}

void sym_lanes_watch(struct lightningd *ld, struct channel *channel)
{
	for (size_t l = 1; l < channel_num_lanes(channel); l++) {
		struct bitcoin_outpoint out;
		struct amount_sat amount;

		channel_lane_funding(channel, l, &out, &amount);
		watch_txo(channel, ld->topology, channel, &out,
			  lane_funding_spent);
	}
}

void sym_lanes_kickoffs(struct lightningd *ld, struct channel *channel)
{
	struct sym_channel sc;
	struct sym_tree ko;
	const u8 *wscript;
	const u8 *spk;

	/* Once per run: each kickoff, once started, goes on until its output
	 * is spent. */
	if (channel->sym_lanes->kicked)
		return;
	channel->sym_lanes->kicked = true;
	sym_channel_from(channel, &sc);
	sym_kickoff_tree(tmpctx, &sc, &ko);
	spk = sym_tree_spk(tmpctx, &ko);
	wscript = bitcoin_redeem_2of2(tmpctx, &channel->local_funding_pubkey,
				      &channel->channel_info.remote_fundingkey);
	for (size_t l = 1; l < channel_num_lanes(channel); l++) {
		struct sym_state_out *outs = tal_arrz(tmpctx,
						      struct sym_state_out, 1);
		struct bitcoin_outpoint out;
		struct amount_sat amount;
		u8 **witness;

		channel_lane_funding(channel, l, &out, &amount);
		outs[0].amount = amount;
		outs[0].spk = cast_const(u8 *, spk);
		outs[0].asset = cast_const(u8 *, channel_lane_asset(channel, l));
		witness = bitcoin_witness_2of2(NULL,
					       &channel->sym_lanes->local_kickoff_sigs[l - 1],
					       &channel->sym_lanes->kickoff_sigs[l - 1],
					       &channel->local_funding_pubkey,
					       &channel->channel_info.remote_fundingkey);
		log_info(channel->log, "Broadcasting the kickoff of lane %zu"
			 " (%s), a fee coin attached", l,
			 fmt_bitcoin_outpoint(tmpctx, &out));
		sym_spend_start_lanes(channel, &out, amount,
				      channel_lane_asset(channel, l), NULL,
				      scriptpubkey_p2wsh(tmpctx, wscript),
				      take(witness), outs, SYM_SEQUENCE, 0,
				      get_block_height(ld->topology) + 6);
	}
}

bool sym_lanes_credit(struct channel *channel, u16 lane,
		      struct amount_msat amount, bool to_us)
{
	assert(lane != 0 && lane < channel_num_lanes(channel));
	if (!lane_move(channel, lane, amount, to_us))
		return false;
	log_debug(channel->log, "Lane %u balance now %s", lane,
		  fmt_amount_msat(tmpctx, channel->sym_lanes->our_msat[lane - 1]));
	sym_lanes_save(channel);
	return true;
}

/* The swap as the requester asked for it: it gives @give in @give_lane and
 * takes @take in @take_lane. */
static void json_add_swap_terms(struct json_stream *js,
				const struct channel *channel,
				u16 give_lane, struct amount_msat give,
				u16 take_lane, struct amount_msat take)
{
	json_add_string(js, "give_asset",
			fmt_asset_id(tmpctx, channel_lane_asset(channel,
								give_lane)));
	json_add_amount_msat(js, "give_msat", give);
	json_add_string(js, "take_asset",
			fmt_asset_id(tmpctx, channel_lane_asset(channel,
								take_lane)));
	json_add_amount_msat(js, "take_msat", take);
}

static void swap_cmd_done(struct channel *channel, const char *err, u64 id)
{
	struct sym_lanes_info *info = channel->sym_lanes;
	struct command *cmd = info->cmd;
	struct json_stream *js;

	if (!cmd)
		return;
	info->cmd = NULL;
	if (err) {
		was_pending(command_fail(cmd, LIGHTNINGD, "%s", err));
		return;
	}
	js = json_stream_success(cmd);
	json_add_u64(js, "id", id);
	json_add_channel_id(js, "channel_id", &channel->cid);
	json_array_start(js, "lanes");
	for (size_t l = 0; l < channel_num_lanes(channel); l++) {
		json_object_start(js, NULL);
		json_add_string(js, "asset",
				fmt_asset_id(tmpctx,
					     channel_lane_asset(channel, l)));
		json_add_amount_msat(js, "to_us_msat",
				     channel_lane_our_msat(channel, l));
		json_object_end(js);
	}
	json_array_end(js);
	was_pending(command_success(cmd, js));
}

static void destroy_swap_cmd(struct command *cmd, struct channel *channel)
{
	if (channel->sym_lanes && channel->sym_lanes->cmd == cmd)
		channel->sym_lanes->cmd = NULL;
}

/* Our request is over, swapped or not. */
static void req_done(struct channel *channel, const char *err)
{
	struct sym_lanes_info *info = channel->sym_lanes;
	u64 id;

	if (!info->req)
		return;
	id = info->req->id;
	if (err && channel->owner && streq(channel->owner->name, "channeld"))
		subd_send_msg(channel->owner,
			      take(towire_channeld_sym_swap_cancel(NULL, id)));

	info->req = tal_free(info->req);
	sym_lanes_save(channel);
	swap_cmd_done(channel, err, id);
}

void sym_lanes_swap_step(struct channel *channel, const struct sym_swap *swap)
{
	struct sym_lanes_info *info = channel->sym_lanes;
	enum side owner;

	if (!info || !swap)
		return;

	/* Ours, asked for: the peer's commitment carried it. */
	if (info->req && info->req->id == swap->id
	    && htlc_state_owner(swap->state) == REMOTE) {
		info->req = tal_free(info->req);
		log_info(channel->log, "Swap %"PRIu64" is in the peer's"
			 " commitment", swap->id);
	}

	tal_free(info->swap);
	info->swap = tal_dup(info, struct sym_swap, swap);
	if (swap->state != SENT_ADD_ACK_REVOCATION
	    && swap->state != RCVD_ADD_ACK_REVOCATION) {
		sym_lanes_save(channel);
		return;
	}

	/* In both sides' balances now: in ours too. */
	owner = htlc_state_owner(swap->state);
	if (!lane_move(channel, swap->give_lane, swap->give, owner != LOCAL)
	    || !lane_move(channel, swap->take_lane, swap->take, owner == LOCAL)) {
		channel_internal_error(channel, "Swap %"PRIu64" overflows our"
				       " balances", swap->id);
		return;
	}
	log_info(channel->log, "Swap %"PRIu64" done: %s gave %s in lane %u"
		 " for %s in lane %u", swap->id,
		 owner == LOCAL ? "we" : "they",
		 fmt_amount_msat(tmpctx, swap->give), swap->give_lane,
		 fmt_amount_msat(tmpctx, swap->take), swap->take_lane);
	info->swap = tal_free(info->swap);
	wallet_channel_save(channel->peer->ld->wallet, channel);
	sym_lanes_save(channel);
	if (owner == REMOTE)
		swap_cmd_done(channel, NULL, swap->id);
}

void sym_lanes_init_args(const tal_t *ctx, const struct channel *channel,
			 struct sym_lane **lanes, struct amount_msat **ours,
			 struct sym_swap **swap, struct sym_swap **req)
{
	const struct sym_lanes_info *info = channel->sym_lanes;

	if (!info) {
		*lanes = tal_arr(ctx, struct sym_lane, 0);
		*ours = tal_arr(ctx, struct amount_msat, 0);
		*swap = *req = NULL;
		return;
	}
	*lanes = tal_dup_talarr(ctx, struct sym_lane, info->lanes);
	*ours = tal_dup_talarr(ctx, struct amount_msat, info->our_msat);
	*swap = info->swap;
	*req = info->req;
}

/*~ symswap: ask the peer for a swap on a channel of several assets. */
static void swap_request_reply(struct subd *channeld, const u8 *msg,
			       const int *fds, struct channel *channel)
{
	char *err;

	if (!fromwire_channeld_sym_swap_request_reply(tmpctx, msg, &err)) {
		channel_internal_error(channel, "bad sym_swap_request_reply %s",
				       tal_hex(tmpctx, msg));
		return;
	}
	if (err)
		req_done(channel, err);
}

static struct command_result *json_symswap(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct lightningd *ld = cmd->ld;
	struct channel_id *cid;
	const u8 *give_asset, *take_asset;
	struct amount_msat *give, *take;
	u32 *blocks;
	struct channel *channel;
	struct sym_lanes_info *info;
	struct sym_swap req;
	int give_lane, take_lane;

	if (!param(cmd, buffer, params,
		   p_req("id", param_channel_id, &cid),
		   p_req("give_asset", param_asset_tag, &give_asset),
		   p_req("give_msat", param_msat, &give),
		   p_req("take_asset", param_asset_tag, &take_asset),
		   p_req("take_msat", param_msat, &take),
		   p_opt_def("expiry_blocks", param_u32, &blocks, 6),
		   NULL))
		return command_param_failed();

	channel = channel_by_cid(ld, cid);
	if (!channel || !channel_is_sym_lanes(channel))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "No channel of several assets %s",
				    fmt_channel_id(tmpctx, cid));
	info = channel->sym_lanes;
	if (channel->state != CHANNELD_NORMAL || !channel->owner
	    || !streq(channel->owner->name, "channeld"))
		return command_fail(cmd, LIGHTNINGD, "Channel is not active");
	give_lane = channel_lane_of_asset(channel, give_asset);
	take_lane = channel_lane_of_asset(channel, take_asset);
	if (give_lane < 0 || take_lane < 0 || give_lane == take_lane)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "A swap is between two of the channel's"
				    " assets");
	if (amount_msat_is_zero(*give) || amount_msat_is_zero(*take))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "A swap moves both its legs");
	if (*blocks == 0 || *blocks > 1008)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "expiry_blocks between 1 and 1008");
	if (info->req || info->swap || info->cmd)
		return command_fail(cmd, LIGHTNINGD, "A swap is in flight");

	/* As the peer will send it: it gives what we take. */
	req.id = pseudorand_u64();
	req.state = RCVD_ADD_HTLC;
	req.give_lane = take_lane;
	req.give = *take;
	req.take_lane = give_lane;
	req.take = *give;

	/* Saved before it goes: a swap for it may come after a restart. */
	info->req = tal_dup(info, struct sym_swap, &req);
	info->req_expiry = get_block_height(ld->topology) + *blocks;
	sym_lanes_save(channel);

	log_info(channel->log, "Asking for swap %"PRIu64": %s in lane %d for"
		 " %s in lane %d until block %u", req.id,
		 fmt_amount_msat(tmpctx, *give), give_lane,
		 fmt_amount_msat(tmpctx, *take), take_lane, info->req_expiry);
	info->cmd = cmd;
	tal_add_destructor2(cmd, destroy_swap_cmd, channel);
	subd_req(channel, channel->owner,
		 take(towire_channeld_sym_swap_request(NULL, &req,
						       info->req_expiry)),
		 -1, 0, swap_request_reply, channel);
	return command_still_pending(cmd);
}

static const struct json_command symswap_command = {
	"symswap",
	json_symswap,
};
AUTODATA(json_command, &symswap_command);

/*~ The peer asks us for a swap: the sym_swap hook decides. */
struct sym_swap_payload {
	struct lightningd *ld;
	u64 channel_dbid;
	struct node_id peer_id;
	struct channel_id cid;
	/* As the requester sees it. */
	u64 id;
	u16 give_lane, take_lane;
	struct amount_msat give, take;
	u32 expiry;
};

static void send_refuse(struct lightningd *ld, const struct node_id *peer_id,
			const struct channel_id *cid, u64 id, const char *why)
{
	struct peer *peer = peer_by_id(ld, peer_id);

	log_debug(ld->log, "Refusing swap %"PRIu64": %s", id, why);
	if (!peer || peer->connected != PEER_CONNECTED)
		return;
	subd_send_msg(ld->connectd,
		      take(towire_connectd_custommsg_out(NULL, peer_id,
							 towire_seq_swap_refuse(tmpctx,
										cid,
										id,
										why))));
}

static void swap_accept_reply(struct subd *channeld, const u8 *msg,
			      const int *fds, struct sym_swap_payload *p)
{
	char *err;

	if (!fromwire_channeld_sym_swap_accept_reply(tmpctx, msg, &err)) {
		log_broken(p->ld->log, "bad sym_swap_accept_reply %s",
			   tal_hex(tmpctx, msg));
		return;
	}
	if (err)
		send_refuse(p->ld, &p->peer_id, &p->cid, p->id, err);
}

static void swap_take(struct sym_swap_payload *p)
{
	struct channel *channel = channel_by_dbid(p->ld, p->channel_dbid);
	struct sym_swap swap;

	if (!channel || !channel->owner
	    || !streq(channel->owner->name, "channeld")) {
		send_refuse(p->ld, &p->peer_id, &p->cid, p->id,
			    "channel is not active");
		return;
	}
	if (get_block_height(p->ld->topology) >= p->expiry) {
		send_refuse(p->ld, &p->peer_id, &p->cid, p->id, "expired");
		return;
	}
	/* Ours to send: we give what they take. */
	swap.id = p->id;
	swap.state = SENT_ADD_HTLC;
	swap.give_lane = p->take_lane;
	swap.give = p->take;
	swap.take_lane = p->give_lane;
	swap.take = p->give;
	log_info(channel->log, "Taking swap %"PRIu64, p->id);
	subd_req(channel->owner, channel->owner,
		 take(towire_channeld_sym_swap_accept(NULL, &swap)), -1, 0,
		 swap_accept_reply, tal_steal(channel->owner, p));
}

static bool sym_swap_hook_cb(struct sym_swap_payload *p,
			     const char *buffer, const jsmntok_t *toks)
{
	const jsmntok_t *result;

	if (!toks || !buffer)
		return true;
	result = json_get_member(buffer, toks, "result");
	if (!result)
		fatal("Plugin returned no result to the sym_swap hook: %s",
		      buffer);
	if (json_tok_streq(buffer, result, "continue"))
		return true;
	if (json_tok_streq(buffer, result, "accept")) {
		/* Steal it away from the hook, which frees it. */
		swap_take(tal_dup(p->ld, struct sym_swap_payload, p));
		return false;
	}
	if (json_tok_streq(buffer, result, "refuse")) {
		const jsmntok_t *why = json_get_member(buffer, toks, "reason");
		send_refuse(p->ld, &p->peer_id, &p->cid, p->id,
			    why ? json_strdup(tmpctx, buffer, why) : "refused");
		return false;
	}
	fatal("Plugin returned an invalid result to the sym_swap hook: %s",
	      buffer);
}

/* No plugin took it. */
static void sym_swap_hook_final(struct sym_swap_payload *p STEALS)
{
	tal_steal(tmpctx, p);
	send_refuse(p->ld, &p->peer_id, &p->cid, p->id, "not taking swaps");
}

static void sym_swap_hook_serialize(struct sym_swap_payload *p,
				    struct json_stream *js,
				    struct plugin *plugin)
{
	struct channel *channel = channel_by_dbid(p->ld, p->channel_dbid);

	json_object_start(js, "sym_swap");
	json_add_node_id(js, "peer_id", &p->peer_id);
	json_add_channel_id(js, "channel_id", &p->cid);
	json_add_u64(js, "id", p->id);
	if (channel)
		json_add_swap_terms(js, channel, p->give_lane, p->give,
				    p->take_lane, p->take);
	json_add_u32(js, "expiry", p->expiry);
	json_object_end(js);
}

REGISTER_PLUGIN_HOOK(sym_swap,
		     sym_swap_hook_cb,
		     sym_swap_hook_final,
		     sym_swap_hook_serialize,
		     struct sym_swap_payload *);

static struct channel *peer_lanes_channel(struct lightningd *ld,
					  const struct node_id *peer_id,
					  const struct channel_id *cid)
{
	struct peer *peer = peer_by_id(ld, peer_id);
	struct channel *channel;

	if (!peer)
		return NULL;
	list_for_each(&peer->channels, channel, list)
		if (channel_id_eq(&channel->cid, cid)
		    && channel_is_sym_lanes(channel))
			return channel;
	return NULL;
}

bool sym_lanes_handle_peer_msg(struct lightningd *ld,
			       const struct node_id *peer_id, const u8 *msg)
{
	struct channel_id cid;
	struct channel *channel;
	int type = fromwire_peektype(msg);

	if (type == SEQ_SWAP_REQUEST_MSG) {
		struct sym_swap_payload *p = tal(NULL, struct sym_swap_payload);

		p->ld = ld;
		p->peer_id = *peer_id;
		if (!fromwire_seq_swap_request(msg, &p->cid, &p->id,
					       &p->give_lane, &p->give,
					       &p->take_lane, &p->take,
					       &p->expiry)) {
			log_unusual(ld->log, "Malformed swap request from %s",
				    fmt_node_id(tmpctx, peer_id));
			tal_free(p);
			return true;
		}
		channel = peer_lanes_channel(ld, peer_id, &p->cid);
		if (!channel || p->give_lane >= channel_num_lanes(channel)
		    || p->take_lane >= channel_num_lanes(channel)
		    || p->give_lane == p->take_lane) {
			send_refuse(ld, peer_id, &p->cid, p->id,
				    "no such lanes");
			tal_free(p);
			return true;
		}
		p->channel_dbid = channel->dbid;
		plugin_hook_call_sym_swap(ld, NULL, p);
		return true;
	}

	if (type == SEQ_SWAP_REFUSE_MSG) {
		u64 id;
		char *why;

		if (!fromwire_seq_swap_refuse(tmpctx, msg, &cid, &id, &why)) {
			log_unusual(ld->log, "Malformed swap refusal from %s",
				    fmt_node_id(tmpctx, peer_id));
			return true;
		}
		channel = peer_lanes_channel(ld, peer_id, &cid);
		if (channel && channel->sym_lanes->req
		    && channel->sym_lanes->req->id == id)
			req_done(channel, tal_fmt(tmpctx, "Peer refused the"
						  " swap: %s", why));
		return true;
	}
	return false;
}

void sym_lanes_notify_new_block(struct lightningd *ld)
{
	u32 height = get_block_height(ld->topology);
	struct peer *peer;
	struct peer_node_id_map_iter it;

	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		struct channel *channel;

		list_for_each(&peer->channels, channel, list) {
			struct sym_lanes_info *info = channel->sym_lanes;

			if (info && info->req
			    && height > info->req_expiry + SYM_SWAP_GRACE)
				req_done(channel, "The swap expired");
		}
	}
}

void json_add_sym_lanes(struct json_stream *js, const struct channel *channel)
{
	const struct sym_lanes_info *info = channel->sym_lanes;

	if (!info)
		return;
	json_array_start(js, "seq_lanes");
	for (size_t l = 0; l < channel_num_lanes(channel); l++) {
		struct bitcoin_outpoint out;
		struct amount_sat amount;
		struct amount_msat total;

		channel_lane_funding(channel, l, &out, &amount);
		if (!amount_sat_to_msat(&total, amount))
			abort();
		json_object_start(js, NULL);
		json_add_u32(js, "lane", l);
		json_add_string(js, "asset",
				fmt_asset_id(tmpctx,
					     channel_lane_asset(channel, l)));
		json_add_outpoint(js, "funding_outpoint", &out);
		json_add_amount_msat(js, "total_msat", total);
		json_add_amount_msat(js, "to_us_msat",
				     channel_lane_our_msat(channel, l));
		json_object_end(js);
	}
	json_array_end(js);
	if (info->swap) {
		json_object_start(js, "seq_swap");
		json_add_u64(js, "id", info->swap->id);
		json_add_string(js, "state",
				htlc_state_name(info->swap->state));
		json_add_string(js, "sender",
				htlc_state_owner(info->swap->state) == LOCAL
				? "local" : "remote");
		json_add_swap_terms(js, channel, info->swap->give_lane,
				    info->swap->give, info->swap->take_lane,
				    info->swap->take);
		json_object_end(js);
	}
}
