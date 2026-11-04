#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/channel_id.h>
#include <common/initial_channel.h>
#include <common/sym_channel.h>
#include <common/sym_lanes.h>
#include <common/sym_scripts.h>
#include <common/utils.h>
#include <wire/wire.h>

u8 *towire_seq_swap_request(const tal_t *ctx, const struct channel_id *cid,
			    u64 id, u16 give_lane, struct amount_msat give,
			    u16 take_lane, struct amount_msat take, u32 expiry)
{
	u8 *p = tal_arr(ctx, u8, 0);

	towire_u16(&p, SEQ_SWAP_REQUEST_MSG);
	towire_channel_id(&p, cid);
	towire_u64(&p, id);
	towire_u16(&p, give_lane);
	towire_amount_msat(&p, give);
	towire_u16(&p, take_lane);
	towire_amount_msat(&p, take);
	towire_u32(&p, expiry);
	return p;
}

bool fromwire_seq_swap_request(const u8 *msg, struct channel_id *cid,
			       u64 *id, u16 *give_lane,
			       struct amount_msat *give, u16 *take_lane,
			       struct amount_msat *take, u32 *expiry)
{
	size_t max = tal_bytelen(msg);

	if (fromwire_u16(&msg, &max) != SEQ_SWAP_REQUEST_MSG)
		return false;
	fromwire_channel_id(&msg, &max, cid);
	*id = fromwire_u64(&msg, &max);
	*give_lane = fromwire_u16(&msg, &max);
	*give = fromwire_amount_msat(&msg, &max);
	*take_lane = fromwire_u16(&msg, &max);
	*take = fromwire_amount_msat(&msg, &max);
	*expiry = fromwire_u32(&msg, &max);
	return msg != NULL;
}

u8 *towire_seq_swap_refuse(const tal_t *ctx, const struct channel_id *cid,
			   u64 id, const char *reason)
{
	u8 *p = tal_arr(ctx, u8, 0);
	size_t len = strlen(reason);

	if (len > 1000)
		len = 1000;
	towire_u16(&p, SEQ_SWAP_REFUSE_MSG);
	towire_channel_id(&p, cid);
	towire_u64(&p, id);
	towire_u16(&p, len);
	towire_u8_array(&p, (const u8 *)reason, len);
	return p;
}

bool fromwire_seq_swap_refuse(const tal_t *ctx, const u8 *msg,
			      struct channel_id *cid, u64 *id, char **reason)
{
	size_t max = tal_bytelen(msg);
	u16 len;
	u8 *r;

	if (fromwire_u16(&msg, &max) != SEQ_SWAP_REFUSE_MSG)
		return false;
	fromwire_channel_id(&msg, &max, cid);
	*id = fromwire_u64(&msg, &max);
	len = fromwire_u16(&msg, &max);
	r = fromwire_tal_arrn(tmpctx, &msg, &max, len);
	if (!msg || !r)
		return false;
	*reason = tal_strndup(ctx, (const char *)r, len);
	return utf8_check(*reason, len);
}

u8 *sym_lanes_open_blob(const tal_t *ctx, const struct sym_lane *lanes)
{
	u8 *p = tal_arr(ctx, u8, 0);

	towire_u16(&p, tal_count(lanes));
	for (size_t i = 0; i < tal_count(lanes); i++) {
		towire_u8_array(&p, lanes[i].asset, sizeof(lanes[i].asset));
		towire_amount_sat(&p, lanes[i].funding_sats);
	}
	return p;
}

bool sym_lanes_from_open_blob(const tal_t *ctx, const u8 *blob,
			      struct sym_lane **lanes)
{
	size_t max = tal_bytelen(blob);
	u16 n = fromwire_u16(&blob, &max);

	if (n > SYM_MAX_LANES)
		return false;
	*lanes = tal_arrz(ctx, struct sym_lane, n);
	for (size_t i = 0; i < n; i++) {
		fromwire_u8_array(&blob, &max, (*lanes)[i].asset,
				  sizeof((*lanes)[i].asset));
		(*lanes)[i].funding_sats = fromwire_amount_sat(&blob, &max);
	}
	if (!blob || max != 0) {
		*lanes = tal_free(*lanes);
		return false;
	}
	return true;
}

u8 *sym_lanes_created_blob(const tal_t *ctx, const struct sym_lane *lanes,
			   const secp256k1_ecdsa_signature *sigs)
{
	u8 *p = tal_arr(ctx, u8, 0);

	assert(tal_count(sigs) == tal_count(lanes));
	towire_u16(&p, tal_count(lanes));
	for (size_t i = 0; i < tal_count(lanes); i++) {
		towire_u32(&p, lanes[i].outnum);
		towire_secp256k1_ecdsa_signature(&p, &sigs[i]);
	}
	return p;
}

bool sym_lanes_from_created_blob(const tal_t *ctx, const u8 *blob,
				 size_t nlanes, u32 **outnums,
				 secp256k1_ecdsa_signature **sigs)
{
	size_t max = tal_bytelen(blob);

	if (fromwire_u16(&blob, &max) != nlanes)
		return false;
	*outnums = tal_arr(ctx, u32, nlanes);
	*sigs = tal_arr(ctx, secp256k1_ecdsa_signature, nlanes);
	for (size_t i = 0; i < nlanes; i++) {
		(*outnums)[i] = fromwire_u32(&blob, &max);
		fromwire_secp256k1_ecdsa_signature(&blob, &max, &(*sigs)[i]);
	}
	return blob && max == 0;
}

u8 *sym_lanes_signed_blob(const tal_t *ctx,
			  const secp256k1_ecdsa_signature *sigs)
{
	u8 *p = tal_arr(ctx, u8, 0);

	towire_u16(&p, tal_count(sigs));
	for (size_t i = 0; i < tal_count(sigs); i++)
		towire_secp256k1_ecdsa_signature(&p, &sigs[i]);
	return p;
}

bool sym_lanes_from_signed_blob(const tal_t *ctx, const u8 *blob,
				size_t nlanes,
				secp256k1_ecdsa_signature **sigs)
{
	size_t max = tal_bytelen(blob);

	if (fromwire_u16(&blob, &max) != nlanes)
		return false;
	*sigs = tal_arr(ctx, secp256k1_ecdsa_signature, nlanes);
	for (size_t i = 0; i < nlanes; i++)
		fromwire_secp256k1_ecdsa_signature(&blob, &max, &(*sigs)[i]);
	return blob && max == 0;
}

void towire_sym_lane(u8 **pptr, const struct sym_lane *lane)
{
	towire_u8_array(pptr, lane->asset, sizeof(lane->asset));
	towire_u32(pptr, lane->outnum);
	towire_amount_sat(pptr, lane->funding_sats);
}

void fromwire_sym_lane(const u8 **cursor, size_t *max, struct sym_lane *lane)
{
	fromwire_u8_array(cursor, max, lane->asset, sizeof(lane->asset));
	lane->outnum = fromwire_u32(cursor, max);
	lane->funding_sats = fromwire_amount_sat(cursor, max);
}

void towire_sym_swap(u8 **pptr, const struct sym_swap *swap)
{
	towire_u64(pptr, swap->id);
	towire_u8(pptr, swap->state);
	towire_u16(pptr, swap->give_lane);
	towire_u16(pptr, swap->take_lane);
	towire_amount_msat(pptr, swap->give);
	towire_amount_msat(pptr, swap->take);
}

void fromwire_sym_swap(const u8 **cursor, size_t *max, struct sym_swap *swap)
{
	swap->id = fromwire_u64(cursor, max);
	swap->state = fromwire_u8(cursor, max);
	if (swap->state >= HTLC_STATE_INVALID)
		fromwire_fail(cursor, max);
	swap->give_lane = fromwire_u16(cursor, max);
	swap->take_lane = fromwire_u16(cursor, max);
	swap->give = fromwire_amount_msat(cursor, max);
	swap->take = fromwire_amount_msat(cursor, max);
}

const char *sym_lanes_check(const tal_t *ctx, const struct sym_lane *lanes,
			    const u8 channel_asset[33])
{
	size_t n = tal_count(lanes);

	if (n == 0 || n > SYM_MAX_LANES)
		return tal_fmt(ctx, "%zu lanes beside the channel's own", n);
	for (size_t i = 0; i < n; i++) {
		if (lanes[i].asset[0] != 0x01)
			return tal_fmt(ctx, "lane %zu's asset is not explicit",
				       i + 1);
		if (memeq(lanes[i].asset, 33, channel_asset, 33))
			return tal_fmt(ctx, "lane %zu holds the channel's own"
				       " asset", i + 1);
		for (size_t j = 0; j < i; j++)
			if (memeq(lanes[i].asset, 33, lanes[j].asset, 33))
				return tal_fmt(ctx, "lanes %zu and %zu hold one"
					       " asset", j + 1, i + 1);
		if (amount_sat_eq(lanes[i].funding_sats, AMOUNT_SAT(0))
		    || lanes[i].funding_sats.satoshis > (u64)INT64_MAX / 1000) /* Raw: range */
			return tal_fmt(ctx, "lane %zu holds %s", i + 1,
				       fmt_amount_sat(tmpctx,
						      lanes[i].funding_sats));
	}
	return NULL;
}

size_t sym_num_lanes(const struct channel *channel)
{
	return 1 + tal_count(channel->sym_lanes);
}

const u8 *sym_lane_asset(const struct channel *channel, size_t lane)
{
	if (lane == 0)
		return channel->channel_asset;
	assert(lane <= tal_count(channel->sym_lanes));
	return channel->sym_lanes[lane - 1].asset;
}

int sym_lane_of_asset(const struct channel *channel, const u8 asset[33])
{
	for (size_t l = 0; l < sym_num_lanes(channel); l++)
		if (memeq(sym_lane_asset(channel, l), 33, asset, 33))
			return l;
	return -1;
}

void sym_lane_funding(const struct channel *channel, size_t lane,
		      struct bitcoin_outpoint *outpoint,
		      struct amount_sat *amount)
{
	*outpoint = channel->funding;
	if (lane == 0) {
		*amount = channel->funding_sats;
		return;
	}
	assert(lane <= tal_count(channel->sym_lanes));
	outpoint->n = channel->sym_lanes[lane - 1].outnum;
	*amount = channel->sym_lanes[lane - 1].funding_sats;
}

struct amount_msat sym_lane_owed(const struct channel *channel, size_t lane,
				 enum side view, enum side side)
{
	if (lane == 0)
		return channel->view[view].owed[side];
	assert(lane <= tal_count(channel->sym_lane_bal));
	return channel->sym_lane_bal[lane - 1].owed[view][side];
}

struct sym_output *sym_lanes_settlement(const tal_t *ctx,
					const struct channel *channel,
					enum side side,
					const struct sym_htlc *htlcs,
					const u16 *htlc_lanes,
					const char **err)
{
	struct pubkey pay[NUM_SIDES], htlc[NUM_SIDES];
	struct sym_output *outs = tal_arr(ctx, struct sym_output, 0);

	for (enum side s = 0; s < NUM_SIDES; s++) {
		pay[s] = channel->basepoints[s].payment;
		htlc[s] = channel->basepoints[s].htlc;
	}
	for (size_t l = 0; l < sym_num_lanes(channel); l++) {
		struct sym_htlc *lh = tal_arr(tmpctx, struct sym_htlc, 0);
		struct amount_msat bal[NUM_SIDES];
		struct bitcoin_outpoint outpoint;
		struct amount_sat funding;
		struct sym_output *lo;

		for (size_t i = 0; i < tal_count(htlcs); i++)
			if ((htlc_lanes ? htlc_lanes[i] : 0) == l)
				tal_arr_expand(&lh, htlcs[i]);
		for (enum side s = 0; s < NUM_SIDES; s++)
			bal[s] = sym_lane_owed(channel, l, side, s);
		sym_lane_funding(channel, l, &outpoint, &funding);
		lo = sym_settlement(tmpctx, funding, channel->opener, pay, htlc,
				    bal, lh, sym_dust_limit(channel), err);
		if (!lo) {
			*err = tal_fmt(ctx, "lane %zu: %s", l, *err);
			return tal_free(outs);
		}
		for (size_t i = 0; i < tal_count(lo); i++) {
			lo[i].asset = l == 0 ? NULL : sym_lane_asset(channel, l);
			lo[i].spk = tal_dup_talarr(outs, u8, lo[i].spk);
			tal_arr_expand(&outs, lo[i]);
		}
	}
	return outs;
}

struct bitcoin_tx *sym_lane_kickoff_tx(const tal_t *ctx,
				       const struct channel *channel,
				       size_t lane, const u8 **wscript)
{
	struct sym_channel sc;
	struct bitcoin_outpoint outpoint;
	struct amount_sat amount;

	sym_channel_of(channel, &sc);
	memcpy(sc.asset, sym_lane_asset(channel, lane), sizeof(sc.asset));
	sym_lane_funding(channel, lane, &outpoint, &amount);
	*wscript = bitcoin_redeem_2of2(ctx, &channel->funding_pubkey[LOCAL],
				       &channel->funding_pubkey[REMOTE]);
	return sym_kickoff_tx(ctx, chainparams, &outpoint, amount, *wscript,
			      &sc);
}

static bool owed_move(struct amount_msat owed[NUM_SIDES], enum side from,
		      struct amount_msat amount)
{
	struct amount_msat f = owed[from], t = owed[!from];

	if (!amount_msat_deduct(&f, amount) || !amount_msat_accumulate(&t, amount))
		return false;
	owed[from] = f;
	owed[!from] = t;
	return true;
}

bool sym_swap_apply(const struct sym_swap *swap,
		    struct amount_msat owed0[NUM_SIDES],
		    struct sym_lane_balance *lanes, enum side view)
{
	enum side owner = htlc_state_owner(swap->state);
	struct amount_msat give[NUM_SIDES], take[NUM_SIDES];
	struct amount_msat *g, *t;
	size_t n = tal_count(lanes);

	if (swap->give_lane == swap->take_lane
	    || swap->give_lane > n || swap->take_lane > n)
		return false;
	g = swap->give_lane ? lanes[swap->give_lane - 1].owed[view] : owed0;
	t = swap->take_lane ? lanes[swap->take_lane - 1].owed[view] : owed0;
	memcpy(give, g, sizeof(give));
	memcpy(take, t, sizeof(take));
	if (!owed_move(give, owner, swap->give)
	    || !owed_move(take, !owner, swap->take))
		return false;
	memcpy(g, give, sizeof(give));
	memcpy(t, take, sizeof(take));
	return true;
}
