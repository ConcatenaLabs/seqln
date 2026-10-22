#include "config.h"
#include <bitcoin/psbt.h>
#include <channeld/channeld.h>
#include <channeld/channeld_htlc.h>
#include <channeld/full_channel.h>
#include <channeld/sym_channeld.h>
#include <common/status.h>
#include <common/sym_channel.h>
#include <common/utils.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>

struct sym_state *sym_channeld_state(const tal_t *ctx,
				     const struct channel *channel,
				     enum side side, u64 commit_num)
{
	const struct htlc **committed
		= channel_committed_htlcs(tmpctx, channel, side);
	struct sym_htlc *htlcs = tal_arr(tmpctx, struct sym_htlc,
					 tal_count(committed));
	struct sym_state *st;
	const char *err;

	for (size_t i = 0; i < tal_count(committed); i++) {
		htlcs[i].owner = htlc_owner(committed[i]);
		htlcs[i].amount = committed[i]->amount;
		ripemd160(&htlcs[i].payment_ripemd, committed[i]->rhash.u.u8,
			  sizeof(committed[i]->rhash.u.u8));
		htlcs[i].cltv_expiry = abs_locktime_to_blocks(&committed[i]->expiry);
		htlcs[i].handle = committed[i];
	}
	st = sym_channel_state(ctx, channel, side, commit_num, htlcs, &err);
	if (!st)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Symmetric state %s %"PRIu64": %s",
			      side_to_str(side), commit_num, err);
	return st;
}

void sym_channeld_sign(const struct channel *channel, struct sym_state *st,
		       const struct hsm_htlc *htlcs)
{
	const u8 *msg;

	msg = towire_hsmd_sign_sym_state(NULL, &channel->funding,
					 channel->opener == LOCAL,
					 &channel->basepoints[REMOTE].delayed_payment,
					 channel->channel_asset,
					 sym_shared_delay(channel), st, htlcs);
	msg = hsm_req(tmpctx, take(msg));
	if (!fromwire_hsmd_sign_sym_state_reply(msg, &st->sig[LOCAL]))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad sign_sym_state reply %s", tal_hex(tmpctx, msg));
	st->has_sig[LOCAL] = true;
}

void sym_channeld_kickoff_sig(const struct channel *channel,
			      struct bitcoin_signature *sig)
{
	const u8 *wscript, *msg;
	struct bitcoin_tx *ko = sym_channel_kickoff(tmpctx, channel, &wscript);

	msg = towire_hsmd_sign_sym_kickoff(NULL, ko,
					   &channel->funding_pubkey[REMOTE]);
	msg = hsm_req(tmpctx, take(msg));
	if (!fromwire_hsmd_sign_tx_reply(msg, sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad sign_sym_kickoff reply %s", tal_hex(tmpctx, msg));
}
