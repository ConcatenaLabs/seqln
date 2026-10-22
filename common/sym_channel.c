#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <common/initial_channel.h>
#include <common/sym_channel.h>
#include <common/utils.h>

u16 sym_shared_delay(const struct channel *channel)
{
	return channel->config[LOCAL].to_self_delay
		> channel->config[REMOTE].to_self_delay
		? channel->config[LOCAL].to_self_delay
		: channel->config[REMOTE].to_self_delay;
}

struct amount_sat sym_dust_limit(const struct channel *channel)
{
	return amount_sat_greater(channel->config[LOCAL].dust_limit,
				  channel->config[REMOTE].dust_limit)
		? channel->config[LOCAL].dust_limit
		: channel->config[REMOTE].dust_limit;
}

void sym_channel_of(const struct channel *channel, struct sym_channel *sc)
{
	enum side opener = channel->opener;

	sym_channel_init(sc, &chainparams->genesis_blockhash,
			 &channel->funding,
			 &channel->basepoints[opener].delayed_payment,
			 &channel->basepoints[!opener].delayed_payment,
			 channel->channel_asset, sym_shared_delay(channel));
}

struct sym_state *sym_channel_state(const tal_t *ctx,
				    const struct channel *channel,
				    enum side side, u64 commit_num,
				    const struct sym_htlc *htlcs,
				    const char **err)
{
	struct pubkey pay[NUM_SIDES], htlc[NUM_SIDES];
	struct sym_output *outs;

	for (enum side s = 0; s < NUM_SIDES; s++) {
		pay[s] = channel->basepoints[s].payment;
		htlc[s] = channel->basepoints[s].htlc;
	}
	outs = sym_settlement(tmpctx, channel->funding_sats, channel->opener,
			      pay, htlc, channel->view[side].owed, htlcs,
			      sym_dust_limit(channel), err);
	if (!outs)
		return NULL;
	return sym_state_new(ctx, side, commit_num,
			     sym_state_num(commit_num, side == channel->opener),
			     outs);
}

void sym_channel_msg(const struct channel *channel, const struct sym_state *st,
		     struct sha256 *msg)
{
	struct sym_channel sc;
	struct sym_tree tree;

	sym_channel_of(channel, &sc);
	sym_state_tree_of(tmpctx, &sc, st, &tree);
	sym_upd_msg(&sc, &tree, msg);
}

bool sym_channel_check_sig(const struct channel *channel,
			   const struct sym_state *st, enum side signer,
			   const struct bip340sig *sig)
{
	struct sha256 msg;

	sym_channel_msg(channel, st, &msg);
	return tap_check_sig(&msg, &channel->basepoints[signer].delayed_payment,
			     sig);
}

struct bitcoin_tx *sym_channel_kickoff(const tal_t *ctx,
				       const struct channel *channel,
				       const u8 **wscript)
{
	struct sym_channel sc;

	sym_channel_of(channel, &sc);
	*wscript = bitcoin_redeem_2of2(ctx, &channel->funding_pubkey[LOCAL],
				       &channel->funding_pubkey[REMOTE]);
	return sym_kickoff_tx(ctx, chainparams, &channel->funding,
			      channel->funding_sats, *wscript, &sc);
}
