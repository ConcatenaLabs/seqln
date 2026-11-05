#include "config.h"
#include <bitcoin/script.h>
#include <common/memleak.h>
#include <common/sym_scripts.h>
#include <common/timeout.h>
#include <lightningd/channel.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/sym_clock.h>
#include <lightningd/symmetric.h>
#include <wallet/wallet.h>

void sym_clock_attach(struct channel *channel,
		      const struct bitcoin_outpoint *issuer,
		      const u32 *seed_outnum)
{
	channel->sym_clock = tal(channel, struct sym_clock_funding);
	channel->sym_clock->issuer = *issuer;
	channel->sym_clock->seed_known = seed_outnum != NULL;
	channel->sym_clock->seed_outnum = seed_outnum ? *seed_outnum : 0;
	wallet_sym_clock_save(channel->peer->ld->wallet, channel);
}

static const u8 *funding_wscript(const struct channel *channel)
{
	return bitcoin_redeem_2of2(tmpctx, &channel->local_funding_pubkey,
				   &channel->channel_info.remote_fundingkey);
}

u8 *sym_clock_seed_of(const tal_t *ctx, const struct channel *channel)
{
	struct sym_channel sc;

	sym_channel_from(channel, &sc);
	return sym_clock_seed(ctx, &sc, &channel->sym_clock->issuer,
			      funding_wscript(channel), channel->funding_sats);
}

/* Forgotten after the funding watch that found it has returned: it is
 * freed with the channel. */
static void forget_channel(struct channel *channel)
{
	if (channel->opener == REMOTE
	    && channel->state == CHANNELD_AWAITING_LOCKIN)
		channel_fail_forget(channel, "Its funding does not issue the"
				    " marker into the seed");
}

bool sym_clock_funding_found(struct channel *channel,
			     const struct bitcoin_tx *tx)
{
	struct sym_clock_funding *c = channel->sym_clock;
	struct lightningd *ld = channel->peer->ld;
	const char *err;
	u32 outnum;

	if (!c || c->seed_known)
		return true;

	err = sym_clock_check_funding(tmpctx, tx, &channel->funding,
				      scriptpubkey_p2wsh(tmpctx,
							 funding_wscript(channel)),
				      channel->channel_asset,
				      channel->funding_sats, &c->issuer,
				      sym_clock_seed_of(tmpctx, channel),
				      &outnum);
	if (err) {
		log_broken(channel->log, "Funding %s is not this settle-clock"
			   " channel's: %s",
			   fmt_bitcoin_txid(tmpctx, &channel->funding.txid),
			   err);
		/* The opener checked its own funding before signing it. */
		if (channel->opener == REMOTE)
			notleak(new_reltimer(ld->timers, channel,
					     time_from_sec(0),
					     forget_channel, channel));
		return false;
	}
	c->seed_known = true;
	c->seed_outnum = outnum;
	wallet_sym_clock_save(ld->wallet, channel);
	log_info(channel->log, "Funding issues the marker into the seed,"
		 " output %u", outnum);
	return true;
}
