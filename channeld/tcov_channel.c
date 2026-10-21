#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/tapscript.h>
#include <channeld/channeld_htlc.h>
#include <channeld/channeld_wiregen.h>
#include <channeld/full_channel.h>
#include <channeld/tcov_channel.h>
#include <common/keyset.h>
#include <common/penalty_base.h>
#include <common/presign_templates.h>
#include <common/tcov_commit_tx.h>
#include <common/tcov_scripts.h>
#include <common/utils.h>

struct bitcoin_tx *tcov_channel_commit_tx(const tal_t *ctx,
					  const struct bitcoin_outpoint *funding,
					  struct amount_sat funding_sats,
					  const struct pubkey *local_funding_key,
					  const struct pubkey *remote_funding_key,
					  const struct channel *channel,
					  const struct keyset *keyset,
					  const struct pubkey *per_commitment_point,
					  struct amount_msat self_pay,
					  struct amount_msat other_pay,
					  const struct htlc **committed,
					  const struct htlc ***htlcmap,
					  struct wally_tx_output *direct_outputs[NUM_SIDES],
					  u64 commitment_number,
					  enum side side)
{
	struct tcov_htlc_out *outs = tal_arr(tmpctx, struct tcov_htlc_out,
					     tal_count(committed));
	const void **map;
	struct bitcoin_tx *tx;

	for (size_t i = 0; i < tal_count(committed); i++) {
		outs[i].owner = htlc_owner(committed[i]);
		outs[i].amount = committed[i]->amount;
		ripemd160(&outs[i].payment_ripemd,
			  committed[i]->rhash.u.u8,
			  sizeof(committed[i]->rhash.u.u8));
		outs[i].cltv_expiry = abs_locktime_to_blocks(&committed[i]->expiry);
		outs[i].handle = committed[i];
	}

	/* A later commitment takes from the opener what it has (NULL
	 * err_reason), as commit_tx does. */
	tx = tcov_commit_tx(ctx, funding, funding_sats,
			    channel->channel_asset,
			    local_funding_key, remote_funding_key,
			    channel->opener,
			    /* They specify our to_self_delay and v.v. */
			    channel->config[!side].to_self_delay,
			    keyset, per_commitment_point,
			    channel_feerate(channel, side),
			    channel->config[side].dust_limit,
			    self_pay, other_pay,
			    outs, &map, direct_outputs,
			    commitment_number ^ channel->commitment_number_obscurer,
			    side, NULL);
	*htlcmap = (const struct htlc **)map;
	return tx;
}

struct watchtower_blob *tcov_justice_blob(const tal_t *ctx,
					  const struct channel *channel,
					  const struct secret *per_commitment_secret,
					  const struct penalty_base *pbase)
{
	struct watchtower_blob *b = tal(ctx, struct watchtower_blob);
	struct pubkey point;
	struct keyset ks;
	struct tap_tree2 tree;
	struct bitcoin_outpoint op;
	u8 **wit;
	u8 *spk;

	if (!pubkey_from_secret(per_commitment_secret, &point)
	    || !derive_keyset(&point, &channel->basepoints[REMOTE],
			      &channel->basepoints[LOCAL], true, &ks))
		return tal_free(b);

	/* Their to_local, delayed by what we asked of them. */
	tcov_to_local_tree(tmpctx, &ks, &point,
			   channel->config[LOCAL].to_self_delay, &tree);
	spk = tap_tree2_scriptpubkey(tmpctx, &tree);

	b->kind = WT_TMPL_TCOV_REVOKE;
	b->commit_num = pbase->commitment_num;
	b->output_index = pbase->outnum;
	b->amount = pbase->amount;
	/* The cheater can sweep to_local, or a claim's D, after this many
	 * blocks: the tower must be first. */
	b->deadline_delta = channel->config[LOCAL].to_self_delay;
	b->wscript = tal_dup_talarr(b, u8, spk);

	/* With no to_local the template's input only carries the witness:
	 * output_index says there is none. */
	op.txid = pbase->txid;
	op.n = pbase->outnum == (u32)-1 ? 0 : pbase->outnum;
	b->tx = bitcoin_tx(b, chainparams, 1, 1, 0);
	bitcoin_tx_set_output_asset(b->tx, channel->channel_asset);
	bitcoin_tx_add_input(b->tx, &op, 0xFFFFFFFF, NULL, pbase->amount,
			     spk, NULL);
	bitcoin_tx_add_output(b->tx, tcov_revoke_dest(tmpctx, &ks), NULL,
			      pbase->amount);
	wit = tal_arr(tmpctx, u8 *, 1);
	wit[0] = tal_dup_arr(wit, u8, per_commitment_secret->data,
			     sizeof(per_commitment_secret->data), 0);
	wit = tap_tree2_witness(tmpctx, &tree, TCOV_LEAF_REVOKE, take(wit));
	bitcoin_tx_input_set_witness(b->tx, 0, take(wit));
	bitcoin_tx_finalize(b->tx);
	return b;
}
