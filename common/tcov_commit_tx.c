#include "config.h"
#include <assert.h>
#include <bitcoin/script.h>
#include <common/htlc_trim.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/permute_tx.h>
#include <common/status.h>
#include <common/tcov_commit_tx.h>
#include <common/tcov_scripts.h>

/* The fee and the trimming are an `option_static_remotekey` channel's: no
 * anchors, and the HTLC transaction fee BOLT 3 counts into the trimming
 * threshold.  A covenant claim costs more than that notional fee, so an HTLC
 * kept by this threshold is no cheaper to claim than on any other type. */
#define TCOV_ANCHORS false
#define TCOV_ZERO_FEE_HTLC false

bool tcov_credit_init(const tal_t *ctx,
		      const struct channel_id *cid,
		      enum side provider,
		      const struct pubkey *provider_funding_key,
		      const struct pubkey *holder_payment_basepoint,
		      u16 window,
		      struct tcov_credit *credit)
{
	credit->provider = provider;
	credit->window = window;
	return credit_params_init(ctx, cid, provider_funding_key,
				  holder_payment_basepoint, &credit->params);
}

struct bitcoin_tx *tcov_commit_tx(const tal_t *ctx,
				  const struct bitcoin_outpoint *funding,
				  struct amount_sat funding_sats,
				  const u8 *channel_asset,
				  const struct pubkey *local_funding_key,
				  const struct pubkey *remote_funding_key,
				  enum side opener,
				  u16 to_self_delay,
				  const struct keyset *keyset,
				  const struct pubkey *per_commitment_point,
				  u32 feerate_per_kw,
				  struct amount_sat dust_limit,
				  struct amount_msat self_pay,
				  struct amount_msat other_pay,
				  const struct tcov_htlc_out *htlcs,
				  const void ***htlcmap,
				  struct wally_tx_output *direct_outputs[NUM_SIDES],
				  u64 obscured_commitment_number,
				  enum side side,
				  const struct tcov_credit *credit,
				  char **err_reason)
{
	struct amount_sat base_fee;
	struct amount_msat total_pay;
	struct bitcoin_tx *tx;
	size_t n, untrimmed;
	u32 *cltvs;
	/* Markers for the two direct outputs, distinct from any handle. */
	static const char dummy_to_local, dummy_to_remote;
	const void **map;
	const u8 *funding_wscript = bitcoin_redeem_2of2(tmpctx,
							local_funding_key,
							remote_funding_key);
	u32 sequence;

	if (!amount_msat_add(&total_pay, self_pay, other_pay))
		abort();
	assert(!amount_msat_greater_sat(total_pay, funding_sats));

	untrimmed = 0;
	for (size_t i = 0; i < tal_count(htlcs); i++)
		untrimmed += !htlc_is_trimmed(htlcs[i].owner, htlcs[i].amount,
					      feerate_per_kw, dust_limit, side,
					      TCOV_ANCHORS, TCOV_ZERO_FEE_HTLC);

	base_fee = commit_tx_base_fee(feerate_per_kw, untrimmed,
				      TCOV_ANCHORS, TCOV_ZERO_FEE_HTLC);
	if (!try_subtract_fee(opener, side, base_fee, &self_pay, &other_pay)
	    && err_reason) {
		/* The initial commitment refuses a fee the opener cannot pay;
		 * later ones, as commit_tx, take what the opener has. */
		*err_reason = "Funder cannot afford fee on initial commitment transaction";
		return NULL;
	}

	tx = bitcoin_tx(ctx, chainparams, 1, untrimmed + 2, 0);
	/* Every output, and the fee output, in the channel's asset. */
	bitcoin_tx_set_output_asset(tx, channel_asset);

	map = tal_arr(tx, const void *, tx->wtx->outputs_allocation_len);
	cltvs = tal_arr(tmpctx, u32, tx->wtx->outputs_allocation_len);

	n = 0;
	/* BOLT 3's order of addition: offered HTLCs, received HTLCs,
	 * to_local, to_remote; permute_outputs sorts them afterwards. */
	for (int pass = 0; pass < 2; pass++) {
		for (size_t i = 0; i < tal_count(htlcs); i++) {
			const struct tcov_htlc_out *h = &htlcs[i];
			struct amount_sat amt;
			struct tap_tree2 tree;
			bool offered = (h->owner == side);

			if (offered != (pass == 0))
				continue;
			if (htlc_is_trimmed(h->owner, h->amount, feerate_per_kw,
					    dust_limit, side, TCOV_ANCHORS,
					    TCOV_ZERO_FEE_HTLC))
				continue;
			amt = amount_msat_to_sat_round_down(h->amount);
			if (offered)
				tcov_offered_htlc_tree(tmpctx, keyset,
						       per_commitment_point,
						       to_self_delay,
						       channel_asset,
						       &h->payment_ripemd,
						       h->lock_point,
						       h->cltv_expiry, amt,
						       &tree);
			else
				tcov_received_htlc_tree(tmpctx, keyset,
							per_commitment_point,
							to_self_delay,
							channel_asset,
							&h->payment_ripemd,
							h->lock_point,
							h->cltv_expiry, amt,
							&tree);
			bitcoin_tx_add_output(tx,
					      tap_tree2_scriptpubkey(tmpctx, &tree),
					      NULL, amt);
			map[n] = h->handle;
			cltvs[n] = h->cltv_expiry;
			n++;
		}
	}

	if (amount_msat_greater_eq_sat(self_pay, dust_limit)) {
		struct tap_tree2 tree;
		struct amount_sat v = amount_msat_to_sat_round_down(self_pay);

		/* SEQUENTIA: the provider's own balance carries CLAIM. */
		if (credit && side == credit->provider)
			credit_to_local_tree(tmpctx, keyset,
					     per_commitment_point,
					     to_self_delay, &credit->params,
					     v, &tree);
		else
			tcov_to_local_tree(tmpctx, keyset,
					   per_commitment_point,
					   to_self_delay, &tree);
		bitcoin_tx_add_output(tx, tap_tree2_scriptpubkey(tmpctx, &tree),
				      NULL, v);
		map[n] = &dummy_to_local;
		n++;
	}

	if (amount_msat_greater_eq_sat(other_pay, dust_limit)) {
		struct amount_sat v = amount_msat_to_sat_round_down(other_pay);
		const u8 *spk;

		/* SEQUENTIA: on the holder's commitment the provider's balance
		 * carries CLAIM, and the provider waits the holder's delay. */
		if (credit && side != credit->provider) {
			struct tap_tree2 tree;

			credit_to_remote_tree(tmpctx,
					      &keyset->other_payment_key,
					      credit->window, &credit->params,
					      v, &tree);
			spk = tap_tree2_scriptpubkey(tmpctx, &tree);
		} else
			spk = scriptpubkey_p2wpkh(tmpctx,
						  &keyset->other_payment_key);
		bitcoin_tx_add_output(tx, spk, NULL, v);
		map[n] = &dummy_to_remote;
		n++;
	}

	/* The reserve, at least the dust limit, keeps one output. */
	assert(n > 0);
	tal_resize(&map, n);
	permute_outputs(tx, cltvs, map);

	assert(tx->wtx->version == 2);
	bitcoin_tx_set_locktime(tx,
	    (0x20000000 | (obscured_commitment_number & 0xFFFFFF)));
	sequence = (0x80000000 | ((obscured_commitment_number>>24) & 0xFFFFFF));
	bitcoin_tx_add_input(tx, funding, sequence, NULL, funding_sats, NULL,
			     funding_wscript);

	if (direct_outputs)
		direct_outputs[LOCAL] = direct_outputs[REMOTE] = NULL;
	for (size_t i = 0; i < n; i++) {
		if (map[i] == &dummy_to_local) {
			map[i] = NULL;
			if (direct_outputs)
				direct_outputs[LOCAL] = tx->wtx->outputs + i;
		} else if (map[i] == &dummy_to_remote) {
			map[i] = NULL;
			if (direct_outputs)
				direct_outputs[REMOTE] = tx->wtx->outputs + i;
		}
	}
	if (htlcmap)
		*htlcmap = map;

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}
