#include "config.h"
#include <assert.h>
#include <bitcoin/script.h>
#include <common/close_tx.h>
#include <common/permute_tx.h>
#include <common/psbt_keypath.h>
#include <wire/wire.h>

static struct bitcoin_tx *close_tx_of(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   u32 *local_wallet_index,
				   const struct ext_key *local_wallet_ext_key,
				   const u8 *our_script,
				   const u8 *their_script,
				   const u8 *funding_wscript,
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   struct amount_sat to_us,
				   struct amount_sat to_them,
				   struct amount_sat dust_limit,
				   const u8 *channel_asset,
				   const struct close_lane *lanes)
{
	struct bitcoin_tx *tx;
	size_t num_outputs = 0, nlanes = tal_count(lanes);
	struct amount_sat total_out, lane0_out = AMOUNT_SAT(0);
	u8 *script;

	/* BOLT #3:
	 * ## Legacy Closing Transaction
	 *...
	 * ### Requirements
	 *
	 * Each node offering a signature:
	 *   - MUST round each output down to whole satoshis.
	 *   - MUST subtract the fee given by `fee_satoshis` from the output to the funder.
	 *   - MUST remove any output below its own `dust_limit_satoshis`.
	 *   - MAY eliminate its own output.
	 */
	assert(amount_sat_add(&total_out, to_us, to_them));
	assert(amount_sat_less_eq(total_out, funding_sats));

	/* BOLT #3:
	 *
	 * ## Legacy Closing Transaction
	 *
	 * This variant is used for `closing_signed` messages (i.e. where
	 * `option_simple_close` is not negotiated).
	 *
	 * Note that there are two possible variants for each node.
	 *
	 * * version: 2
	 * * locktime: 0
	 * * txin count: 1
	 */
	/* Now create close tx: one input, two outputs. */
	/* SEQUENTIA: and one input and up to two outputs per further lane of a
	 * channel of several assets, and the fee output. */
	tx = bitcoin_tx(ctx, chainparams, 1 + nlanes, 3 + 2 * nlanes, 0);

	/* An asset channel closes in its own asset: the funding input, both
	 * outputs and the explicit fee.  Must precede the input and outputs. */
	bitcoin_tx_set_output_asset(tx, channel_asset);

	/* Our input spends the anchor tx output. */
	bitcoin_tx_add_input(tx, funding,
			     BITCOIN_TX_DEFAULT_SEQUENCE, NULL,
			     funding_sats, NULL, funding_wscript);

	/* SEQUENTIA: each further lane's funding output, in its asset (the
	 * input's asset is the output asset set when it is added). */
	for (size_t l = 0; l < nlanes; l++) {
		bitcoin_tx_set_output_asset(tx, lanes[l].asset);
		bitcoin_tx_add_input(tx, &lanes[l].funding,
				     BITCOIN_TX_DEFAULT_SEQUENCE, NULL,
				     lanes[l].funding_sats, NULL,
				     funding_wscript);
	}
	bitcoin_tx_set_output_asset(tx, channel_asset);

	if (amount_sat_greater_eq(to_us, dust_limit)) {
		script = tal_dup_talarr(tx, u8, our_script);
		/* One output is to us. */
		bitcoin_tx_add_output(tx, script, NULL, to_us);
		lane0_out = to_us;
		assert((local_wallet_index == NULL) == (local_wallet_ext_key == NULL));
		if (local_wallet_index) {
			size_t script_len = tal_bytelen(script);
			/* Should not happen! */
			if (!psbt_add_keypath_to_last_output(
				    tx, *local_wallet_index, local_wallet_ext_key,
				    is_p2tr(script, script_len, NULL)))
				return tal_free(tx);
                }
		num_outputs++;
	}

	if (amount_sat_greater_eq(to_them, dust_limit)) {
		script = tal_dup_talarr(tx, u8, their_script);
		/* Other output is to them. */
		bitcoin_tx_add_output(tx, script, NULL, to_them);
		if (!amount_sat_add(&lane0_out, lane0_out, to_them))
			abort();
		num_outputs++;
	}

	/* Can't have no outputs at all! */
	if (num_outputs == 0)
		return tal_free(tx);

	permute_outputs(tx, NULL, NULL);

	if (!nlanes) {
		bitcoin_tx_finalize(tx);
		assert(bitcoin_tx_check(tx));
		return tx;
	}

	/* SEQUENTIA: each further lane's shares, after lane 0's. */
	for (size_t l = 0; l < nlanes; l++) {
		struct amount_sat amt[2] = { lanes[l].to_us, lanes[l].to_them };
		const u8 *spk[2] = { our_script, their_script };
		struct amount_sat sum;
		int first;

		if (!amount_sat_add(&sum, amt[0], amt[1])
		    || !amount_sat_eq(sum, lanes[l].funding_sats))
			return tal_free(tx);
		/* The lower (amount, script) first: both sides build the
		 * same transaction. */
		if (!amount_sat_eq(amt[0], amt[1]))
			first = amount_sat_less(amt[0], amt[1]) ? 0 : 1;
		else {
			size_t l0 = tal_bytelen(spk[0]), l1 = tal_bytelen(spk[1]);
			int c = memcmp(spk[0], spk[1], l0 < l1 ? l0 : l1);
			first = (c < 0 || (c == 0 && l0 <= l1)) ? 0 : 1;
		}
		bitcoin_tx_set_output_asset(tx, lanes[l].asset);
		for (int k = 0; k < 2; k++) {
			int s = k == 0 ? first : !first;

			if (amount_sat_is_zero(amt[s]))
				continue;
			bitcoin_tx_add_output(tx,
					      tal_dup_talarr(tx, u8, spk[s]),
					      NULL, amt[s]);
			if (s == 0 && local_wallet_index
			    && !psbt_add_keypath_to_last_output(
				    tx, *local_wallet_index,
				    local_wallet_ext_key,
				    is_p2tr(spk[s], tal_bytelen(spk[s]), NULL)))
				return tal_free(tx);
		}
	}

	/* The fee: the rest of lane 0, in the channel asset.  Not
	 * bitcoin_tx_finalize, which would count every lane's input. */
	bitcoin_tx_set_output_asset(tx, channel_asset);
	if (!amount_sat_sub(&total_out, funding_sats, lane0_out))
		return tal_free(tx);
	bitcoin_tx_add_output(tx, NULL, NULL, total_out);
	assert(bitcoin_tx_check(tx));
	return tx;
}

struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   u32 *local_wallet_index,
				   const struct ext_key *local_wallet_ext_key,
				   const u8 *our_script,
				   const u8 *their_script,
				   const u8 *funding_wscript,
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   struct amount_sat to_us,
				   struct amount_sat to_them,
				   struct amount_sat dust_limit,
				   const u8 *channel_asset)
{
	return close_tx_of(ctx, chainparams, local_wallet_index,
			   local_wallet_ext_key, our_script, their_script,
			   funding_wscript, funding, funding_sats, to_us,
			   to_them, dust_limit, channel_asset, NULL);
}

struct bitcoin_tx *create_close_tx_lanes(const tal_t *ctx,
					 const struct chainparams *chainparams,
					 u32 *local_wallet_index,
					 const struct ext_key *local_wallet_ext_key,
					 const u8 *our_script,
					 const u8 *their_script,
					 const u8 *funding_wscript,
					 const struct bitcoin_outpoint *funding,
					 struct amount_sat funding_sats,
					 struct amount_sat to_us,
					 struct amount_sat to_them,
					 struct amount_sat dust_limit,
					 const u8 *channel_asset,
					 const struct close_lane *lanes)
{
	return close_tx_of(ctx, chainparams, local_wallet_index,
			   local_wallet_ext_key, our_script, their_script,
			   funding_wscript, funding, funding_sats, to_us,
			   to_them, dust_limit, channel_asset, lanes);
}

void towire_close_lane(u8 **pptr, const struct close_lane *lane)
{
	towire_u8_array(pptr, lane->asset, sizeof(lane->asset));
	towire_bitcoin_outpoint(pptr, &lane->funding);
	towire_amount_sat(pptr, lane->funding_sats);
	towire_amount_sat(pptr, lane->to_us);
	towire_amount_sat(pptr, lane->to_them);
}

void fromwire_close_lane(const u8 **cursor, size_t *max,
			 struct close_lane *lane)
{
	fromwire_u8_array(cursor, max, lane->asset, sizeof(lane->asset));
	fromwire_bitcoin_outpoint(cursor, max, &lane->funding);
	lane->funding_sats = fromwire_amount_sat(cursor, max);
	lane->to_us = fromwire_amount_sat(cursor, max);
	lane->to_them = fromwire_amount_sat(cursor, max);
}
