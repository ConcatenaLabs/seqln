#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <common/psbt_keypath.h>
#include <common/presign_templates.h>
#include <common/status.h>
#include <common/utils.h>
#include <wally_bip32.h>

/* NOTE on WT_TMPL_STEAL_HTLC_TX_PENALTY (2nd-stage penalty):
 *
 * This spends an output on the COUNTERPARTY's HTLC-success/HTLC-timeout tx.
 * That tx's txid does not exist until the cheater broadcasts it post-breach,
 * so under SIGHASH_SINGLE|ANYONECANPAY (which binds the input outpoint) the
 * blob cannot be pre-signed at revoke_and_ack time.  We therefore do NOT emit
 * it from the revoke-time justice set; it is a device-online-only fallback.
 * The revoke-time set relies instead on the first-stage steal_htlc penalty
 * (kind 1), whose outpoint IS known (an output of the revoked commitment tx),
 * given a tight/bumpable fee so speculad sweeps the HTLC commitment output
 * before the counterparty's HTLC-tx can confirm.  The enum value is retained
 * so Phase C can slot the fallback in without reshaping the store schema.
 *
 * NOTE on TIER-2 (HTLC_TIMEOUT / HTLC_SUCCESS): the current-state HTLC
 * 2nd-stage txs are peer-co-signed (remote_htlc_sig) and, absent anchors, only
 * fee-bumpable via the peer's one signature.  Signing them needs the master-fd
 * sign_any_local_htlc_tx(146), which channeld cannot reach.  They are left to
 * the lightningd master-fd pre-sign orchestrator (onchain_presign.c, Phase C);
 * this module provides the tx SHAPE (via presign_sweep_tx for the sweep of
 * their output) but channeld does not pre-sign them in Phase B.
 */

struct bitcoin_tx *presign_sweep_tx(const tal_t *ctx,
				    const struct bitcoin_outpoint *outpoint,
				    struct amount_sat in_sats,
				    const u8 *wscript,
				    u32 input_sequence,
				    u32 locktime,
				    u32 feerate_perkw,
				    struct amount_sat dust_limit,
				    u32 *final_index,
				    struct ext_key *final_ext_key,
				    const u8 *final_scriptpubkey)
{
	struct bitcoin_tx *tx;
	size_t weight;
	struct amount_sat fee, min_out, amt;

	if (amount_sat_less_eq(in_sats, dust_limit)) {
		status_debug("presign_sweep_tx: input %s is dust, skipping",
			     fmt_amount_sat(tmpctx, in_sats));
		return NULL;
	}

	tx = bitcoin_tx(ctx, chainparams, 1, 1, locktime);
	bitcoin_tx_add_input(tx, outpoint, input_sequence,
			     NULL, in_sats, NULL, wscript);

	bitcoin_tx_add_output(tx, final_scriptpubkey, NULL, in_sats);
	assert((final_index == NULL) == (final_ext_key == NULL));
	if (final_index) {
		size_t script_len = tal_bytelen(final_scriptpubkey);
		bool is_tr = is_p2tr(final_scriptpubkey, script_len, NULL);
		if (!psbt_add_keypath_to_last_output(tx, *final_index,
						     final_ext_key, is_tr)) {
			status_broken("presign_sweep_tx: cannot add final keypath");
			return tal_free(tx);
		}
	}

	/* Worst-case sig is 73 bytes (matches penalty_tx_create /
	 * onchaind_tx_unsigned weight model exactly). */
	weight = bitcoin_tx_weight(tx) + 1 + 3 + 73 + 0 + tal_count(wscript);
	weight += elements_tx_overhead(chainparams, 1, 1);
	fee = amount_tx_fee(feerate_perkw, weight);

	if (!amount_sat_add(&min_out, dust_limit, fee)) {
		status_broken("presign_sweep_tx: overflow dust+fee");
		return tal_free(tx);
	}

	if (amount_sat_less(in_sats, min_out)) {
		/* Use the minimum possible fee here; if it doesn't
		 * propagate, speculad RBFs (SINGLE|ACP) or it's a rounding
		 * dust case. */
		fee = amount_tx_fee(FEERATE_FLOOR, weight);
	}

	if (!amount_sat_sub(&amt, in_sats, fee)) {
		status_broken("presign_sweep_tx: can't afford minimal feerate");
		return tal_free(tx);
	}
	bitcoin_tx_output_set_amount(tx, 0, amt);
	bitcoin_tx_finalize(tx);

	return tx;
}

struct presign_template *presign_template_new(const tal_t *ctx,
					      enum wt_tmpl_kind kind,
					      const struct bitcoin_outpoint *outpoint,
					      struct amount_sat in_sats,
					      const u8 *wscript,
					      u32 input_sequence,
					      u32 locktime,
					      u32 deadline_delta,
					      u32 feerate_perkw,
					      struct amount_sat dust_limit,
					      u32 *final_index,
					      struct ext_key *final_ext_key,
					      const u8 *final_scriptpubkey)
{
	struct presign_template *t = tal(ctx, struct presign_template);

	t->kind = kind;
	t->amount = in_sats;
	t->deadline_delta = deadline_delta;
	t->wscript = tal_dup_talarr(t, u8, wscript);
	t->tx = presign_sweep_tx(t, outpoint, in_sats, t->wscript,
				 input_sequence, locktime, feerate_perkw,
				 dust_limit, final_index, final_ext_key,
				 final_scriptpubkey);
	if (!t->tx)
		return tal_free(t);
	return t;
}
