#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/locktime.h>
#include <bitcoin/script.h>
#include <channeld/channeld.h>
#include <channeld/channeld_wiregen.h>
#include <channeld/watchtower.h>
#include <common/features.h>
#include <common/htlc_tx.h>
#include <common/keyset.h>
#include <common/penalty_base.h>
#include <common/presign_templates.h>
#include <common/psbt_keypath.h>
#include <common/status.h>
#include <hsmd/hsmd_wiregen.h>

static const u8 ONE = 0x1;

const struct bitcoin_tx *
penalty_tx_create(const tal_t *ctx,
		  const struct channel *channel,
		  u32 penalty_feerate,
		  u32 *final_index,
		  struct ext_key *final_ext_key,
		  u8 *final_scriptpubkey,
		  const struct secret *revocation_preimage,
		  const struct bitcoin_txid *commitment_txid,
		  s16 to_them_outnum, struct amount_sat to_them_sats,
		  int hsm_fd)
{
	u8 *wscript;
	struct bitcoin_tx *tx;
	struct keyset keyset;
	size_t weight;
	const u8 *msg;
	struct amount_sat fee, min_out, amt;
	struct bitcoin_signature sig;
	u32 locktime = 0;
	bool option_static_remotekey = channel_has(channel, OPT_STATIC_REMOTEKEY);
	u8 **witness;
	u32 remote_to_self_delay = channel->config[REMOTE].to_self_delay;
	const struct amount_sat dust_limit = channel->config[LOCAL].dust_limit;
	BUILD_ASSERT(sizeof(struct secret) == sizeof(*revocation_preimage));
	const struct secret remote_per_commitment_secret = *revocation_preimage;
	struct pubkey remote_per_commitment_point;
	const struct basepoints *basepoints = channel->basepoints;
	struct bitcoin_outpoint outpoint;

	if (to_them_outnum == -1 ||
	    amount_sat_less_eq(to_them_sats, dust_limit)) {
		status_debug(
			    "Cannot create penalty transaction because there "
			    "is no non-dust to_them output in the commitment.");
		return NULL;
	}

	outpoint.txid = *commitment_txid;
	outpoint.n = to_them_outnum;

	if (!pubkey_from_secret(&remote_per_commitment_secret, &remote_per_commitment_point))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed derive from per_commitment_secret %s",
			      fmt_secret(tmpctx, &remote_per_commitment_secret));

	if (!derive_keyset(&remote_per_commitment_point,
			   &basepoints[REMOTE],
			   &basepoints[LOCAL],
			   option_static_remotekey,
			   &keyset))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed deriving keyset");

	/* FIXME: csv_lock */
	wscript = bitcoin_wscript_to_local(tmpctx, remote_to_self_delay, 1,
					   &keyset.self_revocation_key,
					   &keyset.self_delayed_payment_key);

	tx = bitcoin_tx(ctx, chainparams, 1, 1, locktime);
	bitcoin_tx_add_input(tx, &outpoint, 0xFFFFFFFF,
			     NULL, to_them_sats, NULL, wscript);

	bitcoin_tx_add_output(tx, final_scriptpubkey, NULL, to_them_sats);
	assert((final_index == NULL) == (final_ext_key == NULL));
	if (final_index) {
		size_t script_len = tal_bytelen(final_scriptpubkey);
		bool is_tr = is_p2tr(final_scriptpubkey, script_len, NULL);
		if (!psbt_add_keypath_to_last_output(tx, *final_index,
						     final_ext_key, is_tr))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Cannot add final keypath?");

        }

	/* Worst-case sig is 73 bytes */
	weight = bitcoin_tx_weight(tx) + 1 + 3 + 73 + 0 + tal_count(wscript);
	weight += elements_tx_overhead(chainparams, 1, 1);
	fee = amount_tx_fee(penalty_feerate, weight);

	if (!amount_sat_add(&min_out, dust_limit, fee))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot add dust_limit %s and fee %s",
			      fmt_amount_sat(tmpctx, dust_limit),
			      fmt_amount_sat(tmpctx, fee));

	if (amount_sat_less(to_them_sats, min_out)) {
		/* FIXME: We should use SIGHASH_NONE so others can take it */
		/* We use the minimum possible fee here; if it doesn't
		 * propagate, who cares? */
		fee = amount_tx_fee(FEERATE_FLOOR, weight);
	}

	/* This can only happen if feerate_floor() is still too high; shouldn't
	 * happen! */
	if (!amount_sat_sub(&amt, to_them_sats, fee)) {
		amt = dust_limit;
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			   "TX can't afford minimal feerate"
			   "; setting output to %s",
			   fmt_amount_sat(tmpctx, amt));
	}
	bitcoin_tx_output_set_amount(tx, 0, amt);
	bitcoin_tx_finalize(tx);

	u8 *hsm_sign_msg =
	    towire_hsmd_sign_penalty_to_us(tmpctx, &remote_per_commitment_secret,
					  tx, wscript);

	msg = hsm_req(tmpctx, hsm_sign_msg);
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading sign_tx_reply: %s", tal_hex(tmpctx, msg));

	witness = bitcoin_witness_sig_and_element(tx, &sig, &ONE, sizeof(ONE),
						  wscript);

	bitcoin_tx_input_set_witness(tx, 0, take(witness));
	return tx;
}

/* Sign one penalty (input 0 of tx spends wscript via the revocation branch)
 * at the channel HSM fd, attach witness (<sig> <witness_elem>) and package it
 * as a watchtower_blob (allocated off ctx).  Fail-soft: on any HSM/dust
 * failure returns NULL and the caller skips this member (never fatal -- B6). */
static struct watchtower_blob *make_penalty_blob(const tal_t *ctx,
			      enum wt_tmpl_kind kind,
			      u64 commit_num,
			      u32 output_index,
			      struct amount_sat amount,
			      u32 deadline_delta,
			      struct bitcoin_tx *tx,
			      const u8 *wscript,
			      const struct secret *per_commitment_secret,
			      const u8 *witness_elem,
			      size_t witness_elem_len)
{
	const u8 *msg;
	struct bitcoin_signature sig;
	u8 **witness;
	u8 *hsm_sign_msg;
	struct watchtower_blob *blob;

	if (!tx)
		return NULL;

	hsm_sign_msg = towire_hsmd_sign_penalty_to_us(tmpctx,
						      per_commitment_secret,
						      tx, wscript);
	msg = hsm_req(tmpctx, hsm_sign_msg);
	if (!msg || !fromwire_hsmd_sign_tx_reply(msg, &sig)) {
		/* B6 fail-soft: device REJECT / zero-length is logged, never
		 * fatal.  This justice member is simply omitted from the set. */
		status_broken("watchtower: no signature for penalty kind %u"
			      " output %u; omitting from justice set",
			      kind, output_index);
		return NULL;
	}

	witness = bitcoin_witness_sig_and_element(tx, &sig, witness_elem,
						  witness_elem_len, wscript);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));

	blob = tal(ctx, struct watchtower_blob);
	blob->kind = kind;
	blob->commit_num = commit_num;
	blob->output_index = output_index;
	blob->amount = amount;
	blob->deadline_delta = deadline_delta;
	blob->wscript = tal_dup_talarr(blob, u8, wscript);
	blob->tx = tal_steal(blob, tx);
	return blob;
}

struct watchtower_blob **
build_watchtower_justice_set(const tal_t *ctx,
			     const struct channel *channel,
			     u32 penalty_feerate,
			     u32 *final_index,
			     struct ext_key *final_ext_key,
			     u8 *final_scriptpubkey,
			     const struct secret *revocation_preimage,
			     const struct penalty_base *pbase,
			     int hsm_fd)
{
	struct watchtower_blob **blobs = tal_arr(ctx, struct watchtower_blob *, 0);
	struct keyset keyset;
	bool option_static_remotekey = channel_has(channel, OPT_STATIC_REMOTEKEY);
	bool anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS_DEPRECATED);
	bool anchors_zero_fee = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);
	u32 remote_to_self_delay = channel->config[REMOTE].to_self_delay;
	const struct amount_sat dust_limit = channel->config[LOCAL].dust_limit;
	const struct basepoints *basepoints = channel->basepoints;
	const struct secret secret = *revocation_preimage;
	struct pubkey remote_per_commitment_point;
	struct watchtower_blob *b;
	u8 der[PUBKEY_CMPR_LEN];

	if (!pbase)
		return blobs;

	if (!pubkey_from_secret(&secret, &remote_per_commitment_point)) {
		status_broken("watchtower: bad per_commitment_secret; "
			      "no justice set");
		return blobs;
	}
	if (!derive_keyset(&remote_per_commitment_point, &basepoints[REMOTE],
			   &basepoints[LOCAL], option_static_remotekey,
			   &keyset)) {
		status_broken("watchtower: keyset derivation failed; "
			      "no justice set");
		return blobs;
	}

	/* (1) to_local penalty (witness <sig> 0x01), immediate. */
	if (pbase->outnum != (u32)-1
	    && amount_sat_greater(pbase->amount, dust_limit)) {
		struct bitcoin_outpoint outpoint;
		u8 *wscript;
		struct bitcoin_tx *tx;

		outpoint.txid = pbase->txid;
		outpoint.n = pbase->outnum;
		wscript = bitcoin_wscript_to_local(tmpctx, remote_to_self_delay,
						   1, &keyset.self_revocation_key,
						   &keyset.self_delayed_payment_key);
		tx = presign_sweep_tx(tmpctx, &outpoint, pbase->amount, wscript,
				      0xFFFFFFFF, 0, penalty_feerate, dust_limit,
				      true /* SINGLE|ACP: no fee deduction */,
				      channel->channel_asset,
				      final_index, final_ext_key,
				      final_scriptpubkey);
		b = make_penalty_blob(blobs, WT_TMPL_TO_LOCAL_PENALTY,
				      pbase->commitment_num, pbase->outnum,
				      pbase->amount, 0, tx, wscript, &secret,
				      &ONE, sizeof(ONE));
		if (b)
			tal_arr_expand(&blobs, b);
	}

	/* (2) one steal_htlc penalty per revoked HTLC output
	 * (witness <sig> <revocationpubkey>), immediate. */
	pubkey_to_der(der, &keyset.self_revocation_key);
	for (size_t i = 0; i < tal_count(pbase->htlcs); i++) {
		const struct penalty_htlc *h = &pbase->htlcs[i];
		struct bitcoin_outpoint outpoint;
		u8 *wscript;
		struct bitcoin_tx *tx;

		if (amount_sat_less_eq(h->amount, dust_limit))
			continue;

		if (h->remote_offered) {
			wscript = bitcoin_wscript_htlc_offer(tmpctx,
							     &keyset.self_htlc_key,
							     &keyset.other_htlc_key,
							     &h->payment_hash,
							     &keyset.self_revocation_key,
							     anchor_outputs,
							     anchors_zero_fee);
		} else {
			struct abs_locktime abstimeout;
			if (!blocks_to_abs_locktime(h->cltv_expiry, &abstimeout)) {
				status_broken("watchtower: bad htlc cltv %u; "
					      "skipping steal_htlc", h->cltv_expiry);
				continue;
			}
			wscript = bitcoin_wscript_htlc_receive(tmpctx, &abstimeout,
							       &keyset.self_htlc_key,
							       &keyset.other_htlc_key,
							       &h->payment_hash,
							       &keyset.self_revocation_key,
							       anchor_outputs,
							       anchors_zero_fee);
		}

		outpoint.txid = pbase->txid;
		outpoint.n = h->outnum;
		tx = presign_sweep_tx(tmpctx, &outpoint, h->amount, wscript,
				      0xFFFFFFFF, 0, penalty_feerate, dust_limit,
				      true /* SINGLE|ACP: no fee deduction */,
				      channel->channel_asset,
				      final_index, final_ext_key,
				      final_scriptpubkey);
		b = make_penalty_blob(blobs, WT_TMPL_STEAL_HTLC_PENALTY,
				      pbase->commitment_num, h->outnum,
				      h->amount, 0, tx, wscript, &secret,
				      der, sizeof(der));
		if (b)
			tal_arr_expand(&blobs, b);
	}

	return blobs;
}
