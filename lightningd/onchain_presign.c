#include "config.h"
#include <bitcoin/locktime.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/tal/tal.h>
#include <channeld/channeld_wiregen.h>
#include <common/amount.h>
#include <common/fee_states.h>
#include <common/htlc_tx.h>
#include <common/keyset.h>
#include <common/presign_templates.h>
#include <common/utils.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/htlc_end.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/onchain_presign.h>
#include <lightningd/peer_control.h>
#include <lightningd/watchtower_store.h>
#include <wally_bip32.h>

/* Package a signed CLASS-B sweep tx into the on-disk watchtower_blob subtype.
 * kind/output_index/amount/deadline_delta/wscript describe how speculad fee-
 * attaches + schedules it; tx is the DEVICE-signed sweep.  Guards the store
 * call so the daemon never writes an empty set over a good one. */
static struct watchtower_blob *presign_blob(const tal_t *ctx,
					    enum wt_tmpl_kind kind,
					    u64 commit_num,
					    u32 output_index,
					    struct amount_sat amount,
					    u32 deadline_delta,
					    const u8 *wscript,
					    const struct bitcoin_tx *tx)
{
	struct watchtower_blob *b = tal(ctx, struct watchtower_blob);

	b->kind = kind;
	b->commit_num = commit_num;
	b->output_index = output_index;
	b->amount = amount;
	b->deadline_delta = deadline_delta;
	b->wscript = tal_dup_talarr(b, u8, wscript);
	b->tx = clone_bitcoin_tx(b, tx);
	return b;
}

/* Derive the user's own final sweep destination for @channel, mirroring
 * lightningd/onchain_control.c:onchaind_tx_unsigned (BIP86 P2TR if available,
 * else BIP32; p2wpkh on elements, p2tr otherwise).  Fills the outputs used by
 * presign_sweep_tx.  Returns false on a derivation failure (caller skips). */
static bool build_final_dest(struct channel *channel,
			     u32 *final_index,
			     struct ext_key *final_ext_key,
			     const u8 **final_scriptpubkey)
{
	struct lightningd *ld = channel->peer->ld;
	struct pubkey final_key;

	*final_index = channel->final_key_idx;

	if (ld->bip86_base) {
		bip86_pubkey(ld, &final_key, channel->final_key_idx);
		if (bip32_key_from_parent(ld->bip86_base, channel->final_key_idx,
					  BIP32_FLAG_KEY_PUBLIC,
					  final_ext_key) != WALLY_OK)
			return false;
	} else {
		bip32_pubkey(ld, &final_key, channel->final_key_idx);
		if (bip32_key_from_parent(ld->bip32_base, channel->final_key_idx,
					  BIP32_FLAG_KEY_PUBLIC,
					  final_ext_key) != WALLY_OK)
			return false;
	}

	/* Same choice onchaind_tx_unsigned makes: p2wpkh on elements, p2tr
	 * otherwise (so the pre-signed sweep is byte-identical to the live
	 * node's). */
	if (chainparams->is_elements)
		*final_scriptpubkey = scriptpubkey_p2wpkh(channel, &final_key);
	else
		*final_scriptpubkey = scriptpubkey_p2tr(channel, &final_key);
	return true;
}

/* Master-fd (dbid 0) sign of an honest-close sweep; in keyless mode this
 * forwards to the browser device.  Returns false (fail-soft, never fatal --
 * B6) if the device REJECTs / returns a zero-length reply. */
static bool master_sign_sweep(struct lightningd *ld,
			      struct channel *channel,
			      const u8 *sign_msg TAKES,
			      struct bitcoin_signature *sig)
{
	const u8 *msg = hsm_sync_req(tmpctx, ld, sign_msg);
	if (!msg || !fromwire_hsmd_sign_tx_reply(msg, sig))
		return false;
	return true;
}

/* Build the current-state CLASS-B honest-close sweep set for @channel at
 * commitment @commit_num (whose LOCAL keyset is derived from @local_per_commit).
 *
 * IMPLEMENTED here (our own honest unilateral close):
 *   kind 3  WT_TMPL_TO_LOCAL_DELAYED_SWEEP  our to_local; witness <sig> <>, CSV
 *   kind 4  WT_TMPL_HTLC_TIMEOUT            offered HTLCs; 2-of-2 with the peer's
 *                                          stored remote_htlc_sig (last_htlc_sigs)
 * kind 5 (received-HTLC success) is preimage-gated and produced at fulfill time
 * (onchain_presign_htlc_success).
 *
 * DEFERRED SEAM -- kind 6 (WT_TMPL_REMOTE_HTLC_TO_US): defends when the PEER
 * force-closes honestly, sweeping HTLC outputs on the REMOTE commitment.
 * lightningd does NOT hold the remote commitment tx (channel->last_tx is OURS;
 * the remote commitment is built in channeld's send_commit_part), so the
 * remote-commitment HTLC outpoints/amounts must be threaded from channeld's
 * SENDING_COMMITSIG path first (a separate wiregen change).  Until then the
 * peer-honest-close HTLC gap stays on onchaind at real force-close time
 * (device-online), exactly as today. */
static struct watchtower_blob **build_current_sweeps(const tal_t *ctx,
						     struct channel *channel,
						     u64 commit_num,
						     const struct pubkey *local_per_commit,
						     const struct got_commitsig_htlc_info *htlc_infos)
{
	struct watchtower_blob **blobs
		= tal_arr(ctx, struct watchtower_blob *, 0);
	struct lightningd *ld = channel->peer->ld;
	struct keyset keyset;
	struct bitcoin_txid our_last_txid;
	u32 final_index;
	struct ext_key final_ext_key;
	const u8 *final_scriptpubkey;
	const bool static_remotekey
		= commit_num >= channel->static_remotekey_start[LOCAL];
	const bool opt_anchor_outputs
		= channel_has(channel, OPT_ANCHOR_OUTPUTS_DEPRECATED);
	const bool opt_anchors_zero_fee
		= channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);
	/* hsmd's local-htlc-tx signer takes a single "anchors" flag (true for
	 * either anchor type), matching onchain_control.c:sign_htlc_timeout. */
	const bool hsm_anchors = channel_type_has_anchors(channel->type);
	/* OUR to_local CSV = the delay the PEER imposes on us: onchaind_init
	 * passes their_config.to_self_delay as the delay on OUR outputs. */
	const u32 our_to_self_delay
		= channel->channel_info.their_config.to_self_delay;
	const struct amount_sat dust_limit = channel->our_config.dust_limit;
	/* Byte-exact with channel_txs()/full_channel add_htlcs: HTLC 2nd-stage
	 * feerate is 0 for zero-fee-htlc anchors, else the LOCAL commitment
	 * feerate. */
	const u32 htlc_feerate = opt_anchors_zero_fee
		? 0 : get_feerate(channel->fee_states, channel->opener, LOCAL);

	if (!channel->last_tx) {
		log_debug(channel->log, "onchain_presign: no last_tx yet");
		return blobs;
	}

	if (!derive_keyset(local_per_commit, &channel->local_basepoints,
			   &channel->channel_info.theirbase, static_remotekey,
			   &keyset)) {
		log_broken(channel->log,
			   "onchain_presign: LOCAL keyset derivation failed for "
			   "commit %"PRIu64, commit_num);
		return blobs;
	}

	if (!build_final_dest(channel, &final_index, &final_ext_key,
			      &final_scriptpubkey)) {
		log_broken(channel->log,
			   "onchain_presign: final dest derivation failed");
		return blobs;
	}

	bitcoin_txid(channel->last_tx, &our_last_txid);

	/* kind 3: our to_local delayed sweep (SINGLE|ACP so speculad fee-
	 * attaches + RBFs).  Find the to_local output on our commitment by its
	 * P2WSH(to_local wscript). */
	{
		u8 *wscript = bitcoin_wscript_to_local(tmpctx, our_to_self_delay,
						       1, &keyset.self_revocation_key,
						       &keyset.self_delayed_payment_key);
		const u8 *spk = scriptpubkey_p2wsh(tmpctx, wscript);
		bool found = false;
		struct bitcoin_outpoint outpoint;
		struct amount_sat in_sats = AMOUNT_SAT(0);

		outpoint.txid = our_last_txid;
		for (size_t o = 0; o < channel->last_tx->wtx->num_outputs; o++) {
			const struct wally_tx_output *out
				= &channel->last_tx->wtx->outputs[o];
			if (out->script_len == tal_bytelen(spk)
			    && memcmp(out->script, spk, out->script_len) == 0) {
				outpoint.n = o;
				in_sats = bitcoin_tx_output_get_amount_sat(
					channel->last_tx, o);
				found = true;
				break;
			}
		}

		if (found) {
			struct bitcoin_tx *tx;
			struct bitcoin_signature sig;
			u8 **witness;

			tx = presign_sweep_tx(tmpctx, &outpoint, in_sats, wscript,
					      /* CSV input sequence */
					      our_to_self_delay, 0, 0, dust_limit,
					      true /* SINGLE|ACP */,
					      channel->channel_asset,
					      &final_index, &final_ext_key,
					      final_scriptpubkey);
			if (tx
			    && master_sign_sweep(ld, channel,
						 take(towire_hsmd_sign_any_delayed_payment_to_us(
							 NULL, commit_num, tx, wscript,
							 0, &channel->peer->id,
							 channel->dbid)),
						 &sig)) {
				/* to_local delayed branch: <local_delayedsig> <> */
				witness = bitcoin_witness_sig_and_element(
					tx, &sig, NULL, 0, wscript);
				bitcoin_tx_input_set_witness(tx, 0, take(witness));
				tal_arr_expand(&blobs,
					       presign_blob(blobs,
							    WT_TMPL_TO_LOCAL_DELAYED_SWEEP,
							    commit_num, outpoint.n,
							    in_sats,
							    our_to_self_delay,
							    wscript, tx));
			} else {
				log_broken(channel->log,
					   "onchain_presign: to_local sweep "
					   "sign/build failed (commit %"PRIu64")",
					   commit_num);
			}
		}
	}

	/* kind 4: offered-HTLC timeout (2-of-2 with the peer's remote_htlc_sig).
	 * htlc_infos[i] is aligned 1:1 with channel->last_htlc_sigs[i]. */
	for (size_t i = 0; i < tal_count(htlc_infos); i++) {
		const struct got_commitsig_htlc_info *h = &htlc_infos[i];
		struct bitcoin_outpoint commit_outpoint;
		u8 *commit_wscript;
		struct bitcoin_tx *tx;
		struct bitcoin_signature sig;
		u8 **witness;

		if (!h->offered)
			continue;
		if (i >= tal_count(channel->last_htlc_sigs)) {
			log_broken(channel->log,
				   "onchain_presign: htlc_info %zu has no matching "
				   "remote_htlc_sig; skipping", i);
			continue;
		}

		commit_outpoint.txid = our_last_txid;
		commit_outpoint.n = h->output_index;
		commit_wscript = bitcoin_wscript_htlc_offer(tmpctx,
							    &keyset.self_htlc_key,
							    &keyset.other_htlc_key,
							    &h->payment_hash,
							    &keyset.self_revocation_key,
							    opt_anchor_outputs,
							    opt_anchors_zero_fee);
		tx = htlc_timeout_tx(tmpctx, chainparams, &commit_outpoint,
				     commit_wscript, h->amount, h->cltv_expiry,
				     our_to_self_delay, htlc_feerate, &keyset,
				     opt_anchor_outputs, opt_anchors_zero_fee,
				     channel->channel_asset);
		if (!tx) {
			log_broken(channel->log,
				   "onchain_presign: HTLC-timeout build failed "
				   "for output %u (fee > value?)", h->output_index);
			continue;
		}
		if (!master_sign_sweep(ld, channel,
				       take(towire_hsmd_sign_any_local_htlc_tx(
					       NULL, commit_num, tx, commit_wscript,
					       hsm_anchors, 0, &channel->peer->id,
					       channel->dbid)),
				       &sig)) {
			log_broken(channel->log,
				   "onchain_presign: HTLC-timeout sign failed "
				   "for output %u", h->output_index);
			continue;
		}
		/* 2-of-2 witness: our sig + the peer's stored remote_htlc_sig. */
		witness = bitcoin_witness_htlc_timeout_tx(tx, &sig,
							  &channel->last_htlc_sigs[i],
							  commit_wscript);
		bitcoin_tx_input_set_witness(tx, 0, take(witness));
		/* deadline_delta 0: broadcast-eligibility is the tx nLocktime
		 * (== cltv_expiry, absolute), which speculad reads from the tx;
		 * the 2nd-stage output then has its own CSV (our_to_self_delay)
		 * before it can be swept to the wallet. */
		tal_arr_expand(&blobs,
			       presign_blob(blobs, WT_TMPL_HTLC_TIMEOUT,
					    commit_num, h->output_index,
					    amount_msat_to_sat_round_down(h->amount),
					    0, commit_wscript, tx));
	}

	return blobs;
}

void onchain_presign_current_sweeps(struct channel *channel,
				    u64 commit_num,
				    const struct pubkey *local_per_commit,
				    const struct got_commitsig_htlc_info *htlc_infos)
{
	struct lightningd *ld = channel->peer->ld;
	struct watchtower_blob **blobs;

	/* Stash the keyset ingredients for the fulfill-time (kind-5) rebuild:
	 * the preimage is only known then, so onchain_presign_htlc_success()
	 * re-derives the LOCAL keyset from these. */
	channel->presign_commit_num = commit_num;
	tal_free(channel->presign_local_per_commit);
	channel->presign_local_per_commit
		= tal_dup(channel, struct pubkey, local_per_commit);
	tal_free(channel->presign_htlc_infos);
	channel->presign_htlc_infos
		= tal_dup_talarr(channel, struct got_commitsig_htlc_info,
				 htlc_infos);

	blobs = build_current_sweeps(tmpctx, channel, commit_num,
				     local_per_commit, htlc_infos);
	if (tal_count(blobs) == 0) {
		log_debug(channel->log,
			  "onchain_presign: no CLASS-B current-state sweeps for "
			  "commit %"PRIu64" (no to_local + no offered HTLCs); "
			  "keeping prior stored set", commit_num);
		return;
	}

	if (!wt_store_put_sweeps(ld, channel, commit_num, blobs))
		log_broken(channel->log,
			   "onchain_presign: failed storing %zu CLASS-B sweeps",
			   tal_count(blobs));
}

bool onchain_presign_htlc_success(struct channel *channel, struct htlc_in *hin)
{
	struct lightningd *ld = channel->peer->ld;
	struct keyset keyset;
	struct bitcoin_txid our_last_txid;
	struct bitcoin_outpoint commit_outpoint;
	struct abs_locktime abstimeout;
	const struct got_commitsig_htlc_info *match = NULL;
	size_t match_i = 0;
	u8 *commit_wscript;
	struct bitcoin_tx *tx;
	struct bitcoin_signature sig;
	u8 **witness;
	struct watchtower_blob **stored, **out;
	const u64 commit_num = channel->presign_commit_num;
	bool static_remotekey, opt_anchor_outputs, opt_anchors_zero_fee, hsm_anchors;
	u32 htlc_feerate, our_to_self_delay;

	/* Best-effort on testnet: if the keyset stash is absent (e.g. right
	 * after a restart, before the next commitment advance) we cannot build
	 * the success sweep.  Do NOT stall fulfilment -- release best-effort. */
	if (!channel->presign_local_per_commit || !channel->last_tx
	    || !channel->last_htlc_sigs || !hin->preimage) {
		log_debug(channel->log,
			  "onchain_presign: HTLC-success sweep for htlc %"PRIu64
			  " not buildable (keyset stash absent); releasing "
			  "preimage best-effort", hin->key.id);
		return true;
	}

	/* Find this incoming (received-by-us) HTLC in the current-commitment
	 * metadata; match_i indexes channel->last_htlc_sigs. */
	for (size_t i = 0; i < tal_count(channel->presign_htlc_infos); i++) {
		const struct got_commitsig_htlc_info *h
			= &channel->presign_htlc_infos[i];
		if (h->offered)
			continue;
		if (sha256_eq(&h->payment_hash, &hin->payment_hash)
		    && h->cltv_expiry == hin->cltv_expiry
		    && amount_msat_eq(h->amount, hin->msat)) {
			match = h;
			match_i = i;
			break;
		}
	}

	if (!match) {
		/* Not on the current commitment (e.g. trimmed to dust): nothing
		 * to pre-sign, releasing the preimage cannot strand a sweepable
		 * output.  Best-effort release. */
		log_debug(channel->log,
			  "onchain_presign: htlc %"PRIu64" not a current-commitment "
			  "received output; releasing preimage best-effort",
			  hin->key.id);
		return true;
	}
	if (match_i >= tal_count(channel->last_htlc_sigs)) {
		log_broken(channel->log,
			   "onchain_presign: htlc %"PRIu64" has no remote_htlc_sig",
			   hin->key.id);
		return false;
	}

	static_remotekey = commit_num >= channel->static_remotekey_start[LOCAL];
	opt_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS_DEPRECATED);
	opt_anchors_zero_fee = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);
	hsm_anchors = channel_type_has_anchors(channel->type);
	our_to_self_delay = channel->channel_info.their_config.to_self_delay;
	htlc_feerate = opt_anchors_zero_fee
		? 0 : get_feerate(channel->fee_states, channel->opener, LOCAL);

	if (!derive_keyset(channel->presign_local_per_commit,
			   &channel->local_basepoints,
			   &channel->channel_info.theirbase, static_remotekey,
			   &keyset)) {
		log_broken(channel->log,
			   "onchain_presign: keyset derivation failed for htlc "
			   "%"PRIu64, hin->key.id);
		return false;
	}

	if (!blocks_to_abs_locktime(match->cltv_expiry, &abstimeout)) {
		log_broken(channel->log,
			   "onchain_presign: bad cltv %u for htlc %"PRIu64,
			   match->cltv_expiry, hin->key.id);
		return false;
	}

	bitcoin_txid(channel->last_tx, &our_last_txid);
	commit_outpoint.txid = our_last_txid;
	commit_outpoint.n = match->output_index;

	commit_wscript = bitcoin_wscript_htlc_receive(tmpctx, &abstimeout,
						      &keyset.self_htlc_key,
						      &keyset.other_htlc_key,
						      &match->payment_hash,
						      &keyset.self_revocation_key,
						      opt_anchor_outputs,
						      opt_anchors_zero_fee);
	tx = htlc_success_tx(tmpctx, chainparams, &commit_outpoint, commit_wscript,
			     match->amount, our_to_self_delay, htlc_feerate,
			     &keyset, opt_anchor_outputs, opt_anchors_zero_fee,
			     channel->channel_asset);
	if (!tx) {
		log_broken(channel->log,
			   "onchain_presign: HTLC-success build failed for htlc "
			   "%"PRIu64" (fee > value?)", hin->key.id);
		return false;
	}

	if (!master_sign_sweep(ld, channel,
			       take(towire_hsmd_sign_any_local_htlc_tx(
				       NULL, commit_num, tx, commit_wscript,
				       hsm_anchors, 0, &channel->peer->id,
				       channel->dbid)),
			       &sig)) {
		log_broken(channel->log,
			   "onchain_presign: HTLC-success sign failed for htlc "
			   "%"PRIu64" (device REJECT?)", hin->key.id);
		return false;
	}

	/* 2-of-2 witness: our sig + the peer's remote_htlc_sig + the preimage. */
	witness = bitcoin_witness_htlc_success_tx(tx, &sig,
						  &channel->last_htlc_sigs[match_i],
						  hin->preimage, commit_wscript);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));

	/* Merge into the stored CLASS-B set WITHOUT clobbering kinds 3/4 (or a
	 * prior kind-5 for another HTLC): load, drop any existing kind-5 for
	 * this same output (idempotent re-fulfill), append the new one, re-put. */
	stored = wt_store_load_sweeps(tmpctx, ld, channel);
	out = tal_arr(tmpctx, struct watchtower_blob *, 0);
	for (size_t i = 0; i < tal_count(stored); i++) {
		if (stored[i]->kind == WT_TMPL_HTLC_SUCCESS
		    && stored[i]->output_index == match->output_index)
			continue;
		tal_arr_expand(&out, stored[i]);
	}
	tal_arr_expand(&out,
		       presign_blob(out, WT_TMPL_HTLC_SUCCESS, commit_num,
				    match->output_index,
				    amount_msat_to_sat_round_down(match->amount),
				    0, commit_wscript, tx));

	if (!wt_store_put_sweeps(ld, channel, commit_num, out)) {
		log_broken(channel->log,
			   "onchain_presign: failed storing HTLC-success sweep "
			   "for htlc %"PRIu64"; deferring preimage release",
			   hin->key.id);
		return false;
	}

	log_debug(channel->log,
		  "onchain_presign: durable HTLC-success sweep stored for htlc "
		  "%"PRIu64" (output %u); releasing preimage",
		  hin->key.id, match->output_index);
	return true;
}
