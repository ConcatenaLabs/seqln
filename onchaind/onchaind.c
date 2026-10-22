#include "config.h"
#include <bitcoin/script.h>
#include <bitcoin/tapscript.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/channel_id.h>
#include <common/credit_scripts.h>
#include <common/htlc_tx.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/lease_rates.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/point_lock.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/sym_scripts.h>
#include <common/sym_state.h>
#include <common/tcov_scripts.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <onchaind/onchain_types.h>
#include <onchaind/onchaind_wiregen.h>
#include <unistd.h>
#include <wire/wire_sync.h>
  #include "onchain_types_names_gen.h"

/* stdin == requests */
#define REQ_FD STDIN_FILENO
#define HSM_FD 3

/* Required in various places: keys for commitment transaction. */
static const struct keyset *keyset;

/* IFF it's their commitment tx: HSM can't derive their per-commitment point! */
static const struct pubkey *remote_per_commitment_point;

/* The commitment number we're dealing with (if not mutual close) */
static u64 commit_num;

/* Min and max feerates we ever used */
static u32 min_possible_feerate, max_possible_feerate;

/* The dust limit to use when we generate transactions. */
static struct amount_sat dust_limit;

/* The CSV delays for each side. */
static u32 to_self_delay[NUM_SIDES];

/* Their revocation secret (only if they cheated). */
static const struct secret *remote_per_commitment_secret;

/* one value is useful for a few witness scripts */
static const u8 ONE = 0x1;

/* When to tell master about HTLCs which are missing/timed out */
static u32 reasonable_depth;

/* The messages to send at that depth. */
static u8 **missing_htlc_msgs;

/* The messages which were sent to us while waiting for a specific msg. */
static const u8 **queued_msgs;

/* Our recorded channel balance at 'chain time' */
static struct amount_msat our_msat;

/* Needed for anchor outputs */
static struct pubkey funding_pubkey[NUM_SIDES];

/* At what commit number does option_static_remotekey apply? */
static u64 static_remotekey_start[NUM_SIDES];

/* Does option_anchor_outputs apply to this commitment tx? */
static bool option_anchor_outputs;

/* Does option_anchors_zero_fee_htlc_tx apply to this commitment tx? */
static bool option_anchors_zero_fee_htlc_tx;

/* SEQUENTIA: a taproot-covenant channel (common/tcov_scripts.h)? */
static bool option_seq_taproot_covenant;

/* SEQUENTIA: a credit channel (common/credit_scripts.h): who provides, the
 * credit leaves' constants, and the latest note we hold, as its holder. */
static bool option_seq_credit;
static enum side credit_provider;
static struct credit_params *credit_params;
struct credit_note_held {
	u64 credit;
	struct sha256 payment_hash;
	struct bip340sig sig;
	struct preimage preimage;
};
static struct credit_note_held *credit_note;

/* SEQUENTIA: a symmetric channel (common/sym_scripts.h): its constants,
 * the states lightningd holds, the best of them we hold whole, who opened
 * it, each side's basepoints and the HTLCs it may carry. */
static bool option_seq_symmetric;
static struct sym_channel sym_sc;
static const struct sym_state *sym_local, *sym_remote, *sym_remote_pending;
static const struct sym_state *sym_best;
static enum side sym_opener;
static struct basepoints sym_basepoints[NUM_SIDES];
static struct htlcs_info *sym_htlcs;
static struct bitcoin_outpoint sym_funding;

/* Asset-aware channels: the asset this channel is denominated in (33-byte
 * version+tag); the policy asset for an ordinary channel. All resolution/HTLC
 * txs we build (or the amounts we read off the commitment tx) are in it. */
static u8 channel_asset[33];

/* The minimum relay feerate acceptable to the fullnode.  */
static u32 min_relay_feerate;

/* If we broadcast a tx, or need a delay to resolve the output. */
struct proposed_resolution {
	/* Once we had lightningd create tx, here's what it told us
	 * witnesses were (we ignore sigs!). */
	/* NULL if answer is to simply ignore it. */
	const struct onchain_witness_element **welements;
	/* Non-zero if this is CSV-delayed. */
	u32 depth_required;
	enum tx_type tx_type;
};

/* How it actually got resolved. */
struct resolution {
	struct bitcoin_txid txid;
	unsigned int depth;
	enum tx_type tx_type;
};

struct tracked_output {
	enum tx_type tx_type;
	struct bitcoin_outpoint outpoint;
	u32 tx_blockheight;
	/* FIXME: Convert all depths to blocknums, then just get new blk msgs */
	u32 depth;
	struct amount_sat sat;
	enum output_type output_type;

	/* If it is an HTLC, this is set, wscript is non-NULL. */
	struct htlc_stub htlc;
	const u8 *wscript;

	/* If it's an HTLC off our unilateral, this is their sig for htlc_tx */
	const struct bitcoin_signature *remote_htlc_sig;

	/* Our proposed solution (if any) */
	struct proposed_resolution *proposal;

	/* If it is resolved. */
	struct resolution *resolved;

	/* stashed so we can pass it along to the coin ledger */
	struct sha256 payment_hash;

	/* SEQUENTIA: a taproot-covenant output's script tree, else NULL. */
	const struct tap_tree2 *tcov_tree;

	/* SEQUENTIA: a credit output's B, the constant its CLAIM leaf counts
	 * what was paid from (common/credit_scripts.h). */
	struct amount_sat credit_b;

	/* SEQUENTIA: a symmetric channel's state output: its state number
	 * (-1 for KO), the R its update published, and its script. */
	s64 sym_num;
	struct sha256 sym_rest;
	u8 *sym_spk;
};

/* SEQUENTIA: the provider-signed credit, near the end of this file. */
static bool credit_output_spent(struct tracked_output ***outs,
				struct tracked_output *out,
				const struct tx_parts *tx_parts,
				u32 input_num, u32 tx_blockheight,
				bool by_proposal);
static void handle_onchaind_credit_note(struct tracked_output **outs,
					const u8 *msg);

/* SEQUENTIA: the taproot-covenant channel type, near the end of this file. */
static void tcov_resolve_claim(struct tracked_output ***outs,
			       size_t out_index,
			       const struct tx_parts *claim,
			       size_t input_num,
			       u32 tx_blockheight);
static void tcov_steal_claim(struct tracked_output *out,
			     struct tracked_output ***outs,
			     const struct tx_parts *claim,
			     u32 tx_blockheight,
			     enum tx_type claim_type,
			     const struct bitcoin_outpoint *d_outpoint);
static void tcov_extract_preimage(struct tracked_output *out,
				  const struct tx_parts *tx_parts,
				  const struct bitcoin_outpoint *spend);
static void tcov_claim_with_preimage(struct tracked_output *out,
				     const struct preimage *preimage);
static bool tcov_revoke_leaf_paid_us(const struct tx_parts *tx_parts,
				     size_t input_num, u32 tx_blockheight);

/* SEQUENTIA: the symmetric channel type, near the end of this file. */
static void sym_state_spent(struct tracked_output ***outs,
			    struct tracked_output *out,
			    const struct tx_parts *tx, u32 input_num,
			    u32 tx_blockheight);
static void sym_claim_with_preimage(struct tracked_output *out,
				    const struct preimage *preimage);

static const char *tx_type_name(enum tx_type tx_type)
{
	size_t i;

	for (i = 0; enum_tx_type_names[i].name; i++)
		if (enum_tx_type_names[i].v == tx_type)
			return enum_tx_type_names[i].name;
	return "unknown";
}

static const char *output_type_name(enum output_type output_type)
{
	size_t i;

	for (i = 0; enum_output_type_names[i].name; i++)
		if (enum_output_type_names[i].v == output_type)
			return enum_output_type_names[i].name;
	return "unknown";
}

static const u8 *queue_until_msg(const tal_t *ctx, enum onchaind_wire mtype)
{
	const u8 *msg;

	while ((msg = wire_sync_read(ctx, REQ_FD)) != NULL) {
		if (fromwire_peektype(msg) == mtype)
			return msg;
		/* Process later */
		tal_arr_expand(&queued_msgs, tal_steal(queued_msgs, msg));
	}
	status_failed(STATUS_FAIL_HSM_IO, "Waiting for %s: connection lost",
		      onchaind_wire_name(mtype));
}

/* helper to compare output script with our tal'd script */
static bool wally_tx_output_scripteq(const struct wally_tx_output *out,
				     const u8 *script)
{
	return memeq(out->script, out->script_len, script, tal_bytelen(script));
}

/* The feerate for the HTLC txs (which we grind) are the same as the
 * feerate for the main tx.  However, there may be dust HTLCs which
 * were added to the fee, so we can only estimate a maximum feerate */
static void trim_maximum_feerate(struct amount_sat funding,
				 const struct tx_parts *commitment)
{
	size_t weight;
	struct amount_sat fee = funding;

	/* FIXME: This doesn't work for elements? */
	if (chainparams->is_elements)
		return;

	weight = bitcoin_tx_core_weight(tal_count(commitment->inputs),
					tal_count(commitment->outputs));

	/* BOLT #3:
	 * ## Commitment Transaction
	 *...
	 *   * `txin[0]` script bytes: 0
	 *   * `txin[0]` witness: `0 <signature_for_pubkey1> <signature_for_pubkey2>`
	 */
	/* Account for witness (1 empty + sig + sig) */
	assert(tal_count(commitment->inputs) == 1);
	weight += bitcoin_tx_input_weight(false, 1 + 2 * bitcoin_tx_input_sig_weight());

	for (size_t i = 0; i < tal_count(commitment->outputs); i++) {
		struct amount_asset amt;
		weight += bitcoin_tx_output_weight(commitment->outputs[i]
						   ->script_len);

		amt = wally_tx_output_get_amount(commitment->outputs[i]);
		if (!amount_asset_is_main(&amt))
			continue;
		if (!amount_sat_sub(&fee, fee, amount_asset_to_sat(&amt))) {
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Unable to subtract fee");
		}
	}

	status_debug("reducing max_possible_feerate from %u...",
		     max_possible_feerate);
	/* This is naive, but simple. */
	while (amount_sat_greater(amount_tx_fee(max_possible_feerate, weight),
				  fee))
		max_possible_feerate--;
	status_debug("... to %u", max_possible_feerate);
}

static void send_coin_mvt(struct chain_coin_mvt *mvt TAKES)
{
	wire_sync_write(REQ_FD,
			take(towire_onchaind_notify_coin_mvt(NULL, mvt)));

	tal_free_if_taken(mvt);
}

static void record_channel_withdrawal(const struct bitcoin_txid *tx_txid,
				      struct tracked_output *out,
				      u32 blockheight,
				      struct mvt_tags tags)
{
	send_coin_mvt(take(new_onchaind_withdraw(NULL, &out->outpoint, tx_txid,
						 blockheight, out->sat, tags)));
}

static void record_external_spend(const struct bitcoin_txid *txid,
				  struct tracked_output *out,
				  u32 blockheight,
				  struct mvt_tags tags)
{
	send_coin_mvt(take(new_coin_external_spend(NULL, &out->outpoint,
						   txid, blockheight,
						   out->sat, tags)));
}

static void record_external_output(const struct bitcoin_outpoint *out,
				   struct amount_sat amount,
				   u32 blockheight,
				   struct mvt_tags tags)
{
	send_coin_mvt(take(new_coin_external_deposit(NULL, out, blockheight,
						     amount, tags)));
}

static void record_external_deposit(const struct tracked_output *out,
				    u32 blockheight,
				    struct mvt_tags tags)
{
	record_external_output(&out->outpoint, out->sat, blockheight, tags);
}

static void record_mutual_close(const struct tx_parts *tx,
				const u8 *remote_scriptpubkey,
				u32 blockheight)
{
	/* FIXME: if we ever change how closes happen, this will
	 * need to be updated as there's no longer 1 output
	 * per peer */
	for (size_t i = 0; i < tal_count(tx->outputs); i++) {
		struct bitcoin_outpoint out;

		if (!wally_tx_output_scripteq(tx->outputs[i],
					      remote_scriptpubkey))
			continue;

		out.n = i;
		out.txid = tx->txid;
		record_external_output(&out,
				       amount_sat(tx->outputs[i]->satoshi),
				       blockheight,
				       mk_mvt_tags(MVT_TO_THEM));
		break;
	}
}


static void record_channel_deposit(struct tracked_output *out,
				   u32 blockheight, struct mvt_tags tags)
{
	send_coin_mvt(take(new_onchaind_deposit(NULL,
						&out->outpoint,
						blockheight, out->sat,
						tags)));
}

static void record_to_us_htlc_fulfilled(struct tracked_output *out,
					u32 blockheight)
{
	send_coin_mvt(take(new_onchain_htlc_deposit(NULL,
						    &out->outpoint,
						    blockheight,
						    out->sat,
						    &out->payment_hash)));
}

static void record_to_them_htlc_fulfilled(struct tracked_output *out,
					  u32 blockheight)
{

	send_coin_mvt(take(new_onchain_htlc_withdraw(NULL,
						     &out->outpoint,
						     blockheight,
						     out->sat,
						     &out->payment_hash)));
}

static void record_our_anchor(struct tracked_output *out)
{
	/* We *could* treat this as a deposit to our wallet, but we
	* never record spending it, and in many cases we don't: we
	* might not need it, or our peer may use the other anchor, and
	* it can be spent by anyone after 16 blocks.  Our
	* implementation doesn't ever spend it unless it needs to
	* boost, so it's fair to record it as going "external". */
	record_external_deposit(out, out->tx_blockheight, mk_mvt_tags(MVT_ANCHOR));
}

static void record_coin_movements(struct tracked_output *out,
				  u32 blockheight,
				  const struct bitcoin_txid *txid)
{
	/* For 'timeout' htlcs, we re-record them as a deposit
	 * before we withdraw them again. When the channel closed,
	 * we reported this as withdrawn (since we didn't know the
	 * total amount of pending htlcs that are to-them). So
	 * we have to "deposit" it again before we withdraw it.
	 * This is just to make the channel account close out nicely
	 * AND so we can accurately calculate our on-chain fee burden */
	if (out->tx_type == OUR_HTLC_TIMEOUT_TX
	    || out->tx_type == OUR_HTLC_SUCCESS_TX)
		record_channel_deposit(out, out->tx_blockheight, mk_mvt_tags(MVT_HTLC_TX));

	if (out->resolved->tx_type == OUR_HTLC_TIMEOUT_TO_US)
		record_channel_deposit(out, out->tx_blockheight, mk_mvt_tags(MVT_HTLC_TIMEOUT));

	/* there is a case where we've fulfilled an htlc onchain,
	 * in which case we log a deposit to the channel */
	if (out->resolved->tx_type == THEIR_HTLC_FULFILL_TO_US
	    || out->resolved->tx_type == OUR_HTLC_SUCCESS_TX)
		record_to_us_htlc_fulfilled(out, out->tx_blockheight);

	/* If it's our to-us and our close, we publish *another* tx
	 * which spends the output when the timeout ends */
	if (out->tx_type == OUR_UNILATERAL) {
		if (out->output_type == DELAYED_OUTPUT_TO_US)
			record_channel_deposit(out, out->tx_blockheight,
					       mk_mvt_tags(MVT_CHANNEL_TO_US));
		else if (out->output_type == OUR_HTLC) {
			record_channel_deposit(out, out->tx_blockheight,
					       mk_mvt_tags(MVT_HTLC_TIMEOUT));
			record_channel_withdrawal(txid, out, blockheight,
						  mk_mvt_tags(MVT_HTLC_TIMEOUT));
		} else if (out->output_type == THEIR_HTLC)
			record_channel_withdrawal(txid, out, blockheight,
						  mk_mvt_tags(MVT_HTLC_FULFILL));
	}

	if (out->tx_type == THEIR_REVOKED_UNILATERAL
	    || out->resolved->tx_type == OUR_PENALTY_TX)
		record_channel_deposit(out, out->tx_blockheight, mk_mvt_tags(MVT_PENALTY));

	if (out->resolved->tx_type == OUR_DELAYED_RETURN_TO_WALLET
	    || out->resolved->tx_type == THEIR_HTLC_FULFILL_TO_US
	    || out->output_type == DELAYED_OUTPUT_TO_US
	    || out->resolved->tx_type == OUR_HTLC_TIMEOUT_TO_US
	    || out->resolved->tx_type == OUR_PENALTY_TX) {
		/* penalty rbf cases, the amount might be zero */
		if (amount_sat_is_zero(out->sat))
			record_channel_withdrawal(txid, out, blockheight, mk_mvt_tags(MVT_TO_MINER));
		else
			record_channel_withdrawal(txid, out, blockheight, mk_mvt_tags(MVT_TO_WALLET));
	}

	/* Tell lightningd to create penalty_adj on channel balance */
	if (out->resolved->tx_type == OUR_PENALTY_TX) {
		struct amount_msat msat;
		if (!amount_sat_to_msat(&msat, out->sat))
			abort();
		wire_sync_write(REQ_FD,
				take(towire_onchaind_notify_penalty_adj(NULL, msat)));
	}
}

/* We vary feerate until signature they offered matches. */
static bool grind_htlc_tx_fee(struct amount_sat *fee,
			      struct bitcoin_tx *tx,
			      const struct bitcoin_signature *remotesig,
			      const u8 *wscript,
			      u64 weight)
{
	struct amount_sat prev_fee = AMOUNT_SAT(UINT64_MAX), input_amt;
	input_amt = psbt_input_get_amount(tx->psbt, 0);

	for (u64 i = min_possible_feerate; i <= max_possible_feerate; i++) {
		/* BOLT #3:
		 *
		 * The fee for an HTLC-timeout transaction:
		 *   - If `option_anchors` applies:
		 *     1. MUST be 0.
		 *   - Otherwise, MUST be calculated to match:
		 *     1. Multiply `feerate_per_kw` by 663
		 *        and divide by 1000 (rounding down).
		 *
		 * The fee for an HTLC-success transaction:
		 *  - If `option_anchors` applies:
		 *    1. MUST be 0.
		 *  - Otherwise, MUST be calculated to match:
		 *     1. Multiply `feerate_per_kw` by 703
		 *        and divide by 1000 (rounding down).
		 */
		struct amount_sat out;

		*fee = amount_tx_fee(i, weight);

		/* Minor optimization: don't check same fee twice */
		if (amount_sat_eq(*fee, prev_fee))
			continue;

		prev_fee = *fee;
		if (!amount_sat_sub(&out, input_amt, *fee))
			break;

		bitcoin_tx_output_set_amount(tx, 0, out);
		bitcoin_tx_finalize(tx);
		if (!check_tx_sig(tx, 0, NULL, wscript,
				  &keyset->other_htlc_key, remotesig))
			continue;

		status_debug("grind feerate_per_kw for %"PRIu64" = %"PRIu64,
			     weight, i);
		return true;
	}

	/* A Sequentia channel's fees round up (amount_tx_fee), but HTLC
	 * signatures exchanged by a build that rounded down still name the
	 * BOLT 3 fee: try those too. */
	if (!chainparams->has_anchor_header)
		return false;
	prev_fee = AMOUNT_SAT(UINT64_MAX);
	for (u64 i = min_possible_feerate; i <= max_possible_feerate; i++) {
		struct amount_sat out;

		*fee = amount_tx_fee_rounded_down(i, weight);
		if (amount_sat_eq(*fee, prev_fee))
			continue;
		prev_fee = *fee;
		if (!amount_sat_sub(&out, input_amt, *fee))
			break;
		bitcoin_tx_output_set_amount(tx, 0, out);
		bitcoin_tx_finalize(tx);
		if (check_tx_sig(tx, 0, NULL, wscript,
				 &keyset->other_htlc_key, remotesig)) {
			status_debug("grind feerate_per_kw for %"PRIu64" = %"PRIu64
				     " (rounded down)", weight, i);
			return true;
		}
	}
	return false;
}

static bool set_htlc_timeout_fee(struct bitcoin_tx *tx,
				 const struct bitcoin_signature *remotesig,
				 const u8 *wscript)
{
	static struct amount_sat fee = AMOUNT_SAT_INIT(UINT64_MAX);
	struct amount_sat amount;
	struct amount_asset asset = bitcoin_tx_output_get_amount(tx, 0);
	size_t weight;

	amount = amount_sat(asset.value);
	assert(amount_asset_is(&asset, channel_asset));

	/* BOLT #3:
	 *
	 * The fee for an HTLC-timeout transaction:
	 *  - If `option_anchors` applies:
	 *    1. MUST be 0.
	 *  - Otherwise, MUST be calculated to match:
	 *    1. Multiply `feerate_per_kw` by 663 and divide by 1000 (rounding down).
	 */
	if (option_anchors_zero_fee_htlc_tx) {
		fee = AMOUNT_SAT(0);
		goto set_amount;
	}

	/* FIXME: older bolt used to say (666 if `option_anchor_outputs` applies) */
	if (option_anchor_outputs)
		weight = 666;
	else
		weight = 663;
	weight += elements_tx_overhead(chainparams, 1, 1);


	if (amount_sat_eq(fee, AMOUNT_SAT(UINT64_MAX))) {
		struct amount_sat grindfee;
		if (grind_htlc_tx_fee(&grindfee, tx, remotesig, wscript, weight)) {
			/* Cache this for next time */
			fee = grindfee;
			return true;
		}
		return false;
	}

	if (!amount_sat_sub(&amount, amount, fee))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot deduct htlc-timeout fee %s from tx %s",
			      fmt_amount_sat(tmpctx, fee),
			      fmt_bitcoin_tx(tmpctx, tx));

set_amount:
	bitcoin_tx_output_set_amount(tx, 0, amount);
	bitcoin_tx_finalize(tx);

	return check_tx_sig(tx, 0, NULL, wscript,
			    &keyset->other_htlc_key, remotesig);
}

static struct amount_sat get_htlc_success_fee(struct tracked_output *out)
{
	static struct amount_sat fee = AMOUNT_SAT_INIT(UINT64_MAX);
	size_t weight;
	struct amount_msat htlc_amount;
	struct bitcoin_tx *tx;

	/* We only grind once, since they're all equiv. */
	if (!amount_sat_eq(fee, AMOUNT_SAT(UINT64_MAX)))
		return fee;

	if (option_anchors_zero_fee_htlc_tx) {
		fee = AMOUNT_SAT(0);
		return fee;
	}

	if (!amount_sat_to_msat(&htlc_amount, out->sat))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Overflow in get_htlc_success_fee %s",
			      fmt_amount_sat(tmpctx, out->sat));
	/* Asset-aware channels: build the grind/verify htlc tx in the channel
	 * asset so its elements sighash matches the peer's signature. */
	tx = htlc_success_tx(tmpctx, chainparams,
			     &out->outpoint,
			     out->wscript,
			     htlc_amount,
			     to_self_delay[LOCAL],
			     0,
			     keyset,
			     option_anchor_outputs,
			     option_anchors_zero_fee_htlc_tx,
			     channel_asset);

	/* BOLT #3:
	 *
	 * The fee for an HTLC-success transaction:
	 * - If `option_anchors` applies:
	 *   1. MUST be 0.
	 * - Otherwise, MUST be calculated to match:
	 *   1. Multiply `feerate_per_kw` by 703 and divide by 1000 (rounding down).
	 */
	/* FIXME: Older bolt used to say (706 if `option_anchor_outputs` applies) */
	if (option_anchor_outputs)
		weight = 706;
	else
		weight = 703;

	weight += elements_tx_overhead(chainparams, 1, 1);
	if (!grind_htlc_tx_fee(&fee, tx, out->remote_htlc_sig,
			       out->wscript, weight)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "htlc_success_fee can't be found "
			      "for tx %s (weight %zu, feerate %u-%u), signature %s, wscript %s",
			      fmt_bitcoin_tx(tmpctx, tx),
			      weight,
			      min_possible_feerate, max_possible_feerate,
			      fmt_bitcoin_signature(tmpctx,
					     out->remote_htlc_sig),
			      tal_hex(tmpctx, out->wscript));
	}

	return fee;
}

static void hsm_get_per_commitment_point(struct pubkey *per_commitment_point)
{
	u8 *msg = towire_hsmd_get_per_commitment_point(NULL, commit_num);
	struct secret *unused;

	if (!wire_sync_write(HSM_FD, take(msg)))
		status_failed(STATUS_FAIL_HSM_IO, "Writing sign_htlc_tx to hsm");
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg
	    || !fromwire_hsmd_get_per_commitment_point_reply(tmpctx, msg,
							    per_commitment_point,
							    &unused))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading hsm_get_per_commitment_point_reply: %s",
			      tal_hex(tmpctx, msg));
}

static struct tracked_output *
new_tracked_output(struct tracked_output ***outs,
		   const struct bitcoin_outpoint *outpoint,
		   u32 tx_blockheight,
		   enum tx_type tx_type,
		   struct amount_sat sat,
		   enum output_type output_type,
		   const struct htlc_stub *htlc,
		   const u8 *wscript,
		   const struct bitcoin_signature *remote_htlc_sig)
{
	struct tracked_output *out = tal(*outs, struct tracked_output);

	status_debug("Tracking output %s: %s/%s",
		     fmt_bitcoin_outpoint(tmpctx, outpoint),
		     tx_type_name(tx_type),
		     output_type_name(output_type));

	out->tx_type = tx_type;
	out->outpoint = *outpoint;
	out->tx_blockheight = tx_blockheight;
	out->depth = 0;
	out->sat = sat;
	out->output_type = output_type;
	out->proposal = NULL;
	out->resolved = NULL;
	if (htlc)
		out->htlc = *htlc;
	out->wscript = tal_steal(out, wscript);
	out->remote_htlc_sig = tal_dup_or_null(out, struct bitcoin_signature,
					       remote_htlc_sig);
	out->tcov_tree = NULL;
	out->credit_b = AMOUNT_SAT(0);
	out->sym_num = 0;
	memset(&out->sym_rest, 0, sizeof(out->sym_rest));
	out->sym_spk = NULL;

	tal_arr_expand(outs, out);

	return out;
}

static void ignore_output(struct tracked_output *out)
{
	status_debug("Ignoring output %s: %s/%s",
		     fmt_bitcoin_outpoint(tmpctx, &out->outpoint),
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	out->resolved = tal(out, struct resolution);
	out->resolved->txid = out->outpoint.txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = SELF;
}

static void handle_spend_created(struct tracked_output *out, const u8 *msg)
{
	struct onchain_witness_element **witness;
	bool worthwhile;

	if (!fromwire_onchaind_spend_created(tmpctx, msg, &worthwhile, &witness))
		master_badmsg(WIRE_ONCHAIND_SPEND_CREATED, msg);

	out->proposal->welements
		= cast_const2(const struct onchain_witness_element **,
			      tal_steal(out->proposal, witness));

	/* Did it decide it's not worth it?  Don't wait for it. */
	if (!worthwhile)
		ignore_output(out);
}

static struct proposed_resolution *new_proposed_resolution(struct tracked_output *out,
							   unsigned int block_required,
							   enum tx_type tx_type)
{
	struct proposed_resolution *proposal = tal(out, struct proposed_resolution);
	proposal->tx_type = tx_type;
	proposal->depth_required = block_required - out->tx_blockheight;

	return proposal;
}

/* Modern style: we don't create tx outselves, but tell lightningd. */
static void propose_resolution_to_master(struct tracked_output *out,
					 const u8 *send_message TAKES,
					 unsigned int block_required,
					 enum tx_type tx_type)
{
	/* i.e. we want this in @block_required, so it will be broadcast by
	 * lightningd after it sees @block_required - 1. */
	status_debug("Telling lightningd about %s to resolve %s/%s"
		     " after block %u (%i more blocks)",
		     tx_type_name(tx_type),
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     block_required - 1, block_required - 1 - out->tx_blockheight);

	out->proposal = new_proposed_resolution(out, block_required, tx_type);

	wire_sync_write(REQ_FD, send_message);

	/* Get reply now: if we're replaying, tx could be included before we
	 * tell lightningd about it, so we need to recognize it! */
	handle_spend_created(out,
			     queue_until_msg(tmpctx, WIRE_ONCHAIND_SPEND_CREATED));
}

/* Create and broadcast this tx now */
static void propose_immediate_resolution(struct tracked_output *out,
					 const u8 *send_message TAKES,
					 enum tx_type tx_type)
{
	/* We add 1 to blockheight (meaning you can broadcast it now) to avoid
	 * having to check for < 0 in various places we print messages */
	propose_resolution_to_master(out, send_message, out->tx_blockheight+1,
				     tx_type);
}

/* If UTXO reaches this block, ignore it (it's not for us, it's ok!) */
static void propose_ignore(struct tracked_output *out,
			   unsigned int block_required,
			   enum tx_type tx_type)
{
	status_debug("Propose ignoring %s/%s as %s"
		     " after block %u (%i more blocks)",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(tx_type),
		     block_required,
		     block_required - out->tx_blockheight);

	/* If it's already passed, don't underflow. */
	if (block_required < out->tx_blockheight)
		block_required = out->tx_blockheight;

	out->proposal = new_proposed_resolution(out, block_required, tx_type);
	out->proposal->welements = NULL;

	/* Can we immediately ignore? */
	if (out->proposal->depth_required == 0)
		ignore_output(out);
}

/* Do any of these tx_parts spend this outpoint?  If so, return it */
static const struct wally_tx_input *
which_input_spends(const struct tx_parts *tx_parts,
		   const struct bitcoin_outpoint *outpoint)
{
	for (size_t i = 0; i < tal_count(tx_parts->inputs); i++) {
		struct bitcoin_outpoint o;
		if (!tx_parts->inputs[i])
			continue;
		wally_tx_input_get_outpoint(tx_parts->inputs[i], &o);
		if (!bitcoin_outpoint_eq(&o, outpoint))
			continue;
		return tx_parts->inputs[i];
	}
	return NULL;
}

/* Does this tx input's witness match the witness we expected? */
static bool onchain_witness_element_matches(const struct onchain_witness_element **welements,
					    const struct wally_tx_input *input)
{
	const struct wally_tx_witness_stack *stack = input->witness;
	if (stack->num_items != tal_count(welements))
		return false;
	for (size_t i = 0; i < stack->num_items; i++) {
		/* Don't compare signatures: they can change with
		 * other details */
		if (welements[i]->is_signature)
			continue;
		if (!memeq(stack->items[i].witness,
			   stack->items[i].witness_len,
			   welements[i]->witness,
			   tal_bytelen(welements[i]->witness)))
			return false;
	}
	return true;
}

/* This simple case: true if this was resolved by our proposal. */
static bool resolved_by_proposal(struct tracked_output *out,
				 const struct tx_parts *tx_parts)
{
	const struct wally_tx_input *input;

	/* If there's no TX associated, it's not us.  (SEQUENTIA: a credit
	 * output we only watch, whose note owes nothing more, has no
	 * proposal at all.) */
	if (!out->proposal || !out->proposal->welements)
		return false;

	input = which_input_spends(tx_parts, &out->outpoint);
	if (!input || !input->witness)
		return false;
	if (!onchain_witness_element_matches(out->proposal->welements, input))
		return false;

	out->resolved = tal(out, struct resolution);
	out->resolved->txid = tx_parts->txid;
	status_debug("Resolved %s/%s by our proposal %s (%s)",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(out->proposal->tx_type),
		     fmt_bitcoin_txid(tmpctx, &out->resolved->txid));

	out->resolved->depth = 0;
	out->resolved->tx_type = out->proposal->tx_type;
	return true;
}

/* Otherwise, we figure out what happened and then call this. */
static void resolved_by_other(struct tracked_output *out,
			      const struct bitcoin_txid *txid,
			      enum tx_type tx_type)
{
	out->resolved = tal(out, struct resolution);
	out->resolved->txid = *txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = tx_type;

	status_debug("Resolved %s/%s by %s (%s)",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(tx_type),
		     fmt_bitcoin_txid(tmpctx, txid));
}

static void unknown_spend(struct tracked_output *out,
			  const struct tx_parts *tx_parts)
{
	out->resolved = tal(out, struct resolution);
	out->resolved->txid = tx_parts->txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = UNKNOWN_TXTYPE;

	status_broken("Unknown spend of %s/%s by %s",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     fmt_bitcoin_txid(tmpctx, &tx_parts->txid));
}

static u64 unmask_commit_number(const struct tx_parts *tx,
				uint32_t locktime,
				enum side opener,
				const struct pubkey *local_payment_basepoint,
				const struct pubkey *remote_payment_basepoint)
{
	u64 obscurer;
	const struct pubkey *keys[NUM_SIDES];
	keys[LOCAL] = local_payment_basepoint;
	keys[REMOTE] = remote_payment_basepoint;

	/* BOLT #3:
	 *
	 * The 48-bit commitment number is obscured by `XOR` with the lower 48 bits of...
	 */
	obscurer = commit_number_obscurer(keys[opener], keys[!opener]);

	/* BOLT #3:
	 *
	 * * locktime: upper 8 bits are 0x20, lower 24 bits are the lower 24 bits of the obscured commitment number
	 *...
	 * * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
	 */
	return ((locktime & 0x00FFFFFF)
		| (tx->inputs[0]->sequence & (u64)0x00FFFFFF) << 24)
		^ obscurer;
}

static bool is_mutual_close(const struct tx_parts *tx,
			    const u8 *local_scriptpubkey,
			    const u8 *remote_scriptpubkey)
{
	size_t i;
	bool local_matched = false, remote_matched = false;

	for (i = 0; i < tal_count(tx->outputs); i++) {
		/* To be paranoid, we only let each one match once. */
		if (chainparams->is_elements &&
		    tx->outputs[i]->script_len == 0) {
			/* This is a fee output, ignore please */
			continue;
		} else if (wally_tx_output_scripteq(tx->outputs[i],
						    local_scriptpubkey)
			   && !local_matched) {
			local_matched = true;
		} else if (wally_tx_output_scripteq(tx->outputs[i],
						    remote_scriptpubkey)
			   && !remote_matched)
			remote_matched = true;
		else
			return false;
	}

	return true;
}

/* We only ever send out one, so matching it is easy. */
static bool is_local_commitment(const struct bitcoin_txid *txid,
				const struct bitcoin_txid *our_broadcast_txid)
{
	return bitcoin_txid_eq(txid, our_broadcast_txid);
}

/* BOLT #5:
 *
 * Outputs that are *resolved* are considered *irrevocably resolved*
 * once the remote's *resolving* transaction is included in a block at least 100
 * deep, on the most-work blockchain.
 */
static size_t num_not_irrevocably_resolved(struct tracked_output **outs)
{
	size_t i, num = 0;

	for (i = 0; i < tal_count(outs); i++) {
		if (!outs[i]->resolved || outs[i]->resolved->depth < 100)
			num++;
	}
	return num;
}

/* If a tx spends @out, and is CSV delayed by @delay, what's the first
 * block it can get into? */
static u32 rel_blockheight(const struct tracked_output *out, u32 delay)
{
	return out->tx_blockheight + delay;
}

/* What is the first block that the proposal can get into? */
static u32 prop_blockheight(const struct tracked_output *out)
{
	return rel_blockheight(out, out->proposal->depth_required);
}

static void billboard_update(struct tracked_output **outs)
{
	const struct tracked_output *best = NULL;

	/* Highest priority is to report on proposals we have */
	for (size_t i = 0; i < tal_count(outs); i++) {
		if (!outs[i]->proposal || outs[i]->resolved)
			continue;
		if (!best || prop_blockheight(outs[i]) < prop_blockheight(best))
			best = outs[i];
	}

	if (best) {
		/* If we've broadcast and not seen yet, this happens */
		if (best->proposal->depth_required <= best->depth) {
			peer_billboard(false,
				       "%u outputs unresolved: waiting confirmation that we spent %s (%s) using %s",
				       num_not_irrevocably_resolved(outs),
				       output_type_name(best->output_type),
				       fmt_bitcoin_outpoint(tmpctx, &best->outpoint),
				       tx_type_name(best->proposal->tx_type));
		} else {
			peer_billboard(false,
				       "%u outputs unresolved: in %u blocks will spend %s (%s) using %s",
				       num_not_irrevocably_resolved(outs),
				       best->proposal->depth_required - best->depth,
				       output_type_name(best->output_type),
				       fmt_bitcoin_outpoint(tmpctx, &best->outpoint),
				       tx_type_name(best->proposal->tx_type));
		}
		return;
	}

	/* Now, just report on the last thing we're waiting out. */
	for (size_t i = 0; i < tal_count(outs); i++) {
		/* FIXME: Can this happen?  No proposal, no resolution? */
		if (!outs[i]->resolved)
			continue;
		if (!best || outs[i]->resolved->depth < best->resolved->depth)
			best = outs[i];
	}

	if (best) {
		peer_billboard(false,
			       "All outputs resolved:"
			       " waiting %u more blocks before forgetting"
			       " channel",
			       best->resolved->depth < 100
			       ? 100 - best->resolved->depth : 0);
		return;
	}

	/* Not sure this can happen, but take last one (there must be one!) */
	best = outs[tal_count(outs)-1];
	peer_billboard(false, "%u outputs unresolved: %s is one (depth %u)",
		       num_not_irrevocably_resolved(outs),
		       output_type_name(best->output_type), best->depth);
}

/* BOLT #5:
 * - SHOULD extract the payment preimage from the transaction input witness, if
 *   it's not already known.
 */
static void handle_htlc_onchain_fulfill(struct tracked_output *out,
					const struct tx_parts *tx_parts,
					const struct bitcoin_outpoint *htlc_outpoint)
{
	const struct wally_tx_witness_item *preimage_item;
	struct preimage preimage;
	struct sha256 sha;
	struct ripemd160 ripemd;

	/* Our HTLC, they filled (must be an HTLC-success tx). */
	if (out->tx_type == THEIR_UNILATERAL
		|| out->tx_type == THEIR_REVOKED_UNILATERAL) {
		/* BOLT #3:
		 *
		 * ## HTLC-Timeout and HTLC-Success Transactions
		 *
		 * ...  `txin[0]` witness stack: `0 <remotehtlcsig> <localhtlcsig>
		 * <payment_preimage>` for HTLC-success
		 */
		if (tx_parts->inputs[htlc_outpoint->n]->witness->num_items != 5) /* +1 for wscript */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s/%s spent with weird witness %zu",
				      tx_type_name(out->tx_type),
				      output_type_name(out->output_type),
				      tx_parts->inputs[htlc_outpoint->n]->witness->num_items);

		preimage_item = &tx_parts->inputs[htlc_outpoint->n]->witness->items[3];
	} else if (out->tx_type == OUR_UNILATERAL) {
		/* BOLT #3:
		 *
		 * The remote node can redeem the HTLC with the witness:
		 *
		 *    <remotehtlcsig> <payment_preimage>
		 */
		if (tx_parts->inputs[htlc_outpoint->n]->witness->num_items != 3) /* +1 for wscript */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s/%s spent with weird witness %zu",
				      tx_type_name(out->tx_type),
				      output_type_name(out->output_type),
				      tx_parts->inputs[htlc_outpoint->n]->witness->num_items);

		preimage_item = &tx_parts->inputs[htlc_outpoint->n]->witness->items[1];
	} else
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "onchain_fulfill for %s/%s?",
			      tx_type_name(out->tx_type),
			      output_type_name(out->output_type));

	/* cppcheck-suppress uninitvar - doesn't know status_failed exits? */
	if (preimage_item->witness_len != sizeof(preimage)) {
		/* It's possible something terrible happened and we broadcast
		 * an old commitment state, which they're now cleaning up.
		 *
		 * We stumble along.
		 */
		if (out->tx_type == OUR_UNILATERAL
		    && preimage_item->witness_len == PUBKEY_CMPR_LEN) {
			status_unusual("Our cheat attempt failed, they're "
				       "taking our htlc out (%s)",
				       fmt_amount_sat(tmpctx, out->sat));
			return;
		}
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s/%s spent with bad witness length %zu",
			      tx_type_name(out->tx_type),
			      output_type_name(out->output_type),
			      preimage_item->witness_len);
	}
	memcpy(&preimage, preimage_item->witness, sizeof(preimage));
	sha256(&sha, &preimage, sizeof(preimage));
	ripemd160(&ripemd, &sha, sizeof(sha));

	if (!ripemd160_eq(&ripemd, &out->htlc.ripemd))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s/%s spent with bad preimage %s (ripemd not %s)",
			      tx_type_name(out->tx_type),
			      output_type_name(out->output_type),
			      fmt_preimage(tmpctx, &preimage),
			      fmt_ripemd160(tmpctx, &out->htlc.ripemd));

	/* we stash the payment_hash into the tracking_output so we
	 * can pass it along, if needbe, to the coin movement tracker */
	out->payment_hash = sha;

	/* Tell master we found a preimage. */
	status_debug("%s/%s gave us preimage %s",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     fmt_preimage(tmpctx, &preimage));
	wire_sync_write(REQ_FD,
			take(towire_onchaind_extracted_preimage(NULL,
							       &preimage)));
}

static void resolve_htlc_tx(struct tracked_output ***outs,
			    size_t out_index,
			    const struct tx_parts *htlc_tx,
			    size_t input_num,
			    u32 tx_blockheight)
{
	struct tracked_output *out;
	struct amount_sat amt;
	struct amount_asset asset;
	struct bitcoin_outpoint outpoint;
	u8 *msg;
	u8 *wscript = bitcoin_wscript_htlc_tx(tmpctx, to_self_delay[LOCAL],
					      &keyset->self_revocation_key,
					      &keyset->self_delayed_payment_key);


	/* BOLT #5:
	 *
	 *       - SHOULD resolve the HTLC-timeout transaction by spending it to
	 *         a convenient address...
	 *       - MUST wait until the `OP_CHECKSEQUENCEVERIFY` delay has passed
	 *         (as specified by the remote node's `open_channel`
	 *         `to_self_delay` field) before spending that HTLC-timeout
	 *         output.
	 */
	outpoint.txid = htlc_tx->txid;
	outpoint.n = input_num;

	asset = wally_tx_output_get_amount(htlc_tx->outputs[outpoint.n]);
	assert(amount_asset_is(&asset, channel_asset));
	amt = amount_sat(asset.value);
	out = new_tracked_output(outs, &outpoint,
 				 tx_blockheight,
 				 (*outs)[out_index]->resolved->tx_type,
				 amt,
 				 DELAYED_OUTPUT_TO_US,
 				 NULL, NULL, NULL);

	msg = towire_onchaind_spend_to_us(NULL,
					  &outpoint, amt,
					  to_self_delay[LOCAL],
					  rel_blockheight(out, to_self_delay[LOCAL]),
					  commit_num,
					  wscript);
	propose_resolution_to_master(out, take(msg),
				     rel_blockheight(out, to_self_delay[LOCAL]),
				     OUR_DELAYED_RETURN_TO_WALLET);
}

/* BOLT #5:
 *
 *   - MUST *resolve* the _remote node's HTLC-timeout transaction_ by spending it
 *     using the revocation private key.
 *   - MUST *resolve* the _remote node's HTLC-success transaction_ by spending it
 *     using the revocation private key.
 */
static void steal_htlc_tx(struct tracked_output *out,
			  struct tracked_output ***outs,
			  const struct tx_parts *htlc_tx,
			  u32 htlc_tx_blockheight,
			  enum tx_type htlc_tx_type,
			  const struct bitcoin_outpoint *htlc_outpoint)
{
	struct tracked_output *htlc_out;
	struct amount_asset asset;
	struct amount_sat htlc_out_amt;
	const u8 *msg;

	u8 *wscript = bitcoin_wscript_htlc_tx(htlc_tx, to_self_delay[REMOTE],
					      &keyset->self_revocation_key,
					      &keyset->self_delayed_payment_key);

	asset = wally_tx_output_get_amount(htlc_tx->outputs[htlc_outpoint->n]);
	assert(amount_asset_is(&asset, channel_asset));
	htlc_out_amt = amount_sat(asset.value);

	htlc_out = new_tracked_output(outs,
				      htlc_outpoint, htlc_tx_blockheight,
				      htlc_tx_type,
				      htlc_out_amt,
				      DELAYED_CHEAT_OUTPUT_TO_THEM,
				      &out->htlc, wscript, NULL);

	/* mark commitment tx htlc output as 'resolved by them' */
	resolved_by_other(out, &htlc_tx->txid, htlc_tx_type);

	/* BOLT #3:
	 *
	 * To spend this via penalty, the remote node uses a witness stack
	 * `<revocationsig> 1`
	 */
	msg = towire_onchaind_spend_penalty(NULL,
					    htlc_outpoint, htlc_out_amt,
					    remote_per_commitment_secret,
					    tal_dup(tmpctx, u8, &ONE),
					    htlc_out->wscript);

	/* Spend this immediately. */
	propose_immediate_resolution(htlc_out, take(msg), OUR_PENALTY_TX);
}

static void onchain_annotate_txout(const struct bitcoin_outpoint *outpoint,
				   enum wallet_tx_type type)
{
	wire_sync_write(REQ_FD, take(towire_onchaind_annotate_txout(
				    tmpctx, outpoint, type)));
}

static void onchain_annotate_txin(const struct bitcoin_txid *txid, u32 innum,
				  enum wallet_tx_type type)
{
	wire_sync_write(REQ_FD, take(towire_onchaind_annotate_txin(
				    tmpctx, txid, innum, type)));
}

/* An output has been spent: see if it resolves something we care about.
 * Return true if it's useful to know about, false to suppress this and any
 * child transactions.
 */
static bool output_spent(struct tracked_output ***outs,
			 const struct tx_parts *tx_parts,
			 u32 input_num,
			 u32 tx_blockheight)
{
	bool interesting = false;

	for (size_t i = 0; i < tal_count(*outs); i++) {
		struct tracked_output *out = (*outs)[i];
		struct bitcoin_outpoint htlc_outpoint;

		if (!wally_tx_input_spends(tx_parts->inputs[input_num],
					   &out->outpoint))
			continue;

		interesting = true;

		if (out->resolved)
			continue;

		/* SEQUENTIA: a symmetric channel's state output. */
		if (out->output_type == SYM_STATE_OUTPUT) {
			sym_state_spent(outs, out, tx_parts, input_num,
					tx_blockheight);
			continue;
		}

		/* Was this our resolution? */
		if (resolved_by_proposal(out, tx_parts)) {
			/* SEQUENTIA: our credit claim: what it paid us, and
			 * what it left for a later note. */
			if (out->output_type == CREDIT_OUTPUT_TO_THEM)
				credit_output_spent(outs, out, tx_parts,
						    input_num, tx_blockheight,
						    true);
			/* If it's our htlc tx, we need to resolve that, too. */
			if (out->resolved->tx_type == OUR_HTLC_SUCCESS_TX
			    || out->resolved->tx_type == OUR_HTLC_TIMEOUT_TX) {
				/* SEQUENTIA: or our covenant claim's D. */
				if (option_seq_taproot_covenant)
					tcov_resolve_claim(outs, i, tx_parts,
							   input_num,
							   tx_blockheight);
				else
					resolve_htlc_tx(outs, i, tx_parts,
							input_num,
							tx_blockheight);
			}

			record_coin_movements(out, tx_blockheight,
					      &tx_parts->txid);
			break;
		}

		htlc_outpoint.txid = tx_parts->txid;
		htlc_outpoint.n = input_num;

		switch (out->output_type) {
		case OUTPUT_TO_US:
		case DELAYED_OUTPUT_TO_US:
			unknown_spend(out, tx_parts);
			record_external_deposit(out, out->tx_blockheight,
						mk_mvt_tags(MVT_PENALIZED));
			break;

		case THEIR_HTLC:
			if (out->tx_type == THEIR_REVOKED_UNILATERAL) {
				struct mvt_tags tags = mk_mvt_tags(MVT_HTLC_TIMEOUT, MVT_STEALABLE);

				record_external_deposit(out, out->tx_blockheight,
							tags);
				record_external_spend(&tx_parts->txid,
						      out,
						      tx_blockheight,
						      tags);

				/* we've actually got a 'new' output here */
				if (option_seq_taproot_covenant)
					tcov_steal_claim(out, outs, tx_parts,
							 tx_blockheight,
							 THEIR_HTLC_TIMEOUT_TO_THEM,
							 &htlc_outpoint);
				else
					steal_htlc_tx(out, outs, tx_parts,
						      tx_blockheight,
						      THEIR_HTLC_TIMEOUT_TO_THEM,
						      &htlc_outpoint);
			} else {
				/* We ignore this timeout tx, since we should
				 * resolve by ignoring once we reach depth. */
				onchain_annotate_txout(
				    &htlc_outpoint,
				    TX_CHANNEL_HTLC_TIMEOUT | TX_THEIRS);
			}
			break;

		case OUR_HTLC:
			/* The only way	they can spend this: fulfill; even
			 * if it's revoked: */
			/* BOLT #5:
			 *
			 * A node:
			 *   - if the commitment transaction HTLC output is spent using the payment
			 *   preimage, the output is considered *irrevocably resolved*:
			 *     - MUST extract the payment preimage from the transaction input witness.
			 */
			/* BOLT #5:
			 *
			 * A local node:
			 *   - if the commitment transaction HTLC output is spent using the payment
			 *   preimage:
			 *     - MUST extract the payment preimage from the HTLC-success transaction input
			 *     witness.
			 */
			if (option_seq_taproot_covenant
			    || option_seq_symmetric)
				tcov_extract_preimage(out, tx_parts,
						      &htlc_outpoint);
			else
				handle_htlc_onchain_fulfill(out, tx_parts,
							    &htlc_outpoint);

			record_to_them_htlc_fulfilled(out, out->tx_blockheight);

			if (out->tx_type == THEIR_REVOKED_UNILATERAL) {
				record_external_spend(&tx_parts->txid,
						      out,
						      tx_blockheight,
						      mk_mvt_tags(MVT_HTLC_FULFILL, MVT_STEALABLE));
				if (option_seq_taproot_covenant)
					tcov_steal_claim(out, outs, tx_parts,
							 tx_blockheight,
							 OUR_HTLC_FULFILL_TO_THEM,
							 &htlc_outpoint);
				else
					steal_htlc_tx(out, outs, tx_parts,
						      tx_blockheight,
						      OUR_HTLC_FULFILL_TO_THEM,
						      &htlc_outpoint);
			} else {
				record_external_spend(&tx_parts->txid, out,
						      tx_blockheight,
						      mk_mvt_tags(MVT_HTLC_FULFILL));
				/* BOLT #5:
				 *
				 * ## HTLC Output Handling: Local Commitment,
				 *    Local Offers
				 *...
				 *  - if the commitment transaction HTLC output
				 *    is spent using the payment preimage, the
				 *    output is considered *irrevocably resolved*
				 */
				ignore_output(out);

				onchain_annotate_txout(
				    &htlc_outpoint,
				    TX_CHANNEL_HTLC_SUCCESS | TX_THEIRS);
			}
			break;

		case FUNDING_OUTPUT:
			/* Master should be restarting us, as this implies
			 * that our old tx was unspent. */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Funding output spent again!");

		case DELAYED_CHEAT_OUTPUT_TO_THEM:
			/* SEQUENTIA: a taproot-covenant output can also be
			 * taken by its REVOKE leaf, by whoever holds the
			 * revoked secret (our watchtower), into our static
			 * payment script: then it is ours. */
			if (option_seq_taproot_covenant
			    && tcov_revoke_leaf_paid_us(tx_parts, input_num,
							tx_blockheight)) {
				resolved_by_other(out, &tx_parts->txid,
						  OUR_PENALTY_TX);
				break;
			}
			/* They successfully spent a delayed revoked output */
			resolved_by_other(out, &tx_parts->txid,
					  THEIR_DELAYED_CHEAT);

			record_external_deposit(out, out->tx_blockheight, mk_mvt_tags(MVT_STOLEN));
			break;
		case CREDIT_OUTPUT_TO_US:
		case CREDIT_OUTPUT_TO_THEM:
			credit_output_spent(outs, out, tx_parts, input_num,
					    tx_blockheight, false);
			break;

		/* Um, we don't track these! */
		case SYM_STATE_OUTPUT:
		case OUTPUT_TO_THEM:
		case DELAYED_OUTPUT_TO_THEM:
		case ELEMENTS_FEE:
		case ANCHOR_TO_US:
		case ANCHOR_TO_THEM:
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tracked spend of %s/%s?",
				      tx_type_name(out->tx_type),
				      output_type_name(out->output_type));
		}
	}

	if (!interesting) {
		struct bitcoin_txid txid;
		wally_tx_input_get_txid(tx_parts->inputs[input_num], &txid);

		status_debug("Notified about tx %s output %u spend, but we don't care",
			     fmt_bitcoin_txid(tmpctx, &txid),
			     tx_parts->inputs[input_num]->index);
	}

	return interesting;
}

static void update_resolution_depth(struct tracked_output *out, u32 depth)
{
	bool reached_reasonable_depth;

	status_debug("%s/%s->%s depth %u",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(out->resolved->tx_type),
		     depth);

	/* We only set this once. */
	reached_reasonable_depth = (out->resolved->depth < reasonable_depth
				    && depth >= reasonable_depth);

	/* BOLT #5:
	 *
	 *   - if the commitment transaction HTLC output has *timed out* and
	 *     hasn't been *resolved*:
	 *    - MUST *resolve* the output by spending it using the HTLC-timeout
	 *      transaction.
	 *    - once the resolving transaction has reached reasonable depth:
	 *      - MUST fail the corresponding incoming HTLC (if any).
	 */
	if ((out->resolved->tx_type == OUR_HTLC_TIMEOUT_TX
	     || out->resolved->tx_type == OUR_HTLC_TIMEOUT_TO_US)
	    && reached_reasonable_depth) {
		u8 *msg;
		status_debug("%s/%s reached reasonable depth %u",
			     tx_type_name(out->tx_type),
			     output_type_name(out->output_type),
			     depth);
		msg = towire_onchaind_htlc_timeout(out, &out->htlc);
		wire_sync_write(REQ_FD, take(msg));
	}
	out->resolved->depth = depth;
}

static void tx_new_depth(struct tracked_output **outs,
			 const struct bitcoin_txid *txid, u32 depth)
{
	size_t i;

	/* BOLT #5:
	 * - for any committed HTLC that does NOT have an output in this
	 *   commitment transaction:
	 *...
	 *     - otherwise:
	 *       - once the commitment transaction has reached reasonable depth:
	 *         - MUST fail the corresponding incoming HTLC (if any).
	 */
	if (bitcoin_txid_eq(&outs[0]->resolved->txid, txid)
	    && depth >= reasonable_depth
	    && missing_htlc_msgs) {
		status_debug("Sending %zu missing htlc messages",
			     tal_count(missing_htlc_msgs));
		for (i = 0; i < tal_count(missing_htlc_msgs); i++)
			wire_sync_write(REQ_FD, missing_htlc_msgs[i]);
		/* Don't do it again. */
		missing_htlc_msgs = tal_free(missing_htlc_msgs);
	}

	for (i = 0; i < tal_count(outs); i++) {
		/* Is this tx resolving an output? */
		if (outs[i]->resolved) {
			if (bitcoin_txid_eq(&outs[i]->resolved->txid, txid)) {
				update_resolution_depth(outs[i], depth);
			}
			continue;
		}

		/* Does it match this output? */
		if (!bitcoin_txid_eq(&outs[i]->outpoint.txid, txid))
			continue;

		outs[i]->depth = depth;

		/* Are we supposed to ignore it now? */
		if (outs[i]->proposal
		    && depth >= outs[i]->proposal->depth_required
		    && !outs[i]->proposal->welements) {
			ignore_output(outs[i]);

			if (outs[i]->proposal->tx_type == THEIR_HTLC_TIMEOUT_TO_THEM)
				record_external_deposit(outs[i], outs[i]->tx_blockheight,
							mk_mvt_tags(MVT_HTLC_TIMEOUT));
		}
	}
}

/* BOLT #5:
 *
 * A local node:
 *   - if it receives (or already possesses) a payment preimage for an unresolved
 *   HTLC output that it has been offered AND for which it has committed to an
 *   outgoing HTLC:
 *     - MUST *resolve* the output by spending it, using the HTLC-success
 *     transaction.
 *     - MUST NOT reveal its own preimage when it's not the final recipient...
 *     - MUST resolve the output of that HTLC-success transaction.
 *   - otherwise:
 *     - if the *remote node* is NOT irrevocably committed to the HTLC:
 *       - MUST NOT *resolve* the output by spending it.
 */
/* BOLT #5:
 *
 * A local node:
 *  - if it receives (or already possesses) a payment preimage for an unresolved
 *   HTLC output that it was offered AND for which it has committed to an
 *  outgoing HTLC:
 *     - MUST *resolve* the output by spending it to a convenient address.
 *   - otherwise:
 *     - if the remote node is NOT irrevocably committed to the HTLC:
 *       - MUST NOT *resolve* the output by spending it.
 */
/* Master makes sure we only get told preimages once other node is committed. */
static void handle_preimage(struct tracked_output **outs,
			    const struct preimage *preimage)
{
	size_t i;
	struct sha256 sha;
	struct ripemd160 ripemd;
	struct pubkey point;
	bool is_point;

	sha256(&sha, preimage, sizeof(*preimage));
	ripemd160(&ripemd, &sha, sizeof(sha));
	/* SEQUENTIA: for a point-locked HTLC we are told the scalar that
	 * opens its lock point (common/point_lock.h). */
	is_point = point_lock_point_of(preimage, &point);

	for (i = 0; i < tal_count(outs); i++) {
		const u8 *msg;

		if (outs[i]->output_type != THEIR_HTLC)
			continue;

		if (outs[i]->htlc.has_lock_point) {
			if (!is_point
			    || !pubkey_eq(&outs[i]->htlc.lock_point, &point))
				continue;
		} else if (!ripemd160_eq(&outs[i]->htlc.ripemd, &ripemd))
			continue;

		/* If HTLC has timed out, we will already have
		 * proposed a "ignore this, it's their problem".  But
		 * now try this proposal instead! */
		if (outs[i]->resolved) {
			if (outs[i]->resolved->tx_type != SELF) {
				status_broken("HTLC already resolved by %s"
					      " when we found preimage",
					      tx_type_name(outs[i]->resolved->tx_type));
				return;
			}
		}

		/* stash the payment_hash so we can track this coin movement */
		if (outs[i]->htlc.has_lock_point)
			point_lock_payment_hash(&point, &outs[i]->payment_hash);
		else
			outs[i]->payment_hash = sha;

		/* SEQUENTIA: a revoked taproot-covenant commitment's HTLC
		 * is ours by the penalty already proposed. */
		if (option_seq_taproot_covenant
		    && outs[i]->tx_type == THEIR_REVOKED_UNILATERAL)
			continue;

		/* Discard any previous resolution.  Could be a timeout,
		 * could be due to multiple identical rhashes in tx. */
		outs[i]->proposal = tal_free(outs[i]->proposal);

		if (option_seq_taproot_covenant) {
			tcov_claim_with_preimage(outs[i], preimage);
			continue;
		}
		/* SEQUENTIA: a symmetric channel's settlement HTLC. */
		if (option_seq_symmetric) {
			sym_claim_with_preimage(outs[i], preimage);
			continue;
		}

		/* BOLT #5:
		 *
		 * A local node:
		 *  - if it receives (or already possesses) a payment preimage
		 *    for an unresolved HTLC output that it has been offered
		 *    AND for which it has committed to an outgoing HTLC:
		 *    - MUST *resolve* the output by spending it, using the
		 *      HTLC-success transaction.
		 */
		if (outs[i]->remote_htlc_sig) {
			struct amount_sat fee;
			const u8 *htlc_wscript;

			/* FIXME: lightningd could derive this itself? */
			htlc_wscript = bitcoin_wscript_htlc_tx(tmpctx,
							       to_self_delay[LOCAL],
							       &keyset->self_revocation_key,
							       &keyset->self_delayed_payment_key);

			fee = get_htlc_success_fee(outs[i]);
			msg = towire_onchaind_spend_htlc_success(NULL,
								 &outs[i]->outpoint,
								 outs[i]->sat,
								 fee,
								 outs[i]->htlc.id,
								 commit_num,
								 outs[i]->remote_htlc_sig,
								 preimage,
								 outs[i]->wscript,
								 htlc_wscript);
			propose_immediate_resolution(outs[i], take(msg),
						     OUR_HTLC_SUCCESS_TX);
		} else {
			/* BOLT #5:
			 *
			 * A local node:
			 * - if it receives (or already possesses) a payment
			 *   preimage for an unresolved HTLC output that it was
			 *   offered AND for which it has committed to an
			 *  outgoing HTLC:
			 *    - MUST *resolve* the output by spending it to a
			 *      convenient address.
			 */
			msg = towire_onchaind_spend_fulfill(NULL,
							    &outs[i]->outpoint,
							    outs[i]->sat,
							    outs[i]->htlc.id,
							    remote_per_commitment_point,
							    preimage,
							    outs[i]->wscript);

			propose_immediate_resolution(outs[i], take(msg),
						     THEIR_HTLC_FULFILL_TO_US);
		}
	}
}

static void memleak_remove_globals(struct htable *memtable, const tal_t *topctx)
{
	memleak_scan_obj(memtable, keyset);
	memleak_ptr(memtable, remote_per_commitment_point);
	memleak_ptr(memtable, remote_per_commitment_secret);
	memleak_ptr(memtable, topctx);
	memleak_scan_obj(memtable, missing_htlc_msgs);
	memleak_scan_obj(memtable, queued_msgs);
	/* SEQUENTIA: a symmetric channel's states and HTLCs. */
	memleak_scan_obj(memtable, sym_local);
	memleak_scan_obj(memtable, sym_remote);
	memleak_scan_obj(memtable, sym_remote_pending);
	memleak_scan_obj(memtable, sym_htlcs);
}

static void handle_dev_memleak(struct tracked_output ***outs, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	if (!fromwire_onchaind_dev_memleak(msg))
		master_badmsg(WIRE_ONCHAIND_DEV_MEMLEAK, msg);

	memtable = memleak_start(tmpctx);
	memleak_ptr(memtable, msg);

	/* Top-level context is parent of outs */
	memleak_remove_globals(memtable, tal_parent(*outs));
	memleak_scan_obj(memtable, *outs);

	found_leak = dump_memleak(memtable, memleak_status_broken, NULL);
	wire_sync_write(REQ_FD,
			take(towire_onchaind_dev_memleak_reply(NULL,
							      found_leak)));
}

static void handle_onchaind_depth(struct tracked_output ***outs, const u8 *msg)
{
	struct bitcoin_txid txid;
	u32 depth;

	if (!fromwire_onchaind_depth(msg, &txid, &depth))
		master_badmsg(WIRE_ONCHAIND_DEPTH, msg);

	tx_new_depth(*outs, &txid, depth);
}

static void handle_onchaind_spent(struct tracked_output ***outs, const u8 *msg)
{
	struct tx_parts *tx_parts;
	u32 input_num, tx_blockheight;
	bool interesting;

	if (!fromwire_onchaind_spent(msg, msg, &tx_parts, &input_num,
				     &tx_blockheight))
		master_badmsg(WIRE_ONCHAIND_SPENT, msg);

	interesting = output_spent(outs, tx_parts, input_num, tx_blockheight);

	/* Tell lightningd if it was interesting */
	wire_sync_write(REQ_FD, take(towire_onchaind_spent_reply(NULL, interesting)));
}

static void handle_onchaind_known_preimage(struct tracked_output ***outs,
					   const u8 *msg)
{
	struct preimage preimage;

	if (!fromwire_onchaind_known_preimage(msg, &preimage))
		master_badmsg(WIRE_ONCHAIND_KNOWN_PREIMAGE, msg);
	handle_preimage(*outs, &preimage);
}

/* BOLT #5:
 *
 * A node:
 *  - once it has broadcast a funding transaction OR sent a commitment signature
 *  for a commitment transaction that contains an HTLC output:
 *    - until all outputs are *irrevocably resolved*:
 *      - MUST monitor the blockchain for transactions that spend any output that
 *      is NOT *irrevocably resolved*.
 *  - MUST *resolve* all outputs, as specified below.
 *  - MUST be prepared to resolve outputs multiple times, in case of blockchain
 *  reorganizations.
 */
static void wait_for_resolved(struct tracked_output **outs)
{
	billboard_update(outs);

	while (num_not_irrevocably_resolved(outs) != 0) {
		const u8 *msg;
		enum onchaind_wire mtype;

		if (tal_count(queued_msgs)) {
			msg = tal_steal(outs, queued_msgs[0]);
			tal_arr_remove(&queued_msgs, 0);
		} else
			msg = wire_sync_read(outs, REQ_FD);

		mtype = fromwire_peektype(msg);
		status_debug("Got new message %s", onchaind_wire_name(mtype));

		switch (mtype) {
		case WIRE_ONCHAIND_DEPTH:
			handle_onchaind_depth(&outs, msg);
			goto handled;
		case WIRE_ONCHAIND_SPENT:
			handle_onchaind_spent(&outs, msg);
			goto handled;
		case WIRE_ONCHAIND_KNOWN_PREIMAGE:
			handle_onchaind_known_preimage(&outs, msg);
			goto handled;
		case WIRE_ONCHAIND_DEV_MEMLEAK:
			handle_dev_memleak(&outs, msg);
			goto handled;
		case WIRE_ONCHAIND_CREDIT_NOTE:
			handle_onchaind_credit_note(outs, msg);
			goto handled;

		/* Unexpected messages */
		case WIRE_ONCHAIND_INIT:
		case WIRE_ONCHAIND_HTLCS:
		case WIRE_ONCHAIND_SPEND_CREATED:

		/* We send these, not receive! */
		case WIRE_ONCHAIND_INIT_REPLY:
		case WIRE_ONCHAIND_SPENT_REPLY:
		case WIRE_ONCHAIND_EXTRACTED_PREIMAGE:
		case WIRE_ONCHAIND_MISSING_HTLC_OUTPUT:
		case WIRE_ONCHAIND_HTLC_TIMEOUT:
		case WIRE_ONCHAIND_ALL_IRREVOCABLY_RESOLVED:
		case WIRE_ONCHAIND_ADD_UTXO:
		case WIRE_ONCHAIND_DEV_MEMLEAK_REPLY:
		case WIRE_ONCHAIND_ANNOTATE_TXOUT:
		case WIRE_ONCHAIND_ANNOTATE_TXIN:
		case WIRE_ONCHAIND_NOTIFY_COIN_MVT:
		case WIRE_ONCHAIND_NOTIFY_PENALTY_ADJ:
		case WIRE_ONCHAIND_SPEND_TO_US:
		case WIRE_ONCHAIND_SPEND_PENALTY:
		case WIRE_ONCHAIND_SPEND_HTLC_SUCCESS:
		case WIRE_ONCHAIND_SPEND_HTLC_TIMEOUT:
		case WIRE_ONCHAIND_SPEND_FULFILL:
		case WIRE_ONCHAIND_SPEND_HTLC_EXPIRED:
		case WIRE_ONCHAIND_SPEND_TCOV:
		case WIRE_ONCHAIND_SPEND_CREDIT_CLAIM:
		case WIRE_ONCHAIND_SYM_INIT:
		case WIRE_ONCHAIND_SPEND_SYM:
			break;
		}
		master_badmsg(-1, msg);

	handled:
		billboard_update(outs);
		tal_free(msg);
		clean_tmpctx();
	}

	wire_sync_write(REQ_FD,
			take(towire_onchaind_all_irrevocably_resolved(outs)));
}

struct htlcs_info {
	struct htlc_stub *htlcs;
	bool *tell_if_missing;
	bool *tell_immediately;
};

struct htlc_with_tells {
	struct htlc_stub htlc;
	bool tell_if_missing, tell_immediately;
};

static int cmp_htlc_with_tells_cltv(const struct htlc_with_tells *a,
				    const struct htlc_with_tells *b, void *unused)
{
	if (a->htlc.cltv_expiry < b->htlc.cltv_expiry)
		return -1;
	else if (a->htlc.cltv_expiry > b->htlc.cltv_expiry)
		return 1;
	return 0;
}

static struct htlcs_info *init_reply(const tal_t *ctx, const char *what)
{
	struct htlcs_info *htlcs_info = tal(ctx, struct htlcs_info);
	const u8 *msg;
	struct htlc_with_tells *htlcs;

	/* commit_num is 0 for mutual close, but we don't care about HTLCs
	 * then anyway. */

	/* Send init_reply first, so billboard gets credited to ONCHAIND */
	wire_sync_write(REQ_FD,
			take(towire_onchaind_init_reply(NULL, commit_num)));

	peer_billboard(true, what);

	/* Read in htlcs (ignoring everything else for now) */
	msg = queue_until_msg(tmpctx, WIRE_ONCHAIND_HTLCS);
	if (!fromwire_onchaind_htlcs(htlcs_info, msg,
				     &htlcs_info->htlcs,
				     &htlcs_info->tell_if_missing,
				     &htlcs_info->tell_immediately))
		master_badmsg(WIRE_ONCHAIND_HTLCS, msg);

	/* One convenient structure, so we sort them together! */
	htlcs = tal_arr(tmpctx, struct htlc_with_tells, tal_count(htlcs_info->htlcs));
	for (size_t i = 0; i < tal_count(htlcs); i++) {
		htlcs[i].htlc = htlcs_info->htlcs[i];
		htlcs[i].tell_if_missing = htlcs_info->tell_if_missing[i];
		htlcs[i].tell_immediately = htlcs_info->tell_immediately[i];
	}

	/* Sort by CLTV, so matches are in CLTV order (and easy to skip dups) */
	asort(htlcs, tal_count(htlcs), cmp_htlc_with_tells_cltv, NULL);

	/* Now put them back (prev were allocated off tmpctx) */
	htlcs_info->htlcs = tal_arr(htlcs_info, struct htlc_stub, tal_count(htlcs));
	htlcs_info->tell_if_missing = tal_arr(htlcs_info, bool, tal_count(htlcs));
	htlcs_info->tell_immediately = tal_arr(htlcs_info, bool, tal_count(htlcs));
	for (size_t i = 0; i < tal_count(htlcs); i++) {
		htlcs_info->htlcs[i] = htlcs[i].htlc;
		htlcs_info->tell_if_missing[i] = htlcs[i].tell_if_missing;
		htlcs_info->tell_immediately[i] = htlcs[i].tell_immediately;
	}

	return htlcs_info;
}

static void handle_mutual_close(struct tracked_output **outs,
				const struct tx_parts *tx)
{
	/* In this case, we don't care about htlcs: there are none. */
	init_reply(tmpctx, "Tracking mutual close transaction");

	/* Annotate the first input as close. We can currently only have a
	 * single input for these. */
	onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_CLOSE);

	/* BOLT #5:
	 *
	 * A closing transaction *resolves* the funding transaction output.
	 *
	 * In the case of a mutual close, a node need not do anything else, as it has
	 * already agreed to the output, which is sent to its specified `scriptpubkey`
	 */
	resolved_by_other(outs[0], &tx->txid, MUTUAL_CLOSE);
	wait_for_resolved(outs);
}

static u8 **derive_htlc_scripts(const struct htlc_stub *htlcs, enum side side)
{
	size_t i;
	u8 **htlc_scripts = tal_arr(htlcs, u8 *, tal_count(htlcs));

	for (i = 0; i < tal_count(htlcs); i++) {
		if (htlcs[i].owner == side)
			htlc_scripts[i] = htlc_offered_wscript(htlc_scripts,
							       &htlcs[i].ripemd,
							       keyset,
							       option_anchor_outputs,
							       option_anchors_zero_fee_htlc_tx);
		else {
			/* FIXME: remove abs_locktime */
			struct abs_locktime ltime;
			if (!blocks_to_abs_locktime(htlcs[i].cltv_expiry,
						    &ltime))
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Could not convert cltv_expiry %u to locktime",
					      htlcs[i].cltv_expiry);
			htlc_scripts[i] = htlc_received_wscript(htlc_scripts,
								&htlcs[i].ripemd,
								&ltime,
								keyset,
								option_anchor_outputs,
								option_anchors_zero_fee_htlc_tx);
		}
	}
	return htlc_scripts;
}

static size_t resolve_our_htlc_ourcommit(struct tracked_output *out,
					 const size_t *matches,
					 const struct htlc_stub *htlcs,
					 u8 **htlc_scripts)
{
	struct bitcoin_tx *tx = NULL;
	size_t i;
	struct amount_sat fee;
	struct amount_msat htlc_amount;
	const u8 *msg, *htlc_wscript;

	if (!amount_sat_to_msat(&htlc_amount, out->sat))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Overflow in our_htlc output %s",
			      fmt_amount_sat(tmpctx, out->sat));

	assert(tal_count(matches));

	/* These htlcs are all possibilities, but signature will only match
	 * one with the correct cltv: check which that is. */
	for (i = 0; i < tal_count(matches); i++) {
		/* Skip over duplicate HTLCs, since we only need one. */
		if (i > 0
		    && (htlcs[matches[i]].cltv_expiry
			== htlcs[matches[i-1]].cltv_expiry))
			continue;

		/* BOLT #5:
		 *
		 * A node:
		 * ...
		 *  - if the commitment transaction HTLC output has *timed out*
		 *  and hasn't been *resolved*:
		 *    - MUST *resolve* the output by spending it using the
		 *    HTLC-timeout transaction.
		 */
		tx = htlc_timeout_tx(tmpctx, chainparams,
				     &out->outpoint,
				     htlc_scripts[matches[i]], htlc_amount,
				     htlcs[matches[i]].cltv_expiry,
				     to_self_delay[LOCAL], 0, keyset,
				     option_anchor_outputs,
				     option_anchors_zero_fee_htlc_tx,
				     channel_asset);

		if (set_htlc_timeout_fee(tx, out->remote_htlc_sig,
					 htlc_scripts[matches[i]]))
			break;
	}

	/* Since there's been trouble with this before, we go to some length
	 * to give details here! */
	if (i == tal_count(matches)) {
		char *cltvs, *wscripts;

		cltvs = tal_fmt(tmpctx, "%u", htlcs[matches[0]].cltv_expiry);
		wscripts = tal_hex(tmpctx, htlc_scripts[matches[0]]);

		for (i = 1; i < tal_count(matches); i++) {
			tal_append_fmt(&cltvs, "/%u",
				       htlcs[matches[i]].cltv_expiry);
			tal_append_fmt(&wscripts, "/%s",
				       tal_hex(tmpctx, htlc_scripts[matches[i]]));
		}

		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "No valid signature found for %zu htlc_timeout_txs"
			      " feerate %u-%u,"
			      " last tx %s, input %s, signature %s,"
			      " cltvs %s wscripts %s"
			      "%s%s",
			      tal_count(matches),
			      min_possible_feerate, max_possible_feerate,
			      fmt_bitcoin_tx(tmpctx, tx),
			      fmt_amount_sat(tmpctx, out->sat),
			      fmt_bitcoin_signature(tmpctx,
						    out->remote_htlc_sig),
			      cltvs, wscripts,
			      option_anchor_outputs
			      ? " option_anchor_outputs" : "",
			      option_anchors_zero_fee_htlc_tx
			      ? " option_anchors_zero_fee_htlc_tx" : "");
	}

	/* FIXME: lightningd could derive this itself? */
	htlc_wscript = bitcoin_wscript_htlc_tx(tmpctx,
					       to_self_delay[LOCAL],
					       &keyset->self_revocation_key,
					       &keyset->self_delayed_payment_key);
	fee = bitcoin_tx_compute_fee(tx);
	msg = towire_onchaind_spend_htlc_timeout(NULL,
						 &out->outpoint,
						 out->sat,
						 fee,
						 htlcs[matches[i]].id,
						 htlcs[matches[i]].cltv_expiry,
						 commit_num,
						 out->remote_htlc_sig,
						 htlc_scripts[matches[i]],
						 htlc_wscript);

	propose_resolution_to_master(out, take(msg),
				     /* nLocktime: we have to be *after* that block! */
				     htlcs[matches[i]].cltv_expiry + 1,
				     OUR_HTLC_TIMEOUT_TX);
	return matches[i];
}

/* wscript for *received* htlcs (ie. our htlcs in their commit tx, or their
 * htlcs in our commit tx) includes cltv, so they must be the same for all
 * matching htlcs.  Unless, of course, they've found a sha256 clash. */
static u32 matches_cltv(const size_t *matches,
			const struct htlc_stub *htlcs)
{
	for (size_t i = 1; i < tal_count(matches); i++) {
		assert(matches[i] < tal_count(htlcs));
		assert(htlcs[matches[i]].cltv_expiry
		       == htlcs[matches[i-1]].cltv_expiry);
	}
	return htlcs[matches[0]].cltv_expiry;
}

static size_t resolve_our_htlc_theircommit(struct tracked_output *out,
					   const size_t *matches,
					   const struct htlc_stub *htlcs,
					   u8 **htlc_scripts)
{
	const u8 *msg;
	u32 cltv_expiry = matches_cltv(matches, htlcs);
	/* They're all equivalent: might as well use first one. */
	const struct htlc_stub *htlc = &htlcs[matches[0]];

	/* BOLT #5:
	 *
	 * A local node:
	 * ...
	 *   - if the commitment transaction HTLC output has *timed out* AND NOT
	 *     been *resolved*:
	 *     - MUST *resolve* the output, by spending it to a convenient
	 *       address.
	 */
	msg = towire_onchaind_spend_htlc_expired(NULL,
						 &out->outpoint, out->sat,
						 htlc->id,
						 cltv_expiry,
						 remote_per_commitment_point,
						 htlc_scripts[matches[0]]);
	propose_resolution_to_master(out, take(msg),
				     /* nLocktime: we have to be *after* that block! */
				     cltv_expiry + 1,
				     OUR_HTLC_TIMEOUT_TO_US);

	return matches[0];
}

/* Returns which htlcs it chose to use of matches[] */
static size_t resolve_their_htlc(struct tracked_output *out,
				 const size_t *matches,
				 const struct htlc_stub *htlcs,
				 u8 **htlc_scripts)
{
	size_t which_htlc;

	/* BOLT #5:
	 *
	 * If not otherwise resolved, once the HTLC output has expired, it is
	 * considered *irrevocably resolved*.
	 */

	/* BOLT #5:
	 *
	 * If it's NOT otherwise resolved, once the HTLC output has expired, it is
	 * considered *irrevocably resolved*.
	 */

	/* The two cases are identical as far as default handling goes.
	 * But in the remote commitment / remote offer (ie. caller is
	 * handle_their_unilateral), htlcs which match may have different cltvs.
	 * So wait until the worst case (largest HTLC). */
	assert(tal_count(matches));
	which_htlc = matches[0];
	for (size_t i = 1; i < tal_count(matches); i++) {
		if (htlcs[matches[i]].cltv_expiry > htlcs[which_htlc].cltv_expiry)
			which_htlc = matches[i];
	}

	/* If we hit timeout depth, resolve by ignoring. */
	propose_ignore(out, htlcs[which_htlc].cltv_expiry,
		       THEIR_HTLC_TIMEOUT_TO_THEM);
	return which_htlc;
}

/* Return tal_arr of htlc indexes. */
static const size_t *match_htlc_output(const tal_t *ctx,
				       const struct wally_tx_output *out,
				       u8 **htlc_scripts)
{
	size_t *matches = tal_arr(ctx, size_t, 0);

	/* Must be a p2wsh output */
	if (!is_p2wsh(out->script, out->script_len, NULL))
		return matches;

	for (size_t i = 0; i < tal_count(htlc_scripts); i++) {
		struct sha256 sha;
		if (!htlc_scripts[i])
			continue;

		sha256(&sha, htlc_scripts[i], tal_count(htlc_scripts[i]));
		if (memeq(out->script + 2, out->script_len - 2, &sha, sizeof(sha)))
			tal_arr_expand(&matches, i);
	}
	return matches;
}

/* They must all be in the same direction, since the scripts are different for
 * each dir.  Unless, of course, they've found a sha256 clash. */
static enum side matches_direction(const size_t *matches,
				   const struct htlc_stub *htlcs)
{
	for (size_t i = 1; i < tal_count(matches); i++) {
		assert(matches[i] < tal_count(htlcs));
		assert(htlcs[matches[i]].owner == htlcs[matches[i-1]].owner);
	}
	return htlcs[matches[0]].owner;
}

/* Tell master about any we didn't use, if it wants to know. */
static void note_missing_htlcs(u8 **htlc_scripts,
			       const struct htlcs_info *htlcs_info)
{
	/* BOLT #5:
	 * - for any committed HTLC that does NOT have an output in this
	 *   commitment transaction:
	*/
	/* See onchain_control.c for the rest of the quote! */
	for (size_t i = 0; i < tal_count(htlcs_info->htlcs); i++) {
		u8 *msg;

		/* Used. */
		if (!htlc_scripts[i])
			continue;

		/* Doesn't care. */
		if (!htlcs_info->tell_if_missing[i])
			continue;

		msg = towire_onchaind_missing_htlc_output(missing_htlc_msgs,
							  &htlcs_info->htlcs[i]);
		if (htlcs_info->tell_immediately[i])
			wire_sync_write(REQ_FD, take(msg));
		else
			tal_arr_expand(&missing_htlc_msgs, msg);
	}
}

static void get_anchor_scriptpubkeys(const tal_t *ctx, u8 **anchor)
{
	if (!option_anchor_outputs && !option_anchors_zero_fee_htlc_tx) {
		anchor[LOCAL] = anchor[REMOTE] = NULL;
		return;
	}

	for (enum side side = 0; side < NUM_SIDES; side++) {
		u8 *wscript = bitcoin_wscript_anchor(tmpctx,
						     &funding_pubkey[side]);
		anchor[side] = scriptpubkey_p2wsh(ctx, wscript);
	}
}

static u8 *scriptpubkey_to_remote(const tal_t *ctx,
				  const struct pubkey *remotekey,
				  u32 csv_lock)
{
	/* BOLT #3:
	 *
	 * #### `to_remote` Output
	 *
	 * If `option_anchors` applies to the commitment
	 * transaction, the `to_remote` output is encumbered by a one
	 * block csv lock.
	 *    <remotepubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
	 *
	 *...
	 * Otherwise, this output is a simple P2WPKH to `remotepubkey`.
	 */
	if (option_anchor_outputs || option_anchors_zero_fee_htlc_tx) {
		return scriptpubkey_p2wsh(ctx,
					  bitcoin_wscript_to_remote_anchored(tmpctx,
								  remotekey,
								  csv_lock));
	} else {
		return scriptpubkey_p2wpkh(ctx, remotekey);
	}
}

static void our_unilateral_to_us(struct tracked_output ***outs,
				 const struct bitcoin_outpoint *outpoint,
				 u32 tx_blockheight,
				 struct amount_sat amt,
				 u32 sequence,
				 const u8 *local_scriptpubkey,
				 const u8 *local_wscript)
{
	struct tracked_output *out;
	const u8 *msg;

	/* BOLT #5:
	 *
	 * A node:
	 *   - upon discovering its *local commitment
	 *   transaction*:
	 *     - SHOULD spend the `to_local` output to a
	 *       convenient address.
	 *     - MUST wait until the `OP_CHECKSEQUENCEVERIFY`
	 *       delay has passed (as specified by the remote
	 *       node's `to_self_delay` field) before spending
	 *       the output.
	 */
	out = new_tracked_output(outs, outpoint, tx_blockheight,
				 OUR_UNILATERAL,
				 amt,
				 DELAYED_OUTPUT_TO_US,
				 NULL, NULL, NULL);

	msg = towire_onchaind_spend_to_us(NULL,
					  outpoint, amt,
					  sequence,
					  rel_blockheight(out, sequence),
					  commit_num,
					  local_wscript);

	/* BOLT #5:
	 *
	 * Note: if the output is spent (as recommended), the
	 * output is *resolved* by the spending transaction
	 */
	propose_resolution_to_master(out, take(msg),
				     rel_blockheight(out, sequence),
				     OUR_DELAYED_RETURN_TO_WALLET);
}

static void handle_our_unilateral(const struct tx_parts *tx,
				  u32 tx_blockheight,
				  const struct basepoints basepoints[NUM_SIDES],
				  const enum side opener,
				  const struct bitcoin_signature *remote_htlc_sigs,
				  struct tracked_output **outs)
{
	u8 **htlc_scripts;
	u8 *local_wscript, *script[NUM_SIDES], *anchor[NUM_SIDES];
	struct pubkey local_per_commitment_point;
	struct keyset *ks;
	size_t i;
	struct htlcs_info *htlcs_info;

	htlcs_info = init_reply(tx, "Tracking our own unilateral close");
	onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_UNILATERAL);

	/* BOLT #5:
	 *
	 * A node:
	 *   - upon discovering its *local commitment transaction*:
	 *     - SHOULD spend the `to_local` output to a convenient address.
	 *     - MUST wait until the `OP_CHECKSEQUENCEVERIFY` delay has passed (as
	 *     specified by the remote node's `to_self_delay` field) before spending the
	 *     output.
	 *       - Note: if the output is spent (as recommended), the output is *resolved*
	 *       by the spending transaction, otherwise it is considered *resolved* by the
	 *       commitment transaction itself.
	 */
	/* We do NOT spend our unilateral, we remember how to spend it
	 * in the wallet, thus it's immediately resolved. */
	resolved_by_other(outs[0], &tx->txid, OUR_UNILATERAL);

	/* Figure out what delayed to-us output looks like */
	hsm_get_per_commitment_point(&local_per_commitment_point);

	/* keyset is const, we need a non-const ptr to set it up */
	keyset = ks = tal(tx, struct keyset);
	if (!derive_keyset(&local_per_commitment_point,
			   &basepoints[LOCAL],
			   &basepoints[REMOTE],
			   commit_num >= static_remotekey_start[LOCAL],
			   ks))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving keyset for %"PRIu64, commit_num);

	status_debug("Deconstructing unilateral tx: %"PRIu64
		     " using keyset: "
		     " self_revocation_key: %s"
		     " self_delayed_payment_key: %s"
		     " self_payment_key: %s"
		     " other_payment_key: %s"
		     " self_htlc_key: %s"
		     " other_htlc_key: %s",
		     commit_num,
		     fmt_pubkey(tmpctx, &keyset->self_revocation_key),
		     fmt_pubkey(tmpctx, &keyset->self_delayed_payment_key),
		     fmt_pubkey(tmpctx, &keyset->self_payment_key),
		     fmt_pubkey(tmpctx, &keyset->other_payment_key),
		     fmt_pubkey(tmpctx, &keyset->self_htlc_key),
		     fmt_pubkey(tmpctx, &keyset->other_htlc_key));

	local_wscript = to_self_wscript(tmpctx, to_self_delay[LOCAL],
					1, keyset);

	/* Figure out what to-us output looks like. */
	script[LOCAL] = scriptpubkey_p2wsh(tmpctx, local_wscript);

	/* Figure out what direct to-them output looks like. */
	script[REMOTE] = scriptpubkey_to_remote(tmpctx,
						&keyset->other_payment_key, 1);

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs_info->htlcs, LOCAL);

	status_debug("Script to-me: %u: %s (%s)",
		     to_self_delay[LOCAL],
		     tal_hex(tmpctx, script[LOCAL]),
		     tal_hex(tmpctx, local_wscript));
	status_debug("Script to-them: %s",
		     tal_hex(tmpctx, script[REMOTE]));

	for (i = 0; i < tal_count(tx->outputs); i++) {
		if (tx->outputs[i]->script == NULL)
			continue;
		status_debug("Output %zu: %s", i,
			     tal_hexstr(tmpctx, tx->outputs[i]->script,
					tx->outputs[i]->script_len));
	}

	get_anchor_scriptpubkeys(tmpctx, anchor);

	for (i = 0; i < tal_count(tx->outputs); i++) {
		struct tracked_output *out;
		const size_t *matches;
		size_t which_htlc;
		struct amount_asset asset = wally_tx_output_get_amount(tx->outputs[i]);
		struct amount_sat amt;
		struct bitcoin_outpoint outpoint;

		outpoint.txid = tx->txid;
		outpoint.n = i;

		assert(amount_asset_is(&asset, channel_asset));
		amt = amount_sat(asset.value);

		if (chainparams->is_elements
		    && tx->outputs[i]->script_len == 0) {
			status_debug("OUTPUT %zu is a fee output", i);
			/* An empty script simply means that that this is a
			 * fee output. */
			out = new_tracked_output(&outs,
						 &outpoint, tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 ELEMENTS_FEE,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		} else if (script[LOCAL]
			   && wally_tx_output_scripteq(tx->outputs[i],
						       script[LOCAL])) {
			our_unilateral_to_us(&outs, &outpoint, tx_blockheight,
					     amt, to_self_delay[LOCAL],
					     script[LOCAL],
					     local_wscript);

			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						script[REMOTE])) {
			/* BOLT #5:
			 *...
			 *     - MAY ignore the `to_remote` output.
			 *       - Note: No action is required by the local
			 *       node, as `to_remote` is considered *resolved*
			 *       by the commitment transaction itself.
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_external_deposit(out, tx_blockheight, mk_mvt_tags(MVT_TO_THEM));
			script[REMOTE] = NULL;
			continue;
		}
		if (anchor[LOCAL]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[LOCAL])) {
			/* FIXME: We should be able to spend this! */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 ANCHOR_TO_US,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_our_anchor(out);
			anchor[LOCAL] = NULL;
			continue;
		}
		if (anchor[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[REMOTE])) {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 ANCHOR_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_external_deposit(out, tx_blockheight, mk_mvt_tags(MVT_ANCHOR));
			anchor[REMOTE] = NULL;
			continue;
		}

		matches = match_htlc_output(tmpctx, tx->outputs[i], htlc_scripts);
		/* FIXME: limp along when this happens! */
		if (tal_count(matches) == 0) {
			bool found = false;

			/* Maybe they're using option_will_fund? */
			if (opener == REMOTE && script[LOCAL]) {
				status_debug("Grinding for our to_local");
				/* We already tried `1` */
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {

					local_wscript
						= to_self_wscript(tmpctx,
								  to_self_delay[LOCAL],
								  csv, keyset);

					script[LOCAL]
						= scriptpubkey_p2wsh(tmpctx,
								     local_wscript);
					if (!wally_tx_output_scripteq(
						       tx->outputs[i],
						       script[LOCAL]))
						continue;

					our_unilateral_to_us(&outs, &outpoint,
							     tx_blockheight,
							     amt,
							     max_unsigned(to_self_delay[LOCAL], csv),
							     script[LOCAL],
							     local_wscript);

					script[LOCAL] = NULL;
					found = true;
					break;
				}
			} else if (opener == LOCAL && script[REMOTE]) {
				status_debug("Grinding for to_remote (ours)");
				/* We already tried `1` */
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {

					script[REMOTE]
						= scriptpubkey_to_remote(tmpctx,
								&keyset->other_payment_key,
								csv);

					if (!wally_tx_output_scripteq(tx->outputs[i], script[REMOTE]))
						continue;

					/* BOLT #5:
					 *
					 *     - MAY ignore the `to_remote` output.
					 *       - Note: No action is required by the local
					 *       node, as `to_remote` is considered *resolved*
					 *       by the commitment transaction itself.
					 */
					out = new_tracked_output(&outs,
								 &outpoint,
								 tx_blockheight,
								 OUR_UNILATERAL,
								 amt,
								 OUTPUT_TO_THEM,
								 NULL, NULL, NULL);
					ignore_output(out);
					record_external_deposit(out,
								tx_blockheight,
								mk_mvt_tags(MVT_TO_THEM));
					script[REMOTE] = NULL;
					found = true;
					break;
				}
			}


			if (found)
				continue;

			onchain_annotate_txout(&outpoint, TX_CHANNEL_PENALTY | TX_THEIRS);

			record_external_output(&outpoint, amt,
					       tx_blockheight,
					       mk_mvt_tags(MVT_PENALTY));
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find resolution for output %zu",
				      i);
		}

		if (matches_direction(matches, htlcs_info->htlcs) == LOCAL) {
			/* BOLT #5:
			 *
			 *     - MUST handle HTLCs offered by itself as specified
			 *       in [HTLC Output Handling: Local Commitment,
			 *       Local Offers](#htlc-output-handling-local-commitment-local-offers).
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 OUR_HTLC,
						 NULL, NULL,
						 remote_htlc_sigs);
			/* Tells us which htlc to use */
			which_htlc = resolve_our_htlc_ourcommit(out, matches,
								htlcs_info->htlcs,
								htlc_scripts);
		} else {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 OUR_UNILATERAL,
						 amt,
						 THEIR_HTLC,
						 NULL, NULL,
						 remote_htlc_sigs);
			/* BOLT #5:
			 * - MUST handle HTLCs offered by the remote node
			 *   as specified in [HTLC Output Handling: Local
			 *   Commitment, Remote Offers](#htlc-output-handling-local-commitment-remote-offers).
			 */
			/* Tells us which htlc to use */
			which_htlc = resolve_their_htlc(out, matches,
							htlcs_info->htlcs,
							htlc_scripts);
		}
		out->htlc = htlcs_info->htlcs[which_htlc];
		out->wscript = tal_steal(out, htlc_scripts[which_htlc]);

		/* Each of these consumes one HTLC signature */
		remote_htlc_sigs++;
		/* We've matched this HTLC, can't do again. */
		htlc_scripts[which_htlc] = NULL;

	}

	note_missing_htlcs(htlc_scripts, htlcs_info);
	tal_free(htlcs_info);

	wait_for_resolved(outs);
}

/* We produce individual penalty txs.  It's less efficient, but avoids them
 * using HTLC txs to block our penalties for long enough to pass the CSV
 * delay */
static void steal_to_them_output(struct tracked_output *out, u32 csv)
{
	const u8 *wscript, *msg;

	/* BOLT #3:
	 *
	 * If a revoked commitment transaction is published, the other party
	 * can spend this output immediately with the following witness:
	 *
	 *    <revocation_sig> 1
	 */
	wscript = bitcoin_wscript_to_local(tmpctx, to_self_delay[REMOTE], csv,
					   &keyset->self_revocation_key,
					   &keyset->self_delayed_payment_key);

	msg = towire_onchaind_spend_penalty(NULL,
					    &out->outpoint, out->sat,
					    remote_per_commitment_secret,
					    tal_dup(tmpctx, u8, &ONE),
					    wscript);

	/* Spend this immediately. */
	propose_immediate_resolution(out, take(msg), OUR_PENALTY_TX);
}

static void steal_htlc(struct tracked_output *out)
{
	const u8 *msg;
	u8 der[PUBKEY_CMPR_LEN];

	/* BOLT #3:
	 *
	 * If a revoked commitment transaction is published, the remote node can
	 * spend this output immediately with the following witness:
	 *
	 *     <revocation_sig> <revocationpubkey>
	 */
	pubkey_to_der(der, &keyset->self_revocation_key);

	msg = towire_onchaind_spend_penalty(NULL,
					    &out->outpoint, out->sat,
					    remote_per_commitment_secret,
					    tal_dup_arr(tmpctx, u8, der, ARRAY_SIZE(der), 0),
					    out->wscript);

	/* Spend this immediately. */
	propose_immediate_resolution(out, take(msg), OUR_PENALTY_TX);
}

/* Tell wallet that we have discovered a UTXO from a to-remote output,
 * which it can spend with a little additional info we give here. */
static void tell_wallet_to_remote(const struct tx_parts *tx,
				  const struct bitcoin_outpoint *outpoint,
				  u32 tx_blockheight,
				  const u8 *scriptpubkey,
				  const struct pubkey *per_commit_point,
				  bool option_static_remotekey,
				  u32 csv_lock)
{
	struct amount_asset asset = wally_tx_output_get_amount(tx->outputs[outpoint->n]);
	struct amount_sat amt;

	assert(amount_asset_is(&asset, channel_asset));
	amt = amount_sat(asset.value);

	/* A NULL per_commit_point is how we indicate the pubkey doesn't need
	 * changing. */
	if (option_static_remotekey)
		per_commit_point = NULL;

	wire_sync_write(REQ_FD,
			take(towire_onchaind_add_utxo(NULL, outpoint,
						     per_commit_point,
						     amt,
						     tx_blockheight,
						     scriptpubkey,
						     csv_lock)));
}

static void their_unilateral_local(struct tracked_output ***outs,
				   const struct tx_parts *tx,
				   const struct bitcoin_outpoint *outpoint,
				   u32 tx_blockheight,
				   struct amount_sat amt,
				   const u8 *local_scriptpubkey,
				   enum tx_type tx_type,
				   u32 csv_lock)
{
	struct tracked_output *out;
	/* BOLT #5:
	 *
	 * - MAY take no action in regard to the associated
	 *   `to_remote`, which is simply a P2WPKH output to
	 *   the *local node*.
	 *   - Note: `to_remote` is considered *resolved* by the
	 *     commitment transaction itself.
	 */
	out = new_tracked_output(outs,
				 outpoint,
				 tx_blockheight,
				 tx_type,
				 amt,
				 OUTPUT_TO_US,
				 NULL, NULL,
				 NULL);
	ignore_output(out);

	tell_wallet_to_remote(tx, outpoint,
			      tx_blockheight,
			      local_scriptpubkey,
			      remote_per_commitment_point,
			      commit_num >= static_remotekey_start[REMOTE],
			      csv_lock);
}


/* BOLT #5:
 *
 * If any node tries to cheat by broadcasting an outdated commitment
 * transaction (any previous commitment transaction besides the most current
 * one), the other node in the channel can use its revocation private key to
 * claim all the funds from the channel's original funding transaction.
 */
static void handle_their_cheat(const struct tx_parts *tx,
			       u32 tx_blockheight,
			       const struct secret *revocation_preimage,
			       const struct basepoints basepoints[NUM_SIDES],
			       const enum side opener,
			       struct tracked_output **outs)
{
	u8 **htlc_scripts;
	u8 *remote_wscript, *script[NUM_SIDES], *anchor[NUM_SIDES];
	struct keyset *ks;
	struct pubkey *k;
	size_t i;
	struct htlcs_info *htlcs_info;

	htlcs_info = init_reply(tx,
				"Tracking their illegal close: taking all funds");
	onchain_annotate_txin(
	    &tx->txid, 0, TX_CHANNEL_UNILATERAL | TX_CHANNEL_CHEAT | TX_THEIRS);

	/* BOLT #5:
	 *
	 * Once a node discovers a commitment transaction for which *it* has a
	 * revocation private key, the funding transaction output is *resolved*.
	 */
	resolved_by_other(outs[0], &tx->txid, THEIR_REVOKED_UNILATERAL);

	/* FIXME: Types. */
	BUILD_ASSERT(sizeof(struct secret) == sizeof(*revocation_preimage));
	remote_per_commitment_secret = tal_dup(tx, struct secret,
					       (struct secret *)
					       revocation_preimage);

	/* Need tmpvar for non-const.  */
	remote_per_commitment_point = k = tal(tx, struct pubkey);
	if (!pubkey_from_secret(remote_per_commitment_secret, k))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed derive from per_commitment_secret %s",
			      fmt_secret(tmpctx,
					 remote_per_commitment_secret));

	status_debug("Deriving keyset %"PRIu64
		     ": per_commit_point=%s"
		     " self_payment_basepoint=%s"
		     " other_payment_basepoint=%s"
		     " self_htlc_basepoint=%s"
		     " other_htlc_basepoint=%s"
		     " self_delayed_basepoint=%s"
		     " other_revocation_basepoint=%s",
		     commit_num,
		     fmt_pubkey(tmpctx,
				remote_per_commitment_point),
		     fmt_pubkey(tmpctx,
				&basepoints[REMOTE].payment),
		     fmt_pubkey(tmpctx,
				&basepoints[LOCAL].payment),
		     fmt_pubkey(tmpctx,
				&basepoints[REMOTE].htlc),
		     fmt_pubkey(tmpctx,
				&basepoints[LOCAL].htlc),
		     fmt_pubkey(tmpctx,
				&basepoints[REMOTE].delayed_payment),
		     fmt_pubkey(tmpctx,
				&basepoints[LOCAL].revocation));

	/* keyset is const, we need a non-const ptr to set it up */
	keyset = ks = tal(tx, struct keyset);
	if (!derive_keyset(remote_per_commitment_point,
			   &basepoints[REMOTE],
			   &basepoints[LOCAL],
			   commit_num >= static_remotekey_start[REMOTE],
			   ks))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving keyset for %"PRIu64, commit_num);

	status_debug("Deconstructing revoked unilateral tx: %"PRIu64
		     " using keyset: "
		     " self_revocation_key: %s"
		     " self_delayed_payment_key: %s"
		     " self_payment_key: %s"
		     " other_payment_key: %s"
		     " self_htlc_key: %s"
		     " other_htlc_key: %s"
		     " (static_remotekey = %"PRIu64"/%"PRIu64")",
		     commit_num,
		     fmt_pubkey(tmpctx,
				&keyset->self_revocation_key),
		     fmt_pubkey(tmpctx,
				&keyset->self_delayed_payment_key),
		     fmt_pubkey(tmpctx,
				&keyset->self_payment_key),
		     fmt_pubkey(tmpctx,
				&keyset->other_payment_key),
		     fmt_pubkey(tmpctx,
				&keyset->self_htlc_key),
		     fmt_pubkey(tmpctx,
				&keyset->other_htlc_key),
		     static_remotekey_start[LOCAL],
		     static_remotekey_start[REMOTE]);

	remote_wscript = to_self_wscript(tmpctx, to_self_delay[REMOTE],
					 1, keyset);

	/* Figure out what to-them output looks like. */
	script[REMOTE] = scriptpubkey_p2wsh(tmpctx, remote_wscript);

	/* Figure out what direct to-us output looks like. */
	script[LOCAL] = scriptpubkey_to_remote(tmpctx,
					       &keyset->other_payment_key, 1);

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs_info->htlcs, REMOTE);

	status_debug("Script to-them: %u: %s (%s)",
		     to_self_delay[REMOTE],
		     tal_hex(tmpctx, script[REMOTE]),
		     tal_hex(tmpctx, remote_wscript));
	status_debug("Script to-me: %s",
		     tal_hex(tmpctx, script[LOCAL]));

	get_anchor_scriptpubkeys(tmpctx, anchor);

	for (i = 0; i < tal_count(tx->outputs); i++) {
 		if (tx->outputs[i]->script_len == 0)
			continue;
		status_debug("Output %zu: %s",
			     i, tal_hexstr(tmpctx, tx->outputs[i]->script,
					   tx->outputs[i]->script_len));
	}

	for (i = 0; i < tal_count(tx->outputs); i++) {
		struct tracked_output *out;
		const size_t *matches;
		size_t which_htlc;
		struct amount_asset asset = wally_tx_output_get_amount(tx->outputs[i]);
		struct amount_sat amt;
		struct bitcoin_outpoint outpoint;

		outpoint.txid = tx->txid;
		outpoint.n = i;

		assert(amount_asset_is(&asset, channel_asset));
		amt = amount_sat(asset.value);

		if (chainparams->is_elements
		    && tx->outputs[i]->script_len == 0) {
			/* An empty script simply means that that this is a
			 * fee output. */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 ELEMENTS_FEE,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		}

		if (script[LOCAL]
		    && wally_tx_output_scripteq(tx->outputs[i],
						script[LOCAL])) {
			their_unilateral_local(&outs, tx, &outpoint,
					       tx_blockheight,
					       amt, script[LOCAL],
					       THEIR_REVOKED_UNILATERAL, 1);
			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						script[REMOTE])) {
			/* BOLT #5:
			 *
			 *   - MUST *resolve* the _remote node's main output_ by
			 *     spending it using the revocation private key.
			*/
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 DELAYED_CHEAT_OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			steal_to_them_output(out, 1);
			script[REMOTE] = NULL;
			continue;
		}
		if (anchor[LOCAL]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[LOCAL])) {
			/* FIXME: We should be able to spend this! */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 ANCHOR_TO_US,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_our_anchor(out);
			anchor[LOCAL] = NULL;
			continue;
		}
		if (anchor[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[REMOTE])) {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 ANCHOR_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_external_deposit(out, tx_blockheight, mk_mvt_tags(MVT_ANCHOR));
			anchor[REMOTE] = NULL;
			continue;
		}

		matches = match_htlc_output(tmpctx, tx->outputs[i], htlc_scripts);
		if (tal_count(matches) == 0) {
			bool found = false;
			if (opener == REMOTE && script[LOCAL]) {
				status_debug("Grinding for commitment to_remote"
					     " (ours)");
				/* We already tried `1` */
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {
					script[LOCAL]
						= scriptpubkey_to_remote(tmpctx,
								&keyset->other_payment_key,
								csv);
					if (!wally_tx_output_scripteq(
						       tx->outputs[i],
						       script[LOCAL]))
						continue;

					their_unilateral_local(&outs, tx,
							       &outpoint,
							       tx_blockheight,
							       amt,
							       script[LOCAL],
							       THEIR_REVOKED_UNILATERAL,
							       csv);
					script[LOCAL] = NULL;
					found = true;
					break;
				}
			} else if (opener == LOCAL && script[REMOTE]) {
				status_debug("Grinding for commitment to_local"
					     " (theirs)");
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {
					remote_wscript
						= to_self_wscript(tmpctx,
								  to_self_delay[REMOTE],
								  csv, keyset);
					script[REMOTE]
						= scriptpubkey_p2wsh(tmpctx,
								remote_wscript);


					if (!wally_tx_output_scripteq(tx->outputs[i], script[REMOTE]))
						continue;

					out = new_tracked_output(&outs,
								 &outpoint,
								 tx_blockheight,
								 THEIR_REVOKED_UNILATERAL,
								 amt,
								 DELAYED_CHEAT_OUTPUT_TO_THEM,
								 NULL, NULL, NULL);
					steal_to_them_output(out, csv);
					script[REMOTE] = NULL;
					found = true;
					break;
				}
			}

			if (!found) {
				record_external_output(&outpoint, amt,
						       tx_blockheight,
						       mk_mvt_tags(MVT_PENALTY));
				status_broken("Could not find resolution"
					      " for output %zu: did"
					      " *we* cheat?", i);
			}
			continue;
		}

		/* In this case, we don't care which HTLC we choose; so pick
		   first one */
		which_htlc = matches[0];
		if (matches_direction(matches, htlcs_info->htlcs) == LOCAL) {
			/* BOLT #5:
			 *
			 *   - MUST *resolve* the _local node's offered HTLCs_ in one of three ways:
			 *     * spend the *commitment tx* using the payment revocation private key.
			 *     * spend the *commitment tx* once the HTLC timeout has passed.
			 *     * spend the *HTLC-success tx*, if the remote node has published it.
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 OUR_HTLC,
						 &htlcs_info->htlcs[which_htlc],
						 htlc_scripts[which_htlc],
						 NULL);
			steal_htlc(out);
		} else {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_REVOKED_UNILATERAL,
						 amt,
						 THEIR_HTLC,
						 &htlcs_info->htlcs[which_htlc],
						 htlc_scripts[which_htlc],
						 NULL);
			/* BOLT #5:
			 *
			 *   - MUST *resolve* the _remote node's offered HTLCs_ in one of three ways:
			 *     * spend the *commitment tx* using the payment revocation private key.
			 *     * spend the *commitment tx* using the payment preimage (if known).
			 *     * spend the *HTLC-timeout tx*, if the remote node has published it.
			 */
			steal_htlc(out);
		}
		htlc_scripts[which_htlc] = NULL;
	}

	note_missing_htlcs(htlc_scripts, htlcs_info);
	tal_free(htlcs_info);

	wait_for_resolved(outs);
}

static void handle_their_unilateral(const struct tx_parts *tx,
				    u32 tx_blockheight,
				    const struct pubkey *this_remote_per_commitment_point,
				    const struct basepoints basepoints[NUM_SIDES],
				    const enum side opener,
				    struct tracked_output **outs)
{
	u8 **htlc_scripts;
	u8 *remote_wscript, *script[NUM_SIDES], *anchor[NUM_SIDES];
	struct keyset *ks;
	size_t i;
	struct htlcs_info *htlcs_info;

	htlcs_info = init_reply(tx, "Tracking their unilateral close");
	onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_UNILATERAL | TX_THEIRS);

	/* HSM can't derive this. */
	remote_per_commitment_point = this_remote_per_commitment_point;

	/* BOLT #5:
	 *
	 * # Unilateral Close Handling: Remote Commitment Transaction
	 *
	 * The *remote node's* commitment transaction *resolves* the funding
	 * transaction output.
	 *
	 * There are no delays constraining node behavior in this case, so
	 * it's simpler for a node to handle than the case in which it
	 * discovers its local commitment transaction (see [Unilateral Close
	 * Handling: Local Commitment Transaction]
	 */
	resolved_by_other(outs[0], &tx->txid, THEIR_UNILATERAL);

	status_debug("Deriving keyset %"PRIu64
		     ": per_commit_point=%s"
		     " self_payment_basepoint=%s"
		     " other_payment_basepoint=%s"
		     " self_htlc_basepoint=%s"
		     " other_htlc_basepoint=%s"
		     " self_delayed_basepoint=%s"
		     " other_revocation_basepoint=%s",
		     commit_num,
		     fmt_pubkey(tmpctx,
				remote_per_commitment_point),
		     fmt_pubkey(tmpctx,
				&basepoints[REMOTE].payment),
		     fmt_pubkey(tmpctx,
				&basepoints[LOCAL].payment),
		     fmt_pubkey(tmpctx,
				&basepoints[REMOTE].htlc),
		     fmt_pubkey(tmpctx,
				&basepoints[LOCAL].htlc),
		     fmt_pubkey(tmpctx,
				&basepoints[REMOTE].delayed_payment),
		     fmt_pubkey(tmpctx,
				&basepoints[LOCAL].revocation));

	/* keyset is const, we need a non-const ptr to set it up */
	keyset = ks = tal(tx, struct keyset);
	if (!derive_keyset(remote_per_commitment_point,
			   &basepoints[REMOTE],
			   &basepoints[LOCAL],
			   commit_num >= static_remotekey_start[REMOTE],
			   ks))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving keyset for %"PRIu64, commit_num);

	status_debug("Deconstructing unilateral tx: %"PRIu64
		     " using keyset: "
		     " self_revocation_key: %s"
		     " self_delayed_payment_key: %s"
		     " self_payment_key: %s"
		     " other_payment_key: %s"
		     " self_htlc_key: %s"
		     " other_htlc_key: %s",
		     commit_num,
		     fmt_pubkey(tmpctx,
				&keyset->self_revocation_key),
		     fmt_pubkey(tmpctx,
				&keyset->self_delayed_payment_key),
		     fmt_pubkey(tmpctx,
				&keyset->self_payment_key),
		     fmt_pubkey(tmpctx,
				&keyset->other_payment_key),
		     fmt_pubkey(tmpctx,
				&keyset->self_htlc_key),
		     fmt_pubkey(tmpctx,
				&keyset->other_htlc_key));

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs_info->htlcs, REMOTE);

	get_anchor_scriptpubkeys(tmpctx, anchor);

	for (i = 0; i < tal_count(tx->outputs); i++) {
 		if (tx->outputs[i]->script_len == 0)
			continue;
		status_debug("Output %zu: %s",
			     i, tal_hexstr(tmpctx, tx->outputs[i]->script,
					   tx->outputs[i]->script_len));
	}

	remote_wscript = to_self_wscript(tmpctx, to_self_delay[REMOTE],
					 1, keyset);
	script[REMOTE] = scriptpubkey_p2wsh(tmpctx, remote_wscript);

	script[LOCAL] = scriptpubkey_to_remote(tmpctx,
					       &keyset->other_payment_key,
					       1);

	status_debug("Script to-them: %u: %s (%s)",
		     to_self_delay[REMOTE],
		     tal_hex(tmpctx, script[REMOTE]),
		     tal_hex(tmpctx, remote_wscript));
	status_debug("Script to-me: %s",
		     tal_hex(tmpctx, script[LOCAL]));

	for (i = 0; i < tal_count(tx->outputs); i++) {
		struct tracked_output *out;
		const size_t *matches;
		size_t which_htlc;
		struct amount_asset asset = wally_tx_output_get_amount(tx->outputs[i]);
		struct amount_sat amt;
		struct bitcoin_outpoint outpoint;

		assert(amount_asset_is(&asset, channel_asset));
		amt = amount_sat(asset.value);

		outpoint.txid = tx->txid;
		outpoint.n = i;

		if (chainparams->is_elements &&
		    tx->outputs[i]->script_len == 0) {
			/* An empty script simply means that that this is a
			 * fee output. */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 ELEMENTS_FEE,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		} else if (script[LOCAL]
			   && wally_tx_output_scripteq(tx->outputs[i],
						       script[LOCAL])) {
			their_unilateral_local(&outs, tx, &outpoint,
					       tx_blockheight,
					       amt, script[LOCAL],
					       THEIR_UNILATERAL, 1);

			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						script[REMOTE])) {
			/* BOLT #5:
			 *
			 * - MAY take no action in regard to the associated
			 *  `to_local`, which is a payment output to the *remote
			 *   node*.
			 *   - Note: `to_local` is considered *resolved* by the
			 *     commitment transaction itself.
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 DELAYED_OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			record_external_deposit(out, tx_blockheight, mk_mvt_tags(MVT_TO_THEM));
			continue;
		}
		if (anchor[LOCAL]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[LOCAL])) {
			/* FIXME: We should be able to spend this! */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 ANCHOR_TO_US,
						 NULL, NULL, NULL);

			ignore_output(out);
			record_our_anchor(out);
			anchor[LOCAL] = NULL;
			continue;
		}
		if (anchor[REMOTE]
		    && wally_tx_output_scripteq(tx->outputs[i],
						anchor[REMOTE])) {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 ANCHOR_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			anchor[REMOTE] = NULL;
			record_external_deposit(out, tx_blockheight, mk_mvt_tags(MVT_ANCHOR));
			continue;
		}

		matches = match_htlc_output(tmpctx, tx->outputs[i], htlc_scripts);
		if (tal_count(matches) == 0) {
			bool found = false;

			/* We need to hunt for it (option_will_fund?) */
			if (opener == REMOTE && script[LOCAL]) {
				status_debug("Grinding for commitment to_remote"
					     " (ours)");
				/* We already tried `1` */
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {
					script[LOCAL]
						= scriptpubkey_to_remote(tmpctx,
								&keyset->other_payment_key,
								csv);
					if (!wally_tx_output_scripteq(
						       tx->outputs[i],
						       script[LOCAL]))
						continue;

					their_unilateral_local(&outs, tx,
							       &outpoint,
							       tx_blockheight,
							       amt,
							       script[LOCAL],
							       THEIR_UNILATERAL,
							       csv);
					script[LOCAL] = NULL;
					found = true;
					break;
				}
			} else if (opener == LOCAL && script[REMOTE]) {
				status_debug("Grinding for commitment to_local"
					     " (theirs)");
				/* We already tried `1` */
				for (size_t csv = 2;
				     csv <= LEASE_RATE_DURATION;
				     csv++) {
					remote_wscript
						= to_self_wscript(tmpctx,
								  to_self_delay[REMOTE],
								  csv, keyset);
					script[REMOTE]
						= scriptpubkey_p2wsh(tmpctx,
								remote_wscript);


					if (!wally_tx_output_scripteq(tx->outputs[i], script[REMOTE]))
						continue;

					out = new_tracked_output(&outs,
								 &outpoint,
								 tx_blockheight,
								 THEIR_UNILATERAL,
								 amt,
								 DELAYED_OUTPUT_TO_THEM,
								 NULL, NULL, NULL);
					ignore_output(out);
					record_external_deposit(out,
								tx_blockheight,
								mk_mvt_tags(MVT_TO_THEM));
					found = true;
					break;
				}
			}

			if (found)
				continue;

			record_external_output(&outpoint, amt,
					       tx_blockheight,
					       mk_mvt_tags(MVT_PENALTY));
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find resolution for output %zu",
				      i);
		}

		if (matches_direction(matches, htlcs_info->htlcs) == LOCAL) {
			/* BOLT #5:
			 *
			 * - MUST handle HTLCs offered by itself as specified in
			 *   [HTLC Output Handling: Remote Commitment,
			 *   Local Offers]
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 OUR_HTLC,
						 NULL, NULL,
						 NULL);
			which_htlc = resolve_our_htlc_theircommit(out,
								  matches,
								  htlcs_info->htlcs,
								  htlc_scripts);
		} else {
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 THEIR_UNILATERAL,
						 amt,
						 THEIR_HTLC,
						 NULL, NULL,
						 NULL);
			/* BOLT #5:
			 *
			 * - MUST handle HTLCs offered by the remote node as
			 *   specified in [HTLC Output Handling: Remote
			 *   Commitment, Remote Offers]
			 */
			which_htlc = resolve_their_htlc(out, matches,
							htlcs_info->htlcs,
							htlc_scripts);
		}
		out->htlc = htlcs_info->htlcs[which_htlc];
		out->wscript = tal_steal(out, htlc_scripts[which_htlc]);
		htlc_scripts[which_htlc] = NULL;
	}

	note_missing_htlcs(htlc_scripts, htlcs_info);
	tal_free(htlcs_info);

	wait_for_resolved(outs);
}

static void handle_unknown_commitment(const struct tx_parts *tx,
				      u32 tx_blockheight,
				      const struct basepoints basepoints[NUM_SIDES],
				      struct tracked_output **outs)
{
	int to_us_output = -1;
	struct htlcs_info *htlcs_info;

	onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_UNILATERAL | TX_THEIRS);

	resolved_by_other(outs[0], &tx->txid, UNKNOWN_UNILATERAL);

	/* Normally, csv is 1, but for option_will_fund, we need to
	 * figure out what CSV lock was used */
	for (size_t csv = 1; csv <= LEASE_RATE_DURATION; csv++) {
		const u8 *local_script;
		local_script = scriptpubkey_to_remote(tmpctx,
						      &basepoints[LOCAL].payment,
						      csv);

		for (size_t i = 0; i < tal_count(tx->outputs); i++) {
			struct amount_asset asset;
			struct amount_sat amt;
			struct bitcoin_outpoint outpoint;
			struct tracked_output *out;

			if (!wally_tx_output_scripteq(tx->outputs[i],
						      local_script))
				continue;

			asset = wally_tx_output_get_amount(tx->outputs[i]);
			assert(amount_asset_is(&asset, channel_asset));
			amt = amount_sat(asset.value);

			outpoint.txid = tx->txid;
			outpoint.n = i;

			/* BOLT #5:
			 *
			 * - MAY take no action in regard to the associated
			 *   `to_remote`, which is simply a P2WPKH output to
			 *   the *local node*.
			 *   - Note: `to_remote` is considered *resolved* by the
			 *     commitment transaction itself.
			 */
			out = new_tracked_output(&outs, &outpoint,
						 tx_blockheight,
						 UNKNOWN_UNILATERAL,
						 amt,
						 OUTPUT_TO_US, NULL, NULL, NULL);
			ignore_output(out);

			tell_wallet_to_remote(tx, &outpoint,
					      tx_blockheight,
					      local_script,
					      NULL,
					      true,
					      csv);
			to_us_output = i;
			goto found;
		}
	}

found:
	/* Record every unidentified output on this tx as an external
	 * 'penalty' */
	for (size_t i = 0; i < tal_count(tx->outputs); i++) {
		struct amount_asset asset;
		struct amount_sat amt;
		struct bitcoin_outpoint outpoint;

		if (i == to_us_output)
			continue;

		asset = wally_tx_output_get_amount(tx->outputs[i]);
		assert(amount_asset_is(&asset, channel_asset));
		amt = amount_sat(asset.value);

		outpoint.txid = tx->txid;
		outpoint.n = i;

		record_external_output(&outpoint, amt,
				       tx_blockheight,
				       mk_mvt_tags(MVT_PENALTY));
	}

	if (to_us_output == -1) {
		status_broken("FUNDS LOST.  Unknown commitment #%"PRIu64"!",
			      commit_num);
		htlcs_info = init_reply(tx, "ERROR: FUNDS LOST.  Unknown commitment!");
	} else {
		status_broken("ERROR: Unknown commitment #%"PRIu64
			      ", recovering our funds!",
			      commit_num);
		htlcs_info = init_reply(tx, "ERROR: Unknown commitment, recovering our funds!");
	}

	/* Tell master to give up on HTLCs immediately. */
	for (size_t i = 0; i < tal_count(htlcs_info->htlcs); i++) {
		u8 *msg;

		if (!htlcs_info->tell_if_missing[i])
			continue;

		msg = towire_onchaind_missing_htlc_output(NULL,
							  &htlcs_info->htlcs[i]);
		wire_sync_write(REQ_FD, take(msg));
	}

	tal_free(htlcs_info);
	wait_for_resolved(outs);
}

/*~ SEQUENTIA: the taproot-covenant channel type (common/tcov_scripts.h).
 *
 * Every output of its commitments is a taproot output (to_remote apart, a
 * P2WPKH as ever), spent by one leaf or, on a revoked commitment, by the key
 * path.  An HTLC claim from the holder's own commitment goes by a covenant
 * leaf to the holder's delayed output D, which has to_local's script, and is
 * swept from there after the delay.  lightningd builds every spend with a fee
 * input from our wallet in an asset this node accepts (onchain_control.c):
 * the covenant demands the HTLC's whole value at the claim's output, so the
 * fee cannot come out of it. */

static const struct tap_tree2 *keep_tree(const tal_t *ctx,
					 const struct tap_tree2 *tree)
{
	struct tap_tree2 *t = tal_dup(ctx, struct tap_tree2, tree);
	t->leaf[0] = tal_dup_talarr(t, u8, tree->leaf[0]);
	t->leaf[1] = tal_dup_talarr(t, u8, tree->leaf[1]);
	t->leaf[2] = tree->nleaves == 3
		? tal_dup_talarr(t, u8, tree->leaf[2]) : NULL;
	return t;
}

/* Ask lightningd to spend @out by @leaf of its tree (-1: the key path). */
static void tcov_propose(struct tracked_output *out,
			 enum tcov_spend_signer signer,
			 int leaf,
			 const struct preimage *preimage,
			 const struct tap_tree2 *dest,
			 u32 locktime, u32 sequence, u32 minblock,
			 enum tcov_spend_deadline deadline,
			 enum tx_type tx_type)
{
	const struct tap_tree2 *tree = out->tcov_tree;
	u8 *leaf_script, *cb, *cov_program;
	const u8 *msg;

	if (leaf >= 0) {
		leaf_script = tal_dup_talarr(tmpctx, u8, tree->leaf[leaf]);
		cb = tap_tree2_control_block(tmpctx, tree, leaf);
	} else {
		leaf_script = tal_arr(tmpctx, u8, 0);
		cb = tal_arr(tmpctx, u8, 0);
	}
	if (dest) {
		cov_program = tal_arr(tmpctx, u8, 32);
		tap_tree2_program(dest, cov_program);
	} else
		cov_program = tal_arr(tmpctx, u8, 0);

	msg = towire_onchaind_spend_tcov(NULL, &out->outpoint, out->sat,
					 tap_tree2_scriptpubkey(tmpctx, tree),
					 signer, commit_num,
					 remote_per_commitment_point,
					 remote_per_commitment_secret,
					 leaf_script, cb, &tree->merkle_root,
					 preimage, cov_program,
					 locktime, sequence, minblock,
					 deadline, out->htlc.id);
	propose_resolution_to_master(out, take(msg), minblock, tx_type);
}

/* to_local of commitment @holder's (us: our keyset; them: theirs), which is
 * also the D of every claim from it. */
static void tcov_holder_to_local(const struct pubkey *holder_point,
				 enum side holder,
				 struct tap_tree2 *tree)
{
	tcov_to_local_tree(tmpctx, keyset, holder_point, to_self_delay[holder],
			   tree);
}

static bool tcov_match_htlc(const struct wally_tx_output *o,
			    struct amount_sat amt,
			    const struct htlc_stub *htlc,
			    const struct pubkey *holder_point,
			    enum side holder,
			    struct tap_tree2 *tree)
{
	/* The commitment's holder offered it? */
	if (htlc->owner == holder)
		tcov_offered_htlc_tree(tmpctx, keyset, holder_point,
				       to_self_delay[holder], channel_asset,
				       &htlc->ripemd,
				       htlc->has_lock_point ? &htlc->lock_point : NULL,
				       htlc->cltv_expiry, amt, tree);
	else
		tcov_received_htlc_tree(tmpctx, keyset, holder_point,
					to_self_delay[holder], channel_asset,
					&htlc->ripemd,
					htlc->has_lock_point ? &htlc->lock_point : NULL,
					htlc->cltv_expiry, amt, tree);
	return wally_tx_output_scripteq(o, tap_tree2_scriptpubkey(tmpctx, tree));
}

/* Our delayed output (to_local, or a claim's D): the DELAY leaf. */
static void tcov_sweep_delayed(struct tracked_output *out)
{
	tcov_propose(out, TCOV_SIGN_DELAYED, TCOV_LEAF_DELAY, NULL, NULL,
		     0, to_self_delay[LOCAL],
		     rel_blockheight(out, to_self_delay[LOCAL]),
		     TCOV_DEADLINE_SWEEP, OUR_DELAYED_RETURN_TO_WALLET);
}

/* A claim of ours from our commitment confirmed: track its D. */
static void tcov_resolve_claim(struct tracked_output ***outs,
			       size_t out_index,
			       const struct tx_parts *claim,
			       size_t input_num,
			       u32 tx_blockheight)
{
	struct tracked_output *out;
	struct amount_asset asset;
	struct bitcoin_outpoint outpoint;
	struct pubkey point;
	struct tap_tree2 d;

	/* The covenant put D at the input's own index. */
	outpoint.txid = claim->txid;
	outpoint.n = input_num;
	asset = wally_tx_output_get_amount(claim->outputs[input_num]);
	assert(amount_asset_is(&asset, channel_asset));
	out = new_tracked_output(outs, &outpoint, tx_blockheight,
				 (*outs)[out_index]->resolved->tx_type,
				 amount_sat(asset.value),
				 DELAYED_OUTPUT_TO_US, NULL, NULL, NULL);
	hsm_get_per_commitment_point(&point);
	tcov_holder_to_local(&point, LOCAL, &d);
	if (!wally_tx_output_scripteq(claim->outputs[input_num],
				      tap_tree2_scriptpubkey(tmpctx, &d)))
		status_broken("Claim %s output %zu is not our delayed output",
			      fmt_bitcoin_txid(tmpctx, &claim->txid), input_num);
	out->tcov_tree = keep_tree(out, &d);
	tcov_sweep_delayed(out);
}

/* They claimed an HTLC of their revoked commitment into their D: take it. */
static void tcov_steal_claim(struct tracked_output *out,
			     struct tracked_output ***outs,
			     const struct tx_parts *claim,
			     u32 tx_blockheight,
			     enum tx_type claim_type,
			     const struct bitcoin_outpoint *d_outpoint)
{
	struct tracked_output *d_out;
	struct amount_asset asset;
	struct tap_tree2 d;

	asset = wally_tx_output_get_amount(claim->outputs[d_outpoint->n]);
	assert(amount_asset_is(&asset, channel_asset));
	d_out = new_tracked_output(outs, d_outpoint, tx_blockheight,
				   claim_type, amount_sat(asset.value),
				   DELAYED_CHEAT_OUTPUT_TO_THEM,
				   &out->htlc, NULL, NULL);
	resolved_by_other(out, &claim->txid, claim_type);

	tcov_holder_to_local(remote_per_commitment_point, REMOTE, &d);
	d_out->tcov_tree = keep_tree(d_out, &d);
	tcov_propose(d_out, TCOV_SIGN_PENALTY, -1, NULL, NULL, 0, 0xFFFFFFFF,
		     tx_blockheight + 1, TCOV_DEADLINE_NOW, OUR_PENALTY_TX);
}

/* They spent an HTLC we offered with its preimage: SUCCESS leaf, on either
 * commitment, witness <sig> <preimage> <leaf> <control block>. */
static void tcov_extract_preimage(struct tracked_output *out,
				  const struct tx_parts *tx_parts,
				  const struct bitcoin_outpoint *spend)
{
	const struct wally_tx_witness_stack *wit
		= tx_parts->inputs[spend->n]->witness;
	struct preimage preimage;
	struct sha256 sha;
	struct ripemd160 ripemd;

	/* An annex, which whoever mined the claim may have added, does not
	 * hide the preimage. */
	if (!wit || tap_witness_items(wit) != 4
	    || wit->items[1].witness_len != sizeof(preimage)) {
		status_broken("%s/%s spent by %s with a witness that is not"
			      " the SUCCESS leaf's",
			      tx_type_name(out->tx_type),
			      output_type_name(out->output_type),
			      fmt_bitcoin_txid(tmpctx, &tx_parts->txid));
		return;
	}
	memcpy(&preimage, wit->items[1].witness, sizeof(preimage));
	/* SEQUENTIA: a point-locked HTLC's SUCCESS leaf took the scalar of
	 * its lock point (common/point_lock.h). */
	if (out->htlc.has_lock_point) {
		if (!point_lock_opens(&out->htlc.lock_point, &preimage)) {
			status_broken("%s/%s spent with scalar %s, which does"
				      " not open its point lock",
				      tx_type_name(out->tx_type),
				      output_type_name(out->output_type),
				      fmt_preimage(tmpctx, &preimage));
			return;
		}
		point_lock_payment_hash(&out->htlc.lock_point,
					&out->payment_hash);
		status_debug("%s/%s gave us scalar %s",
			     tx_type_name(out->tx_type),
			     output_type_name(out->output_type),
			     fmt_preimage(tmpctx, &preimage));
		wire_sync_write(REQ_FD,
				take(towire_onchaind_extracted_preimage(NULL,
								       &preimage)));
		return;
	}
	sha256(&sha, &preimage, sizeof(preimage));
	ripemd160(&ripemd, &sha, sizeof(sha));
	if (!ripemd160_eq(&ripemd, &out->htlc.ripemd)) {
		status_broken("%s/%s spent with preimage %s, not ours",
			      tx_type_name(out->tx_type),
			      output_type_name(out->output_type),
			      fmt_preimage(tmpctx, &preimage));
		return;
	}
	out->payment_hash = sha;
	status_debug("%s/%s gave us preimage %s",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     fmt_preimage(tmpctx, &preimage));
	wire_sync_write(REQ_FD,
			take(towire_onchaind_extracted_preimage(NULL,
							       &preimage)));
}

/* We hold @out's preimage: claim it, by covenant on our commitment, directly
 * on theirs. */
static void tcov_claim_with_preimage(struct tracked_output *out,
				     const struct preimage *preimage)
{
	if (out->tx_type == OUR_UNILATERAL) {
		struct pubkey point;
		struct tap_tree2 d;

		hsm_get_per_commitment_point(&point);
		tcov_holder_to_local(&point, LOCAL, &d);
		tcov_propose(out, TCOV_SIGN_LOCAL_HTLC,
			     TCOV_LEAF_RECEIVED_SUCCESS, preimage, &d,
			     0, 0xFFFFFFFF, out->tx_blockheight + 1,
			     TCOV_DEADLINE_HTLC_IN, OUR_HTLC_SUCCESS_TX);
	} else {
		/* Their commitment: they offered it, our leaf of their
		 * offered tree. */
		tcov_propose(out, TCOV_SIGN_REMOTE_HTLC,
			     TCOV_LEAF_OFFERED_SUCCESS, preimage, NULL,
			     0, 0xFFFFFFFF, out->tx_blockheight + 1,
			     TCOV_DEADLINE_HTLC_IN, THEIR_HTLC_FULFILL_TO_US);
	}
}

/* Did the spend of input @input_num pay our static payment script at the
 * same index?  That is a REVOKE leaf's KEEP, run by whoever held the
 * revoked secret: the coin is ours, and the wallet learns it here. */
static bool tcov_revoke_leaf_paid_us(const struct tx_parts *tx_parts,
				     size_t input_num, u32 tx_blockheight)
{
	const u8 *ours = scriptpubkey_p2wpkh(tmpctx, &keyset->other_payment_key);
	struct bitcoin_outpoint outpoint;
	struct amount_asset asset;

	if (input_num >= tal_count(tx_parts->outputs)
	    || !tx_parts->outputs[input_num]
	    || !wally_tx_output_scripteq(tx_parts->outputs[input_num], ours))
		return false;
	asset = wally_tx_output_get_amount(tx_parts->outputs[input_num]);
	if (!amount_asset_is(&asset, channel_asset))
		return false;
	outpoint.txid = tx_parts->txid;
	outpoint.n = input_num;
	status_debug("REVOKE leaf paid us %s at %s",
		     fmt_amount_sat(tmpctx, amount_sat(asset.value)),
		     fmt_bitcoin_outpoint(tmpctx, &outpoint));
	wire_sync_write(REQ_FD,
			take(towire_onchaind_add_utxo(NULL, &outpoint, NULL,
						     amount_sat(asset.value),
						     tx_blockheight, ours, 1)));
	return true;
}

/*~ SEQUENTIA: the provider-signed credit (common/credit_scripts.h).
 *
 * On a credit channel the provider's balance output, on either commitment,
 * carries CLAIM: whoever holds a note (and its payment's preimage) moves what
 * it owes to the holder's static payment script, the rest staying under the
 * same script.  As provider we sweep that output (or what a claim left of it)
 * to our wallet after our delay: by DELAY from our own commitment, by
 * PROVIDER from the holder's.  As holder we claim it with our latest note,
 * which lightningd hands us (onchaind_credit_note), and claim again whenever
 * a higher one arrives while some of it remains. */

/* Is @o the provider's credit output of the commitment @holder holds? */
static bool credit_match(const struct wally_tx_output *o,
			 struct amount_sat amt,
			 const struct pubkey *holder_point,
			 enum side holder,
			 struct tap_tree2 *tree)
{
	if (holder == credit_provider)
		credit_to_local_tree(tmpctx, keyset, holder_point,
				     to_self_delay[holder], credit_params,
				     amt, tree);
	else
		credit_to_remote_tree(tmpctx, &keyset->other_payment_key,
				      to_self_delay[credit_provider],
				      credit_params, amt, tree);
	return wally_tx_output_scripteq(o, tap_tree2_scriptpubkey(tmpctx, tree));
}

/* Ours: to our wallet after our delay, by DELAY (our own commitment's
 * to_local, three leaves) or PROVIDER (on the holder's, two). */
static void credit_propose_own(struct tracked_output *out)
{
	bool to_local = (out->tcov_tree->nleaves == 3);

	tcov_propose(out, to_local ? TCOV_SIGN_DELAYED : TCOV_SIGN_PAYMENT,
		     to_local ? TCOV_LEAF_DELAY : CREDIT_REMOTE_LEAF_PROVIDER,
		     NULL, NULL, 0, to_self_delay[LOCAL],
		     rel_blockheight(out, to_self_delay[LOCAL]),
		     TCOV_DEADLINE_SWEEP, OUR_DELAYED_RETURN_TO_WALLET);
}

/* Theirs: claimed with our note, if it owes more than was paid from it. */
static void credit_propose_claim(struct tracked_output *out)
{
	struct amount_sat paid;
	const struct tap_tree2 *tree = out->tcov_tree;
	int leaf = tree->nleaves == 3 ? CREDIT_LEAF_CLAIM
		: CREDIT_REMOTE_LEAF_CLAIM;
	const u8 *msg;

	if (!credit_note)
		return;
	if (!amount_sat_sub(&paid, out->credit_b, out->sat))
		paid = AMOUNT_SAT(0);
	if (credit_note->credit <= paid.satoshis) { /* Raw: credit atoms */
		status_debug("Credit note %"PRIu64" owes nothing more from %s"
			     " (%s already paid)", credit_note->credit,
			     fmt_bitcoin_outpoint(tmpctx, &out->outpoint),
			     fmt_amount_sat(tmpctx, paid));
		return;
	}
	out->proposal = tal_free(out->proposal);
	msg = towire_onchaind_spend_credit_claim(NULL, &out->outpoint,
						 out->sat,
						 tap_tree2_scriptpubkey(tmpctx, tree),
						 out->credit_b,
						 tree->leaf[leaf],
						 tap_tree2_control_block(tmpctx, tree, leaf),
						 credit_note->credit,
						 &credit_note->sig,
						 &credit_note->preimage,
						 credit_params->holder_spk);
	propose_immediate_resolution(out, take(msg), CREDIT_CLAIM);
}

static void credit_track(struct tracked_output ***outs,
			 const struct bitcoin_outpoint *outpoint,
			 u32 tx_blockheight, enum tx_type tx_type,
			 struct amount_sat amt, struct amount_sat b,
			 const struct tap_tree2 *tree)
{
	struct tracked_output *out;

	out = new_tracked_output(outs, outpoint, tx_blockheight, tx_type, amt,
				 credit_provider == LOCAL
				 ? CREDIT_OUTPUT_TO_US : CREDIT_OUTPUT_TO_THEM,
				 NULL, NULL, NULL);
	out->tcov_tree = keep_tree(out, tree);
	out->credit_b = b;
	if (credit_provider == LOCAL)
		credit_propose_own(out);
	else
		credit_propose_claim(out);
}

/* A credit output was spent.  A claim's output 1 pays the holder (us, if we
 * hold the credit: our wallet learns it) and its output 0 keeps the rest
 * under the same script, which we track again. */
static bool credit_output_spent(struct tracked_output ***outs,
				struct tracked_output *out,
				const struct tx_parts *tx_parts,
				u32 input_num, u32 tx_blockheight,
				bool by_proposal)
{
	const u8 *spk = tap_tree2_scriptpubkey(tmpctx, out->tcov_tree);
	bool claim = input_num + 1 < tal_count(tx_parts->outputs)
		&& tx_parts->outputs[input_num]
		&& tx_parts->outputs[input_num + 1]
		&& wally_tx_output_scripteq(tx_parts->outputs[input_num], spk)
		&& wally_tx_output_scripteq(tx_parts->outputs[input_num + 1],
					    credit_params->holder_spk);

	if (!claim) {
		if (!by_proposal)
			resolved_by_other(out, &tx_parts->txid,
					  out->output_type == CREDIT_OUTPUT_TO_US
					  ? THEIR_DELAYED_CHEAT
					  : CREDIT_SWEEP_TO_THEM);
		return false;
	}

	if (!by_proposal)
		resolved_by_other(out, &tx_parts->txid, CREDIT_CLAIM);

	/* What it paid the holder. */
	if (credit_provider == REMOTE) {
		struct bitcoin_outpoint paid;
		struct amount_asset a
			= wally_tx_output_get_amount(tx_parts->outputs[input_num + 1]);

		paid.txid = tx_parts->txid;
		paid.n = input_num + 1;
		if (amount_asset_is(&a, channel_asset)) {
			status_debug("Credit claim paid us %s at %s",
				     fmt_amount_sat(tmpctx, amount_sat(a.value)),
				     fmt_bitcoin_outpoint(tmpctx, &paid));
			wire_sync_write(REQ_FD,
					take(towire_onchaind_add_utxo(NULL, &paid,
								     NULL,
								     amount_sat(a.value),
								     tx_blockheight,
								     credit_params->holder_spk,
								     0)));
		}
	}

	/* What it left, under the same script. */
	{
		struct bitcoin_outpoint rem;
		struct amount_asset a
			= wally_tx_output_get_amount(tx_parts->outputs[input_num]);

		rem.txid = tx_parts->txid;
		rem.n = input_num;
		if (amount_asset_is(&a, channel_asset) && a.value > 0)
			credit_track(outs, &rem, tx_blockheight, CREDIT_CLAIM,
				     amount_sat(a.value), out->credit_b,
				     out->tcov_tree);
	}
	return true;
}

static void handle_onchaind_credit_note(struct tracked_output **outs,
					const u8 *msg)
{
	struct credit_note_held n;

	if (!fromwire_onchaind_credit_note(msg, &n.credit, &n.payment_hash,
					   &n.sig, &n.preimage))
		master_badmsg(WIRE_ONCHAIND_CREDIT_NOTE, msg);
	if (!option_seq_credit || credit_provider == LOCAL)
		return;
	if (credit_note && credit_note->credit >= n.credit)
		return;
	tal_free(credit_note);
	credit_note = notleak(tal_dup(NULL, struct credit_note_held, &n));
	status_debug("Credit note %"PRIu64" to claim", n.credit);

	for (size_t i = 0; i < tal_count(outs); i++) {
		if (outs[i]->output_type == CREDIT_OUTPUT_TO_THEM
		    && !outs[i]->resolved)
			credit_propose_claim(outs[i]);
	}
}

static void handle_unilateral_tcov(const struct tx_parts *tx,
				   u32 tx_blockheight,
				   enum side holder,
				   bool revoked,
				   const struct basepoints basepoints[NUM_SIDES],
				   struct tracked_output **outs)
{
	struct htlcs_info *htlcs_info;
	struct keyset *ks;
	struct pubkey holder_point;
	struct tap_tree2 to_local;
	u8 *to_local_spk, *to_remote_spk, **unmatched;
	enum tx_type tx_type;
	static const u8 marker;

	if (holder == LOCAL) {
		htlcs_info = init_reply(tx, "Tracking our own unilateral close");
		onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_UNILATERAL);
		resolved_by_other(outs[0], &tx->txid, OUR_UNILATERAL);
		hsm_get_per_commitment_point(&holder_point);
		tx_type = OUR_UNILATERAL;
	} else {
		htlcs_info = init_reply(tx, revoked
					? "Tracking their illegal close: taking all funds"
					: "Tracking their unilateral close");
		onchain_annotate_txin(&tx->txid, 0,
				      TX_CHANNEL_UNILATERAL | TX_THEIRS
				      | (revoked ? TX_CHANNEL_CHEAT : 0));
		holder_point = *remote_per_commitment_point;
		tx_type = revoked ? THEIR_REVOKED_UNILATERAL : THEIR_UNILATERAL;
		resolved_by_other(outs[0], &tx->txid, tx_type);
	}

	keyset = ks = tal(tx, struct keyset);
	if (!derive_keyset(&holder_point, &basepoints[holder],
			   &basepoints[!holder], true, ks))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving keyset for %"PRIu64, commit_num);

	tcov_holder_to_local(&holder_point, holder, &to_local);
	to_local_spk = tap_tree2_scriptpubkey(tmpctx, &to_local);
	/* The holder's to_remote pays the other side's static key. */
	to_remote_spk = scriptpubkey_p2wpkh(tmpctx, &keyset->other_payment_key);
	status_debug("Taproot-covenant commitment %"PRIu64" held by %s:"
		     " to_local %s, to_remote %s",
		     commit_num, side_to_str(holder),
		     tal_hex(tmpctx, to_local_spk),
		     tal_hex(tmpctx, to_remote_spk));

	/* note_missing_htlcs() reads a NULL entry as "found". */
	unmatched = tal_arr(tmpctx, u8 *, tal_count(htlcs_info->htlcs));
	for (size_t i = 0; i < tal_count(unmatched); i++)
		unmatched[i] = (u8 *)&marker;

	for (size_t i = 0; i < tal_count(tx->outputs); i++) {
		struct tracked_output *out;
		struct amount_asset asset = wally_tx_output_get_amount(tx->outputs[i]);
		struct amount_sat amt;
		struct bitcoin_outpoint outpoint;
		struct tap_tree2 tree;
		size_t h;

		outpoint.txid = tx->txid;
		outpoint.n = i;
		assert(amount_asset_is(&asset, channel_asset));
		amt = amount_sat(asset.value);

		if (tx->outputs[i]->script_len == 0) {
			out = new_tracked_output(&outs, &outpoint, tx_blockheight,
						 tx_type, amt, ELEMENTS_FEE,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		}

		/* SEQUENTIA: a credit channel's provider balance output. */
		if (option_seq_credit
		    && credit_match(tx->outputs[i], amt, &holder_point,
				    holder, &tree)) {
			if (revoked && holder == credit_provider) {
				/* Their revoked commitment: all ours, by the
				 * key path, as any revoked to_local. */
				out = new_tracked_output(&outs, &outpoint,
							 tx_blockheight, tx_type,
							 amt,
							 DELAYED_CHEAT_OUTPUT_TO_THEM,
							 NULL, NULL, NULL);
				out->tcov_tree = keep_tree(out, &tree);
				tcov_propose(out, TCOV_SIGN_PENALTY, -1, NULL,
					     NULL, 0, 0xFFFFFFFF,
					     tx_blockheight + 1,
					     TCOV_DEADLINE_NOW, OUR_PENALTY_TX);
			} else
				credit_track(&outs, &outpoint, tx_blockheight,
					     tx_type, amt, amt, &tree);
			continue;
		}

		if (wally_tx_output_scripteq(tx->outputs[i], to_local_spk)) {
			if (holder == LOCAL) {
				out = new_tracked_output(&outs, &outpoint,
							 tx_blockheight, tx_type,
							 amt, DELAYED_OUTPUT_TO_US,
							 NULL, NULL, NULL);
				out->tcov_tree = keep_tree(out, &to_local);
				tcov_sweep_delayed(out);
			} else if (revoked) {
				out = new_tracked_output(&outs, &outpoint,
							 tx_blockheight, tx_type,
							 amt,
							 DELAYED_CHEAT_OUTPUT_TO_THEM,
							 NULL, NULL, NULL);
				out->tcov_tree = keep_tree(out, &to_local);
				tcov_propose(out, TCOV_SIGN_PENALTY, -1, NULL,
					     NULL, 0, 0xFFFFFFFF,
					     tx_blockheight + 1,
					     TCOV_DEADLINE_NOW, OUR_PENALTY_TX);
			} else {
				out = new_tracked_output(&outs, &outpoint,
							 tx_blockheight, tx_type,
							 amt, DELAYED_OUTPUT_TO_THEM,
							 NULL, NULL, NULL);
				ignore_output(out);
				record_external_deposit(out, tx_blockheight,
							mk_mvt_tags(MVT_TO_THEM));
			}
			continue;
		}

		if (wally_tx_output_scripteq(tx->outputs[i], to_remote_spk)) {
			if (holder == LOCAL) {
				out = new_tracked_output(&outs, &outpoint,
							 tx_blockheight, tx_type,
							 amt, OUTPUT_TO_THEM,
							 NULL, NULL, NULL);
				ignore_output(out);
				record_external_deposit(out, tx_blockheight,
							mk_mvt_tags(MVT_TO_THEM));
			} else
				their_unilateral_local(&outs, tx, &outpoint,
						       tx_blockheight, amt,
						       to_remote_spk, tx_type,
						       1);
			continue;
		}

		for (h = 0; h < tal_count(htlcs_info->htlcs); h++) {
			if (!unmatched[h])
				continue;
			if (tcov_match_htlc(tx->outputs[i], amt,
					    &htlcs_info->htlcs[h],
					    &holder_point, holder, &tree))
				break;
		}
		if (h == tal_count(htlcs_info->htlcs)) {
			record_external_output(&outpoint, amt, tx_blockheight,
					       mk_mvt_tags(MVT_PENALTY));
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find resolution for output %zu",
				      i);
		}
		unmatched[h] = NULL;

		out = new_tracked_output(&outs, &outpoint, tx_blockheight,
					 tx_type, amt,
					 htlcs_info->htlcs[h].owner == LOCAL
					 ? OUR_HTLC : THEIR_HTLC,
					 &htlcs_info->htlcs[h], NULL, NULL);
		out->tcov_tree = keep_tree(out, &tree);

		if (revoked) {
			/* Ours by the key path, at once. */
			tcov_propose(out, TCOV_SIGN_PENALTY, -1, NULL, NULL,
				     0, 0xFFFFFFFF, tx_blockheight + 1,
				     TCOV_DEADLINE_NOW, OUR_PENALTY_TX);
		} else if (holder == LOCAL && out->output_type == OUR_HTLC) {
			/* Our timeout, by covenant to D, after its CLTV. */
			tcov_propose(out, TCOV_SIGN_LOCAL_HTLC,
				     TCOV_LEAF_OFFERED_TIMEOUT, NULL, &to_local,
				     out->htlc.cltv_expiry, 0xFFFFFFFE,
				     out->htlc.cltv_expiry + 1,
				     TCOV_DEADLINE_HTLC_OUT,
				     OUR_HTLC_TIMEOUT_TX);
		} else if (holder == REMOTE && out->output_type == OUR_HTLC) {
			/* Our timeout on their commitment: their received
			 * tree's TIMEOUT leaf, to our wallet. */
			tcov_propose(out, TCOV_SIGN_REMOTE_HTLC,
				     TCOV_LEAF_RECEIVED_TIMEOUT, NULL, NULL,
				     out->htlc.cltv_expiry, 0xFFFFFFFE,
				     out->htlc.cltv_expiry + 1,
				     TCOV_DEADLINE_HTLC_OUT,
				     OUR_HTLC_TIMEOUT_TO_US);
		} else {
			/* Their HTLC: claimed once we hold the preimage
			 * (handle_preimage), else theirs after its CLTV. */
			propose_ignore(out, out->htlc.cltv_expiry,
				       THEIR_HTLC_TIMEOUT_TO_THEM);
		}
	}

	note_missing_htlcs(unmatched, htlcs_info);
	tal_free(htlcs_info);
	wait_for_resolved(outs);
}

/*~ SEQUENTIA: the symmetric channel type (common/sym_scripts.h).
 *
 * The funding output is spent by the kickoff, whose output 0, KO, any state
 * can spend.  We publish the best state we hold whole over KO, and over any
 * older state anybody else publishes, and the settlement of whichever state
 * stays on chain once the shared delay has passed.  None of that needs a
 * key: the update signatures are stored and SETTLE takes none.  The
 * settlement's own outputs are resolved as the taproot-covenant type's are:
 * our balance goes to the wallet, our HTLCs time out, and theirs we claim
 * with the preimage. */
static void sym_track_state(struct tracked_output ***outs,
			    const struct bitcoin_outpoint *outpoint,
			    u32 tx_blockheight, struct amount_sat amt,
			    s64 num, const struct sha256 *rest,
			    enum tx_type tx_type);

/* The state we know by number (ours, theirs, their newest), or NULL. */
static const struct sym_state *sym_known(s64 num)
{
	const struct sym_state *cands[] = { sym_local, sym_remote,
					    sym_remote_pending };

	for (size_t i = 0; i < ARRAY_SIZE(cands); i++)
		if (cands[i] && cands[i]->num == num)
			return cands[i];
	return NULL;
}

static struct onchain_witness_element **sym_welements(const tal_t *ctx,
						       u8 **wit)
{
	struct onchain_witness_element **w
		= tal_arr(ctx, struct onchain_witness_element *, tal_count(wit));
	for (size_t i = 0; i < tal_count(wit); i++) {
		w[i] = tal(w, struct onchain_witness_element);
		w[i]->is_signature = false;
		w[i]->witness = tal_dup_talarr(w[i], u8, wit[i]);
	}
	return w;
}

/* Ask lightningd to spend @out with @wit into @st's outputs. */
static void sym_propose(struct tracked_output *out, u8 **wit,
			const struct sym_state *outs, u32 sequence,
			u32 minblock, u32 deadline, enum tx_type tx_type)
{
	const u8 *msg;

	msg = towire_onchaind_spend_sym(NULL, &out->outpoint, out->sat,
					out->sym_spk,
					cast_const2(const struct onchain_witness_element **,
						    sym_welements(tmpctx, wit)),
					outs, sequence, minblock, deadline);
	propose_resolution_to_master(out, take(msg), minblock, tx_type);
}

/* What to do with a state output (KO: num -1): replace it by our best state
 * if that is newer, else settle it once the delay has passed if we know its
 * settlement, else leave it to whoever holds it. */
static void sym_resolve_state(struct tracked_output *out)
{
	const struct bip340sig *sig_op, *sig_acc;
	struct sym_tree tree, prev;
	u8 *prev_leaf, *prev_cb, *spk;
	const struct sym_state *st;

	if (sym_best && sym_best->num > out->sym_num
	    && sym_state_signed(sym_best, sym_opener, &sig_op, &sig_acc)) {
		struct sym_state *o;

		if (out->sym_num == -1) {
			sym_kickoff_tree(tmpctx, &sym_sc, &prev);
			prev_leaf = prev.upd;
			prev_cb = sym_tree_control_block(tmpctx, &prev,
							 SYM_LEAF_UPD);
		} else
			sym_rebuild_state(tmpctx, &sym_sc, out->sym_num,
					  &out->sym_rest, &spk, &prev_leaf,
					  &prev_cb);
		sym_state_tree_of(tmpctx, &sym_sc, sym_best, &tree);
		o = sym_state_new(tmpctx, LOCAL, 0, sym_best->num, NULL);
		o->outs = tal_arr(o, struct sym_state_out, 1);
		o->outs[0].amount = out->sat;
		o->outs[0].spk = sym_tree_spk(o->outs, &tree);
		status_info("Replacing state %"PRId64" by our state %"PRId64,
			    out->sym_num, sym_best->num);
		sym_propose(out, sym_update_witness(tmpctx, sig_op, sig_acc,
						    &tree, prev_leaf, prev_cb),
			    o, SYM_SEQUENCE, out->tx_blockheight + 1,
			    out->tx_blockheight + 2, SYM_UPDATE);
		return;
	}

	st = out->sym_num >= 0 ? sym_known(out->sym_num) : NULL;
	if (st) {
		sym_state_tree_of(tmpctx, &sym_sc, st, &tree);
		spk = sym_tree_spk(tmpctx, &tree);
		if (memeq(spk, tal_bytelen(spk), out->sym_spk,
			  tal_bytelen(out->sym_spk))) {
			status_info("Settling state %"PRId64" after %u blocks",
				    st->num, sym_sc.delay);
			sym_propose(out, sym_settle_witness(tmpctx, &tree), st,
				    sym_sc.delay,
				    rel_blockheight(out, sym_sc.delay),
				    rel_blockheight(out, sym_sc.delay) + 6,
				    SYM_SETTLE);
			return;
		}
	}
	status_unusual("State %"PRId64" is on chain and we do not know its"
		       " settlement: its holder settles it", out->sym_num);
	propose_ignore(out, out->tx_blockheight + 100000, SYM_SETTLE);
}

static void sym_track_state(struct tracked_output ***outs,
			    const struct bitcoin_outpoint *outpoint,
			    u32 tx_blockheight, struct amount_sat amt,
			    s64 num, const struct sha256 *rest,
			    enum tx_type tx_type)
{
	struct tracked_output *out;
	struct sym_tree tree;

	out = new_tracked_output(outs, outpoint, tx_blockheight, tx_type, amt,
				 SYM_STATE_OUTPUT, NULL, NULL, NULL);
	out->sym_num = num;
	if (num == -1) {
		sym_kickoff_tree(tmpctx, &sym_sc, &tree);
		out->sym_spk = sym_tree_spk(out, &tree);
	} else {
		u8 *spk, *leaf, *cb;
		out->sym_rest = *rest;
		sym_rebuild_state(tmpctx, &sym_sc, num, rest, &spk, &leaf, &cb);
		out->sym_spk = tal_steal(out, spk);
	}
	sym_resolve_state(out);
}

/* The settlement of a state: our balance to the wallet, the HTLCs as on a
 * taproot-covenant commitment's (common/sym_scripts.h). */
static void sym_settled(struct tracked_output ***outs,
			const struct tx_parts *tx, u32 tx_blockheight)
{
	const u8 *ours = scriptpubkey_p2wpkh(tmpctx,
					     &sym_basepoints[LOCAL].payment);
	u8 **unmatched = tal_arr(tmpctx, u8 *, tal_count(sym_htlcs->htlcs));
	static const u8 marker;

	onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_UNILATERAL);
	for (size_t i = 0; i < tal_count(unmatched); i++)
		unmatched[i] = (u8 *)&marker;

	for (size_t i = 0; i < tal_count(tx->outputs); i++) {
		struct amount_asset asset;
		struct bitcoin_outpoint outpoint;
		struct tracked_output *out;
		struct amount_sat amt;
		size_t h;

		if (!tx->outputs[i] || tx->outputs[i]->script_len == 0)
			continue;
		asset = wally_tx_output_get_amount(tx->outputs[i]);
		if (!amount_asset_is(&asset, channel_asset))
			continue;
		amt = amount_sat(asset.value);
		outpoint.txid = tx->txid;
		outpoint.n = i;

		if (wally_tx_output_scripteq(tx->outputs[i], ours)) {
			out = new_tracked_output(outs, &outpoint, tx_blockheight,
						 SYM_SETTLE, amt, OUTPUT_TO_US,
						 NULL, NULL, NULL);
			ignore_output(out);
			tell_wallet_to_remote(tx, &outpoint, tx_blockheight,
					      ours, NULL, true, 1);
			continue;
		}
		for (h = 0; h < tal_count(sym_htlcs->htlcs); h++) {
			const struct htlc_stub *s = &sym_htlcs->htlcs[h];
			struct tap_tree2 tree;

			if (!unmatched[h] || s->has_lock_point)
				continue;
			sym_htlc_tree(tmpctx, &sym_basepoints[s->owner].htlc,
				      &sym_basepoints[!s->owner].htlc,
				      &s->ripemd, s->cltv_expiry, &tree);
			if (!wally_tx_output_scripteq(tx->outputs[i],
						      tap_tree2_scriptpubkey(tmpctx,
									     &tree)))
				continue;
			unmatched[h] = NULL;
			out = new_tracked_output(outs, &outpoint,
						 tx_blockheight, SYM_SETTLE,
						 amt,
						 s->owner == LOCAL
						 ? OUR_HTLC : THEIR_HTLC,
						 s, NULL, NULL);
			out->tcov_tree = keep_tree(out, &tree);
			if (s->owner == LOCAL)
				/* Ours: its TIMEOUT leaf, after its CLTV. */
				tcov_propose(out, TCOV_SIGN_SYM_HTLC,
					     SYM_HTLC_LEAF_TIMEOUT, NULL, NULL,
					     s->cltv_expiry, 0xFFFFFFFE,
					     s->cltv_expiry + 1,
					     TCOV_DEADLINE_HTLC_OUT,
					     OUR_HTLC_TIMEOUT_TO_US);
			else
				/* Theirs: claimed once we hold the preimage
				 * (handle_preimage), else theirs after its
				 * CLTV. */
				propose_ignore(out, s->cltv_expiry,
					       THEIR_HTLC_TIMEOUT_TO_THEM);
			break;
		}
	}
	note_missing_htlcs(unmatched, sym_htlcs);
}

/* @out, a state output, was spent by input @input_num of @tx. */
static void sym_state_spent(struct tracked_output ***outs,
			    struct tracked_output *out,
			    const struct tx_parts *tx, u32 input_num,
			    u32 tx_blockheight)
{
	const struct wally_tx_witness_stack *wit = tx->inputs[input_num]->witness;
	u8 **items;
	s64 num;
	struct sha256 rest;
	struct bitcoin_outpoint next;
	struct amount_asset asset;

	if (!resolved_by_proposal(out, tx))
		resolved_by_other(out, &tx->txid,
				  tap_witness_items(wit) == 2
				  ? SYM_SETTLE : SYM_UPDATE);
	if (!wit) {
		status_broken("State %"PRId64" spent by %s without a witness",
			      out->sym_num, fmt_bitcoin_txid(tmpctx, &tx->txid));
		return;
	}

	/* A settle: leaf and control block (and perhaps an annex, which
	 * whoever mined it may have added). */
	if (tap_witness_items(wit) == 2) {
		status_info("State %"PRId64" settled by %s", out->sym_num,
			    fmt_bitcoin_txid(tmpctx, &tx->txid));
		sym_settled(outs, tx, tx_blockheight);
		return;
	}

	items = tal_arr(tmpctx, u8 *, wit->num_items);
	for (size_t i = 0; i < wit->num_items; i++)
		items[i] = tal_dup_arr(items, u8, wit->items[i].witness,
				       wit->items[i].witness_len, 0);
	if (!sym_parse_update_witness((const u8 **)items, &num, &rest)) {
		status_broken("State %"PRId64" spent by %s, neither an update"
			      " nor a settle", out->sym_num,
			      fmt_bitcoin_txid(tmpctx, &tx->txid));
		return;
	}

	/* UPD pays the next state at the input's own index. */
	next.txid = tx->txid;
	next.n = input_num;
	if (input_num >= tal_count(tx->outputs) || !tx->outputs[input_num]) {
		status_broken("Update %s has no output %u",
			      fmt_bitcoin_txid(tmpctx, &tx->txid), input_num);
		return;
	}
	asset = wally_tx_output_get_amount(tx->outputs[input_num]);
	status_info("State %"PRId64" replaced by state %"PRId64" (%s)",
		    out->sym_num, num, fmt_bitcoin_txid(tmpctx, &tx->txid));
	sym_track_state(outs, &next, tx_blockheight, amount_sat(asset.value),
			num, &rest, SYM_UPDATE);
}

/* Their HTLC, whose preimage we now hold: its SUCCESS leaf, to our wallet. */
static void sym_claim_with_preimage(struct tracked_output *out,
				    const struct preimage *preimage)
{
	tcov_propose(out, TCOV_SIGN_SYM_HTLC, SYM_HTLC_LEAF_SUCCESS, preimage,
		     NULL, 0, 0xFFFFFFFF, out->tx_blockheight + 1,
		     TCOV_DEADLINE_HTLC_IN, THEIR_HTLC_FULFILL_TO_US);
}

static void handle_symmetric_close(const struct tx_parts *tx,
				   u32 tx_blockheight,
				   struct tracked_output **outs)
{
	struct amount_asset asset;
	struct bitcoin_outpoint ko;

	/* Kept for the settlement, which comes later: a copy, so nothing
	 * init_reply re-sorted is left behind. */
	{
		struct htlcs_info *hi = init_reply(tmpctx, "Tracking a symmetric"
						   " channel's close");
		sym_htlcs = tal(NULL, struct htlcs_info);
		sym_htlcs->htlcs = tal_dup_talarr(sym_htlcs, struct htlc_stub,
						  hi->htlcs);
		sym_htlcs->tell_if_missing = tal_dup_talarr(sym_htlcs, bool,
							    hi->tell_if_missing);
		sym_htlcs->tell_immediately = tal_dup_talarr(sym_htlcs, bool,
							     hi->tell_immediately);
	}
	onchain_annotate_txin(&tx->txid, 0, TX_CHANNEL_UNILATERAL);
	resolved_by_other(outs[0], &tx->txid, SYM_UPDATE);

	/* KO is the output at the funding input's index. */
	ko.txid = tx->txid;
	ko.n = 0;
	for (size_t i = 0; i < tal_count(tx->inputs); i++)
		if (tx->inputs[i]
		    && wally_tx_input_spends(tx->inputs[i], &sym_funding))
			ko.n = i;
	if (ko.n >= tal_count(tx->outputs) || !tx->outputs[ko.n])
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Kickoff %s has no output %u",
			      fmt_bitcoin_txid(tmpctx, &tx->txid), ko.n);
	asset = wally_tx_output_get_amount(tx->outputs[ko.n]);
	status_info("Kickoff %s: our best state is %"PRId64,
		    fmt_bitcoin_txid(tmpctx, &tx->txid),
		    sym_best ? sym_best->num : (s64)-1);
	sym_track_state(&outs, &ko, tx_blockheight, amount_sat(asset.value),
			-1, NULL, SYM_UPDATE);
	wait_for_resolved(outs);
}

int main(int argc, char *argv[])
{
	setup_locale();

	const tal_t *ctx = tal(NULL, char);
	u8 *msg;
	struct pubkey remote_per_commit_point, old_remote_per_commit_point;
	enum side opener;
	struct basepoints basepoints[NUM_SIDES];
	struct shachain shachain;
	struct tx_parts *tx;
	struct tracked_output **outs;
	struct bitcoin_outpoint funding;
	struct bitcoin_txid our_broadcast_txid;
	struct bitcoin_signature *remote_htlc_sigs;
	struct amount_sat funding_sats;
	u8 *scriptpubkey[NUM_SIDES];
	u32 locktime, tx_blockheight;

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	missing_htlc_msgs = tal_arr(ctx, u8 *, 0);
	queued_msgs = tal_arr(ctx, const u8 *, 0);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_onchaind_init(tmpctx, msg,
				   &shachain,
				   &chainparams,
				   &funding_sats,
				   channel_asset,
				   &our_msat,
				   &old_remote_per_commit_point,
				   &remote_per_commit_point,
				   &to_self_delay[LOCAL],
				   &to_self_delay[REMOTE],
				   &dust_limit,
				   &our_broadcast_txid,
				   &scriptpubkey[LOCAL],
				   &scriptpubkey[REMOTE],
				   &opener,
				   &basepoints[LOCAL],
				   &basepoints[REMOTE],
				   &tx,
				   &locktime,
				   &tx_blockheight,
				   &reasonable_depth,
				   &remote_htlc_sigs,
				   &min_possible_feerate,
				   &max_possible_feerate,
				   &funding_pubkey[LOCAL],
				   &funding_pubkey[REMOTE],
				   &static_remotekey_start[LOCAL],
				   &static_remotekey_start[REMOTE],
				   &option_anchor_outputs,
				   &option_anchors_zero_fee_htlc_tx,
				   &option_seq_taproot_covenant,
				   &option_seq_credit,
				   &option_seq_symmetric,
				   &min_relay_feerate)) {
		master_badmsg(WIRE_ONCHAIND_INIT, msg);
	}

	/* SEQUENTIA: a symmetric channel's states follow. */
	if (option_seq_symmetric) {
		u16 delay;
		struct sym_state *l, *r, *rp;

		msg = wire_sync_read(tmpctx, REQ_FD);
		if (!fromwire_onchaind_sym_init(ctx, msg, &sym_funding, &delay,
						&l, &r, &rp))
			master_badmsg(WIRE_ONCHAIND_SYM_INIT, msg);
		sym_channel_init(&sym_sc, &chainparams->genesis_blockhash,
				 &sym_funding,
				 &basepoints[opener].delayed_payment,
				 &basepoints[!opener].delayed_payment,
				 channel_asset, delay);
		sym_local = l;
		sym_remote = r;
		sym_remote_pending = rp;
		sym_opener = opener;
		sym_basepoints[LOCAL] = basepoints[LOCAL];
		sym_basepoints[REMOTE] = basepoints[REMOTE];
		sym_best = NULL;
		if (l && l->has_sig[LOCAL] && l->has_sig[REMOTE])
			sym_best = l;
		if (r && r->has_sig[LOCAL] && r->has_sig[REMOTE]
		    && (!sym_best || r->num > sym_best->num))
			sym_best = r;
	}

	/* We need to keep tx around, but there's only one: not really a leak */
	tal_steal(ctx, notleak(tx));

	outs = tal_arr(ctx, struct tracked_output *, 0);
	wally_tx_input_get_txid(tx->inputs[0], &funding.txid);
	funding.n = tx->inputs[0]->index;
	/* SEQUENTIA: a kickoff may spend the funding at any input. */
	if (option_seq_symmetric)
		funding = sym_funding;

	/* SEQUENTIA: a credit channel's leaves (common/credit_scripts.h): the
	 * opener provides. */
	if (option_seq_credit) {
		struct channel_id cid;

		credit_provider = opener;
		derive_channel_id(&cid, &funding);
		credit_params = notleak(tal(ctx, struct credit_params));
		if (!credit_params_init(credit_params, &cid,
					&funding_pubkey[credit_provider],
					&basepoints[!credit_provider].payment,
					credit_params))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "No credit key for this channel");
	}
	new_tracked_output(&outs, &funding,
			   0, /* We don't care about funding blockheight */
			   FUNDING_TRANSACTION,
			   funding_sats,
			   FUNDING_OUTPUT, NULL, NULL, NULL);

	/* Record funding output spent */
	send_coin_mvt(take(new_coin_channel_close(NULL, NULL, "", &tx->txid,
						  &funding, tx_blockheight,
						  our_msat,
						  funding_sats,
						  is_elements(chainparams) ?
						  /* Minus 1, fee output */
						  tal_count(tx->outputs) - 1 :
						  tal_count(tx->outputs),
						  /* is_splice? */ false)));

	status_debug("Remote per-commit point: %s",
		     fmt_pubkey(tmpctx, &remote_per_commit_point));
	status_debug("Old remote per-commit point: %s",
		     fmt_pubkey(tmpctx, &old_remote_per_commit_point));

	trim_maximum_feerate(funding_sats, tx);

	/* BOLT #5:
	 *
	 * There are three ways a channel can end:
	 *
	 * 1. The good way (*mutual close*): at some point the local and
	 * remote nodes agree to close the channel. They generate a *closing
	 * transaction* (which is similar to a commitment transaction, but
	 * without any pending payments) and publish it on the blockchain (see
	 * [BOLT #2: Channel Close](02-peer-protocol.md#channel-close)).
	 */
	if (is_mutual_close(tx, scriptpubkey[LOCAL], scriptpubkey[REMOTE])) {
		record_mutual_close(tx, scriptpubkey[REMOTE],
				    tx_blockheight);
		handle_mutual_close(outs, tx);
	} else if (option_seq_symmetric) {
		/* SEQUENTIA: the kickoff of a symmetric channel. */
		handle_symmetric_close(tx, tx_blockheight, outs);
	} else {
		/* BOLT #5:
		 *
		 * 2. The bad way (*unilateral close*): something goes wrong,
		 *    possibly without evil intent on either side. Perhaps one
		 *    party crashed, for instance. One side publishes its
		 *    *latest commitment transaction*.
		 */
		struct secret revocation_preimage;
		commit_num = unmask_commit_number(tx, locktime, opener,
						  &basepoints[LOCAL].payment,
						  &basepoints[REMOTE].payment);

		status_debug("commitnum = %"PRIu64
			     ", revocations_received = %"PRIu64,
			     commit_num, revocations_received(&shachain));

		if (option_seq_taproot_covenant
		    && is_local_commitment(&tx->txid, &our_broadcast_txid))
			handle_unilateral_tcov(tx, tx_blockheight, LOCAL,
					       false, basepoints, outs);
		else if (option_seq_taproot_covenant
			 && shachain_get_secret(&shachain, commit_num,
						&revocation_preimage)) {
			struct pubkey *k = tal(tx, struct pubkey);
			remote_per_commitment_secret
				= tal_dup(tx, struct secret,
					  (struct secret *)&revocation_preimage);
			if (!pubkey_from_secret(remote_per_commitment_secret, k))
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Bad per_commitment_secret");
			remote_per_commitment_point = k;
			handle_unilateral_tcov(tx, tx_blockheight, REMOTE,
					       true, basepoints, outs);
		} else if (option_seq_taproot_covenant
			   && (commit_num == revocations_received(&shachain)
			       || commit_num == revocations_received(&shachain) + 1)) {
			remote_per_commitment_point
				= commit_num == revocations_received(&shachain)
				? &old_remote_per_commit_point
				: &remote_per_commit_point;
			handle_unilateral_tcov(tx, tx_blockheight, REMOTE,
					       false, basepoints, outs);
		} else if (is_local_commitment(&tx->txid, &our_broadcast_txid))
			handle_our_unilateral(tx, tx_blockheight,
					      basepoints,
					      opener,
					      remote_htlc_sigs,
					      outs);
		/* BOLT #5:
		 *
		 * 3. The ugly way (*revoked transaction close*): one of the
		 * parties deliberately tries to cheat, by publishing an
		 * *outdated commitment transaction* (presumably, a prior
		 * version, which is more in its favor).
		 */
		else if (shachain_get_secret(&shachain, commit_num,
					     &revocation_preimage)) {
			handle_their_cheat(tx,
					   tx_blockheight,
					   &revocation_preimage,
					   basepoints,
					   opener,
					   outs);
		/* BOLT #5:
		 *
		 * There may be more than one valid, *unrevoked* commitment
		 * transaction after a signature has been received via
		 * `commitment_signed` and before the corresponding
		 * `revoke_and_ack`. As such, either commitment may serve as
		 * the *remote node's* commitment transaction; hence, the
		 * local node is required to handle both.
		 */
		} else if (commit_num == revocations_received(&shachain)) {
			status_debug("Their unilateral tx, old commit point");
			handle_their_unilateral(tx, tx_blockheight,
						&old_remote_per_commit_point,
						basepoints,
						opener,
						outs);
		} else if (commit_num == revocations_received(&shachain) + 1) {
			status_debug("Their unilateral tx, new commit point");
			handle_their_unilateral(tx, tx_blockheight,
						&remote_per_commit_point,
						basepoints,
						opener,
						outs);
		} else {
			handle_unknown_commitment(tx, tx_blockheight,
						  basepoints,
						  outs);
		}
	}

	/* We're done! */
	tal_free(ctx);
	daemon_shutdown();

	return 0;
}
