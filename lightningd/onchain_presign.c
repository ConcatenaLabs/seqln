#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/tal/tal.h>
#include <channeld/channeld_wiregen.h>
#include <common/presign_templates.h>
#include <common/utils.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/htlc_end.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/onchain_presign.h>
#include <lightningd/peer_control.h>
#include <lightningd/watchtower_store.h>

/* Package a signed CLASS-B sweep tx into the on-disk watchtower_blob subtype.
 * kind/output_index/amount/deadline_delta/wscript describe how speculad fee-
 * attaches + schedules it; tx is the DEVICE-signed sweep.  (Reachable once the
 * template builders below are filled in; guards the store call so the daemon
 * never writes an empty set over a good one.) */
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

/* Build the current-state CLASS-B honest-close sweep set for @channel.
 *
 * SEAM (openIssues): this needs the LOCAL commitment keyset (local
 * per_commitment_point + per-HTLC 2nd-stage wscripts) threaded up from channeld
 * in WIRE_CHANNELD_GOT_COMMITSIG, plus a master-fd sign of each template via
 * hsm_sync_req(ld, towire_hsmd_sign_any_delayed_payment_to_us(142) /
 * _any_remote_htlc_to_us(143) / _any_local_htlc_tx(146)) mirroring
 * lightningd/onchain_control.c:747/807/791.  Until that wire field exists,
 * lightningd (keyless) cannot derive the keyset, so we return an empty set and
 * the honest force-close stays on onchaind (device-online) as today.  The
 * presign_blob() packager + wt_store_put_sweeps() plumbing below are wired so
 * only the template construction + master-sign remain to drop in here. */
static struct watchtower_blob **build_current_sweeps(const tal_t *ctx,
						     struct channel *channel)
{
	struct watchtower_blob **blobs
		= tal_arr(ctx, struct watchtower_blob *, 0);

	/* Once the keyset is threaded, for each current-state defensible output
	 * build the template (common/presign_templates.c: presign_sweep_tx for
	 * kinds 3 & 6; a new htlc_tx()-based builder for kind 4), master-sign it,
	 * then:
	 *   tal_arr_expand(&blobs, presign_blob(blobs, kind, commit_num, outnum,
	 *                                       amount, deadline_delta, wscript,
	 *                                       signed_tx));
	 */
	(void)channel;
	(void)presign_blob;
	return blobs;
}

void onchain_presign_current_sweeps(struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;
	struct watchtower_blob **blobs;

	blobs = build_current_sweeps(tmpctx, channel);
	if (tal_count(blobs) == 0) {
		log_debug(channel->log,
			  "onchain_presign: CLASS-B current-state sweeps not yet "
			  "pre-signed (awaiting channeld local-keyset threading); "
			  "honest force-close remains device-gated for commit "
			  "%"PRIu64, channel->next_index[LOCAL]);
		return;
	}

	if (!wt_store_put_sweeps(ld, channel, channel->next_index[LOCAL], blobs))
		log_broken(channel->log,
			   "onchain_presign: failed storing %zu CLASS-B sweeps",
			   tal_count(blobs));
}

bool onchain_presign_htlc_success(struct channel *channel, struct htlc_in *hin)
{
	/* SEAM / JBA fulfill hard-gate (openIssues): the HTLC-success sweep
	 * (kind 5) embeds the peer's remote_htlc_sig (channel->last_htlc_sigs) +
	 * the just-learned preimage over an htlc_tx() body signed with
	 * hsmd_sign_any_local_htlc_tx(146).  As with the commit-advance path the
	 * local keyset is not yet threaded up from channeld, so we cannot
	 * build+master-sign+store it here.  On TESTNET we do NOT hard-gate
	 * preimage release on it (that would stall fulfilment); we return true
	 * (best-effort).  Once the keyset is threaded this must sign+store the
	 * success sweep durably and return false on failure so the caller defers
	 * releasing the preimage this pass. */
	log_debug(channel->log,
		  "onchain_presign: HTLC-success sweep for htlc %"PRIu64" not "
		  "pre-signed (awaiting keyset threading); releasing preimage "
		  "best-effort", hin->key.id);
	return true;
}
