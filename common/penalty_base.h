#ifndef LIGHTNING_COMMON_PENALTY_BASE_H
#define LIGHTNING_COMMON_PENALTY_BASE_H
#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/crypto/sha256/sha256.h>

/* One non-dust HTLC output on a (revoked) remote commitment, enough to rebuild
 * its witness script + a steal_htlc penalty at revoke time.  Captured at
 * commit-sig time (channeld send_commit_part) since the keyset is re-derived
 * from the revealed per-commitment secret at revoke time. */
struct penalty_htlc {
	/* Index of this HTLC output in the remote commitment tx. */
	u32 outnum;
	/* The HTLC output amount. */
	struct amount_sat amount;
	/* The payment hash (sha256; the wscript builders ripemd it). */
	struct sha256 payment_hash;
	/* HTLC absolute CLTV expiry (needed for a received-HTLC wscript). */
	u32 cltv_expiry;
	/* True if REMOTE offered this HTLC (an OFFERED output on their
	 * commitment -> bitcoin_wscript_htlc_offer); false if we offered it
	 * (a RECEIVED output -> bitcoin_wscript_htlc_receive). */
	bool remote_offered;
};

/* To create a penalty, all we need are these. */
struct penalty_base {
	/* The remote commitment index. */
	u64 commitment_num;
	/* The remote commitment txid. */
	struct bitcoin_txid txid;
	/* The remote commitment's "to-local" output. */
	u32 outnum;
	/* The amount of the remote commitment's "to-local" output. */
	struct amount_sat amount;
	/* The remote commitment's non-dust HTLC outputs (for steal_htlc
	 * justice).  NULL when empty (tal_count(NULL) == 0), else a tal array
	 * parented on this penalty_base. */
	struct penalty_htlc *htlcs;
};

/* txout must be within tx! */
struct penalty_base *penalty_base_new(const tal_t *ctx,
				      u64 commitment_num,
				      const struct bitcoin_tx *tx,
				      const struct wally_tx_output *txout);

/* Record an HTLC output for later steal_htlc justice. */
void penalty_base_add_htlc(struct penalty_base *pbase,
			   u32 outnum,
			   struct amount_sat amount,
			   const struct sha256 *payment_hash,
			   u32 cltv_expiry,
			   bool remote_offered);

void towire_penalty_base(u8 **pptr, const struct penalty_base *pbase);
/* Wiregen varsize type: pbase (and its htlcs) are allocated off ctx, so the
 * ARRAY form (channeld_init) gets per-element tal objects parented on the
 * array instead of mid-array element pointers that cannot parent the htlcs. */
struct penalty_base *fromwire_penalty_base(const tal_t *ctx,
					   const u8 **ptr, size_t *max);

#endif /* LIGHTNING_COMMON_PENALTY_BASE_H */
