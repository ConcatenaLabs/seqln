#ifndef LIGHTNING_COMMON_TCOV_COMMIT_TX_H
#define LIGHTNING_COMMON_TCOV_COMMIT_TX_H
/* Commitment transactions of the taproot-covenant channel type
 * (`option_seq_taproot_covenant`, scripts in common/tcov_scripts.h).
 *
 * It spends the 2-of-2 funding output as every other type does.  Its fee,
 * its trimming and its output order are those of an `option_static_remotekey`
 * channel without anchors: only the outputs' scripts differ, and a P2TR output
 * weighs what a P2WSH one does, so both sides compute the same fee.  It has no
 * second-stage HTLC transactions: the HTLC outputs' own leaves send a claim
 * to the holder's delayed output, and `commitment_signed` carries no HTLC
 * signatures. */
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/tx.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <common/credit_scripts.h>
#include <common/htlc.h>

struct bitcoin_outpoint;
struct channel_id;
struct keyset;
struct wally_tx_output;

/* An HTLC as the commitment sees it. */
struct tcov_htlc_out {
	/* The side that offered it. */
	enum side owner;
	struct amount_msat amount;
	/* RIPEMD160 of its payment hash. */
	struct ripemd160 payment_ripemd;
	/* Its lock point if it is point-locked (common/point_lock.h), else
	 * NULL. */
	const struct pubkey *lock_point;
	u32 cltv_expiry;
	/* The caller's handle for it, returned in @htlcmap. */
	const void *handle;
};

/* SEQUENTIA: a credit channel (common/credit_scripts.h): who provides, and
 * what the provider's credit outputs are built from. */
struct tcov_credit {
	enum side provider;
	/* The provider's wait on its output on the holder's commitment: the
	 * delay the holder asked of it (its to_self_delay). */
	u16 window;
	struct credit_params params;
};

/* Fill @credit for a channel whose @provider has funding key
 * @provider_funding_key and whose holder has payment basepoint
 * @holder_payment_basepoint. */
bool tcov_credit_init(const tal_t *ctx,
		      const struct channel_id *cid,
		      enum side provider,
		      const struct pubkey *provider_funding_key,
		      const struct pubkey *holder_payment_basepoint,
		      u16 window,
		      struct tcov_credit *credit);

/**
 * tcov_commit_tx: the commitment transaction held by @side.
 * @keyset: derived from @per_commitment_point, @side's own.
 * @to_self_delay: @side's delay (the one the other side asked for).
 * @htlcs: every committed HTLC (trimmed ones included), or NULL.
 * @htlcmap: (out) per output, the handle of its HTLC, or NULL.
 * @direct_outputs: (out, may be NULL) to_local [LOCAL] and to_remote [REMOTE].
 * @credit: a credit channel's (the provider's balance output carries CLAIM),
 * or NULL.
 *
 * @err_reason: non-NULL for the initial commitment, which fails (NULL, with
 * @err_reason set) if the opener cannot pay the fee; later commitments take
 * what the opener has, as commit_tx does.
 */
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
				  char **err_reason);

#endif /* LIGHTNING_COMMON_TCOV_COMMIT_TX_H */
