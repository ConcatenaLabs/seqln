#ifndef LIGHTNING_CHANNELD_TCOV_CHANNEL_H
#define LIGHTNING_CHANNELD_TCOV_CHANNEL_H
/* SEQUENTIA: channeld's side of the taproot-covenant channel type
 * (common/tcov_commit_tx.h). */
#include "config.h"
#include <bitcoin/tx.h>
#include <common/htlc.h>

struct channel;
struct htlc;
struct keyset;
struct penalty_base;
struct secret;
struct watchtower_blob;
struct wally_tx_output;

/* The commitment @side holds, with every HTLC in @committed (trimmed ones
 * included: the builder trims).  @htlcmap gets, per output, its HTLC or
 * NULL, as commit_tx's does. */
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
					  enum side side);

/* The tower's justice for the peer's revoked commitment @pbase, which it
 * revoked with @per_commitment_secret: a WT_TMPL_TCOV_REVOKE blob. */
struct watchtower_blob *tcov_justice_blob(const tal_t *ctx,
					  const struct channel *channel,
					  const struct secret *per_commitment_secret,
					  const struct penalty_base *pbase);

#endif /* LIGHTNING_CHANNELD_TCOV_CHANNEL_H */
