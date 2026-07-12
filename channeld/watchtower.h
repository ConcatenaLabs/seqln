#ifndef LIGHTNING_CHANNELD_WATCHTOWER_H
#define LIGHTNING_CHANNELD_WATCHTOWER_H
#include "config.h"
#include <common/initial_channel.h>

struct ext_key;
struct penalty_base;
struct watchtower_blob;

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
		  int hsm_fd);

/* Watchtower Phase B: build + sign the FULL justice set for the just-revoked
 * remote state -- the counterparty to_local penalty plus one steal_htlc
 * penalty per revoked HTLC output recorded in pbase.  Each tx is signed at the
 * channel HSM fd (fail-soft, as penalty_tx_create) via sign_penalty_to_us and
 * returned as a tal array of struct watchtower_blob (the channeld_got_revoke
 * wire subtype), ready for lightningd to persist to the fsync-durable store.
 * Returns a (possibly empty, non-NULL) tal array of watchtower_blob POINTERS,
 * matching the channeld_got_revoke wire encoding. */
struct watchtower_blob **
build_watchtower_justice_set(const tal_t *ctx,
			     const struct channel *channel,
			     u32 penalty_feerate,
			     u32 *final_index,
			     struct ext_key *final_ext_key,
			     u8 *final_scriptpubkey,
			     const struct secret *revocation_preimage,
			     const struct penalty_base *pbase,
			     int hsm_fd);

#endif /* LIGHTNING_CHANNELD_WATCHTOWER_H */
