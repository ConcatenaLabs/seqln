#ifndef LIGHTNING_COMMON_PRESIGN_TEMPLATES_H
#define LIGHTNING_COMMON_PRESIGN_TEMPLATES_H
#include "config.h"
#include <bitcoin/tx.h>

/* Shared byte-exact defensive-tx templates for the Specula keyless watchtower
 * (Phase B).
 *
 * The device pre-signs a defensive set as the user transacts; speculad
 * (Phase C) broadcasts it while the device is offline.  For a pre-signed blob
 * to be usable at breach/close time it MUST be byte-identical to the tx the
 * live node (onchaind + lightningd/onchain_control.c) would build then.  This
 * module factors the single tx-construction primitive so both the pre-sign
 * path (channeld/watchtower.c) and the breach path build the same bytes.
 *
 * Each defensive tx is a 1-in / 1-out spend that sends the swept value to the
 * user's own final_scriptpubkey (derived from channel.final_key_idx).  The
 * caller supplies the input outpoint, amount, witness script and the input
 * sequence (0xFFFFFFFF for immediate penalties; to_self_delay for a CSV-locked
 * to_local sweep).  Signing + witness assembly stay with the caller (they own
 * the HSM fd and the per-kind witness stack element).
 */

struct ext_key;
struct bitcoin_outpoint;

/* Which defensive template.  Stored on-disk (u8) so speculad can dispatch the
 * right witness/fee policy without re-deriving; keep values stable. */
enum wt_tmpl_kind {
	/* Justice, revoke-time pre-signable (outpoints known on the revoked
	 * commitment tx): */
	WT_TMPL_TO_LOCAL_PENALTY = 0,	  /* counterparty to_local; witness <sig> 0x01 */
	WT_TMPL_STEAL_HTLC_PENALTY = 1,	  /* revoked HTLC output; witness <sig> <revocationpubkey> */

	/* Justice, NOT revoke-time pre-signable (input is the cheater's future
	 * HTLC-tx, txid unknown until they broadcast).  Kept as a device-online
	 * fallback / Phase-C seam; see note in presign_templates.c. */
	WT_TMPL_STEAL_HTLC_TX_PENALTY = 2,

	/* Current-state honest sweeps (refreshed each advance): */
	WT_TMPL_TO_LOCAL_DELAYED_SWEEP = 3, /* our to_local; witness <sig> <> (empty), CSV seq */
	WT_TMPL_HTLC_TIMEOUT = 4,	    /* TIER-2 (peer-cosigned); master-fd seam */
	WT_TMPL_HTLC_SUCCESS = 5,	    /* TIER-2, needs preimage; master-fd seam */
	WT_TMPL_REMOTE_HTLC_TO_US = 6,	    /* sweep of an HTLC offered to us */
};

/* An unsigned defensive template: the tx-to-be-signed + the metadata the
 * caller needs to sign it and that the store needs to persist. */
struct presign_template {
	enum wt_tmpl_kind kind;
	/* Unsigned 1-in/1-out tx (input witness not yet set). */
	struct bitcoin_tx *tx;
	/* The witness script being spent (input 0). */
	u8 *wscript;
	/* The value of the spent output. */
	struct amount_sat amount;
	/* Blocks from the confirming (close) height until this becomes
	 * spendable: to_self_delay for a CSV sweep, HTLC CLTV delta, or 0 for
	 * an immediate penalty.  Stored as a DELTA (not an absolute height) so
	 * speculad recomputes the deadline after a reorg. */
	u32 deadline_delta;
};

/* Build the shared 1-in/1-out sweep tx (unsigned).  Byte-exact with
 * channeld/watchtower.c:penalty_tx_create and
 * lightningd/onchain_control.c:onchaind_tx_unsigned for the same inputs:
 * output = final_scriptpubkey, fee = amount_tx_fee(feerate_perkw, weight)
 * with the same worst-case-73-byte-sig weight model, falls back to
 * FEERATE_FLOOR if the output would go below dust+fee.  Adds the BIP32/BIP86
 * keypath to the output when final_index is non-NULL.  Returns NULL on the
 * dust/no-output cases (caller logs + skips). */
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
				    const u8 *final_scriptpubkey);

/* Convenience wrapper returning a fully-populated template (allocates the
 * template off ctx; tx + wscript are children of it).  Returns NULL if the
 * output is dust / absent. */
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
					      const u8 *final_scriptpubkey);

#endif /* LIGHTNING_COMMON_PRESIGN_TEMPLATES_H */
