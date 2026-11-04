#ifndef LIGHTNING_COMMON_CLOSE_TX_H
#define LIGHTNING_COMMON_CLOSE_TX_H
#include "config.h"
#include <bitcoin/tx.h>

struct ext_key;

/* Create close tx to spend the anchor tx output; doesn't fill in
 * input scriptsig.  On elements, every output and the fee are in
 * `channel_asset` (33 bytes; NULL means the policy asset). */
struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   u32 *local_wallet_index,
				   const struct ext_key *local_wallet_ext_key,
				   const u8 *our_script,
				   const u8 *their_script,
				   const u8 *funding_wscript,
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   struct amount_sat to_us,
				   struct amount_sat to_them,
				   struct amount_sat dust_limit,
				   const u8 *channel_asset);

/* A further lane of a channel of several assets (common/sym_lanes.h), as a
 * mutual close pays it: its funding output and each side's share. */
struct close_lane {
	u8 asset[33];
	struct bitcoin_outpoint funding;
	struct amount_sat funding_sats;
	struct amount_sat to_us, to_them;
};

void towire_close_lane(u8 **pptr, const struct close_lane *lane);
void fromwire_close_lane(const u8 **cursor, size_t *max,
			 struct close_lane *lane);

/* The mutual close of a channel of several assets.  Input 0 is the
 * channel's own funding output (lane 0), then each further lane's, in lane
 * order, all to the same 2-of-2 (`funding_wscript`).  Lane 0 pays as
 * create_close_tx does, and the fee is the rest of lane 0, in the channel
 * asset.  Each further lane then pays each side its whole share in its own
 * asset, in lane order, the lower (amount, script) first: an output in an
 * asset other than the fee's is never dust, and leaving one out would leave
 * its value to nobody.  A share of 0 has no output. */
struct bitcoin_tx *create_close_tx_lanes(const tal_t *ctx,
					 const struct chainparams *chainparams,
					 u32 *local_wallet_index,
					 const struct ext_key *local_wallet_ext_key,
					 const u8 *our_script,
					 const u8 *their_script,
					 const u8 *funding_wscript,
					 const struct bitcoin_outpoint *funding,
					 struct amount_sat funding_sats,
					 struct amount_sat to_us,
					 struct amount_sat to_them,
					 struct amount_sat dust_limit,
					 const u8 *channel_asset,
					 const struct close_lane *lanes);
#endif /* LIGHTNING_COMMON_CLOSE_TX_H */
