#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#include "config.h"
#include <lightningd/lightningd.h>

struct channel;
struct bitcoin_tx;
struct block;

enum watch_result onchaind_funding_spent(struct channel *channel,
					 const struct bitcoin_tx *tx,
					 u32 blockheight);

void onchaind_replay_channels(struct lightningd *ld);

/* SEQUENTIA: another lane's funding output of a channel of several assets
 * is spent by @tx's input @input_num (lightningd/sym_lanes.h): tell
 * onchaind, and watch what follows. */
void onchaind_lane_spent(struct channel *channel, const struct bitcoin_tx *tx,
			 size_t input_num, u32 blockheight);

#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H */
