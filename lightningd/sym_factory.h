#ifndef LIGHTNING_LIGHTNINGD_SYM_FACTORY_H
#define LIGHTNING_LIGHTNINGD_SYM_FACTORY_H
/* SEQUENTIA: lightningd's side of factory channels
 * (`option_seq_symmetric_factory`, common/sym_factory.h).
 *
 * A factory channel is a symmetric channel (lightningd/symmetric.h) whose
 * `funding` is its id in the factory, (nonce, slot), which the tag binds.
 * Its output on chain is the factory output F until the split, and its KO
 * after it.  The node watches F once, whichever of its channels in that
 * factory holds the watch: when F is spent, by anyone, every one of those
 * channels takes its KO as its output and goes on; one that is closing then
 * publishes its best state over its KO.  When a KO is spent, by an update,
 * onchaind takes the channel from there as for any symmetric channel.
 *
 * Nothing here signs: the split takes no signature, and an update over KO
 * takes the two update signatures the channel holds.  Each spend pays its
 * fee from a wallet coin attached when it is built (lightningd/symmetric.h),
 * and none starts for an output already seen spent. */
#include "config.h"
#include <stdbool.h>

struct channel;
struct lightningd;
struct sym_factory;

/* Is this a factory channel? */
bool channel_is_sym_factory(const struct channel *channel);

/* The channel's output on chain: F, or its KO after the split. */
const struct bitcoin_outpoint *sym_factory_anchor(const struct channel *channel);

/* Set the channel's factory (taken), saved at once. */
void sym_factory_attach(struct channel *channel, struct sym_factory *f TAKES);

/* Watch the channel's output: F's confirmation (for the channel's short
 * id) and its spend, or its KO's spend.  In place of channel_watch_funding
 * for a factory channel. */
void sym_factory_watch(struct lightningd *ld, struct channel *channel);

/* Is the channel's output watched? */
bool sym_factory_watching(const struct channel *channel);

/* Go to chain unilaterally: the split, if F is unspent, else our best state
 * over the KO.  False if the channel holds no state to publish. */
bool sym_factory_close(struct lightningd *ld, struct channel *channel);

#endif /* LIGHTNING_LIGHTNINGD_SYM_FACTORY_H */
