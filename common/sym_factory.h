#ifndef LIGHTNING_COMMON_SYM_FACTORY_H
#define LIGHTNING_COMMON_SYM_FACTORY_H
/* A factory of symmetric channels (`option_seq_symmetric_factory`): one
 * funding output that opens many symmetric channels (common/sym_scripts.h)
 * between a hub and its members.
 *
 *   F        tr(H, SPLIT), H the NUMS point: no key path and no signature.
 *   SPLIT    outputs 0 .. N-1 are (asset, c_j, KO_j), slot by slot, fixed by
 *            the streaming hash SETTLE uses, with no delay:
 *              for each output i in 0 .. N-1:
 *                <i> OP_INSPECTOUTPUTASSET OP_CAT OP_SHA256INITIALIZE (UPDATE)
 *                <i> OP_INSPECTOUTPUTVALUE OP_CAT OP_SHA256UPDATE
 *                <i> OP_INSPECTOUTPUTSCRIPTPUBKEY OP_CAT OP_SHA256
 *                    OP_SHA256UPDATE (the last: OP_SHA256FINALIZE)
 *              <digest> OP_EQUAL
 *            Any other input, and any output after them, pays the fee, in
 *            any asset the publisher's node accepts.
 *   KO_j     slot j's channel's KO, tr(H, UPD(-1)), exactly as the kickoff of
 *            a plain symmetric channel pays it.
 *
 * A channel of a factory has no funding outpoint of its own: its KO is fixed
 * before the factory's funding exists.  Where a plain channel's tag binds its
 * funding outpoint, a factory channel's binds its id, (nonce, slot): the
 * hub's 32-byte nonce as the txid, the slot as the output index.  The node
 * keeps that id as the channel's `funding`, so the channel id, the tag and
 * every signer message are those of a plain channel with that outpoint, and
 * tracks the channel's real output apart: F until the split, KO_j after it.
 * Each channel's update keys are its own, so no two channels share both a
 * tag and a pair of keys.
 *
 * A member's channel is used while the others are offline: nothing at the
 * factory level is ever signed.  One member exits alone: the split puts
 * every KO on chain, its own channel updates and settles over its KO, and
 * every other channel goes on, anchored on its KO, which has no clock. */
#include "config.h"
#include <bitcoin/tx.h>
#include <common/amount.h>

struct sym_factory_slot {
	/* KO_j's witness v1 program. */
	u8 program[32];
	struct amount_sat amount;
};

struct sym_factory {
	/* The hub's nonce, and this channel's slot. */
	struct bitcoin_txid nonce;
	u16 slot;
	/* The factory's asset (0x01 || 32-byte id). */
	u8 asset[33];
	/* Every slot's KO, in slot order. */
	struct sym_factory_slot *slots;
	/* F on chain. */
	struct bitcoin_outpoint out;
};

/* The channel's id, which its tag binds: (nonce, slot). */
void sym_factory_id(const struct sym_factory *f, struct bitcoin_outpoint *id);

/* Add up the slots; false on overflow. */
bool sym_factory_value(const struct sym_factory_slot *slots,
		       struct amount_sat *total);

/* SPLIT, and the digest it compares. */
u8 *sym_leaf_split(const tal_t *ctx, const u8 asset[33],
		   const struct sym_factory_slot *slots);
void sym_split_digest(const u8 asset[33],
		      const struct sym_factory_slot *slots,
		      struct sha256 *digest);

/* F's scriptPubKey, and the witness that spends it by SPLIT. */
u8 *sym_factory_spk(const tal_t *ctx, const u8 asset[33],
		    const struct sym_factory_slot *slots);
u8 **sym_split_witness(const tal_t *ctx, const u8 asset[33],
		       const struct sym_factory_slot *slots);

/* Slot j's KO as an output script. */
u8 *sym_factory_ko_spk(const tal_t *ctx, const struct sym_factory *f,
		       size_t slot);

/* What a member checks of a factory before it holds a channel in it: at
 * least two slots, its slot among them, whose KO and amount are its own
 * channel's, every amount above zero, and the total in range.  NULL if
 * sound, else why not. */
const char *sym_factory_check(const tal_t *ctx, const struct sym_factory *f,
			      const u8 own_ko_program[32],
			      struct amount_sat own_amount);

void towire_sym_factory(u8 **pptr, const struct sym_factory *f);
struct sym_factory *fromwire_sym_factory(const tal_t *ctx,
					 const u8 **cursor, size_t *max);

#endif /* LIGHTNING_COMMON_SYM_FACTORY_H */
