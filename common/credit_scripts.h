#ifndef LIGHTNING_COMMON_CREDIT_SCRIPTS_H
#define LIGHTNING_COMMON_CREDIT_SCRIPTS_H
/* SEQUENTIA: the provider-signed credit (option_seq_credit,
 * doc/sequentia-fork.md section 5d), on a taproot-covenant channel
 * (common/tcov_scripts.h).
 *
 * The side that opened the channel is its provider; the other side, the
 * holder, can be credited by the provider while it cannot sign a channel
 * update.  The provider's balance output, in both sides' commitments,
 * carries a CLAIM leaf that pays the holder whatever a credit note signed by
 * the provider says it is owed:
 *
 *   witness <sig> <c> <x>
 *   OP_SIZE <32> OP_EQUALVERIFY OP_SHA256              sig c H
 *   OP_OVER <Dtag> OP_SWAP OP_CAT OP_SWAP OP_CAT       sig c M     M = Dtag||c||H
 *   OP_ROT OP_SWAP <Pc> OP_CHECKSIGFROMSTACKVERIFY     c
 *   <B> PCII INSPECTINPUTVALUE 1 EQUALVERIFY SUB64 VERIFY      c paid
 *   OP_2DUP OP_GREATERTHAN64 OP_VERIFY                 c > paid
 *   OP_OVER OP_SWAP OP_SUB64 OP_VERIFY                 c delta
 *   output i+1: value delta, the holder's program U, this input's asset
 *   <B> OP_SWAP OP_SUB64 OP_VERIFY                     rem = B - c
 *   output i: value rem, this input's own script, this input's asset
 *
 * c is the cumulative credit (8 bytes, little-endian, in the channel asset's
 * atoms), so one note supersedes every earlier one; x is the preimage of the
 * payment that note was issued for (the hash-locked form: a note is good
 * only once its payment's preimage is out, which is when the provider has
 * collected that payment).  B is the output's value in its commitment plus
 * the credit already folded into the holder's balance there (0 while credit
 * is never folded), so paid = B - (the input's value) is what earlier claims
 * on this output took.  Anyone holding a note and its preimage can make the
 * claim: it pays the holder's program U, needs no signature from the holder,
 * and leaves the rest under the same script for a later note.
 *
 * Dtag = tagged_hash("SeqLN/credit", channel_id) binds a note to its
 * channel, channel_id being BOLT 2's derivation from the funding outpoint
 * (for every credit channel, however it was opened); Pc, the credit key, is the provider's funding key tweaked by
 * tagged_hash("SeqLN/credit-key", funding key), so it signs nothing but
 * notes; U is the holder's static payment script (P2WPKH of its payment
 * basepoint, the script its to_remote pays on the provider's commitment).
 *
 * The provider's to_local on its own commitment: internal key the
 * revocation key, CLAIM at depth one, DELAY and REVOKE (common/tcov_scripts.h)
 * at depth two.  What the provider's HTLC claims pay (D) keeps the two-leaf
 * to_local tree without CLAIM: a smaller output under the CLAIM script would
 * let one note pay a second time.  The provider's output on the holder's
 * commitment: no key path (BIP341's NUMS point), CLAIM, and PROVIDER, the
 * provider's own spend after the holder's to_self_delay:
 *   <provider payment key> OP_CHECKSIGVERIFY <delay> OP_CHECKSEQUENCEVERIFY
 * Each claim leaves the remainder under the same script, so the provider's
 * delay starts again from it.
 */
#include "config.h"
#include <bitcoin/tapscript.h>
#include <common/amount.h>

struct channel_id;
struct keyset;

/* Leaf indexes of the provider's to_local (DELAY and REVOKE as tcov's). */
#define CREDIT_LEAF_CLAIM 2
/* ... and of its output on the holder's commitment. */
#define CREDIT_REMOTE_LEAF_CLAIM 0
#define CREDIT_REMOTE_LEAF_PROVIDER 1

/* Dtag: tagged_hash("SeqLN/credit", channel_id). */
void credit_tag(const struct channel_id *cid, struct sha256 *dtag);

/* Pc from the provider's funding key, and the tweak that makes it. */
void credit_key_tweak(const struct pubkey *provider_funding_key,
		      struct sha256 *tweak);
bool credit_key(const struct pubkey *provider_funding_key,
		struct pubkey *credit_key);

/* The 72-byte message a note signs: Dtag || c (8 LE) || payment_hash. */
void credit_note_msg(const struct sha256 *dtag, u64 c_atoms,
		     const struct sha256 *payment_hash, u8 msg[72]);

/* Does @sig (64 bytes, BIP340) sign the note (@c_atoms, @payment_hash) for
 * channel @dtag under @credit_key? */
bool credit_note_check(const struct sha256 *dtag,
		       const struct pubkey *credit_key,
		       u64 c_atoms, const struct sha256 *payment_hash,
		       const u8 sig[64]);

/* The CLAIM leaf.  @b_atoms is B; @holder_spk the holder's v0 program. */
u8 *credit_leaf_claim(const tal_t *ctx,
		      const struct sha256 *dtag,
		      const struct pubkey *credit_key,
		      struct amount_sat b,
		      const u8 *holder_spk);

/* What a channel's credit leaves are built from. */
struct credit_params {
	struct sha256 dtag;
	struct pubkey credit_key;
	/* The holder's static payment script, P2WPKH. */
	const u8 *holder_spk;
	/* Credit folded into the holder's balance in this commitment. */
	struct amount_sat folded;
};

/* Fill @params for a channel whose provider has funding key
 * @provider_funding_key and whose holder's payment basepoint is
 * @holder_payment_basepoint. */
bool credit_params_init(const tal_t *ctx,
			const struct channel_id *cid,
			const struct pubkey *provider_funding_key,
			const struct pubkey *holder_payment_basepoint,
			struct credit_params *params);

/* The provider's to_local on its own commitment (value @value): leaf 0
 * DELAY, leaf 1 REVOKE, leaf 2 CLAIM. */
void credit_to_local_tree(const tal_t *ctx,
			  const struct keyset *keyset,
			  const struct pubkey *per_commitment_point,
			  u16 to_self_delay,
			  const struct credit_params *params,
			  struct amount_sat value,
			  struct tap_tree2 *tree);

/* The provider's output on the holder's commitment (value @value): leaf 0
 * CLAIM, leaf 1 PROVIDER after @delay blocks, by @provider_payment_key. */
void credit_to_remote_tree(const tal_t *ctx,
			   const struct pubkey *provider_payment_key,
			   u16 delay,
			   const struct credit_params *params,
			   struct amount_sat value,
			   struct tap_tree2 *tree);

/* BIP341's NUMS point: an internal key nobody can spend with. */
void credit_nums_key(struct pubkey *nums);

#endif /* LIGHTNING_COMMON_CREDIT_SCRIPTS_H */
