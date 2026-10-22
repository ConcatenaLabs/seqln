#ifndef LIGHTNING_COMMON_SYM_SCRIPTS_H
#define LIGHTNING_COMMON_SYM_SCRIPTS_H
/* Scripts and transactions of the symmetric channel type
 * (`option_seq_symmetric`).
 *
 * There is no penalty: an old state is replaced by a newer one, and only the
 * latest state need be kept.  The funding output is the usual 2-of-2 P2WSH,
 * so opening, gossip and the mutual close are those of every other type.  A
 * unilateral close takes three transactions, and each pays its fee from an
 * input attached when it is broadcast, in any asset the node accepts:
 *
 *   kickoff  spends the funding output; output 0 is KO = tr(H, UPD(-1)), the
 *            funding's whole value and asset.  Both funding keys sign it once,
 *            at open, SIGHASH_SINGLE|SIGHASH_ANYONECANPAY: a fee input and its
 *            change can be added by anyone, and it is the same whatever the
 *            state.
 *   update   spends KO, or the output of any older state k, by UPD(k); the
 *            output at the input's index is state n's output, of the same
 *            value and asset.
 *   settle   spends state n's output by SETTLE(n) after the shared delay;
 *            outputs 0 .. m-1 are the settlement.
 *
 * A state output is tr(H, {UPD(n), R(n)}), H the NUMS point (no key path),
 * where R(n) is SETTLE(n), or a branch over SETTLE(n) and a Simplicity leaf
 * (leaf version 0xbe over its CMR): the state output is a mixed tree, and a
 * Simplicity settle path can be added as a channel-type bit without changing
 * UPD, its signatures or the watcher.
 *
 * UPD(k), witness <sig_accepter> <sig_opener> <n: 8 bytes LE> <R(n)'s hash>:
 *   OP_OVER <k: 8 bytes LE> OP_GREATERTHAN64 OP_VERIFY          n > k, signed
 *   OP_PUSHCURRENTINPUTINDEX OP_INSPECTOUTPUTSCRIPTPUBKEY
 *   OP_1 OP_EQUALVERIFY                                         P, a v1 program
 *   OP_ROT OP_SWAP OP_CAT OP_SWAP OP_CAT                        n || P || R
 *   <tag> OP_SWAP OP_CAT OP_SHA256                              m
 *   OP_TUCK <opener key> OP_CHECKSIGFROMSTACKVERIFY
 *   <accepter key> OP_CHECKSIGFROMSTACKVERIFY
 *   OP_PUSHCURRENTINPUTINDEX OP_INSPECTOUTPUTVALUE
 *   OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE
 *   OP_ROT OP_EQUALVERIFY OP_EQUALVERIFY                        value kept
 *   OP_PUSHCURRENTINPUTINDEX OP_INSPECTOUTPUTASSET
 *   OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTASSET
 *   OP_ROT OP_EQUALVERIFY OP_EQUAL                              asset kept
 *
 *   m = SHA256(tag || n || P || R), tag = SHA256("SeqLN symmetric update v1"
 *   || genesis hash || funding txid || funding output index, 4 bytes LE).
 *   One signature from each side over m covers the update and, through P,
 *   which commits to R, the settlement.  It binds the chain and the channel
 *   (the tag), the state, and nothing else: it spends any older state output
 *   of this channel, whatever its txid, and leaves every other input and
 *   output free for the fee.
 *
 * SETTLE(n), no witness but the leaf and its control block:
 *   <delay> OP_CHECKSEQUENCEVERIFY OP_DROP
 *   for each output i in 0 .. m-1:
 *     <i> OP_INSPECTOUTPUTASSET OP_CAT OP_SHA256INITIALIZE (i > 0: UPDATE)
 *     <i> OP_INSPECTOUTPUTVALUE OP_CAT OP_SHA256UPDATE
 *     <i> OP_INSPECTOUTPUTSCRIPTPUBKEY OP_CAT OP_SHA256 OP_SHA256UPDATE
 *         (the last: OP_SHA256FINALIZE)
 *   <digest> OP_EQUAL
 *
 *   digest = SHA256 over each output of asset || 0x01 || value, 8 bytes LE ||
 *   0x01 || SHA256(program || version), version empty for v0.  The script's
 *   hash makes every field of fixed length, so no other list of outputs
 *   hashes to the same digest.  The settlement's values add up to the state
 *   output's value: nothing is left for whoever builds the settle.
 *
 * Settlement outputs: each side's balance to P2WPKH of its payment basepoint,
 * and each HTLC to tr(H, {SUCCESS, TIMEOUT}):
 *   SUCCESS OP_SIZE <32> OP_EQUALVERIFY OP_HASH160 <RIPEMD160(payment_hash)>
 *           OP_EQUALVERIFY <receiver's HTLC basepoint> OP_CHECKSIG
 *   TIMEOUT <offerer's HTLC basepoint> OP_CHECKSIGVERIFY <cltv_expiry> OP_CLTV
 * There is no revocation, so no key is tweaked per commitment.
 *
 * Every key in a leaf is in the script, as a 32-byte x-only key: no leaf
 * takes a key from its witness, and a checksig of any kind on a key of
 * another length would pass any signature.
 *
 * common/test/run-sym_scripts.c checks these against vectors from the
 * Sequentia node's test framework, whose builders were proved on a Sequentia
 * chain with each negative case forced into a block. */
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/signature.h>
#include <bitcoin/tapscript.h>
#include <bitcoin/tx.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <common/amount.h>
#include <common/htlc.h>

struct bitcoin_blkid;
struct bitcoin_outpoint;

#define SYM_TAG_PREFIX "SeqLN symmetric update v1"
/* Simplicity's leaf version on Elements chains. */
#define SIMPLICITY_LEAF_VERSION_ELEMENTS 0xbe
/* Every input of a kickoff and an update signals replacement. */
#define SYM_SEQUENCE 0xFFFFFFFD

/* The constants of one channel. */
struct sym_channel {
	struct sha256 tag;
	/* The opener's and the accepter's update keys: UPD reads the
	 * opener's signature first. */
	struct pubkey upd_key[2];
	/* The channel asset: 0x01 || 32-byte id. */
	u8 asset[33];
	/* The shared delay, blocks: the larger of the two to_self_delays. */
	u16 delay;
};

#define SYM_OPENER 0
#define SYM_ACCEPTER 1

/* @genesis and @funding as the chain hashes them (internal byte order). */
void sym_channel_init(struct sym_channel *sc,
		      const struct bitcoin_blkid *genesis,
		      const struct bitcoin_outpoint *funding,
		      const struct pubkey *opener_upd_key,
		      const struct pubkey *accepter_upd_key,
		      const u8 *asset_tag, u16 delay);

/* The state number of a commitment: each side's commitments in its own
 * sequence, opener's even, accepter's odd.  When a side revokes commitment
 * i, it hands the other its signature on commitment i+1, so whoever is
 * cheated always holds a state numbered above the one it is cheated with. */
s64 sym_state_num(u64 commitment_index, bool opener);

/* One output of a settlement. */
enum sym_output_kind {
	SYM_OUT_BALANCE,
	SYM_OUT_HTLC,
};

struct sym_output {
	enum sym_output_kind kind;
	/* SYM_OUT_BALANCE: whose; SYM_OUT_HTLC: who offered it. */
	enum side side;
	struct amount_sat amount;
	const u8 *spk;
	/* SYM_OUT_HTLC: the caller's handle and its expiry. */
	const void *htlc;
	u32 cltv_expiry;
};

/* An HTLC a settlement carries. */
struct sym_htlc {
	enum side owner;
	struct amount_msat amount;
	struct ripemd160 payment_ripemd;
	u32 cltv_expiry;
	const void *handle;
};

/**
 * sym_settlement - the settlement of a state.
 * @balance: each side's balance in this state.
 * @payment_basepoint, @htlc_basepoint: each side's.
 * @dust_limit: the larger of the two sides' dust limits.
 *
 * An HTLC below the dust limit is not an output: its value stays with the
 * side that offered it.  A balance below it goes to the other side.  What
 * msat rounding leaves goes to the opener.  The outputs are sorted by
 * amount, then script, then expiry, so both sides build the same list, and
 * they add up to @funding_sats.  NULL (and *err set) if the state cannot be
 * paid out of the funding.
 */
struct sym_output *sym_settlement(const tal_t *ctx,
				  struct amount_sat funding_sats,
				  enum side opener,
				  const struct pubkey payment_basepoint[NUM_SIDES],
				  const struct pubkey htlc_basepoint[NUM_SIDES],
				  const struct amount_msat balance[NUM_SIDES],
				  const struct sym_htlc *htlcs,
				  struct amount_sat dust_limit,
				  const char **err);

/* Leaves. */
u8 *sym_leaf_upd(const tal_t *ctx, const struct sym_channel *sc, s64 k);
u8 *sym_leaf_settle(const tal_t *ctx, const struct sym_channel *sc,
		    const struct sym_output *outs);
void sym_settle_digest(const struct sym_channel *sc,
		       const struct sym_output *outs, struct sha256 *digest);
u8 *sym_leaf_htlc_success(const tal_t *ctx,
			  const struct ripemd160 *payment_ripemd,
			  const struct pubkey *receiver_key);
u8 *sym_leaf_htlc_timeout(const tal_t *ctx,
			  const struct pubkey *offerer_key, u32 cltv_expiry);

#define SYM_HTLC_LEAF_SUCCESS 0
#define SYM_HTLC_LEAF_TIMEOUT 1

/* An HTLC output: leaf 0 SUCCESS, leaf 1 TIMEOUT, internal key H. */
void sym_htlc_tree(const tal_t *ctx,
		   const struct pubkey *offerer_key,
		   const struct pubkey *receiver_key,
		   const struct ripemd160 *payment_ripemd,
		   u32 cltv_expiry, struct tap_tree2 *tree);

/* A state output's tree, or KO's (n = -1, UPD alone). */
struct sym_tree {
	s64 n;
	u8 *upd, *settle;
	struct sha256 upd_hash;
	/* R: UPD's sibling, which UPD's signatures cover. */
	struct sha256 rest;
	/* With a Simplicity leaf: SETTLE's sibling. */
	bool has_sim;
	struct sha256 settle_hash, sim_hash;
	struct sha256 merkle_root;
	u8 output_der[PUBKEY_CMPR_LEN];
};

#define SYM_LEAF_UPD 0
#define SYM_LEAF_SETTLE 1
#define SYM_LEAF_SIM 2

/* @sim_cmr: a Simplicity program's CMR beside SETTLE, or NULL. */
void sym_state_tree(const tal_t *ctx, const struct sym_channel *sc, s64 n,
		    const struct sym_output *outs, const u8 *sim_cmr,
		    struct sym_tree *tree);
void sym_kickoff_tree(const tal_t *ctx, const struct sym_channel *sc,
		      struct sym_tree *tree);

/* What a watcher does with a state output it finds on chain: from k and R,
 * which the update that made it published in its witness, and the channel's
 * constants, the output's script, UPD(k) and its control block.  Nothing is
 * stored per state. */
void sym_rebuild_state(const tal_t *ctx, const struct sym_channel *sc, s64 k,
		       const struct sha256 *rest, u8 **spk, u8 **upd_leaf,
		       u8 **upd_cb);

u8 *sym_tree_spk(const tal_t *ctx, const struct sym_tree *tree);
void sym_tree_program(const struct sym_tree *tree, u8 program[32]);
u8 *sym_tree_control_block(const tal_t *ctx, const struct sym_tree *tree,
			   int leaf);

/* The message both sides sign for state @tree. */
void sym_upd_msg(const struct sym_channel *sc, const struct sym_tree *tree,
		 struct sha256 *msg);

/* Witnesses: an update spending a state output whose UPD leaf and control
 * block are @prev_leaf and @prev_cb, into state @tree; a settle of @tree. */
u8 **sym_update_witness(const tal_t *ctx,
			const struct bip340sig *sig_opener,
			const struct bip340sig *sig_accepter,
			const struct sym_tree *tree,
			const u8 *prev_leaf, const u8 *prev_cb);
u8 **sym_settle_witness(const tal_t *ctx, const struct sym_tree *tree);

/* What an update's witness published: its new state's number and R.
 * False if @wit is not an update's. */
bool sym_parse_update_witness(const u8 **wit, s64 *n, struct sha256 *rest);

/* The kickoff, unsigned: one input, the funding output (@funding_wscript),
 * and output 0 KO; bitcoin_tx_finalize adds Elements' (empty) fee output. */
struct bitcoin_tx *sym_kickoff_tx(const tal_t *ctx,
				  const struct chainparams *chainparams,
				  const struct bitcoin_outpoint *funding,
				  struct amount_sat funding_sats,
				  const u8 *funding_wscript,
				  const struct sym_channel *sc);

/* The kickoff's witness from both funding signatures. */
u8 **sym_kickoff_witness(const tal_t *ctx,
			 const struct bitcoin_signature *sig_a,
			 const struct pubkey *key_a,
			 const struct bitcoin_signature *sig_b,
			 const struct pubkey *key_b);

#endif /* LIGHTNING_COMMON_SYM_SCRIPTS_H */
