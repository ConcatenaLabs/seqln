#ifndef LIGHTNING_BITCOIN_TAPSCRIPT_H
#define LIGHTNING_BITCOIN_TAPSCRIPT_H
/* Taproot outputs with a script tree, and their signature hashes, as the
 * Elements chains (Sequentia among them) compute them: leaf version 0xc4 and
 * the tags "TapLeaf/elements", "TapBranch/elements", "TapTweak/elements" and
 * "TapSighash/elements", the last committing to the chain's genesis hash. */
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct bitcoin_tx;
struct bip340sig;
struct privkey;

/* Tapscript's leaf version on Elements chains (0xc0 on Bitcoin). */
#define TAPSCRIPT_LEAF_VERSION_ELEMENTS 0xc4

/* BIP341's default sighash type: SIGHASH_ALL, with a 64-byte signature. */
#define TAP_SIGHASH_DEFAULT 0x00

/* A taproot output whose script tree holds two leaves, or three: with three,
 * leaf 2 sits at depth one and leaves 0 and 1 below it, at depth two (the
 * tree [leaf 2, [leaf 0, leaf 1]]). */
struct tap_tree2 {
	/* 2 or 3: set by whoever fills in leaf[]. */
	int nleaves;
	/* The leaf scripts (tapscript); leaf[2] only with three. */
	const u8 *leaf[3];
	struct sha256 leaf_hash[3];
	/* With three leaves: the branch over leaves 0 and 1. */
	struct sha256 branch01;
	struct sha256 merkle_root;
	struct pubkey internal_key;
	/* The tweaked output key, compressed: its first byte gives its
	 * parity, which the control block carries. */
	u8 output_der[PUBKEY_CMPR_LEN];
};

/* The 32-byte x-only form of a key (its x coordinate). */
void pubkey_to_xonly(const struct pubkey *key, u8 xonly[32]);

/* BIP341: when a taproot witness has at least two items and the last one
 * starts with 0x50, that item is the annex, which no script sees and no
 * script-path signature here covers: anyone who relays or mines the spend
 * can add one.  The number of items a reader of the witness should look at,
 * the annex left out. */
#define TAP_ANNEX_TAG 0x50
struct wally_tx_witness_stack;
size_t tap_witness_items(const struct wally_tx_witness_stack *wit);

/* tagged_hash("TapLeaf/elements", 0xc4 || compact_size(len) || script) */
void tap_leaf_hash(const u8 *script, struct sha256 *hash);

/* The same for a leaf of any version: a Simplicity leaf (0xbe) hashes its
 * program's 32-byte CMR. */
void tap_leaf_hash_version(u8 version, const u8 *script, size_t script_len,
			   struct sha256 *hash);

/* tagged_hash("TapBranch/elements", min(a,b) || max(a,b)) */
void tap_branch_hash(const struct sha256 *a, const struct sha256 *b,
		     struct sha256 *hash);

/* Given tree->leaf[] and tree->internal_key, fill in the leaf hashes, the
 * merkle root and the output key. */
void tap_tree2_finish(struct tap_tree2 *tree);

/* The output's scriptPubKey: OP_1 <32-byte output key>. */
u8 *tap_tree2_scriptpubkey(const tal_t *ctx, const struct tap_tree2 *tree);

/* The 32-byte witness program of that scriptPubKey. */
void tap_tree2_program(const struct tap_tree2 *tree, u8 program[32]);

/* The control block that spends leaf @leaf (0 or 1, or 2 with three leaves):
 * (0xc4 | parity) || x-only internal key || the merkle path: the other
 * leaf's hash; with three leaves, for leaf 0 or 1 then leaf 2's hash, and
 * for leaf 2 the branch over leaves 0 and 1. */
u8 *tap_tree2_control_block(const tal_t *ctx, const struct tap_tree2 *tree,
			    int leaf);

/* The script-path witness for leaf @leaf: @stack, then the leaf, then its
 * control block. */
u8 **tap_tree2_witness(const tal_t *ctx, const struct tap_tree2 *tree,
		       int leaf, u8 **stack TAKES);

/* The signature hash of input @innum of @tx, a transaction on the Elements
 * chain tx->chainparams names, whose PSBT holds the previous output of
 * every input: the
 * script path of @leaf_script, or the key path if @leaf_script is NULL.
 * Returns false if a previous output is missing or @innum's is not
 * taproot. */
bool tap_sighash(const struct bitcoin_tx *tx, size_t innum,
		 const u8 *leaf_script, u8 sighash_type,
		 struct sha256 *sighash);

/* BIP340 signature of @sighash by @privkey (deterministic: no auxiliary
 * randomness, so the same request always gets the same signature). */
void tap_sign(const struct sha256 *sighash, const struct privkey *privkey,
	      struct bip340sig *sig);

/* The key path: @privkey tweaked for the tree's merkle root, then signed. */
void tap_sign_keypath(const struct sha256 *sighash,
		      const struct privkey *internal_privkey,
		      const struct sha256 *merkle_root,
		      struct bip340sig *sig);

/* Verify a BIP340 signature by the x-only form of @key. */
bool tap_check_sig(const struct sha256 *sighash, const struct pubkey *key,
		   const struct bip340sig *sig);

/* The serialized witness element of a signature: 64 bytes, or 65 with the
 * sighash type appended when it is not the default. */
u8 *tap_sig_to_witness(const tal_t *ctx, const struct bip340sig *sig,
		       u8 sighash_type);

#endif /* LIGHTNING_BITCOIN_TAPSCRIPT_H */
