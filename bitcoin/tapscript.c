#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/signature.h>
#include <bitcoin/tapscript.h>
#include <bitcoin/tx.h>
#include <bitcoin/varint.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_transaction.h>

void pubkey_to_xonly(const struct pubkey *key, u8 xonly[32])
{
	u8 der[PUBKEY_CMPR_LEN];

	pubkey_to_der(der, key);
	memcpy(xonly, der + 1, 32);
}

/* tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg) */
static void tagged_init(struct sha256_ctx *sctx, const char *tag)
{
	struct sha256 taghash;

	sha256(&taghash, tag, strlen(tag));
	sha256_init(sctx);
	sha256_update(sctx, &taghash, sizeof(taghash));
	sha256_update(sctx, &taghash, sizeof(taghash));
}

void tap_leaf_hash_version(u8 version, const u8 *script, size_t script_len,
			   struct sha256 *hash)
{
	struct sha256_ctx sctx;
	u8 len[VARINT_MAX_LEN];
	size_t lenlen = varint_put(len, script_len);

	tagged_init(&sctx, "TapLeaf/elements");
	sha256_update(&sctx, &version, 1);
	sha256_update(&sctx, len, lenlen);
	sha256_update(&sctx, script, script_len);
	sha256_done(&sctx, hash);
}

void tap_leaf_hash(const u8 *script, struct sha256 *hash)
{
	tap_leaf_hash_version(TAPSCRIPT_LEAF_VERSION_ELEMENTS, script,
			      tal_bytelen(script), hash);
}

void tap_branch_hash(const struct sha256 *a, const struct sha256 *b,
		     struct sha256 *hash)
{
	struct sha256_ctx sctx;

	/* BIP341: the two children are hashed in lexicographic order. */
	if (memcmp(a->u.u8, b->u.u8, sizeof(a->u.u8)) > 0) {
		const struct sha256 *t = a;
		a = b;
		b = t;
	}
	tagged_init(&sctx, "TapBranch/elements");
	sha256_update(&sctx, a->u.u8, sizeof(a->u.u8));
	sha256_update(&sctx, b->u.u8, sizeof(b->u.u8));
	sha256_done(&sctx, hash);
}

void tap_tree2_finish(struct tap_tree2 *tree)
{
	u8 der[PUBKEY_CMPR_LEN];

	assert(tree->nleaves == 2 || tree->nleaves == 3);
	tap_leaf_hash(tree->leaf[0], &tree->leaf_hash[0]);
	tap_leaf_hash(tree->leaf[1], &tree->leaf_hash[1]);
	tap_branch_hash(&tree->leaf_hash[0], &tree->leaf_hash[1],
			&tree->branch01);
	if (tree->nleaves == 3) {
		tap_leaf_hash(tree->leaf[2], &tree->leaf_hash[2]);
		tap_branch_hash(&tree->leaf_hash[2], &tree->branch01,
				&tree->merkle_root);
	} else
		tree->merkle_root = tree->branch01;

	pubkey_to_der(der, &tree->internal_key);
	/* libwally lifts the key to its even-y form (BIP341's x-only
	 * internal key) and adds tagged_hash("TapTweak/elements", x || root). */
	if (wally_ec_public_key_bip341_tweak(der, sizeof(der),
					     tree->merkle_root.u.u8,
					     sizeof(tree->merkle_root.u.u8),
					     EC_FLAG_ELEMENTS,
					     tree->output_der,
					     sizeof(tree->output_der))
	    != WALLY_OK)
		abort();
}

void tap_tree2_program(const struct tap_tree2 *tree, u8 program[32])
{
	memcpy(program, tree->output_der + 1, 32);
}

u8 *tap_tree2_scriptpubkey(const tal_t *ctx, const struct tap_tree2 *tree)
{
	u8 *spk = tal_arr(ctx, u8, BITCOIN_SCRIPTPUBKEY_P2TR_LEN);

	spk[0] = 0x51; /* OP_1 */
	spk[1] = 32;
	tap_tree2_program(tree, spk + 2);
	return spk;
}

u8 *tap_tree2_control_block(const tal_t *ctx, const struct tap_tree2 *tree,
			    int leaf)
{
	size_t depth = (tree->nleaves == 3 && leaf != 2) ? 2 : 1;
	u8 *cb = tal_arr(ctx, u8, 1 + 32 + 32 * depth);

	assert(leaf >= 0 && leaf < tree->nleaves);
	cb[0] = TAPSCRIPT_LEAF_VERSION_ELEMENTS
		| (tree->output_der[0] == SECP256K1_TAG_PUBKEY_ODD ? 1 : 0);
	pubkey_to_xonly(&tree->internal_key, cb + 1);
	if (leaf == 2)
		memcpy(cb + 33, tree->branch01.u.u8, 32);
	else {
		memcpy(cb + 33, tree->leaf_hash[!leaf].u.u8, 32);
		if (depth == 2)
			memcpy(cb + 65, tree->leaf_hash[2].u.u8, 32);
	}
	return cb;
}

u8 **tap_tree2_witness(const tal_t *ctx, const struct tap_tree2 *tree,
		       int leaf, u8 **stack TAKES)
{
	u8 **wit = tal_arr(ctx, u8 *, 0);

	for (size_t i = 0; i < tal_count(stack); i++)
		tal_arr_expand(&wit, tal_dup_talarr(wit, u8, stack[i]));
	if (taken(stack))
		tal_free(stack);
	tal_arr_expand(&wit, tal_dup_talarr(wit, u8, tree->leaf[leaf]));
	tal_arr_expand(&wit, tap_tree2_control_block(wit, tree, leaf));
	return wit;
}

bool tap_sighash(const struct bitcoin_tx *tx, size_t innum,
		 const u8 *leaf_script, u8 sighash_type,
		 struct sha256 *sighash)
{
	const struct wally_psbt *psbt = tx->psbt;
	struct wally_map scripts, assets, values;
	int ret;
	bool ok = false;

	if (innum >= tx->wtx->num_inputs
	    || psbt->num_inputs != tx->wtx->num_inputs)
		return false;

	tal_wally_start();
	if (wally_map_init(psbt->num_inputs, NULL, &scripts) != WALLY_OK
	    || wally_map_init(psbt->num_inputs, NULL, &assets) != WALLY_OK
	    || wally_map_init(psbt->num_inputs, NULL, &values) != WALLY_OK)
		abort();

	for (size_t i = 0; i < psbt->num_inputs; i++) {
		const struct wally_tx_output *utxo = psbt->inputs[i].witness_utxo;
		if (!utxo || !utxo->asset || !utxo->value)
			goto out;
		if (wally_map_add_integer(&scripts, i, utxo->script,
					  utxo->script_len) != WALLY_OK
		    || wally_map_add_integer(&assets, i, utxo->asset,
					     utxo->asset_len) != WALLY_OK
		    || wally_map_add_integer(&values, i, utxo->value,
					     utxo->value_len) != WALLY_OK)
			goto out;
	}

	/* BIP342's key_version is 0 for every tapscript key. */
	ret = wally_tx_get_input_signature_hash(tx->wtx, innum,
						&scripts, &assets, &values,
						leaf_script,
						tal_bytelen(leaf_script),
						0, WALLY_NO_CODESEPARATOR,
						NULL, 0,
						tx->chainparams->genesis_blockhash.shad.sha.u.u8,
						sizeof(tx->chainparams->genesis_blockhash.shad.sha.u.u8),
						sighash_type,
						WALLY_SIGTYPE_SW_V1,
						NULL,
						sighash->u.u8,
						sizeof(sighash->u.u8));
	ok = (ret == WALLY_OK);
out:
	wally_map_clear(&scripts);
	wally_map_clear(&assets);
	wally_map_clear(&values);
	tal_wally_end(tmpctx);
	return ok;
}

static void sign_with_keypair(const struct sha256 *sighash,
			      const secp256k1_keypair *kp,
			      struct bip340sig *sig)
{
	if (!secp256k1_schnorrsig_sign32(secp256k1_ctx, sig->u8,
					 sighash->u.u8, kp, NULL))
		abort();
}

void tap_sign(const struct sha256 *sighash, const struct privkey *privkey,
	      struct bip340sig *sig)
{
	secp256k1_keypair kp;

	if (!secp256k1_keypair_create(secp256k1_ctx, &kp,
				      privkey->secret.data))
		abort();
	sign_with_keypair(sighash, &kp, sig);
}

void tap_sign_keypath(const struct sha256 *sighash,
		      const struct privkey *internal_privkey,
		      const struct sha256 *merkle_root,
		      struct bip340sig *sig)
{
	struct privkey tweaked;

	/* Negates the key first when its point has an odd y, as BIP341's
	 * x-only internal key requires, then adds the TapTweak/elements. */
	if (wally_ec_private_key_bip341_tweak(internal_privkey->secret.data,
					      sizeof(internal_privkey->secret.data),
					      merkle_root->u.u8,
					      sizeof(merkle_root->u.u8),
					      EC_FLAG_ELEMENTS,
					      tweaked.secret.data,
					      sizeof(tweaked.secret.data))
	    != WALLY_OK)
		abort();
	tap_sign(sighash, &tweaked, sig);
	memset(&tweaked, 0, sizeof(tweaked));
}

bool tap_check_sig(const struct sha256 *sighash, const struct pubkey *key,
		   const struct bip340sig *sig)
{
	return check_schnorr_sig(sighash, &key->pubkey, sig);
}

u8 *tap_sig_to_witness(const tal_t *ctx, const struct bip340sig *sig,
		       u8 sighash_type)
{
	u8 *w = tal_dup_arr(ctx, u8, sig->u8, sizeof(sig->u8), 1);

	if (sighash_type == TAP_SIGHASH_DEFAULT)
		tal_resize(&w, sizeof(sig->u8));
	else
		w[64] = sighash_type;
	return w;
}
