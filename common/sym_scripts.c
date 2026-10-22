#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <ccan/asort/asort.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <common/sym_scripts.h>
#include <common/utils.h>
#include <wally_core.h>
#include <wally_script.h>

/* The Elements opcodes the leaves use, beyond Bitcoin's. */
#define SYM_OP_CAT 0x7e
#define SYM_OP_SHA256INITIALIZE 0xc4
#define SYM_OP_SHA256UPDATE 0xc5
#define SYM_OP_SHA256FINALIZE 0xc6
#define SYM_OP_INSPECTINPUTASSET 0xc8
#define SYM_OP_INSPECTINPUTVALUE 0xc9
#define SYM_OP_PUSHCURRENTINPUTINDEX 0xcd
#define SYM_OP_INSPECTOUTPUTASSET 0xce
#define SYM_OP_INSPECTOUTPUTVALUE 0xcf
#define SYM_OP_INSPECTOUTPUTSCRIPTPUBKEY 0xd1
#define SYM_OP_GREATERTHAN64 0xde
#define SYM_OP_CHECKSIGFROMSTACKVERIFY 0xc2

/* BIP341's H: lift_x(0x50929b74...803ac0), whose discrete log nobody knows. */
static const u8 nums_der[PUBKEY_CMPR_LEN] = {
	0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b,
	0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28,
	0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
};

static void op(u8 **s, u8 opcode)
{
	tal_arr_expand(s, opcode);
}

static void push(u8 **s, const void *mem, size_t len)
{
	script_push_bytes(s, mem, len);
}

/* A non-negative script number, minimally encoded. */
static void push_num(u8 **s, u32 num)
{
	u8 buf[5];
	size_t len = 0;

	if (num == 0) {
		op(s, OP_0);
		return;
	}
	if (num <= 16) {
		op(s, OP_1 + num - 1);
		return;
	}
	while (num) {
		buf[len++] = num & 0xff;
		num >>= 8;
	}
	if (buf[len - 1] & 0x80)
		buf[len++] = 0;
	push(s, buf, len);
}

static void push_xonly(u8 **s, const struct pubkey *key)
{
	u8 x[32];
	pubkey_to_xonly(key, x);
	push(s, x, sizeof(x));
}

/* The 64-bit opcodes' operand: 8 bytes, little-endian, two's complement. */
static void le8s(s64 v, u8 out[8])
{
	le64 le = cpu_to_le64((u64)v);
	memcpy(out, &le, 8);
}

void sym_channel_init(struct sym_channel *sc,
		      const struct bitcoin_blkid *genesis,
		      const struct bitcoin_outpoint *funding,
		      const struct pubkey *opener_upd_key,
		      const struct pubkey *accepter_upd_key,
		      const u8 *asset_tag, u16 delay)
{
	struct sha256_ctx sctx;
	le32 vout = cpu_to_le32(funding->n);

	sha256_init(&sctx);
	sha256_update(&sctx, SYM_TAG_PREFIX, strlen(SYM_TAG_PREFIX));
	sha256_update(&sctx, genesis->shad.sha.u.u8, 32);
	sha256_update(&sctx, funding->txid.shad.sha.u.u8, 32);
	sha256_update(&sctx, &vout, sizeof(vout));
	sha256_done(&sctx, &sc->tag);

	sc->upd_key[SYM_OPENER] = *opener_upd_key;
	sc->upd_key[SYM_ACCEPTER] = *accepter_upd_key;
	if (!asset_tag)
		asset_tag = chainparams->fee_asset_tag;
	assert(asset_tag && asset_tag[0] == 0x01);
	memcpy(sc->asset, asset_tag, sizeof(sc->asset));
	sc->delay = delay;
}

s64 sym_state_num(u64 commitment_index, bool opener)
{
	assert(commitment_index < (1ULL << 61));
	return (s64)(commitment_index * 2 + (opener ? 0 : 1));
}

u8 *sym_leaf_upd(const tal_t *ctx, const struct sym_channel *sc, s64 k)
{
	u8 *s = tal_arr(ctx, u8, 0);
	u8 kb[8];

	le8s(k, kb);
	/* n > k */
	op(&s, OP_OVER);
	push(&s, kb, sizeof(kb));
	op(&s, SYM_OP_GREATERTHAN64);
	op(&s, OP_VERIFY);
	/* P: the v1 program at this input's index. */
	op(&s, SYM_OP_PUSHCURRENTINPUTINDEX);
	op(&s, SYM_OP_INSPECTOUTPUTSCRIPTPUBKEY);
	op(&s, OP_1);
	op(&s, OP_EQUALVERIFY);
	/* m = SHA256(tag || n || P || R) */
	op(&s, OP_ROT);
	op(&s, OP_SWAP);
	op(&s, SYM_OP_CAT);
	op(&s, OP_SWAP);
	op(&s, SYM_OP_CAT);
	push(&s, sc->tag.u.u8, sizeof(sc->tag.u.u8));
	op(&s, OP_SWAP);
	op(&s, SYM_OP_CAT);
	op(&s, OP_SHA256);
	/* Both signatures over m. */
	op(&s, OP_TUCK);
	push_xonly(&s, &sc->upd_key[SYM_OPENER]);
	op(&s, SYM_OP_CHECKSIGFROMSTACKVERIFY);
	push_xonly(&s, &sc->upd_key[SYM_ACCEPTER]);
	op(&s, SYM_OP_CHECKSIGFROMSTACKVERIFY);
	/* The output keeps this input's value... */
	op(&s, SYM_OP_PUSHCURRENTINPUTINDEX);
	op(&s, SYM_OP_INSPECTOUTPUTVALUE);
	op(&s, SYM_OP_PUSHCURRENTINPUTINDEX);
	op(&s, SYM_OP_INSPECTINPUTVALUE);
	op(&s, OP_ROT);
	op(&s, OP_EQUALVERIFY);
	op(&s, OP_EQUALVERIFY);
	/* ...and its asset. */
	op(&s, SYM_OP_PUSHCURRENTINPUTINDEX);
	op(&s, SYM_OP_INSPECTOUTPUTASSET);
	op(&s, SYM_OP_PUSHCURRENTINPUTINDEX);
	op(&s, SYM_OP_INSPECTINPUTASSET);
	op(&s, OP_ROT);
	op(&s, OP_EQUALVERIFY);
	op(&s, OP_EQUAL);
	return s;
}

/* A segwit scriptPubKey's version and program. */
static void witness_program(const u8 *spk, u8 *version, const u8 **prog,
			    size_t *proglen)
{
	size_t len = tal_bytelen(spk);

	assert(len >= 4 && spk[1] == len - 2);
	assert(spk[0] == OP_0 || (spk[0] >= OP_1 && spk[0] <= OP_16));
	*version = spk[0] == OP_0 ? 0 : spk[0] - OP_1 + 1;
	*prog = spk + 2;
	*proglen = len - 2;
}

void sym_settle_digest(const struct sym_channel *sc,
		       const struct sym_output *outs, struct sha256 *digest)
{
	struct sha256_ctx sctx;

	sha256_init(&sctx);
	for (size_t i = 0; i < tal_count(outs); i++) {
		u8 one = 0x01, version;
		le64 v = cpu_to_le64(outs[i].amount.satoshis); /* Raw: script operand */
		const u8 *prog;
		size_t proglen;
		struct sha256_ctx pctx;
		struct sha256 ph;

		sha256_update(&sctx, sc->asset + 1, 32);
		sha256_update(&sctx, &one, 1);
		sha256_update(&sctx, &v, sizeof(v));
		sha256_update(&sctx, &one, 1);
		witness_program(outs[i].spk, &version, &prog, &proglen);
		sha256_init(&pctx);
		sha256_update(&pctx, prog, proglen);
		/* The introspected version is a script number: v0 is empty. */
		if (version)
			sha256_update(&pctx, &version, 1);
		sha256_done(&pctx, &ph);
		sha256_update(&sctx, ph.u.u8, sizeof(ph.u.u8));
	}
	sha256_done(&sctx, digest);
}

u8 *sym_leaf_settle(const tal_t *ctx, const struct sym_channel *sc,
		    const struct sym_output *outs)
{
	u8 *s = tal_arr(ctx, u8, 0);
	size_t m = tal_count(outs);
	struct sha256 digest;

	assert(m >= 1);
	push_num(&s, sc->delay);
	op(&s, OP_CHECKSEQUENCEVERIFY);
	op(&s, OP_DROP);
	for (size_t i = 0; i < m; i++) {
		push_num(&s, i);
		op(&s, SYM_OP_INSPECTOUTPUTASSET);
		op(&s, SYM_OP_CAT);
		op(&s, i == 0 ? SYM_OP_SHA256INITIALIZE : SYM_OP_SHA256UPDATE);
		push_num(&s, i);
		op(&s, SYM_OP_INSPECTOUTPUTVALUE);
		op(&s, SYM_OP_CAT);
		op(&s, SYM_OP_SHA256UPDATE);
		push_num(&s, i);
		op(&s, SYM_OP_INSPECTOUTPUTSCRIPTPUBKEY);
		op(&s, SYM_OP_CAT);
		op(&s, OP_SHA256);
		op(&s, i == m - 1 ? SYM_OP_SHA256FINALIZE : SYM_OP_SHA256UPDATE);
	}
	sym_settle_digest(sc, outs, &digest);
	push(&s, digest.u.u8, sizeof(digest.u.u8));
	op(&s, OP_EQUAL);
	return s;
}

u8 *sym_leaf_htlc_success(const tal_t *ctx,
			  const struct ripemd160 *payment_ripemd,
			  const struct pubkey *receiver_key)
{
	u8 *s = tal_arr(ctx, u8, 0);

	op(&s, OP_SIZE);
	push_num(&s, 32);
	op(&s, OP_EQUALVERIFY);
	op(&s, OP_HASH160);
	push(&s, payment_ripemd->u.u8, sizeof(payment_ripemd->u.u8));
	op(&s, OP_EQUALVERIFY);
	push_xonly(&s, receiver_key);
	op(&s, OP_CHECKSIG);
	return s;
}

u8 *sym_leaf_htlc_timeout(const tal_t *ctx,
			  const struct pubkey *offerer_key, u32 cltv_expiry)
{
	u8 *s = tal_arr(ctx, u8, 0);

	push_xonly(&s, offerer_key);
	op(&s, OP_CHECKSIGVERIFY);
	push_num(&s, cltv_expiry);
	op(&s, OP_CHECKLOCKTIMEVERIFY);
	return s;
}

static void nums_key(struct pubkey *nums)
{
	if (!pubkey_from_der(nums_der, sizeof(nums_der), nums))
		abort();
}

void sym_htlc_tree(const tal_t *ctx,
		   const struct pubkey *offerer_key,
		   const struct pubkey *receiver_key,
		   const struct ripemd160 *payment_ripemd,
		   u32 cltv_expiry, struct tap_tree2 *tree)
{
	tree->nleaves = 2;
	tree->leaf[SYM_HTLC_LEAF_SUCCESS]
		= sym_leaf_htlc_success(ctx, payment_ripemd, receiver_key);
	tree->leaf[SYM_HTLC_LEAF_TIMEOUT]
		= sym_leaf_htlc_timeout(ctx, offerer_key, cltv_expiry);
	nums_key(&tree->internal_key);
	tap_tree2_finish(tree);
}

static void tweak_nums(const struct sha256 *root, u8 output_der[PUBKEY_CMPR_LEN])
{
	if (wally_ec_public_key_bip341_tweak(nums_der, sizeof(nums_der),
					     root->u.u8, sizeof(root->u.u8),
					     EC_FLAG_ELEMENTS, output_der,
					     PUBKEY_CMPR_LEN) != WALLY_OK)
		abort();
}

void sym_state_tree(const tal_t *ctx, const struct sym_channel *sc, s64 n,
		    const struct sym_output *outs, const u8 *sim_cmr,
		    struct sym_tree *tree)
{
	tree->n = n;
	tree->upd = sym_leaf_upd(ctx, sc, n);
	tree->settle = sym_leaf_settle(ctx, sc, outs);
	tap_leaf_hash(tree->upd, &tree->upd_hash);
	tap_leaf_hash(tree->settle, &tree->settle_hash);
	tree->has_sim = (sim_cmr != NULL);
	if (tree->has_sim) {
		tap_leaf_hash_version(SIMPLICITY_LEAF_VERSION_ELEMENTS,
				      sim_cmr, 32, &tree->sim_hash);
		tap_branch_hash(&tree->settle_hash, &tree->sim_hash,
				&tree->rest);
	} else
		tree->rest = tree->settle_hash;
	tap_branch_hash(&tree->upd_hash, &tree->rest, &tree->merkle_root);
	tweak_nums(&tree->merkle_root, tree->output_der);
}

void sym_kickoff_tree(const tal_t *ctx, const struct sym_channel *sc,
		      struct sym_tree *tree)
{
	tree->n = -1;
	tree->upd = sym_leaf_upd(ctx, sc, -1);
	tree->settle = NULL;
	tree->has_sim = false;
	tap_leaf_hash(tree->upd, &tree->upd_hash);
	tree->merkle_root = tree->upd_hash;
	memset(&tree->rest, 0, sizeof(tree->rest));
	memset(&tree->settle_hash, 0, sizeof(tree->settle_hash));
	tweak_nums(&tree->merkle_root, tree->output_der);
}

void sym_rebuild_state(const tal_t *ctx, const struct sym_channel *sc, s64 k,
		       const struct sha256 *rest, u8 **spk, u8 **upd_leaf,
		       u8 **upd_cb)
{
	struct sym_tree tree;

	tree.n = k;
	tree.upd = sym_leaf_upd(ctx, sc, k);
	tree.settle = NULL;
	tree.has_sim = false;
	tap_leaf_hash(tree.upd, &tree.upd_hash);
	tree.rest = *rest;
	tap_branch_hash(&tree.upd_hash, &tree.rest, &tree.merkle_root);
	tweak_nums(&tree.merkle_root, tree.output_der);
	*spk = sym_tree_spk(ctx, &tree);
	*upd_leaf = tree.upd;
	*upd_cb = sym_tree_control_block(ctx, &tree, SYM_LEAF_UPD);
}

void sym_tree_program(const struct sym_tree *tree, u8 program[32])
{
	memcpy(program, tree->output_der + 1, 32);
}

u8 *sym_tree_spk(const tal_t *ctx, const struct sym_tree *tree)
{
	u8 *spk = tal_arr(ctx, u8, BITCOIN_SCRIPTPUBKEY_P2TR_LEN);

	spk[0] = OP_1;
	spk[1] = 32;
	sym_tree_program(tree, spk + 2);
	return spk;
}

u8 *sym_tree_control_block(const tal_t *ctx, const struct sym_tree *tree,
			   int leaf)
{
	u8 *cb = tal_arr(ctx, u8, 33);
	u8 parity = tree->output_der[0] == SECP256K1_TAG_PUBKEY_ODD ? 1 : 0;

	cb[0] = (leaf == SYM_LEAF_SIM ? SIMPLICITY_LEAF_VERSION_ELEMENTS
		 : TAPSCRIPT_LEAF_VERSION_ELEMENTS) | parity;
	memcpy(cb + 1, nums_der + 1, 32);
	/* KO: UPD alone, no path. */
	if (tree->n == -1) {
		assert(leaf == SYM_LEAF_UPD);
		return cb;
	}
	switch (leaf) {
	case SYM_LEAF_UPD:
		tal_resize(&cb, 65);
		memcpy(cb + 33, tree->rest.u.u8, 32);
		break;
	case SYM_LEAF_SETTLE:
		if (tree->has_sim) {
			tal_resize(&cb, 97);
			memcpy(cb + 33, tree->sim_hash.u.u8, 32);
			memcpy(cb + 65, tree->upd_hash.u.u8, 32);
		} else {
			tal_resize(&cb, 65);
			memcpy(cb + 33, tree->upd_hash.u.u8, 32);
		}
		break;
	case SYM_LEAF_SIM:
		assert(tree->has_sim);
		tal_resize(&cb, 97);
		memcpy(cb + 33, tree->settle_hash.u.u8, 32);
		memcpy(cb + 65, tree->upd_hash.u.u8, 32);
		break;
	default:
		abort();
	}
	return cb;
}

void sym_upd_msg(const struct sym_channel *sc, const struct sym_tree *tree,
		 struct sha256 *msg)
{
	struct sha256_ctx sctx;
	u8 nb[8], prog[32];

	assert(tree->n >= 0);
	le8s(tree->n, nb);
	sym_tree_program(tree, prog);
	sha256_init(&sctx);
	sha256_update(&sctx, sc->tag.u.u8, sizeof(sc->tag.u.u8));
	sha256_update(&sctx, nb, sizeof(nb));
	sha256_update(&sctx, prog, sizeof(prog));
	sha256_update(&sctx, tree->rest.u.u8, sizeof(tree->rest.u.u8));
	sha256_done(&sctx, msg);
}

u8 **sym_update_witness(const tal_t *ctx,
			const struct bip340sig *sig_opener,
			const struct bip340sig *sig_accepter,
			const struct sym_tree *tree,
			const u8 *prev_leaf, const u8 *prev_cb)
{
	u8 **w = tal_arr(ctx, u8 *, 6);
	u8 nb[8];

	le8s(tree->n, nb);
	w[0] = tal_dup_arr(w, u8, sig_accepter->u8, 64, 0);
	w[1] = tal_dup_arr(w, u8, sig_opener->u8, 64, 0);
	w[2] = tal_dup_arr(w, u8, nb, 8, 0);
	w[3] = tal_dup_arr(w, u8, tree->rest.u.u8, 32, 0);
	w[4] = tal_dup_talarr(w, u8, prev_leaf);
	w[5] = tal_dup_talarr(w, u8, prev_cb);
	return w;
}

u8 **sym_settle_witness(const tal_t *ctx, const struct sym_tree *tree)
{
	u8 **w = tal_arr(ctx, u8 *, 2);

	w[0] = tal_dup_talarr(w, u8, tree->settle);
	w[1] = sym_tree_control_block(w, tree, SYM_LEAF_SETTLE);
	return w;
}

bool sym_parse_update_witness(const u8 **wit, s64 *n, struct sha256 *rest)
{
	le64 le;

	if (tal_count(wit) != 6
	    || tal_bytelen(wit[0]) != 64 || tal_bytelen(wit[1]) != 64
	    || tal_bytelen(wit[2]) != 8 || tal_bytelen(wit[3]) != 32)
		return false;
	memcpy(&le, wit[2], 8);
	*n = (s64)le64_to_cpu(le);
	memcpy(rest->u.u8, wit[3], 32);
	return true;
}

struct bitcoin_tx *sym_kickoff_tx(const tal_t *ctx,
				  const struct chainparams *chainparams,
				  const struct bitcoin_outpoint *funding,
				  struct amount_sat funding_sats,
				  const u8 *funding_wscript,
				  const struct sym_channel *sc)
{
	struct bitcoin_tx *tx = bitcoin_tx(ctx, chainparams, 1, 2, 0);
	struct sym_tree ko;

	sym_kickoff_tree(tmpctx, sc, &ko);
	bitcoin_tx_set_output_asset(tx, sc->asset);
	bitcoin_tx_add_output(tx, sym_tree_spk(tmpctx, &ko), NULL,
			      funding_sats);
	bitcoin_tx_add_input(tx, funding, SYM_SEQUENCE, NULL, funding_sats,
			     NULL, funding_wscript);
	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}

u8 **sym_kickoff_witness(const tal_t *ctx,
			 const struct bitcoin_signature *sig_a,
			 const struct pubkey *key_a,
			 const struct bitcoin_signature *sig_b,
			 const struct pubkey *key_b)
{
	return bitcoin_witness_2of2(ctx, sig_a, sig_b, key_a, key_b);
}

/* Settlement outputs, sorted as BIP69 with expiry last. */
static int cmp_output(const struct sym_output *a, const struct sym_output *b,
		      void *unused)
{
	size_t la = tal_bytelen(a->spk), lb = tal_bytelen(b->spk);
	int c;

	if (amount_sat_less(a->amount, b->amount))
		return -1;
	if (amount_sat_greater(a->amount, b->amount))
		return 1;
	c = memcmp(a->spk, b->spk, la < lb ? la : lb);
	if (c)
		return c;
	if (la != lb)
		return la < lb ? -1 : 1;
	if (a->cltv_expiry != b->cltv_expiry)
		return a->cltv_expiry < b->cltv_expiry ? -1 : 1;
	return 0;
}

struct sym_output *sym_settlement(const tal_t *ctx,
				  struct amount_sat funding_sats,
				  enum side opener,
				  const struct pubkey payment_basepoint[NUM_SIDES],
				  const struct pubkey htlc_basepoint[NUM_SIDES],
				  const struct amount_msat balance[NUM_SIDES],
				  const struct sym_htlc *htlcs,
				  struct amount_sat dust_limit,
				  const char **err)
{
	struct sym_output *outs = tal_arr(ctx, struct sym_output, 0);
	struct amount_msat bal[NUM_SIDES] = { balance[0], balance[1] };
	struct amount_sat total = AMOUNT_SAT(0), node[NUM_SIDES], left;

	for (size_t i = 0; i < tal_count(htlcs); i++) {
		struct amount_sat amt
			= amount_msat_to_sat_round_down(htlcs[i].amount);
		struct amount_msat rem;
		struct sym_output o;
		struct tap_tree2 tree;
		enum side owner = htlcs[i].owner;

		if (amount_sat_less(amt, dust_limit)) {
			/* Trimmed: its value stays with whoever offered it. */
			if (!amount_msat_accumulate(&bal[owner], htlcs[i].amount))
				goto overflow;
			continue;
		}
		/* What the output's whole atoms leave stays with the offerer. */
		if (!amount_msat_sub_sat(&rem, htlcs[i].amount, amt)
		    || !amount_msat_accumulate(&bal[owner], rem))
			goto overflow;
		sym_htlc_tree(tmpctx, &htlc_basepoint[owner],
			      &htlc_basepoint[!owner],
			      &htlcs[i].payment_ripemd,
			      htlcs[i].cltv_expiry, &tree);
		o.kind = SYM_OUT_HTLC;
		o.side = owner;
		o.amount = amt;
		o.spk = tap_tree2_scriptpubkey(outs, &tree);
		o.htlc = htlcs[i].handle;
		o.cltv_expiry = htlcs[i].cltv_expiry;
		tal_arr_expand(&outs, o);
		if (!amount_sat_add(&total, total, amt))
			goto overflow;
	}

	for (enum side s = 0; s < NUM_SIDES; s++) {
		node[s] = amount_msat_to_sat_round_down(bal[s]);
		if (!amount_sat_add(&total, total, node[s]))
			goto overflow;
	}
	if (!amount_sat_sub(&left, funding_sats, total)) {
		*err = "state pays more than the funding";
		return tal_free(outs);
	}
	/* msat rounding leaves a few atoms: the opener's. */
	if (!amount_sat_add(&node[opener], node[opener], left))
		goto overflow;
	/* A balance below the dust limit is no output: the other side's. */
	for (enum side s = 0; s < NUM_SIDES; s++) {
		if (!amount_sat_eq(node[s], AMOUNT_SAT(0))
		    && amount_sat_less(node[s], dust_limit)
		    && amount_sat_greater_eq(node[!s], node[s])) {
			if (!amount_sat_add(&node[!s], node[!s], node[s]))
				goto overflow;
			node[s] = AMOUNT_SAT(0);
		}
	}
	for (enum side s = 0; s < NUM_SIDES; s++) {
		struct sym_output o;

		if (amount_sat_eq(node[s], AMOUNT_SAT(0)))
			continue;
		o.kind = SYM_OUT_BALANCE;
		o.side = s;
		o.amount = node[s];
		o.spk = scriptpubkey_p2wpkh(outs, &payment_basepoint[s]);
		o.htlc = NULL;
		o.cltv_expiry = 0;
		tal_arr_expand(&outs, o);
	}
	if (tal_count(outs) == 0) {
		*err = "state pays nothing";
		return tal_free(outs);
	}
	asort(outs, tal_count(outs), cmp_output, NULL);
	return outs;

overflow:
	*err = "overflow building the settlement";
	return tal_free(outs);
}
