#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <ccan/endian/endian.h>
#include <common/keyset.h>
#include <common/tcov_scripts.h>
#include <common/utils.h>
#include <wally_script.h>

/* The Elements opcodes the leaves use, beyond Bitcoin's. */
#define TCOV_OP_INSPECTINPUTASSET 0xc8
#define TCOV_OP_INSPECTINPUTVALUE 0xc9
#define TCOV_OP_PUSHCURRENTINPUTINDEX 0xcd
#define TCOV_OP_INSPECTOUTPUTASSET 0xce
#define TCOV_OP_INSPECTOUTPUTVALUE 0xcf
#define TCOV_OP_INSPECTOUTPUTSCRIPTPUBKEY 0xd1
#define TCOV_OP_GREATERTHANOREQUAL64 0xdf
#define TCOV_OP_ECMULSCALARVERIFY 0xe3

/* secp256k1's generator, compressed. */
static const u8 generator_der[PUBKEY_CMPR_LEN] = {
	0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
	0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
	0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
};

static void op(u8 **s, u8 opcode)
{
	tal_arr_expand(s, opcode);
}

static void push(u8 **s, const void *mem, size_t len)
{
	script_push_bytes(s, mem, len);
}

/* A positive script number, minimally encoded. */
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
	/* The top bit is the sign: keep the number positive. */
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

static void push_der(u8 **s, const struct pubkey *key)
{
	u8 der[PUBKEY_CMPR_LEN];
	pubkey_to_der(der, key);
	push(s, der, sizeof(der));
}

static void push_le8(u8 **s, struct amount_sat amt)
{
	le64 v = cpu_to_le64(amt.satoshis); /* Raw: an 8-byte script operand */
	push(s, &v, sizeof(v));
}

const u8 *tcov_asset_id(const u8 *asset_tag)
{
	if (!asset_tag)
		asset_tag = chainparams->fee_asset_tag;
	assert(asset_tag && asset_tag[0] == 0x01);
	return asset_tag + 1;
}

/* COV(A, X, D) */
static void add_cov(u8 **s, const u8 *asset_id, struct amount_sat x,
		    const u8 d_program[32])
{
	op(s, TCOV_OP_PUSHCURRENTINPUTINDEX);
	op(s, OP_DUP);
	op(s, OP_DUP);
	op(s, TCOV_OP_INSPECTOUTPUTASSET);
	op(s, OP_1);
	op(s, OP_EQUALVERIFY);
	push(s, asset_id, 32);
	op(s, OP_EQUALVERIFY);
	op(s, TCOV_OP_INSPECTOUTPUTVALUE);
	op(s, OP_1);
	op(s, OP_EQUALVERIFY);
	push_le8(s, x);
	op(s, TCOV_OP_GREATERTHANOREQUAL64);
	op(s, OP_VERIFY);
	op(s, TCOV_OP_INSPECTOUTPUTSCRIPTPUBKEY);
	op(s, OP_1);
	op(s, OP_EQUALVERIFY);
	push(s, d_program, 32);
	op(s, OP_EQUAL);
}

/* KEEP(S) */
static void add_keep(u8 **s, const u8 *dest_spk)
{
	size_t len = tal_bytelen(dest_spk);
	u8 version;

	/* A segwit program: OP_0 or OP_1..OP_16, then a push of the rest. */
	assert(len >= 4 && dest_spk[1] == len - 2);
	assert(dest_spk[0] == OP_0 || (dest_spk[0] >= OP_1 && dest_spk[0] <= OP_16));
	version = dest_spk[0];

	op(s, TCOV_OP_PUSHCURRENTINPUTINDEX);
	op(s, OP_DUP);
	op(s, TCOV_OP_INSPECTOUTPUTASSET);
	op(s, OP_1);
	op(s, OP_EQUALVERIFY);
	op(s, OP_OVER);
	op(s, TCOV_OP_INSPECTINPUTASSET);
	op(s, OP_1);
	op(s, OP_EQUALVERIFY);
	op(s, OP_EQUALVERIFY);
	op(s, OP_DUP);
	op(s, TCOV_OP_INSPECTOUTPUTVALUE);
	op(s, OP_1);
	op(s, OP_EQUALVERIFY);
	op(s, OP_OVER);
	op(s, TCOV_OP_INSPECTINPUTVALUE);
	op(s, OP_1);
	op(s, OP_EQUALVERIFY);
	op(s, TCOV_OP_GREATERTHANOREQUAL64);
	op(s, OP_VERIFY);
	op(s, TCOV_OP_INSPECTOUTPUTSCRIPTPUBKEY);
	/* The introspected version is a script number: OP_0 pushes v0's,
	 * OP_1..OP_16 the others. */
	op(s, version);
	op(s, OP_EQUALVERIFY);
	push(s, dest_spk + 2, len - 2);
	op(s, OP_EQUAL);
}

u8 *tcov_leaf_delay(const tal_t *ctx, const struct pubkey *delayed_key,
		    u16 to_self_delay)
{
	u8 *s = tal_arr(ctx, u8, 0);

	push_xonly(&s, delayed_key);
	op(&s, OP_CHECKSIGVERIFY);
	push_num(&s, to_self_delay);
	op(&s, OP_CHECKSEQUENCEVERIFY);
	return s;
}

u8 *tcov_leaf_revoke(const tal_t *ctx,
		     const struct pubkey *per_commitment_point,
		     const u8 *dest_spk)
{
	u8 *s = tal_arr(ctx, u8, 0);

	/* Witness <secret>: [secret pcp G] -> OP_ROT -> [pcp G secret]:
	 * OP_ECMULSCALARVERIFY checks pcp == secret * G, secret 32 bytes. */
	push_der(&s, per_commitment_point);
	push(&s, generator_der, sizeof(generator_der));
	op(&s, OP_ROT);
	op(&s, TCOV_OP_ECMULSCALARVERIFY);
	add_keep(&s, dest_spk);
	return s;
}

u8 *tcov_leaf_offered_timeout(const tal_t *ctx,
			      const struct pubkey *self_htlc_key,
			      u32 cltv_expiry, const u8 *asset_id,
			      struct amount_sat x, const u8 d_program[32])
{
	u8 *s = tal_arr(ctx, u8, 0);

	push_xonly(&s, self_htlc_key);
	op(&s, OP_CHECKSIGVERIFY);
	push_num(&s, cltv_expiry);
	op(&s, OP_CHECKLOCKTIMEVERIFY);
	op(&s, OP_DROP);
	add_cov(&s, asset_id, x, d_program);
	return s;
}

static void add_hashlock(u8 **s, const struct ripemd160 *payment_ripemd)
{
	op(s, OP_SIZE);
	push_num(s, 32);
	op(s, OP_EQUALVERIFY);
	op(s, OP_HASH160);
	push(s, payment_ripemd->u.u8, sizeof(payment_ripemd->u.u8));
	op(s, OP_EQUALVERIFY);
}

/* The point lock: witness <t>, [t L G] -> OP_ROT -> [L G t]:
 * OP_ECMULSCALARVERIFY checks L == t * G, t 32 bytes (the opcode refuses any
 * other size), L with its parity. */
static void add_pointlock(u8 **s, const struct pubkey *lock_point)
{
	push_der(s, lock_point);
	push(s, generator_der, sizeof(generator_der));
	op(s, OP_ROT);
	op(s, TCOV_OP_ECMULSCALARVERIFY);
}

u8 *tcov_leaf_offered_success_point(const tal_t *ctx,
				    const struct pubkey *lock_point,
				    const struct pubkey *other_htlc_key)
{
	u8 *s = tal_arr(ctx, u8, 0);

	add_pointlock(&s, lock_point);
	push_xonly(&s, other_htlc_key);
	op(&s, OP_CHECKSIG);
	return s;
}

u8 *tcov_leaf_received_success_point(const tal_t *ctx,
				     const struct pubkey *lock_point,
				     const struct pubkey *self_htlc_key,
				     const u8 *asset_id,
				     struct amount_sat x,
				     const u8 d_program[32])
{
	u8 *s = tal_arr(ctx, u8, 0);

	add_pointlock(&s, lock_point);
	push_xonly(&s, self_htlc_key);
	op(&s, OP_CHECKSIGVERIFY);
	add_cov(&s, asset_id, x, d_program);
	return s;
}

u8 *tcov_leaf_offered_success(const tal_t *ctx,
			      const struct ripemd160 *payment_ripemd,
			      const struct pubkey *other_htlc_key)
{
	u8 *s = tal_arr(ctx, u8, 0);

	add_hashlock(&s, payment_ripemd);
	push_xonly(&s, other_htlc_key);
	op(&s, OP_CHECKSIG);
	return s;
}

u8 *tcov_leaf_received_success(const tal_t *ctx,
			       const struct ripemd160 *payment_ripemd,
			       const struct pubkey *self_htlc_key,
			       const u8 *asset_id,
			       struct amount_sat x, const u8 d_program[32])
{
	u8 *s = tal_arr(ctx, u8, 0);

	add_hashlock(&s, payment_ripemd);
	push_xonly(&s, self_htlc_key);
	op(&s, OP_CHECKSIGVERIFY);
	add_cov(&s, asset_id, x, d_program);
	return s;
}

u8 *tcov_leaf_received_timeout(const tal_t *ctx,
			       const struct pubkey *other_htlc_key,
			       u32 cltv_expiry)
{
	u8 *s = tal_arr(ctx, u8, 0);

	push_xonly(&s, other_htlc_key);
	op(&s, OP_CHECKSIGVERIFY);
	push_num(&s, cltv_expiry);
	op(&s, OP_CHECKLOCKTIMEVERIFY);
	return s;
}

u8 *tcov_revoke_dest(const tal_t *ctx, const struct keyset *keyset)
{
	/* Under option_static_remotekey, other_payment_key is other's
	 * payment basepoint itself: the script its to_remote output pays. */
	return scriptpubkey_p2wpkh(ctx, &keyset->other_payment_key);
}

void tcov_to_local_tree(const tal_t *ctx,
			const struct keyset *keyset,
			const struct pubkey *per_commitment_point,
			u16 to_self_delay,
			struct tap_tree2 *tree)
{
	tree->internal_key = keyset->self_revocation_key;
	tree->leaf[TCOV_LEAF_DELAY]
		= tcov_leaf_delay(ctx, &keyset->self_delayed_payment_key,
				  to_self_delay);
	tree->leaf[TCOV_LEAF_REVOKE]
		= tcov_leaf_revoke(ctx, per_commitment_point,
				   tcov_revoke_dest(tmpctx, keyset));
	tree->nleaves = 2;
	tap_tree2_finish(tree);
}

void tcov_offered_htlc_tree(const tal_t *ctx,
			    const struct keyset *keyset,
			    const struct pubkey *per_commitment_point,
			    u16 to_self_delay,
			    const u8 *asset_tag,
			    const struct ripemd160 *payment_ripemd,
			    const struct pubkey *lock_point,
			    u32 cltv_expiry,
			    struct amount_sat htlc_sats,
			    struct tap_tree2 *tree)
{
	struct tap_tree2 d;
	u8 d_program[32];

	tcov_to_local_tree(tmpctx, keyset, per_commitment_point,
			   to_self_delay, &d);
	tap_tree2_program(&d, d_program);

	tree->internal_key = keyset->self_revocation_key;
	tree->leaf[TCOV_LEAF_OFFERED_TIMEOUT]
		= tcov_leaf_offered_timeout(ctx, &keyset->self_htlc_key,
					    cltv_expiry,
					    tcov_asset_id(asset_tag),
					    htlc_sats, d_program);
	if (lock_point)
		tree->leaf[TCOV_LEAF_OFFERED_SUCCESS]
			= tcov_leaf_offered_success_point(ctx, lock_point,
							  &keyset->other_htlc_key);
	else
		tree->leaf[TCOV_LEAF_OFFERED_SUCCESS]
			= tcov_leaf_offered_success(ctx, payment_ripemd,
						    &keyset->other_htlc_key);
	tree->nleaves = 2;
	tap_tree2_finish(tree);
}

void tcov_received_htlc_tree(const tal_t *ctx,
			     const struct keyset *keyset,
			     const struct pubkey *per_commitment_point,
			     u16 to_self_delay,
			     const u8 *asset_tag,
			     const struct ripemd160 *payment_ripemd,
			     const struct pubkey *lock_point,
			     u32 cltv_expiry,
			     struct amount_sat htlc_sats,
			     struct tap_tree2 *tree)
{
	struct tap_tree2 d;
	u8 d_program[32];

	tcov_to_local_tree(tmpctx, keyset, per_commitment_point,
			   to_self_delay, &d);
	tap_tree2_program(&d, d_program);

	tree->internal_key = keyset->self_revocation_key;
	if (lock_point)
		tree->leaf[TCOV_LEAF_RECEIVED_SUCCESS]
			= tcov_leaf_received_success_point(ctx, lock_point,
							   &keyset->self_htlc_key,
							   tcov_asset_id(asset_tag),
							   htlc_sats, d_program);
	else
		tree->leaf[TCOV_LEAF_RECEIVED_SUCCESS]
			= tcov_leaf_received_success(ctx, payment_ripemd,
						     &keyset->self_htlc_key,
						     tcov_asset_id(asset_tag),
						     htlc_sats, d_program);
	tree->leaf[TCOV_LEAF_RECEIVED_TIMEOUT]
		= tcov_leaf_received_timeout(ctx, &keyset->other_htlc_key,
					     cltv_expiry);
	tree->nleaves = 2;
	tap_tree2_finish(tree);
}
