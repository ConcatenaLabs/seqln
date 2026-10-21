#include "config.h"
#include <assert.h>
#include <bitcoin/script.h>
#include <ccan/endian/endian.h>
#include <common/channel_id.h>
#include <common/credit_scripts.h>
#include <common/keyset.h>
#include <common/tcov_scripts.h>
#include <common/utils.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <wally_script.h>

/* The Elements opcodes CLAIM uses, beyond Bitcoin's. */
#define CREDIT_OP_CHECKSIGFROMSTACKVERIFY 0xc2
#define CREDIT_OP_INSPECTINPUTASSET 0xc8
#define CREDIT_OP_INSPECTINPUTVALUE 0xc9
#define CREDIT_OP_INSPECTINPUTSCRIPTPUBKEY 0xca
#define CREDIT_OP_PUSHCURRENTINPUTINDEX 0xcd
#define CREDIT_OP_INSPECTOUTPUTASSET 0xce
#define CREDIT_OP_INSPECTOUTPUTVALUE 0xcf
#define CREDIT_OP_INSPECTOUTPUTSCRIPTPUBKEY 0xd1
#define CREDIT_OP_SUB64 0xd8
#define CREDIT_OP_GREATERTHAN64 0xde

/* BIP341's H: lift_x(0x50929b74...803ac0), whose discrete log nobody knows. */
static const u8 nums_der[PUBKEY_CMPR_LEN] = {
	0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b,
	0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28,
	0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
};

static void cop(u8 **s, u8 opcode)
{
	tal_arr_expand(s, opcode);
}

static void cpush(u8 **s, const void *mem, size_t len)
{
	script_push_bytes(s, mem, len);
}

static void cpush_le8(u8 **s, struct amount_sat amt)
{
	le64 v = cpu_to_le64(amt.satoshis); /* Raw: an 8-byte script operand */
	cpush(s, &v, sizeof(v));
}

/* tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg) */
static void tagged_hash(const char *tag, const void *msg, size_t len,
			struct sha256 *out)
{
	struct sha256 taghash;
	struct sha256_ctx sctx;

	sha256(&taghash, tag, strlen(tag));
	sha256_init(&sctx);
	sha256_update(&sctx, &taghash, sizeof(taghash));
	sha256_update(&sctx, &taghash, sizeof(taghash));
	sha256_update(&sctx, msg, len);
	sha256_done(&sctx, out);
}

void credit_tag(const struct channel_id *cid, struct sha256 *dtag)
{
	tagged_hash("SeqLN/credit", cid->id, sizeof(cid->id), dtag);
}

void credit_key_tweak(const struct pubkey *provider_funding_key,
		      struct sha256 *tweak)
{
	u8 der[PUBKEY_CMPR_LEN];

	pubkey_to_der(der, provider_funding_key);
	tagged_hash("SeqLN/credit-key", der, sizeof(der), tweak);
}

bool credit_key(const struct pubkey *provider_funding_key,
		struct pubkey *ck)
{
	struct sha256 tweak;

	credit_key_tweak(provider_funding_key, &tweak);
	*ck = *provider_funding_key;
	return secp256k1_ec_pubkey_tweak_add(secp256k1_ctx, &ck->pubkey,
					     tweak.u.u8) == 1;
}

void credit_note_msg(const struct sha256 *dtag, u64 c_atoms,
		     const struct sha256 *payment_hash, u8 msg[72])
{
	le64 c = cpu_to_le64(c_atoms);

	memcpy(msg, dtag->u.u8, 32);
	memcpy(msg + 32, &c, 8);
	memcpy(msg + 40, payment_hash->u.u8, 32);
}

bool credit_note_check(const struct sha256 *dtag,
		       const struct pubkey *ck,
		       u64 c_atoms, const struct sha256 *payment_hash,
		       const u8 sig[64])
{
	secp256k1_xonly_pubkey xonly;
	u8 msg[72];

	if (secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &xonly, NULL,
					       &ck->pubkey) != 1)
		return false;
	credit_note_msg(dtag, c_atoms, payment_hash, msg);
	return secp256k1_schnorrsig_verify(secp256k1_ctx, sig, msg,
					   sizeof(msg), &xonly) == 1;
}

u8 *credit_leaf_claim(const tal_t *ctx,
		      const struct sha256 *dtag,
		      const struct pubkey *ck,
		      struct amount_sat b,
		      const u8 *holder_spk)
{
	u8 *s = tal_arr(ctx, u8, 0);
	u8 xonly[32];
	size_t len = tal_bytelen(holder_spk);

	/* The holder's program: v0 (P2WPKH), as tcov_revoke_dest's. */
	assert(len == 22 && holder_spk[0] == OP_0 && holder_spk[1] == 20);
	pubkey_to_xonly(ck, xonly);

	/* sig c x -> sig c H */
	cop(&s, OP_SIZE);
	cop(&s, 0x01);
	cop(&s, 32);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, OP_SHA256);
	/* M = Dtag || c || H, checked against Pc */
	cop(&s, OP_OVER);
	cpush(&s, dtag->u.u8, sizeof(dtag->u.u8));
	cop(&s, OP_SWAP);
	cop(&s, OP_CAT);
	cop(&s, OP_SWAP);
	cop(&s, OP_CAT);
	cop(&s, OP_ROT);
	cop(&s, OP_SWAP);
	cpush(&s, xonly, sizeof(xonly));
	cop(&s, CREDIT_OP_CHECKSIGFROMSTACKVERIFY);
	/* paid = B - input value */
	cpush_le8(&s, b);
	cop(&s, CREDIT_OP_PUSHCURRENTINPUTINDEX);
	cop(&s, CREDIT_OP_INSPECTINPUTVALUE);
	cop(&s, OP_1);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, CREDIT_OP_SUB64);
	cop(&s, OP_VERIFY);
	/* c > paid; delta = c - paid */
	cop(&s, OP_2DUP);
	cop(&s, CREDIT_OP_GREATERTHAN64);
	cop(&s, OP_VERIFY);
	cop(&s, OP_OVER);
	cop(&s, OP_SWAP);
	cop(&s, CREDIT_OP_SUB64);
	cop(&s, OP_VERIFY);
	/* output i+1: value delta, program U, this input's asset */
	cop(&s, CREDIT_OP_PUSHCURRENTINPUTINDEX);
	cop(&s, OP_1ADD);
	cop(&s, OP_DUP);
	cop(&s, CREDIT_OP_INSPECTOUTPUTVALUE);
	cop(&s, OP_1);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, OP_ROT);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, OP_DUP);
	cop(&s, CREDIT_OP_INSPECTOUTPUTSCRIPTPUBKEY);
	cop(&s, OP_0);
	cop(&s, OP_EQUALVERIFY);
	cpush(&s, holder_spk + 2, len - 2);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, CREDIT_OP_INSPECTOUTPUTASSET);
	cop(&s, CREDIT_OP_PUSHCURRENTINPUTINDEX);
	cop(&s, CREDIT_OP_INSPECTINPUTASSET);
	cop(&s, OP_ROT);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, OP_EQUALVERIFY);
	/* rem = B - c */
	cpush_le8(&s, b);
	cop(&s, OP_SWAP);
	cop(&s, CREDIT_OP_SUB64);
	cop(&s, OP_VERIFY);
	/* output i: value rem, this input's own script and asset */
	cop(&s, CREDIT_OP_PUSHCURRENTINPUTINDEX);
	cop(&s, CREDIT_OP_INSPECTOUTPUTVALUE);
	cop(&s, OP_1);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, CREDIT_OP_PUSHCURRENTINPUTINDEX);
	cop(&s, CREDIT_OP_INSPECTOUTPUTSCRIPTPUBKEY);
	cop(&s, CREDIT_OP_PUSHCURRENTINPUTINDEX);
	cop(&s, CREDIT_OP_INSPECTINPUTSCRIPTPUBKEY);
	cop(&s, OP_ROT);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, CREDIT_OP_PUSHCURRENTINPUTINDEX);
	cop(&s, CREDIT_OP_INSPECTOUTPUTASSET);
	cop(&s, CREDIT_OP_PUSHCURRENTINPUTINDEX);
	cop(&s, CREDIT_OP_INSPECTINPUTASSET);
	cop(&s, OP_ROT);
	cop(&s, OP_EQUALVERIFY);
	cop(&s, OP_EQUAL);
	return s;
}

bool credit_params_init(const tal_t *ctx,
			const struct channel_id *cid,
			const struct pubkey *provider_funding_key,
			const struct pubkey *holder_payment_basepoint,
			struct credit_params *params)
{
	credit_tag(cid, &params->dtag);
	if (!credit_key(provider_funding_key, &params->credit_key))
		return false;
	params->holder_spk = scriptpubkey_p2wpkh(ctx, holder_payment_basepoint);
	params->folded = AMOUNT_SAT(0);
	return true;
}

static struct amount_sat credit_b(const struct credit_params *params,
				  struct amount_sat value)
{
	struct amount_sat b;

	if (!amount_sat_add(&b, value, params->folded))
		abort();
	return b;
}

void credit_to_local_tree(const tal_t *ctx,
			  const struct keyset *keyset,
			  const struct pubkey *per_commitment_point,
			  u16 to_self_delay,
			  const struct credit_params *params,
			  struct amount_sat value,
			  struct tap_tree2 *tree)
{
	tree->internal_key = keyset->self_revocation_key;
	tree->leaf[TCOV_LEAF_DELAY]
		= tcov_leaf_delay(ctx, &keyset->self_delayed_payment_key,
				  to_self_delay);
	tree->leaf[TCOV_LEAF_REVOKE]
		= tcov_leaf_revoke(ctx, per_commitment_point,
				   tcov_revoke_dest(tmpctx, keyset));
	tree->leaf[CREDIT_LEAF_CLAIM]
		= credit_leaf_claim(ctx, &params->dtag, &params->credit_key,
				    credit_b(params, value), params->holder_spk);
	tree->nleaves = 3;
	tap_tree2_finish(tree);
}

void credit_nums_key(struct pubkey *nums)
{
	if (!pubkey_from_der(nums_der, sizeof(nums_der), nums))
		abort();
}

void credit_to_remote_tree(const tal_t *ctx,
			   const struct pubkey *provider_payment_key,
			   u16 delay,
			   const struct credit_params *params,
			   struct amount_sat value,
			   struct tap_tree2 *tree)
{
	credit_nums_key(&tree->internal_key);
	tree->leaf[CREDIT_REMOTE_LEAF_CLAIM]
		= credit_leaf_claim(ctx, &params->dtag, &params->credit_key,
				    credit_b(params, value), params->holder_spk);
	tree->leaf[CREDIT_REMOTE_LEAF_PROVIDER]
		= tcov_leaf_delay(ctx, provider_payment_key, delay);
	tree->leaf[2] = NULL;
	tree->nleaves = 2;
	tap_tree2_finish(tree);
}
