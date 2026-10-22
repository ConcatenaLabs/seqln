#include "config.h"
#include <assert.h>
#include <bitcoin/script.h>
#include <bitcoin/tapscript.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/sym_factory.h>
#include <common/utils.h>
#include <wally_core.h>
#include <wally_script.h>
#include <wire/wire.h>

/* The Elements opcodes SPLIT uses, beyond Bitcoin's. */
#define SF_OP_CAT 0x7e
#define SF_OP_SHA256INITIALIZE 0xc4
#define SF_OP_SHA256UPDATE 0xc5
#define SF_OP_SHA256FINALIZE 0xc6
#define SF_OP_INSPECTOUTPUTASSET 0xce
#define SF_OP_INSPECTOUTPUTVALUE 0xcf
#define SF_OP_INSPECTOUTPUTSCRIPTPUBKEY 0xd1

/* A factory of one channel is a plain channel with extra steps; the wire
 * counts slots in 16 bits. */
#define SYM_FACTORY_MAX_SLOTS 1000

/* BIP341's H, as common/sym_scripts.c has it. */
static const u8 sf_nums_der[PUBKEY_CMPR_LEN] = {
	0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b,
	0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28,
	0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
};

static void sf_op(u8 **s, u8 opcode)
{
	tal_arr_expand(s, opcode);
}

/* A non-negative script number, minimally encoded. */
static void sf_push_num(u8 **s, u32 num)
{
	u8 buf[5];
	size_t len = 0;

	if (num == 0) {
		sf_op(s, OP_0);
		return;
	}
	if (num <= 16) {
		sf_op(s, OP_1 + num - 1);
		return;
	}
	while (num) {
		buf[len++] = num & 0xff;
		num >>= 8;
	}
	if (buf[len - 1] & 0x80)
		buf[len++] = 0;
	script_push_bytes(s, buf, len);
}

void sym_factory_id(const struct sym_factory *f, struct bitcoin_outpoint *id)
{
	id->txid = f->nonce;
	id->n = f->slot;
}

bool sym_factory_value(const struct sym_factory_slot *slots,
		       struct amount_sat *total)
{
	*total = AMOUNT_SAT(0);
	for (size_t i = 0; i < tal_count(slots); i++)
		if (!amount_sat_add(total, *total, slots[i].amount))
			return false;
	return true;
}

/* Each output as SETTLE hashes it (common/sym_scripts.c): asset || 0x01 ||
 * value, 8 bytes LE || 0x01 || SHA256(program || 0x01), the witness
 * version as the introspection opcode pushes it. */
void sym_split_digest(const u8 asset[33],
		      const struct sym_factory_slot *slots,
		      struct sha256 *digest)
{
	struct sha256_ctx sctx;

	sha256_init(&sctx);
	for (size_t i = 0; i < tal_count(slots); i++) {
		u8 one = 0x01;
		le64 v = cpu_to_le64(slots[i].amount.satoshis); /* Raw: script operand */
		struct sha256_ctx pctx;
		struct sha256 ph;

		sha256_update(&sctx, asset + 1, 32);
		sha256_update(&sctx, &one, 1);
		sha256_update(&sctx, &v, sizeof(v));
		sha256_update(&sctx, &one, 1);
		sha256_init(&pctx);
		sha256_update(&pctx, slots[i].program, 32);
		sha256_update(&pctx, &one, 1);
		sha256_done(&pctx, &ph);
		sha256_update(&sctx, ph.u.u8, sizeof(ph.u.u8));
	}
	sha256_done(&sctx, digest);
}

u8 *sym_leaf_split(const tal_t *ctx, const u8 asset[33],
		   const struct sym_factory_slot *slots)
{
	u8 *s = tal_arr(ctx, u8, 0);
	size_t m = tal_count(slots);
	struct sha256 digest;

	assert(m >= 1);
	for (size_t i = 0; i < m; i++) {
		sf_push_num(&s, i);
		sf_op(&s, SF_OP_INSPECTOUTPUTASSET);
		sf_op(&s, SF_OP_CAT);
		sf_op(&s, i == 0 ? SF_OP_SHA256INITIALIZE : SF_OP_SHA256UPDATE);
		sf_push_num(&s, i);
		sf_op(&s, SF_OP_INSPECTOUTPUTVALUE);
		sf_op(&s, SF_OP_CAT);
		sf_op(&s, SF_OP_SHA256UPDATE);
		sf_push_num(&s, i);
		sf_op(&s, SF_OP_INSPECTOUTPUTSCRIPTPUBKEY);
		sf_op(&s, SF_OP_CAT);
		sf_op(&s, OP_SHA256);
		sf_op(&s, i == m - 1 ? SF_OP_SHA256FINALIZE : SF_OP_SHA256UPDATE);
	}
	sym_split_digest(asset, slots, &digest);
	script_push_bytes(&s, digest.u.u8, sizeof(digest.u.u8));
	sf_op(&s, OP_EQUAL);
	return s;
}

/* F's output key: H tweaked by SPLIT's leaf hash, its only leaf. */
static void factory_key(const u8 asset[33],
			const struct sym_factory_slot *slots,
			u8 output_der[PUBKEY_CMPR_LEN], u8 **leaf)
{
	struct sha256 root;

	*leaf = sym_leaf_split(tmpctx, asset, slots);
	tap_leaf_hash(*leaf, &root);
	if (wally_ec_public_key_bip341_tweak(sf_nums_der, sizeof(sf_nums_der),
					     root.u.u8, sizeof(root.u.u8),
					     EC_FLAG_ELEMENTS, output_der,
					     PUBKEY_CMPR_LEN) != WALLY_OK)
		abort();
}

u8 *sym_factory_spk(const tal_t *ctx, const u8 asset[33],
		    const struct sym_factory_slot *slots)
{
	u8 der[PUBKEY_CMPR_LEN], *leaf;
	u8 *spk = tal_arr(ctx, u8, BITCOIN_SCRIPTPUBKEY_P2TR_LEN);

	factory_key(asset, slots, der, &leaf);
	spk[0] = OP_1;
	spk[1] = 32;
	memcpy(spk + 2, der + 1, 32);
	return spk;
}

u8 **sym_split_witness(const tal_t *ctx, const u8 asset[33],
		       const struct sym_factory_slot *slots)
{
	u8 der[PUBKEY_CMPR_LEN], *leaf;
	u8 **w = tal_arr(ctx, u8 *, 2);

	factory_key(asset, slots, der, &leaf);
	w[0] = tal_dup_talarr(w, u8, leaf);
	/* One leaf: the control block is the leaf version, parity and H. */
	w[1] = tal_arr(w, u8, 33);
	w[1][0] = TAPSCRIPT_LEAF_VERSION_ELEMENTS
		| (der[0] == SECP256K1_TAG_PUBKEY_ODD ? 1 : 0);
	memcpy(w[1] + 1, sf_nums_der + 1, 32);
	return w;
}

u8 *sym_factory_ko_spk(const tal_t *ctx, const struct sym_factory *f,
		       size_t slot)
{
	u8 *spk = tal_arr(ctx, u8, BITCOIN_SCRIPTPUBKEY_P2TR_LEN);

	assert(slot < tal_count(f->slots));
	spk[0] = OP_1;
	spk[1] = 32;
	memcpy(spk + 2, f->slots[slot].program, 32);
	return spk;
}

const char *sym_factory_check(const tal_t *ctx, const struct sym_factory *f,
			      const u8 own_ko_program[32],
			      struct amount_sat own_amount)
{
	struct amount_sat total;
	size_t n = tal_count(f->slots);

	if (n < 2 || n > SYM_FACTORY_MAX_SLOTS)
		return tal_fmt(ctx, "a factory of %zu slots", n);
	if (f->slot >= n)
		return tal_fmt(ctx, "slot %u of a factory of %zu", f->slot, n);
	if (f->asset[0] != 0x01)
		return tal_fmt(ctx, "the factory's asset is not explicit");
	if (!memeq(f->slots[f->slot].program, 32, own_ko_program, 32))
		return tal_fmt(ctx, "slot %u is not this channel's kickoff"
			       " output", f->slot);
	if (!amount_sat_eq(f->slots[f->slot].amount, own_amount))
		return tal_fmt(ctx, "slot %u pays %s, the channel is %s",
			       f->slot,
			       fmt_amount_sat(tmpctx, f->slots[f->slot].amount),
			       fmt_amount_sat(tmpctx, own_amount));
	for (size_t i = 0; i < n; i++)
		if (amount_sat_eq(f->slots[i].amount, AMOUNT_SAT(0)))
			return tal_fmt(ctx, "slot %zu pays nothing", i);
	if (!sym_factory_value(f->slots, &total)
	    || total.satoshis > (u64)INT64_MAX) /* Raw: script range */
		return tal_fmt(ctx, "the factory's value overflows");
	return NULL;
}

void towire_sym_factory(u8 **pptr, const struct sym_factory *f)
{
	towire_bitcoin_txid(pptr, &f->nonce);
	towire_u16(pptr, f->slot);
	towire_u8_array(pptr, f->asset, sizeof(f->asset));
	towire_bitcoin_outpoint(pptr, &f->out);
	towire_u16(pptr, tal_count(f->slots));
	for (size_t i = 0; i < tal_count(f->slots); i++) {
		towire_u8_array(pptr, f->slots[i].program, 32);
		towire_amount_sat(pptr, f->slots[i].amount);
	}
}

struct sym_factory *fromwire_sym_factory(const tal_t *ctx,
					 const u8 **cursor, size_t *max)
{
	struct sym_factory *f = tal(ctx, struct sym_factory);
	u16 n;

	fromwire_bitcoin_txid(cursor, max, &f->nonce);
	f->slot = fromwire_u16(cursor, max);
	fromwire_u8_array(cursor, max, f->asset, sizeof(f->asset));
	fromwire_bitcoin_outpoint(cursor, max, &f->out);
	n = fromwire_u16(cursor, max);
	if (n > SYM_FACTORY_MAX_SLOTS) {
		fromwire_fail(cursor, max);
		return tal_free(f);
	}
	f->slots = tal_arr(f, struct sym_factory_slot, n);
	for (size_t i = 0; i < n; i++) {
		fromwire_u8_array(cursor, max, f->slots[i].program, 32);
		f->slots[i].amount = fromwire_amount_sat(cursor, max);
	}
	if (!*cursor)
		return tal_free(f);
	return f;
}
