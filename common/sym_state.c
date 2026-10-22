#include "config.h"
#include <common/sym_scripts.h>
#include <common/sym_state.h>
#include <common/utils.h>
#include <wire/wire.h>

struct sym_state *sym_state_new(const tal_t *ctx, enum side owner,
				u64 commit_num, s64 num,
				const struct sym_output *outs)
{
	struct sym_state *st = tal(ctx, struct sym_state);

	st->owner = owner;
	st->commit_num = commit_num;
	st->num = num;
	st->outs = tal_arr(st, struct sym_state_out, tal_count(outs));
	for (size_t i = 0; i < tal_count(outs); i++) {
		st->outs[i].amount = outs[i].amount;
		st->outs[i].spk = tal_dup_talarr(st->outs, u8, outs[i].spk);
	}
	st->has_sig[LOCAL] = st->has_sig[REMOTE] = false;
	memset(st->sig, 0, sizeof(st->sig));
	return st;
}

struct sym_output *sym_state_outputs(const tal_t *ctx,
				     const struct sym_state *st)
{
	struct sym_output *outs = tal_arr(ctx, struct sym_output,
					  tal_count(st->outs));

	for (size_t i = 0; i < tal_count(st->outs); i++) {
		outs[i].kind = SYM_OUT_BALANCE;
		outs[i].side = LOCAL;
		outs[i].amount = st->outs[i].amount;
		outs[i].spk = st->outs[i].spk;
		outs[i].htlc = NULL;
		outs[i].cltv_expiry = 0;
	}
	return outs;
}

void sym_state_tree_of(const tal_t *ctx, const struct sym_channel *sc,
		       const struct sym_state *st, struct sym_tree *tree)
{
	sym_state_tree(ctx, sc, st->num, sym_state_outputs(tmpctx, st), NULL,
		       tree);
}

bool sym_state_signed(const struct sym_state *st, enum side opener,
		      const struct bip340sig **sig_opener,
		      const struct bip340sig **sig_accepter)
{
	if (!st->has_sig[LOCAL] || !st->has_sig[REMOTE])
		return false;
	*sig_opener = &st->sig[opener];
	*sig_accepter = &st->sig[!opener];
	return true;
}

struct amount_sat sym_state_total(const struct sym_state *st)
{
	struct amount_sat t = AMOUNT_SAT(0);

	for (size_t i = 0; i < tal_count(st->outs); i++)
		if (!amount_sat_add(&t, t, st->outs[i].amount))
			abort();
	return t;
}

void towire_sym_state(u8 **pptr, const struct sym_state *st)
{
	towire_u8(pptr, st->owner);
	towire_u64(pptr, st->commit_num);
	towire_u64(pptr, (u64)st->num);
	towire_u16(pptr, tal_count(st->outs));
	for (size_t i = 0; i < tal_count(st->outs); i++) {
		towire_amount_sat(pptr, st->outs[i].amount);
		towire_u16(pptr, tal_bytelen(st->outs[i].spk));
		towire_u8_array(pptr, st->outs[i].spk,
				tal_bytelen(st->outs[i].spk));
	}
	for (enum side s = 0; s < NUM_SIDES; s++) {
		towire_bool(pptr, st->has_sig[s]);
		towire_bip340sig(pptr, &st->sig[s]);
	}
}

struct sym_state *fromwire_sym_state(const tal_t *ctx,
				     const u8 **pptr, size_t *max)
{
	struct sym_state *st = tal(ctx, struct sym_state);
	u16 n;

	st->owner = fromwire_u8(pptr, max);
	if (st->owner != LOCAL && st->owner != REMOTE)
		fromwire_fail(pptr, max);
	st->commit_num = fromwire_u64(pptr, max);
	st->num = (s64)fromwire_u64(pptr, max);
	n = fromwire_u16(pptr, max);
	st->outs = tal_arr(st, struct sym_state_out, n);
	for (size_t i = 0; i < n; i++) {
		u16 len;
		st->outs[i].amount = fromwire_amount_sat(pptr, max);
		len = fromwire_u16(pptr, max);
		st->outs[i].spk = fromwire_tal_arrn(st->outs, pptr, max, len);
	}
	for (enum side s = 0; s < NUM_SIDES; s++) {
		st->has_sig[s] = fromwire_bool(pptr, max);
		fromwire_bip340sig(pptr, max, &st->sig[s]);
	}
	if (!*pptr)
		return tal_free(st);
	return st;
}
