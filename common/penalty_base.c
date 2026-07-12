#include "config.h"
#include <assert.h>
#include <common/penalty_base.h>
#include <common/utils.h>
#include <wire/wire.h>

/* txout must be within tx! */
struct penalty_base *penalty_base_new(const tal_t *ctx,
				      u64 commitment_num,
				      const struct bitcoin_tx *tx,
				      const struct wally_tx_output *txout)
{
	struct penalty_base *pbase = tal(ctx, struct penalty_base);

	pbase->commitment_num = commitment_num;
	bitcoin_txid(tx, &pbase->txid);
	pbase->outnum = txout - tx->wtx->outputs;
	assert(pbase->outnum < tx->wtx->num_outputs);
	pbase->amount = amount_sat(txout->satoshi);
	pbase->htlcs = tal_arr(pbase, struct penalty_htlc, 0);

	return pbase;
}

void penalty_base_add_htlc(struct penalty_base *pbase,
			   u32 outnum,
			   struct amount_sat amount,
			   const struct sha256 *payment_hash,
			   u32 cltv_expiry,
			   bool remote_offered)
{
	struct penalty_htlc h;

	h.outnum = outnum;
	h.amount = amount;
	h.payment_hash = *payment_hash;
	h.cltv_expiry = cltv_expiry;
	h.remote_offered = remote_offered;
	tal_arr_expand(&pbase->htlcs, h);
}

void towire_penalty_base(u8 **pptr, const struct penalty_base *pbase)
{
	towire_u64(pptr, pbase->commitment_num);
	towire_bitcoin_txid(pptr, &pbase->txid);
	towire_u32(pptr, pbase->outnum);
	towire_amount_sat(pptr, pbase->amount);
	towire_u16(pptr, tal_count(pbase->htlcs));
	for (size_t i = 0; i < tal_count(pbase->htlcs); i++) {
		towire_u32(pptr, pbase->htlcs[i].outnum);
		towire_amount_sat(pptr, pbase->htlcs[i].amount);
		towire_sha256(pptr, &pbase->htlcs[i].payment_hash);
		towire_u32(pptr, pbase->htlcs[i].cltv_expiry);
		towire_bool(pptr, pbase->htlcs[i].remote_offered);
	}
}

void fromwire_penalty_base(const u8 **pptr, size_t *max,
			   struct penalty_base *pbase)
{
	u16 num_htlcs;

	pbase->commitment_num = fromwire_u64(pptr, max);
	fromwire_bitcoin_txid(pptr, max, &pbase->txid);
	pbase->outnum = fromwire_u32(pptr, max);
	pbase->amount = fromwire_amount_sat(pptr, max);
	num_htlcs = fromwire_u16(pptr, max);
	pbase->htlcs = tal_arr(pbase, struct penalty_htlc, num_htlcs);
	for (size_t i = 0; i < num_htlcs; i++) {
		pbase->htlcs[i].outnum = fromwire_u32(pptr, max);
		pbase->htlcs[i].amount = fromwire_amount_sat(pptr, max);
		fromwire_sha256(pptr, max, &pbase->htlcs[i].payment_hash);
		pbase->htlcs[i].cltv_expiry = fromwire_u32(pptr, max);
		pbase->htlcs[i].remote_offered = fromwire_bool(pptr, max);
	}
}
