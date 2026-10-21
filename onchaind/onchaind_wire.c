#include "config.h"
#include <common/htlc_wire.h>
#include <onchaind/onchaind_wire.h>

void towire_htlc_stub(u8 **pptr, const struct htlc_stub *htlc_stub)
{
	towire_side(pptr, htlc_stub->owner);
	towire_u32(pptr, htlc_stub->cltv_expiry);
	towire_u64(pptr, htlc_stub->id);
	towire_ripemd160(pptr, &htlc_stub->ripemd);
	towire_bool(pptr, htlc_stub->has_lock_point);
	if (htlc_stub->has_lock_point)
		towire_pubkey(pptr, &htlc_stub->lock_point);
}

void fromwire_htlc_stub(const u8 **cursor, size_t *max,
			struct htlc_stub *htlc_stub)
{
	htlc_stub->owner = fromwire_side(cursor, max);
	htlc_stub->cltv_expiry = fromwire_u32(cursor, max);
	htlc_stub->id = fromwire_u64(cursor, max);
	fromwire_ripemd160(cursor, max, &htlc_stub->ripemd);
	htlc_stub->has_lock_point = fromwire_bool(cursor, max);
	if (htlc_stub->has_lock_point)
		fromwire_pubkey(cursor, max, &htlc_stub->lock_point);
}
