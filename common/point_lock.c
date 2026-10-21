#include "config.h"
#include <common/point_lock.h>
#include <common/utils.h>
#include <secp256k1.h>
#include <string.h>

bool point_lock_scalar_valid(const struct preimage *s)
{
	return secp256k1_ec_seckey_verify(secp256k1_ctx, s->r) == 1;
}

bool point_lock_point_of(const struct preimage *s, struct pubkey *point)
{
	if (!point_lock_scalar_valid(s))
		return false;
	return secp256k1_ec_pubkey_create(secp256k1_ctx, &point->pubkey, s->r)
		== 1;
}

bool point_lock_opens(const struct pubkey *lock, const struct preimage *s)
{
	struct pubkey p;

	if (!point_lock_point_of(s, &p))
		return false;
	return pubkey_eq(&p, lock);
}

void point_lock_payment_hash(const struct pubkey *lock,
			     struct sha256 *payment_hash)
{
	u8 der[PUBKEY_CMPR_LEN];

	pubkey_to_der(der, lock);
	memcpy(payment_hash->u.u8, der + 1, sizeof(payment_hash->u.u8));
}

bool point_lock_tweak(const struct pubkey *lock, const struct secret *tweak,
		      struct pubkey *out)
{
	*out = *lock;
	if (secp256k1_ec_seckey_verify(secp256k1_ctx, tweak->data) != 1)
		return false;
	return secp256k1_ec_pubkey_tweak_add(secp256k1_ctx, &out->pubkey,
					     tweak->data) == 1;
}

bool point_lock_scalar_add(const struct preimage *a, const struct secret *b,
			   struct preimage *out)
{
	if (!point_lock_scalar_valid(a)
	    || secp256k1_ec_seckey_verify(secp256k1_ctx, b->data) != 1)
		return false;
	*out = *a;
	return secp256k1_ec_seckey_tweak_add(secp256k1_ctx, out->r, b->data)
		== 1;
}

bool point_lock_scalar_negate(const struct secret *a, struct secret *out)
{
	*out = *a;
	if (secp256k1_ec_seckey_verify(secp256k1_ctx, out->data) != 1)
		return false;
	return secp256k1_ec_seckey_negate(secp256k1_ctx, out->data) == 1;
}

bool point_lock_scalar_sub(const struct preimage *a, const struct secret *b,
			   struct preimage *out)
{
	struct secret negb;

	if (!point_lock_scalar_negate(b, &negb))
		return false;
	return point_lock_scalar_add(a, &negb, out);
}
