#ifndef LIGHTNING_COMMON_POINT_LOCK_H
#define LIGHTNING_COMMON_POINT_LOCK_H
/* SEQUENTIA: point locks (option_seq_point_locks, doc/sequentia-fork.md
 * section 5c).
 *
 * A point-locked HTLC opens with a 32-byte scalar t where t*G equals its lock
 * point L, rather than with a preimage of its payment hash.  On a
 * taproot-covenant channel its SUCCESS leaf checks that in script
 * (common/tcov_scripts.h).  Everywhere else the HTLC keeps the shape of a
 * hash-locked one: its payment_hash field carries L's x coordinate, its
 * preimage field the scalar, and the point itself (with its parity) rides in
 * the update_add_htlc TLV `seq_point_lock` and in the database.
 *
 * Every hop sees a different point.  The payer locks the first HTLC to
 * L0 = T + c*G, where T = p*G is the point in the payee's invoice and p the
 * invoice's preimage; hop i, told d_i in its onion, forwards with
 * L(i+1) = L(i) + d_i*G; the payee, told r = c + sum(d_i) and the invoice's
 * payment hash, opens its HTLC with p + r.  Each hop takes d_i off the scalar
 * it learns, and the payer, taking off c, ends with p.
 */
#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/crypto/sha256/sha256.h>

/* Is @s a scalar a point lock can take: 32 bytes, nonzero, below the
 * group order? */
bool point_lock_scalar_valid(const struct preimage *s);

/* @s * G, if @s is a valid scalar. */
bool point_lock_point_of(const struct preimage *s, struct pubkey *point);

/* Does @s open @lock: @s * G == @lock (parity included)? */
bool point_lock_opens(const struct pubkey *lock, const struct preimage *s);

/* The payment_hash field of an HTLC locked to @lock: its x coordinate. */
void point_lock_payment_hash(const struct pubkey *lock,
			     struct sha256 *payment_hash);

/* @lock + @tweak * G (false if @tweak is not a valid scalar or the sum is
 * the point at infinity). */
bool point_lock_tweak(const struct pubkey *lock, const struct secret *tweak,
		      struct pubkey *out);

/* @a + @b mod n (false if either is not a valid scalar or the sum is 0). */
bool point_lock_scalar_add(const struct preimage *a, const struct secret *b,
			   struct preimage *out);

/* -@a mod n. */
bool point_lock_scalar_negate(const struct secret *a, struct secret *out);

/* @a - @b mod n (false on the same conditions as point_lock_scalar_add). */
bool point_lock_scalar_sub(const struct preimage *a, const struct secret *b,
			   struct preimage *out);

#endif /* LIGHTNING_COMMON_POINT_LOCK_H */
