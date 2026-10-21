#ifndef LIGHTNING_COMMON_TCOV_SCRIPTS_H
#define LIGHTNING_COMMON_TCOV_SCRIPTS_H
/* Scripts of the taproot-covenant channel type (`option_seq_taproot_covenant`).
 *
 * The commitment transaction spends the usual 2-of-2 P2WSH funding output and
 * pays taproot outputs.  On the commitment held by "self", the side whose
 * keyset this is (counterparty "other"), commitment n:
 *
 *   to_local, and the destination D of every HTLC claim from this commitment:
 *     internal key  self's revocation key for n (other's once self revokes n)
 *     leaf 0 DELAY  <self_delayed_key> OP_CHECKSIGVERIFY <to_self_delay> OP_CSV
 *     leaf 1 REVOKE <per_commitment_point> <G> OP_ROT OP_ECMULSCALARVERIFY KEEP(S)
 *       where S is other's static payment script (P2WPKH of its payment
 *       basepoint, the script its to_remote output pays) and KEEP(S) is "the
 *       output at this input's index carries this input's explicit asset, at
 *       least its explicit value, and pays S": whoever holds self's
 *       per-commitment secret for n, which other learns when self revokes n,
 *       moves the output whole to other, with no signature.
 *
 *   to_remote: P2WPKH of other's payment basepoint, as option_static_remotekey.
 *
 *   an HTLC self offered:
 *     internal key  the revocation key
 *     leaf 0 TIMEOUT <self_htlc_key> OP_CHECKSIGVERIFY <cltv_expiry> OP_CLTV OP_DROP COV(A, X, D)
 *     leaf 1 SUCCESS OP_SIZE <32> OP_EQUALVERIFY OP_HASH160 <RIPEMD160(payment_hash)>
 *                    OP_EQUALVERIFY <other_htlc_key> OP_CHECKSIG
 *
 *   an HTLC self received:
 *     internal key  the revocation key
 *     leaf 0 SUCCESS OP_SIZE <32> OP_EQUALVERIFY OP_HASH160 <RIPEMD160(payment_hash)>
 *                    OP_EQUALVERIFY <self_htlc_key> OP_CHECKSIGVERIFY COV(A, X, D)
 *     leaf 1 TIMEOUT <other_htlc_key> OP_CHECKSIGVERIFY <cltv_expiry> OP_CLTV
 *
 *   COV(A, X, D): the output at this input's index carries explicit asset A
 *   (the channel's), an explicit value of at least X (the HTLC output's own
 *   value) and pays the witness v1 program D (to_local's).  So self's claims
 *   need no signature from other, and their fee comes from another input.
 *
 * Every key in a leaf is in the script, as an x-only key: no leaf takes a key
 * from its witness.  common/test/run-tcov_scripts.c checks the trees and
 * signature hashes against vectors from the Sequentia node's test framework.
 */
#include "config.h"
#include <bitcoin/tapscript.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <common/amount.h>

struct keyset;

#define TCOV_LEAF_DELAY 0
#define TCOV_LEAF_REVOKE 1
#define TCOV_LEAF_OFFERED_TIMEOUT 0
#define TCOV_LEAF_OFFERED_SUCCESS 1
#define TCOV_LEAF_RECEIVED_SUCCESS 0
#define TCOV_LEAF_RECEIVED_TIMEOUT 1

/* Which key signs a spend lightningd builds for onchaind
 * (onchaind_spend_tcov), and so which hsmd message asks for it. */
enum tcov_spend_signer {
	/* Our delayed payment key for our commitment: the DELAY leaf. */
	TCOV_SIGN_DELAYED = 0,
	/* Our HTLC key for our commitment: a covenant leaf. */
	TCOV_SIGN_LOCAL_HTLC = 1,
	/* Our HTLC key for their commitment: the leaf that pays us. */
	TCOV_SIGN_REMOTE_HTLC = 2,
	/* The revocation key, tweaked: the key path. */
	TCOV_SIGN_PENALTY = 3,
};

/* When the spend must be mined by. */
enum tcov_spend_deadline {
	/* A sweep to our wallet: no hurry. */
	TCOV_DEADLINE_SWEEP = 0,
	/* An HTLC we received: before the incoming HTLC it pays expires. */
	TCOV_DEADLINE_HTLC_IN = 1,
	/* An HTLC we offered: before the HTLC it was forwarded from expires. */
	TCOV_DEADLINE_HTLC_OUT = 2,
	/* A penalty: at once. */
	TCOV_DEADLINE_NOW = 3,
};

/* The asset id an introspection opcode pushes: the 32 bytes of the
 * 33-byte tag after its 0x01 prefix (internal byte order).  A NULL tag is
 * the policy asset. */
const u8 *tcov_asset_id(const u8 *asset_tag);

/* S: the script KEEP pays in REVOKE, other's static payment script. */
u8 *tcov_revoke_dest(const tal_t *ctx, const struct keyset *keyset);

/* to_local (and D): leaf 0 DELAY, leaf 1 REVOKE. */
void tcov_to_local_tree(const tal_t *ctx,
			const struct keyset *keyset,
			const struct pubkey *per_commitment_point,
			u16 to_self_delay,
			struct tap_tree2 *tree);

/* An HTLC the commitment's holder offered: leaf 0 TIMEOUT, leaf 1 SUCCESS.
 * @htlc_sats is the HTLC output's value, the X its covenant requires. */
void tcov_offered_htlc_tree(const tal_t *ctx,
			    const struct keyset *keyset,
			    const struct pubkey *per_commitment_point,
			    u16 to_self_delay,
			    const u8 *asset_tag,
			    const struct ripemd160 *payment_ripemd,
			    u32 cltv_expiry,
			    struct amount_sat htlc_sats,
			    struct tap_tree2 *tree);

/* An HTLC the commitment's holder received: leaf 0 SUCCESS, leaf 1 TIMEOUT. */
void tcov_received_htlc_tree(const tal_t *ctx,
			     const struct keyset *keyset,
			     const struct pubkey *per_commitment_point,
			     u16 to_self_delay,
			     const u8 *asset_tag,
			     const struct ripemd160 *payment_ripemd,
			     u32 cltv_expiry,
			     struct amount_sat htlc_sats,
			     struct tap_tree2 *tree);

/* The leaves on their own, for a signer that rebuilds what it signs. */
u8 *tcov_leaf_delay(const tal_t *ctx, const struct pubkey *delayed_key,
		    u16 to_self_delay);
u8 *tcov_leaf_revoke(const tal_t *ctx,
		     const struct pubkey *per_commitment_point,
		     const u8 *dest_spk);
u8 *tcov_leaf_offered_timeout(const tal_t *ctx,
			      const struct pubkey *self_htlc_key,
			      u32 cltv_expiry, const u8 *asset_id,
			      struct amount_sat x, const u8 d_program[32]);
u8 *tcov_leaf_offered_success(const tal_t *ctx,
			      const struct ripemd160 *payment_ripemd,
			      const struct pubkey *other_htlc_key);
u8 *tcov_leaf_received_success(const tal_t *ctx,
			       const struct ripemd160 *payment_ripemd,
			       const struct pubkey *self_htlc_key,
			       const u8 *asset_id,
			       struct amount_sat x, const u8 d_program[32]);
u8 *tcov_leaf_received_timeout(const tal_t *ctx,
			       const struct pubkey *other_htlc_key,
			       u32 cltv_expiry);

#endif /* LIGHTNING_COMMON_TCOV_SCRIPTS_H */
