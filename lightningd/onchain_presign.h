#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_PRESIGN_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_PRESIGN_H
#include "config.h"
#include <stdbool.h>

/* Specula keyless watchtower (Phase E, seam #1): the master-fd pre-sign
 * orchestrator for the CURRENT-state HONEST force-close defenses (CLASS-B
 * sweeps).
 *
 * The BREACH (justice) set is already pre-signed by channeld at the channel fd
 * at revoke_and_ack (Phase B).  But the current-state honest-close sweeps that
 * need the MASTER hsm fd -- to_local-delayed, remote_htlc_to_us, HTLC-timeout
 * (offered HTLCs) and HTLC-success (received HTLCs, once the preimage is known)
 * -- cannot be signed there: hsmd_sign_any_local_htlc_tx(146) and friends are
 * master-client ops (dbid 0, keyless-forwarded to the device).  This module
 * drives the device via the master hsm client at each commitment advance (and
 * each HTLC fulfill for success) and writes the results into the store sweeps/
 * dir so speculad can broadcast them while the device is offline.
 *
 * SEAM #1 CLOSED (Phase E2): channeld now threads the LOCAL per_commitment_point
 * + per-HTLC 2nd-stage metadata up in WIRE_CHANNELD_GOT_COMMITSIG (the
 * got_commitsig_htlc_info subtype, aligned 1:1 with channel->last_htlc_sigs),
 * so keyless lightningd can derive the LOCAL commitment keyset and master-sign
 * the honest-close sweeps here.  IMPLEMENTED: kind 3 (to_local-delayed) + kind 4
 * (offered HTLC-timeout, 2-of-2 with the stored remote_htlc_sig) at commitment
 * advance, and kind 5 (received HTLC-success, 2-of-2 + preimage) at fulfill.
 *
 * SEAM #2 CLOSED (Phase F): channeld now threads the REMOTE per_commitment_point
 * up in WIRE_CHANNELD_SENDING_COMMITSIG (alongside the penalty_base, which already
 * carries the remote-commitment txid + per-HTLC outpoints/amounts/cltv/offered
 * flags), so keyless lightningd can derive the REMOTE keyset and master-sign the
 * remote_htlc_to_us sweeps of OUR HTLC outputs on the PEER commitment.  IMPLEMENTED:
 * kind 6 offered-by-us (timeout, no preimage) at commitment advance, and kind 6
 * received-by-us (preimage) at fulfill.  These defend a PEER honest force-close
 * while the device is offline, completing the honest-close taxonomy.
 */

struct channel;
struct htlc_in;
struct pubkey;
struct penalty_base;
struct got_commitsig_htlc_info;

/* Pre-sign the current-state CLASS-B honest sweeps (kind 3 to_local-delayed +
 * kind 4 offered-HTLC-timeout) for the just-advanced local commitment
 * @commit_num (whose keyset is derived from @local_per_commit), and atomically
 * replace the store sweeps/ set.  @htlc_infos is the per-HTLC metadata aligned
 * 1:1 with channel->last_htlc_sigs.  Also stashes the keyset ingredients on the
 * channel for the fulfill-time kind-5 rebuild.  Call at commitment advance,
 * AFTER channel->last_htlc_sigs and channel->last_tx are set. */
void onchain_presign_current_sweeps(struct channel *channel,
				    u64 commit_num,
				    const struct pubkey *local_per_commit,
				    const struct got_commitsig_htlc_info *htlc_infos);

/* Pre-sign + store the HTLC-success sweep (kind 5) for a just-fulfilled incoming
 * HTLC, using the preimage (only known now) + the stashed local keyset.  The JBA
 * fulfill hard-gate: returns true iff it is safe to release the preimage (a
 * durable success sweep is stored, or -- when the keyset stash is absent, e.g.
 * right after a restart -- best-effort on testnet).  Returns false when we HAVE
 * the ingredients but the sign or the durable store failed, so the caller defers
 * releasing the preimage this pass. */
bool onchain_presign_htlc_success(struct channel *channel, struct htlc_in *hin);

/* Phase F (kind 6): pre-sign the remote_htlc_to_us sweeps of OUR HTLC outputs on
 * the CURRENT peer commitment described by @pbase (its txid + per-HTLC metadata),
 * whose REMOTE keyset is derived from @remote_per_commit.  Builds the offered-by-us
 * (timeout, no preimage) legs now and stashes @pbase/@remote_per_commit on the
 * channel so onchain_presign_htlc_success() can add the received-by-us (preimage)
 * legs at fulfill time.  Merges kind 6 into the sweeps/ store WITHOUT clobbering
 * kinds 3/4/5.  Call at commitment advance (peer_sending_commitsig), when the
 * peer's new commitment (which they can broadcast) is known. */
void onchain_presign_remote_htlc_sweeps(struct channel *channel,
					const struct pubkey *remote_per_commit,
					const struct penalty_base *pbase);

#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_PRESIGN_H */
