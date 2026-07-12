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
 * PREREQUISITE / SEAM (documented in openIssues): building these templates needs
 * the LOCAL commitment keyset (local per_commitment_point + per-HTLC 2nd-stage
 * wscripts).  lightningd is KEYLESS and cannot derive it, and
 * hsmd_get_per_commitment_point(18) is a channel-fd-only op.  channeld already
 * derives the keyset in commit_tx.c; it must thread the point (or the fully
 * built unsigned CLASS-B templates + per-HTLC metadata) up in
 * WIRE_CHANNELD_GOT_COMMITSIG -- a byte-exact wiregen change -- before the
 * template construction below can be filled in.  Until then these entry points
 * are structurally in place but produce no blobs, and the honest force-close
 * path stays on onchaind at real force-close time (device-online), exactly as
 * today -- i.e. no regression, only the not-yet-closed keyless honest-close gap.
 */

struct channel;
struct htlc_in;

/* Pre-sign the current-state CLASS-B honest sweeps (to_local-delayed,
 * remote_htlc_to_us, HTLC-timeout) for the just-advanced local commitment and
 * atomically replace the store sweeps/ set.  Call at commitment advance, AFTER
 * channel->last_htlc_sigs and channel->last_tx are set. */
void onchain_presign_current_sweeps(struct channel *channel);

/* Best-effort pre-sign + store of the HTLC-success sweep (kind 5) for a just-
 * fulfilled incoming HTLC.  The JBA fulfill hard-gate: returns true iff it is
 * safe to release the preimage (a durable success sweep is stored, OR -- until
 * the keyset is threaded -- best-effort on testnet).  Returns false only once
 * signing is wired and the sign/store failed, so the caller defers releasing
 * the preimage this pass. */
bool onchain_presign_htlc_success(struct channel *channel, struct htlc_in *hin);

#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_PRESIGN_H */
