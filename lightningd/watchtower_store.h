#ifndef LIGHTNING_LIGHTNINGD_WATCHTOWER_STORE_H
#define LIGHTNING_LIGHTNINGD_WATCHTOWER_STORE_H
#include "config.h"
#include <bitcoin/tx.h>

/* Specula keyless watchtower store (Phase B): a secret-free, fsync-durable
 * on-disk store of the device-pre-signed defensive set, so speculad (Phase C)
 * can broadcast justice/sweeps while the signing device is offline and can
 * reach defensive posture from disk with NO hsm_init.
 *
 * ON-DISK FORMAT (documented so Phase C/D slot in without a schema change):
 *
 *   <config_netdir>/watchtower/<channel_dbid>/
 *     meta                     little-endian: u64 version(=2),
 *                              u64 channel_dbid, u64 current_commit_num,
 *                              bitcoin_outpoint funding (txid+u32 vout),
 *                              u16 remote_to_self_delay.  (v1 wrote only the
 *                              first three fields; speculad reads both.)  The
 *                              funding outpoint is for the future preemptive-
 *                              close/funding-watch; remote_to_self_delay gives
 *                              speculad the exact RBF deadline window
 *                              (close_height + to_self_delay[REMOTE]).
 *     justice/<txid_hex>/      CLASS A: one directory per REVOKED commitment,
 *                              named by the full 64-char remote-commitment
 *                              txid hex (a stable, self-describing locator; a
 *                              revoked state never un-revokes and can resurface
 *                              in a reorg, so these are kept for channel life).
 *       blob_0000 .. blob_NNNN each = one pre-signed defensive tx, encoded as
 *                              the `watchtower_blob` wire subtype
 *                              (towire_watchtower_blob): u8 kind, u64
 *                              commit_num, u32 output_index, amount_sat amount,
 *                              u32 deadline_delta, u16 wscript_len, u8 wscript[],
 *                              bitcoin_tx tx.  deadline_delta is a DELTA (not an
 *                              absolute height) so speculad recomputes the
 *                              deadline after a reorg; the blob binds only its
 *                              input outpoint, never a height.
 *     sweeps/                  CLASS B: CURRENT-state honest sweeps only,
 *       blob_0000 .. blob_NNNN atomically replaced (rename) on each state
 *                              advance so it obsoletes the prior set.
 *     preempt/                 Phase F preemptive-close (withhold-revoke / JBA
 *                              defense) slot:
 *       commit                 little-endian: u64 commit_num, then
 *                              towire_bitcoin_tx of OUR CURRENT fully-signed
 *                              (2-of-2) local commitment.  Rewritten atomically
 *                              on EACH state advance in the SAME durable step
 *                              that bumps meta.current_commit_num, so it always
 *                              names the CURRENT (never a revoked) local state.
 *       armed                  presence-flag (little-endian u64 commit_num it was
 *                              armed for): set by lightningd when it detects the
 *                              signer dropped mid-round, cleared on the next
 *                              clean advance / device reconnect.  speculad only
 *                              broadcasts the preempt commitment while this is
 *                              present AND commit==meta.current_commit_num.
 *
 * NO seed / key / per-commitment-secret is EVER written -- only signed txs +
 * the metadata needed to broadcast + fee-bump them.  Every write is durable:
 * temp file -> fsync(file) -> rename -> fsync(dir), exactly as hsmd fsyncs
 * hsm_secret (hsmd/hsmd.c:maybe_create_new_hsm).
 */

struct lightningd;
struct channel;
struct watchtower_blob;
struct bitcoin_txid;

/* Persist the justice set for one revoked commitment (CLASS A).  Durable on
 * return (all blobs fsync'd).  Returns false on any I/O failure (caller keeps
 * the JBA barrier closed / logs). */
bool wt_store_put_justice(struct lightningd *ld,
			  const struct channel *channel,
			  const struct bitcoin_txid *commitment_txid,
			  u64 commitment_num,
			  struct watchtower_blob *const *blobs);

/* Persist the current-state honest sweep set (CLASS B), atomically obsoleting
 * the prior set.  Durable on return.  Also bumps meta.current_commit_num. */
bool wt_store_put_sweeps(struct lightningd *ld,
			 const struct channel *channel,
			 u64 current_commit_num,
			 struct watchtower_blob *const *blobs);

/* Phase C read API: load every stored justice blob for a channel (across all
 * revoked commitments).  Returns a tal array of pointers (possibly empty). */
struct watchtower_blob **wt_store_load_justice(const tal_t *ctx,
					       struct lightningd *ld,
					       const struct channel *channel);

/* Phase C read API: load the current-state sweep blobs for a channel. */
struct watchtower_blob **wt_store_load_sweeps(const tal_t *ctx,
					      struct lightningd *ld,
					      const struct channel *channel);

/* Phase F preemptive close: durably store OUR current fully-signed local
 * commitment @signed_commit_tx into the preempt/ slot, keyed to @commit_num, and
 * (unconditionally) bump meta.current_commit_num to @commit_num in the SAME
 * durable step -- so the broadcast guard (commit_num == meta.current_commit_num)
 * can never see a REVOKED local commitment.  Also clears the armed flag (a clean
 * advance completed).  Returns false on any I/O failure (fail-soft: the caller
 * logs, never fatal). */
bool wt_store_put_preempt(struct lightningd *ld,
			  const struct channel *channel,
			  u64 commit_num,
			  const struct bitcoin_tx *signed_commit_tx);

/* Phase F: set/clear the preempt "armed" flag (device-down-mid-round signal that
 * tells speculad it may broadcast the stored preempt commitment).  When arming,
 * it records the current local commit_num so a stale arm cannot fire against a
 * newer state (speculad also enforces commit_num == meta.current_commit_num). */
bool wt_store_set_preempt_armed(struct lightningd *ld,
				const struct channel *channel,
				bool armed);

#endif /* LIGHTNING_LIGHTNINGD_WATCHTOWER_STORE_H */
