#ifndef LIGHTNING_LIGHTNINGD_WATCHTOWER_STORE_H
#define LIGHTNING_LIGHTNINGD_WATCHTOWER_STORE_H
#include "config.h"
#include <bitcoin/tx.h>

/* Specula keyless watchtower store (Phase B): a secret-free, fsync-durable
 * on-disk store of the device-pre-signed defensive set, so speculad (Phase C)
 * can broadcast justice/sweeps while the signing device is offline and can
 * reach defensive posture from disk with NO hsm_init.
 *
 * ON-DISK FORMAT:
 *
 *   <config_netdir>/watchtower/<channel_dbid>/
 *     state                    the channel's CURRENT state, one file,
 *                              atomically replaced (rename) on each state
 *                              advance.  Little-endian: u64 version(=3),
 *                              u64 channel_dbid, u64 current_commit_num,
 *                              bitcoin_outpoint funding (txid+u32 vout),
 *                              u16 remote_to_self_delay, then the CLASS-B
 *                              current-state honest sweeps as a blob set (u64
 *                              set version(=1), u64 count, count blobs), then
 *                              bool has_preempt [u64 preempt_commit_num,
 *                              towire_bitcoin_tx of OUR CURRENT fully-signed
 *                              (2-of-2) local commitment], then bool armed
 *                              [u64 armed_commit_num].
 *                              The funding outpoint is for the preemptive-
 *                              close/funding-watch; remote_to_self_delay gives
 *                              speculad the exact RBF deadline window
 *                              (close_height + to_self_delay[REMOTE]).  The
 *                              preempt commitment is rewritten in the SAME
 *                              durable step that bumps current_commit_num, so
 *                              it always names the CURRENT (never a revoked)
 *                              local state; armed is set by lightningd when it
 *                              detects the signer dropped mid-round and cleared
 *                              on the next clean advance / device reconnect --
 *                              speculad only broadcasts the preempt commitment
 *                              while it is set AND preempt_commit_num ==
 *                              current_commit_num.
 *     justice/<txid_hex>       CLASS A: one blob-set file per REVOKED
 *                              commitment, named by the full 64-char remote-
 *                              commitment txid hex (a stable, self-describing
 *                              locator; a revoked state never un-revokes and
 *                              can resurface in a reorg, so these are kept for
 *                              channel life).
 *
 *   A blob = one pre-signed defensive tx, encoded as the `watchtower_blob`
 *   wire subtype (towire_watchtower_blob): u8 kind, u64 commit_num, u32
 *   output_index, amount_sat amount, u32 deadline_delta, u16 wscript_len, u8
 *   wscript[], bitcoin_tx tx.  deadline_delta is a DELTA (not an absolute
 *   height) so speculad recomputes the deadline after a reorg; the blob binds
 *   only its input outpoint, never a height.
 *
 *   Readers also take the layouts this grew out of, so a store written by an
 *   earlier lightningd is read as it stands until its next advance rewrites
 *   it: a `meta` file (u64 version 1|2, u64 dbid, u64 current_commit_num[,
 *   funding, u16 to_self_delay]) beside `sweeps/` and `preempt/commit` +
 *   `preempt/armed`, and `justice/<txid>/` as a DIRECTORY -- each blob set
 *   there either a `blobs` set file or one `blob_NNNN` file per blob.
 *
 * NO seed / key / per-commitment-secret is EVER written -- only signed txs +
 * the metadata needed to broadcast + fee-bump them.  Every put is durable
 * before it returns: temp file -> fsync(file) -> rename -> fsync(dir), exactly
 * as hsmd fsyncs hsm_secret (hsmd/hsmd.c:maybe_create_new_hsm).  Every fsync
 * is a device flush, so what bounds how fast a payment can settle is the
 * number of files a commitment step writes: one here, whatever the step.
 */

#define WT_STATE_VERSION 3
#define WT_STATE_FILE "state"
#define WT_BLOB_SET_VERSION 1
#define WT_BLOB_SET_FILE "blobs"

struct lightningd;
struct channel;
struct watchtower_blob;
struct bitcoin_txid;

/* Persist the justice set for one revoked commitment (CLASS A).  Durable on
 * return.  Returns false on any I/O failure (caller keeps
 * the JBA barrier closed / logs). */
bool wt_store_put_justice(struct lightningd *ld,
			  const struct channel *channel,
			  const struct bitcoin_txid *commitment_txid,
			  u64 commitment_num,
			  struct watchtower_blob *const *blobs);

/* Persist the current-state honest sweep set (CLASS B), atomically obsoleting
 * the prior set: wt_store_put_advance with only the sweeps. */
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

/* A state advance in one durable write: bump current_commit_num to
 * @commit_num and, when given, replace the sweep set and/or store OUR current
 * fully-signed local commitment @preempt_tx keyed to @commit_num.  Storing a
 * preempt commitment also clears the armed flag (a clean advance completed).
 * Because the preempt commitment and current_commit_num move together, the
 * broadcast guard (preempt_commit_num == current_commit_num) can never see a
 * REVOKED local commitment.  Returns false on any I/O failure (fail-soft: the
 * caller logs, never fatal). */
bool wt_store_put_advance(struct lightningd *ld,
			  const struct channel *channel,
			  u64 commit_num,
			  struct watchtower_blob *const *sweeps,
			  const struct bitcoin_tx *preempt_tx);

/* Phase F preemptive close: wt_store_put_advance with only the preempt
 * commitment. */
bool wt_store_put_preempt(struct lightningd *ld,
			  const struct channel *channel,
			  u64 commit_num,
			  const struct bitcoin_tx *signed_commit_tx);

/* Phase F: set/clear the preempt "armed" flag (device-down-mid-round signal that
 * tells speculad it may broadcast the stored preempt commitment).  When arming,
 * it records the current local commit_num so a stale arm cannot fire against a
 * newer state (speculad also enforces preempt_commit_num == current_commit_num). */
bool wt_store_set_preempt_armed(struct lightningd *ld,
				const struct channel *channel,
				bool armed);

#endif /* LIGHTNING_LIGHTNINGD_WATCHTOWER_STORE_H */
