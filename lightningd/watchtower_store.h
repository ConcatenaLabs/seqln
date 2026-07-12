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
 *     meta                     little-endian: u64 version(=1),
 *                              u64 channel_dbid, u64 current_commit_num.
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

#endif /* LIGHTNING_LIGHTNINGD_WATCHTOWER_STORE_H */
