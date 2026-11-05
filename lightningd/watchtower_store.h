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
 *                              towire_bitcoin_tx], then bool armed
 *                              [u64 armed_commit_num]: both written false.
 *                              They held a fully signed commitment of ours
 *                              for a tower to broadcast; the store keeps
 *                              none, since the signing device signs one for
 *                              broadcast only to close (doc/seqln-design/
 *                              seqln-device-broadcast-signature.md), and a
 *                              slot an earlier build wrote goes at the next
 *                              write.  The funding outpoint is for the
 *                              funding watch; remote_to_self_delay gives
 *                              speculad the exact RBF deadline window
 *                              (close_height + to_self_delay[REMOTE]).
 *     justice/<txid_hex>       CLASS A: one blob-set file per REVOKED
 *                              commitment, named by the full 64-char remote-
 *                              commitment txid hex (a stable, self-describing
 *                              locator; a revoked state never un-revokes and
 *                              can resurface in a reorg, so these are kept for
 *                              channel life, and the whole <dbid> directory
 *                              is removed when lightningd forgets the closed
 *                              channel: wt_store_forget_channel).
 *
 *   A blob = one pre-signed defensive tx, encoded as the `watchtower_blob`
 *   wire subtype (towire_watchtower_blob): u8 kind, u64 commit_num, u32
 *   output_index, amount_sat amount, u32 deadline_delta, u16 wscript_len, u8
 *   wscript[], bitcoin_tx tx.  deadline_delta is a DELTA (not an absolute
 *   height) so speculad recomputes the deadline after a reorg; the blob binds
 *   only its input outpoint, never a height.
 *
 *     sym                      a SYMMETRIC channel's whole record (common/
 *                              sym_scripts.h), in place of the files above:
 *                              nothing is ever punished, so nothing is kept
 *                              per old state.  u64 version (1; 2 for a
 *                              factory channel, 3 for several assets, 4 for
 *                              a settle clock), u64 channel_dbid, bitcoin_blkid genesis,
 *                              bitcoin_outpoint funding, u32 funding_height
 *                              (0 before lock-in), amount_sat funding_sats,
 *                              u8 asset[33], u16 shared_delay, pubkey
 *                              opener_update_key, pubkey accepter_update_key,
 *                              bool we_opened, then bool has_best [sym_state
 *                              best: the best state this node holds with both
 *                              update signatures], then bool has_pending
 *                              [sym_state pending: the peer's newest, signed
 *                              by this node only], each towire_sym_state,
 *                              then (version 2 and up) bool is_factory [the
 *                              channel's factory, towire_sym_factory
 *                              (common/sym_factory.h): `funding` is then the
 *                              channel's id in the factory, and its output
 *                              on chain the factory output until the split,
 *                              its KO after it], then (version 3 and up) bool
 *                              has_lanes [a channel of several assets
 *                              (lightningd/sym_lanes.h): u16 count, then
 *                              each other lane, towire_sym_lane: its asset,
 *                              its funding output's index in the funding
 *                              transaction, its amount], then (version 4
 *                              only) bool has_clock [a settle-clock channel
 *                              (lightningd/sym_clock.h): bitcoin_outpoint
 *                              issuer, the funding input whose issuance made
 *                              its marker, then both funding pubkeys].  A
 *                              plain channel's record is version 1, as an
 *                              older tower reads it.  Rewritten whenever either state
 *                              changes, before channeld goes on
 *                              (wt_store_put_sym).
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

/* Whether this node keeps the store at all: --watchtower-store, resolved at
 * startup (auto = only when hsmd is a signer proxy, the keyless case the
 * store exists for).  Every writer checks it; readers are unaffected. */
bool wt_store_enabled(const struct lightningd *ld);

#define WT_STATE_VERSION 3
#define WT_STATE_FILE "state"
#define WT_BLOB_SET_VERSION 1
#define WT_BLOB_SET_FILE "blobs"
#define WT_SYM_VERSION 2
#define WT_SYM_VERSION_LANES 3
#define WT_SYM_VERSION_CLOCK 4
#define WT_SYM_FILE "sym"

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
 * @commit_num and, when given, replace the sweep set.  The state file keeps
 * no commitment of ours (it writes has_preempt and armed false, and drops a
 * slot an earlier build stored).  Returns false on any I/O failure
 * (fail-soft: the caller logs, never fatal). */
bool wt_store_put_advance(struct lightningd *ld,
			  const struct channel *channel,
			  u64 commit_num,
			  struct watchtower_blob *const *sweeps);

/* A symmetric channel's record (the `sym` file above): durable on return.
 * False on any I/O failure (the caller logs). */
bool wt_store_put_sym(struct lightningd *ld, const struct channel *channel);

/* The channel is gone from this node (lightningd forgets a closed channel
 * once every output of its close is irrevocably resolved): remove its whole
 * directory, so the store holds only channels that can still be breached.
 * Best effort; a leftover is only disk. */
void wt_store_forget_channel(struct lightningd *ld, u64 channel_dbid);

#endif /* LIGHTNING_LIGHTNINGD_WATCHTOWER_STORE_H */
