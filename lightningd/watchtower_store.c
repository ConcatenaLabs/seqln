#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <channeld/channeld_wiregen.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/watchtower_store.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wire/wire.h>

/* The channeld_wiregen towire/fromwire_watchtower_blob helpers are static, so
 * the store owns its (identical) on-disk encoding of a watchtower_blob.  This
 * keeps the durable format independent of the channeld wire and documented in
 * watchtower_store.h. */
static void wt_blob_encode(u8 **pptr, const struct watchtower_blob *b)
{
	towire_u8(pptr, b->kind);
	towire_u64(pptr, b->commit_num);
	towire_u32(pptr, b->output_index);
	towire_amount_sat(pptr, b->amount);
	towire_u32(pptr, b->deadline_delta);
	towire_u16(pptr, tal_count(b->wscript));
	towire_u8_array(pptr, b->wscript, tal_count(b->wscript));
	towire_bitcoin_tx(pptr, b->tx);
}

static struct watchtower_blob *wt_blob_decode(const tal_t *ctx,
					      const u8 **cursor, size_t *max)
{
	struct watchtower_blob *b = tal(ctx, struct watchtower_blob);
	u16 wscript_len;

	b->kind = fromwire_u8(cursor, max);
	b->commit_num = fromwire_u64(cursor, max);
	b->output_index = fromwire_u32(cursor, max);
	b->amount = fromwire_amount_sat(cursor, max);
	b->deadline_delta = fromwire_u32(cursor, max);
	wscript_len = fromwire_u16(cursor, max);
	b->wscript = tal_arr(b, u8, wscript_len);
	fromwire_u8_array(cursor, max, b->wscript, wscript_len);
	b->tx = fromwire_bitcoin_tx(b, cursor, max);
	if (!*cursor)
		return tal_free(b);
	return b;
}

/* fsync a directory so a newly-created/renamed dirent is durable.  (You may
 * only open directories read-only on modern Unix.) */
static bool fsync_dir(const char *dir)
{
	int fd = open(dir, O_RDONLY);
	if (fd < 0)
		return false;
	if (fsync(fd) != 0) {
		close_noerr(fd);
		return false;
	}
	return close(fd) == 0;
}

/* mkdir a single component, tolerating EEXIST, and fsync its parent so the new
 * dirent is durable. */
static bool ensure_dir(const char *path)
{
	char *parent;

	if (mkdir(path, 0700) != 0 && errno != EEXIST)
		return false;
	/* Sync the parent dir so the new subdir survives a crash. */
	parent = path_dirname(tmpctx, path);
	return fsync_dir(parent);
}

/* Ensure <netdir>/watchtower/<dbid>[/sub] exists, returning its path. */
static char *channel_store_dir(const tal_t *ctx,
			       struct lightningd *ld,
			       const struct channel *channel,
			       const char *sub)
{
	char *base = path_join(ctx, ld->config_netdir, "watchtower");
	char *chan, *subdir;

	if (!ensure_dir(base))
		return tal_free(base);
	chan = tal_fmt(ctx, "%s/%"PRIu64, base, channel->dbid);
	tal_free(base);
	if (!ensure_dir(chan))
		return tal_free(chan);
	if (!sub)
		return chan;
	subdir = path_join(ctx, chan, sub);
	tal_free(chan);
	if (!ensure_dir(subdir))
		return tal_free(subdir);
	return subdir;
}

/* Durable file write: temp -> fsync(file) -> rename -> fsync(dir).  Mirrors
 * hsmd/hsmd.c:maybe_create_new_hsm's fsync discipline. */
static bool write_durable(const char *dir, const char *name,
			  const u8 *data, size_t len)
{
	char *final = path_join(tmpctx, dir, name);
	char *tmp = tal_fmt(tmpctx, "%s/.tmp.%s", dir, name);
	int fd;

	fd = open(tmp, O_CREAT|O_TRUNC|O_WRONLY, 0600);
	if (fd < 0)
		return false;
	if (!write_all(fd, data, len)) {
		close_noerr(fd);
		unlink_noerr(tmp);
		return false;
	}
	if (fsync(fd) != 0) {
		close_noerr(fd);
		unlink_noerr(tmp);
		return false;
	}
	if (close(fd) != 0) {
		unlink_noerr(tmp);
		return false;
	}
	if (rename(tmp, final) != 0) {
		unlink_noerr(tmp);
		return false;
	}
	/* rename() durability requires the directory be fsync'd. */
	return fsync_dir(dir);
}

static bool write_blob_set(const struct channel *channel,
			   const char *dir,
			   struct watchtower_blob *const *blobs)
{
	for (size_t i = 0; i < tal_count(blobs); i++) {
		u8 *enc = tal_arr(tmpctx, u8, 0);
		char *name = tal_fmt(tmpctx, "blob_%04zu", i);

		wt_blob_encode(&enc, blobs[i]);
		if (!write_durable(dir, name, enc, tal_bytelen(enc))) {
			log_broken(channel->log,
				   "watchtower store: failed writing %s/%s: %s",
				   dir, name, strerror(errno));
			return false;
		}
	}
	return true;
}

/* meta = LE u64 version(=2), u64 dbid, u64 current_commit_num,
 * bitcoin_outpoint funding, u16 remote_to_self_delay.
 *
 * v2 (Phase E, seam #3) appends the funding outpoint (for the future
 * preemptive-close / funding-watch) and the REMOTE to_self_delay so speculad
 * can compute the exact RBF deadline = close_height + to_self_delay[REMOTE]
 * instead of an assumed CSV.  A v1 reader/writer only ever wrote the first
 * three fields; speculad reads both versions. */
static bool write_meta(const struct channel *channel,
		       const char *chandir,
		       u64 current_commit_num)
{
	u8 *enc = tal_arr(tmpctx, u8, 0);

	towire_u64(&enc, 2 /* version */);
	towire_u64(&enc, channel->dbid);
	towire_u64(&enc, current_commit_num);
	towire_bitcoin_outpoint(&enc, &channel->funding);
	towire_u16(&enc, channel->channel_info.their_config.to_self_delay);
	return write_durable(chandir, "meta", enc, tal_bytelen(enc));
}

bool wt_store_put_justice(struct lightningd *ld,
			  const struct channel *channel,
			  const struct bitcoin_txid *commitment_txid,
			  u64 commitment_num,
			  struct watchtower_blob *const *blobs)
{
	char *justice, *commitdir;
	char *locator;
	bool ok;

	justice = channel_store_dir(tmpctx, ld, channel, "justice");
	if (!justice)
		return false;

	/* Locator = full remote-commitment txid hex (stable + self-describing;
	 * a Phase-C/D teos-style 16-byte locator layers on top later). */
	locator = fmt_bitcoin_txid(tmpctx, commitment_txid);
	commitdir = path_join(tmpctx, justice, locator);
	if (!ensure_dir(commitdir))
		return false;

	ok = write_blob_set(channel, commitdir, blobs);
	if (ok)
		log_debug(channel->log,
			  "watchtower store: persisted %zu justice blobs for "
			  "commit %"PRIu64" (%s)",
			  tal_count(blobs), commitment_num, locator);

	/* Phase E (seam #3): the only other write_meta caller (wt_store_put_sweeps)
	 * has no producer yet, so without this the live breach path would never
	 * write the funding outpoint / remote to_self_delay that speculad needs for
	 * the exact RBF deadline.  current_commit_num here = our next local index. */
	if (ok) {
		char *chandir = channel_store_dir(tmpctx, ld, channel, NULL);
		if (!chandir
		    || !write_meta(channel, chandir, channel->next_index[LOCAL]))
			log_broken(channel->log,
				   "watchtower store: failed writing meta");
	}
	return ok;
}

bool wt_store_put_sweeps(struct lightningd *ld,
			 const struct channel *channel,
			 u64 current_commit_num,
			 struct watchtower_blob *const *blobs)
{
	char *sweeps, *chandir;

	sweeps = channel_store_dir(tmpctx, ld, channel, "sweeps");
	if (!sweeps)
		return false;
	if (!write_blob_set(channel, sweeps, blobs))
		return false;

	chandir = channel_store_dir(tmpctx, ld, channel, NULL);
	if (!chandir)
		return false;
	return write_meta(channel, chandir, current_commit_num);
}

bool wt_store_put_preempt(struct lightningd *ld,
			  const struct channel *channel,
			  u64 commit_num,
			  const struct bitcoin_tx *signed_commit_tx)
{
	char *preemptdir, *chandir, *armed;
	u8 *enc = tal_arr(tmpctx, u8, 0);

	preemptdir = channel_store_dir(tmpctx, ld, channel, "preempt");
	if (!preemptdir)
		return false;

	/* preempt/commit = LE u64 commit_num + our fully-signed 2-of-2 commitment. */
	towire_u64(&enc, commit_num);
	towire_bitcoin_tx(&enc, signed_commit_tx);
	if (!write_durable(preemptdir, "commit", enc, tal_bytelen(enc)))
		return false;

	/* A fresh clean advance completed -> we are NOT mid-round; clear any
	 * stale armed flag so speculad won't preempt-broadcast an active channel. */
	armed = path_join(tmpctx, preemptdir, "armed");
	if (unlink(armed) == 0)
		fsync_dir(preemptdir);

	/* Bump meta.current_commit_num UNCONDITIONALLY on every advance so the
	 * broadcast guard's reference is never stale (the CLASS-B sweeps path can
	 * early-return without a meta bump when a state has no sweepable output). */
	chandir = channel_store_dir(tmpctx, ld, channel, NULL);
	if (!chandir || !write_meta(channel, chandir, commit_num)) {
		log_broken(channel->log,
			   "watchtower store: preempt stored but meta bump failed");
		return false;
	}
	return true;
}

bool wt_store_set_preempt_armed(struct lightningd *ld,
				const struct channel *channel,
				bool armed)
{
	char *preemptdir, *path;

	preemptdir = channel_store_dir(tmpctx, ld, channel, "preempt");
	if (!preemptdir)
		return false;

	if (armed) {
		u8 *enc = tal_arr(tmpctx, u8, 0);
		u64 cn = channel->next_index[LOCAL]
			? channel->next_index[LOCAL] - 1 : 0;
		towire_u64(&enc, cn);
		return write_durable(preemptdir, "armed", enc, tal_bytelen(enc));
	}

	path = path_join(tmpctx, preemptdir, "armed");
	if (unlink(path) == 0)
		return fsync_dir(preemptdir);
	/* Already absent (ENOENT) is success; any other error is a failure. */
	return errno == ENOENT;
}

/* Load every blob_* file under dir, decoding each as a watchtower_blob. */
static struct watchtower_blob **load_blob_dir(const tal_t *ctx,
					      const struct channel *channel,
					      const char *dir)
{
	struct watchtower_blob **out = tal_arr(ctx, struct watchtower_blob *, 0);
	DIR *d = opendir(dir);
	struct dirent *ent;

	if (!d)
		return out;

	while ((ent = readdir(d)) != NULL) {
		char *path;
		u8 *contents;
		const u8 *cursor;
		size_t max;
		struct watchtower_blob *blob;

		if (strncmp(ent->d_name, "blob_", 5) != 0)
			continue;
		path = path_join(tmpctx, dir, ent->d_name);
		contents = grab_file_str(tmpctx, path);
		if (!contents) {
			log_broken(channel->log,
				   "watchtower store: cannot read %s", path);
			continue;
		}
		/* grab_file NUL-terminates; real length is tal_count-1. */
		cursor = contents;
		max = tal_count(contents) - 1;
		blob = wt_blob_decode(ctx, &cursor, &max);
		if (!blob) {
			log_broken(channel->log,
				   "watchtower store: corrupt blob %s", path);
			continue;
		}
		tal_arr_expand(&out, blob);
	}
	closedir(d);
	return out;
}

struct watchtower_blob **wt_store_load_justice(const tal_t *ctx,
					       struct lightningd *ld,
					       const struct channel *channel)
{
	struct watchtower_blob **out = tal_arr(ctx, struct watchtower_blob *, 0);
	char *chandir = tal_fmt(tmpctx, "%s/watchtower/%"PRIu64,
				ld->config_netdir, channel->dbid);
	char *justice = path_join(tmpctx, chandir, "justice");
	DIR *d = opendir(justice);
	struct dirent *ent;

	if (!d)
		return out;

	while ((ent = readdir(d)) != NULL) {
		char *commitdir;
		struct watchtower_blob **set;

		if (ent->d_name[0] == '.')
			continue;
		commitdir = path_join(tmpctx, justice, ent->d_name);
		set = load_blob_dir(ctx, channel, commitdir);
		for (size_t i = 0; i < tal_count(set); i++)
			tal_arr_expand(&out, set[i]);
	}
	closedir(d);
	return out;
}

struct watchtower_blob **wt_store_load_sweeps(const tal_t *ctx,
					      struct lightningd *ld,
					      const struct channel *channel)
{
	char *chandir = tal_fmt(tmpctx, "%s/watchtower/%"PRIu64,
				ld->config_netdir, channel->dbid);
	char *sweeps = path_join(tmpctx, chandir, "sweeps");
	return load_blob_dir(ctx, channel, sweeps);
}
