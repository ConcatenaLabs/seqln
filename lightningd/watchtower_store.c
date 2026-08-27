#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/str/str.h>
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

/* A blob set: the version, the count, then each blob. */
static void encode_blob_set(u8 **pptr, struct watchtower_blob *const *blobs)
{
	towire_u64(pptr, WT_BLOB_SET_VERSION);
	towire_u64(pptr, tal_count(blobs));
	for (size_t i = 0; i < tal_count(blobs); i++)
		wt_blob_encode(pptr, blobs[i]);
}

static struct watchtower_blob **decode_blob_set(const tal_t *ctx,
						const struct channel *channel,
						const char *what,
						const u8 **cursor, size_t *max)
{
	struct watchtower_blob **out = tal_arr(ctx, struct watchtower_blob *, 0);
	u64 version = fromwire_u64(cursor, max);
	u64 count = fromwire_u64(cursor, max);

	if (!*cursor || version != WT_BLOB_SET_VERSION) {
		log_broken(channel->log,
			   "watchtower store: %s: unknown blob set version %"PRIu64,
			   what, version);
		*cursor = NULL;
		return out;
	}
	for (u64 i = 0; i < count; i++) {
		struct watchtower_blob *blob = wt_blob_decode(ctx, cursor, max);

		if (!blob) {
			log_broken(channel->log,
				   "watchtower store: corrupt blob set %s", what);
			break;
		}
		tal_arr_expand(&out, blob);
	}
	return out;
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

/* mkdir a single component.  A directory that already exists needs nothing:
 * fsyncing its parent on every put, as this used to, was most of what the
 * store cost per commitment step. */
static bool ensure_dir(const char *path)
{
	char *parent;

	if (mkdir(path, 0700) != 0)
		return errno == EEXIST;

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

/* The channel dir without creating anything: for reads. */
static char *channel_dir_path(const tal_t *ctx,
			      struct lightningd *ld,
			      const struct channel *channel)
{
	return tal_fmt(ctx, "%s/watchtower/%"PRIu64,
		       ld->config_netdir, channel->dbid);
}

/* Durable file write: temp -> fsync(file) -> rename -> fsync(dir), exactly as
 * hsmd fsyncs hsm_secret (hsmd/hsmd.c:maybe_create_new_hsm).
 *
 * Every fsync is a device flush, and each costs the same whether or not one
 * just ran, so the number of files a commitment step writes is what bounds
 * how fast a payment can settle.  The layout keeps that at one file per put:
 * the state bundle, or one justice file. */
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

bool wt_store_enabled(const struct lightningd *ld)
{
	return ld->config.watchtower_store_on;
}

/* ---- the state bundle ---------------------------------------------------- */

/* Everything about a channel's CURRENT state that the store holds, as one
 * file, so a state advance is one durable write. */
struct wt_state {
	u64 current_commit_num;
	struct watchtower_blob **sweeps;
	/* NULL: no preempt commitment stored. */
	struct bitcoin_tx *preempt_tx;
	u64 preempt_commit_num;
	bool armed;
	u64 armed_commit_num;
};

static void encode_state(u8 **pptr,
			 const struct channel *channel,
			 const struct wt_state *st)
{
	towire_u64(pptr, WT_STATE_VERSION);
	towire_u64(pptr, channel->dbid);
	towire_u64(pptr, st->current_commit_num);
	towire_bitcoin_outpoint(pptr, &channel->funding);
	towire_u16(pptr, channel->channel_info.their_config.to_self_delay);
	encode_blob_set(pptr, st->sweeps);
	towire_bool(pptr, st->preempt_tx != NULL);
	if (st->preempt_tx) {
		towire_u64(pptr, st->preempt_commit_num);
		towire_bitcoin_tx(pptr, st->preempt_tx);
	}
	towire_bool(pptr, st->armed);
	if (st->armed)
		towire_u64(pptr, st->armed_commit_num);
}

static struct wt_state *empty_state(const tal_t *ctx)
{
	struct wt_state *st = tal(ctx, struct wt_state);

	st->current_commit_num = 0;
	st->sweeps = tal_arr(st, struct watchtower_blob *, 0);
	st->preempt_tx = NULL;
	st->preempt_commit_num = 0;
	st->armed = false;
	st->armed_commit_num = 0;
	return st;
}

/* Read the state file; NULL when there is none (or it does not decode). */
static struct wt_state *read_state_file(const tal_t *ctx,
					const struct channel *channel,
					const char *chandir)
{
	char *path = path_join(tmpctx, chandir, WT_STATE_FILE);
	u8 *contents = grab_file_str(tmpctx, path);
	const u8 *cursor;
	size_t max;
	u64 version, dbid;
	struct bitcoin_outpoint funding;
	struct wt_state *st;

	if (!contents)
		return NULL;
	st = empty_state(ctx);
	cursor = contents;
	/* grab_file NUL-terminates; real length is tal_count-1. */
	max = tal_count(contents) - 1;
	version = fromwire_u64(&cursor, &max);
	dbid = fromwire_u64(&cursor, &max);
	st->current_commit_num = fromwire_u64(&cursor, &max);
	fromwire_bitcoin_outpoint(&cursor, &max, &funding);
	(void)fromwire_u16(&cursor, &max);
	if (!cursor || version != WT_STATE_VERSION || dbid != channel->dbid) {
		log_broken(channel->log,
			   "watchtower store: %s: bad state file (version %"
			   PRIu64", dbid %"PRIu64")", path, version, dbid);
		return tal_free(st);
	}
	st->sweeps = decode_blob_set(st, channel, path, &cursor, &max);
	if (fromwire_bool(&cursor, &max)) {
		st->preempt_commit_num = fromwire_u64(&cursor, &max);
		st->preempt_tx = fromwire_bitcoin_tx(st, &cursor, &max);
	}
	st->armed = fromwire_bool(&cursor, &max);
	if (st->armed)
		st->armed_commit_num = fromwire_u64(&cursor, &max);
	if (!cursor) {
		log_broken(channel->log,
			   "watchtower store: %s: truncated state file", path);
		return tal_free(st);
	}
	return st;
}

/* Load every blob_* file under dir: the layout before the set file. */
static struct watchtower_blob **load_legacy_blob_files(const tal_t *ctx,
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

/* Load a blob set kept as a directory: its `blobs` set file when present,
 * else its blob_* files. */
static struct watchtower_blob **load_blob_dir(const tal_t *ctx,
					      const struct channel *channel,
					      const char *dir)
{
	char *setpath = path_join(tmpctx, dir, WT_BLOB_SET_FILE);
	u8 *contents = grab_file_str(tmpctx, setpath);

	if (contents) {
		const u8 *cursor = contents;
		size_t max = tal_count(contents) - 1;

		return decode_blob_set(ctx, channel, setpath, &cursor, &max);
	}
	return load_legacy_blob_files(ctx, channel, dir);
}

/* The state as stores before the bundle kept it: meta, sweeps/, preempt/. */
static struct wt_state *load_legacy_state(const tal_t *ctx,
					  const struct channel *channel,
					  const char *chandir)
{
	struct wt_state *st = empty_state(ctx);
	u8 *contents;
	const u8 *cursor;
	size_t max;

	contents = grab_file_str(tmpctx, path_join(tmpctx, chandir, "meta"));
	if (contents) {
		u64 version;

		cursor = contents;
		max = tal_count(contents) - 1;
		version = fromwire_u64(&cursor, &max);
		(void)fromwire_u64(&cursor, &max); /* dbid */
		st->current_commit_num = fromwire_u64(&cursor, &max);
		if (!cursor || (version != 1 && version != 2))
			st->current_commit_num = 0;
	}
	tal_free(st->sweeps);
	st->sweeps = load_blob_dir(st, channel,
				   path_join(tmpctx, chandir, "sweeps"));
	contents = grab_file_str(tmpctx,
				 path_join(tmpctx, chandir, "preempt/commit"));
	if (contents) {
		cursor = contents;
		max = tal_count(contents) - 1;
		st->preempt_commit_num = fromwire_u64(&cursor, &max);
		st->preempt_tx = fromwire_bitcoin_tx(st, &cursor, &max);
		if (!cursor) {
			st->preempt_tx = tal_free(st->preempt_tx);
			st->preempt_commit_num = 0;
		}
	}
	contents = grab_file_str(tmpctx,
				 path_join(tmpctx, chandir, "preempt/armed"));
	if (contents) {
		cursor = contents;
		max = tal_count(contents) - 1;
		st->armed_commit_num = fromwire_u64(&cursor, &max);
		st->armed = cursor != NULL;
	}
	return st;
}

static struct wt_state *load_state(const tal_t *ctx,
				   const struct channel *channel,
				   const char *chandir)
{
	struct wt_state *st = read_state_file(ctx, channel, chandir);

	if (st)
		return st;
	return load_legacy_state(ctx, channel, chandir);
}

/* Once the bundle is durable, the files of the earlier layout say nothing a
 * reader wants (readers take the bundle first); clear them so the directory
 * describes one layout.  Best effort, no flush: a leftover is harmless. */
static void remove_legacy_state(const char *chandir)
{
	const char *subs[] = { "sweeps", "preempt" };

	unlink_noerr(path_join(tmpctx, chandir, "meta"));
	for (size_t i = 0; i < ARRAY_SIZE(subs); i++) {
		char *dir = path_join(tmpctx, chandir, subs[i]);
		DIR *d = opendir(dir);
		struct dirent *ent;

		if (!d)
			continue;
		while ((ent = readdir(d)) != NULL) {
			if (streq(ent->d_name, ".") || streq(ent->d_name, ".."))
				continue;
			unlink_noerr(path_join(tmpctx, dir, ent->d_name));
		}
		closedir(d);
		rmdir(dir);
	}
}

/* Write the bundle durably: one file, one directory. */
static bool write_state(struct lightningd *ld,
			const struct channel *channel,
			const struct wt_state *st)
{
	char *chandir = channel_store_dir(tmpctx, ld, channel, NULL);
	u8 *enc = tal_arr(tmpctx, u8, 0);

	if (!chandir)
		return false;
	encode_state(&enc, channel, st);
	if (!write_durable(chandir, WT_STATE_FILE, enc, tal_bytelen(enc))) {
		log_broken(channel->log,
			   "watchtower store: failed writing %s/%s: %s",
			   chandir, WT_STATE_FILE, strerror(errno));
		return false;
	}
	remove_legacy_state(chandir);
	return true;
}

bool wt_store_put_advance(struct lightningd *ld,
			  const struct channel *channel,
			  u64 commit_num,
			  struct watchtower_blob *const *sweeps,
			  const struct bitcoin_tx *preempt_tx)
{
	char *chandir = channel_store_dir(tmpctx, ld, channel, NULL);
	struct wt_state *st;

	if (!chandir)
		return false;
	st = load_state(tmpctx, channel, chandir);
	st->current_commit_num = commit_num;
	if (sweeps) {
		tal_free(st->sweeps);
		st->sweeps = tal_dup_talarr(st, struct watchtower_blob *, sweeps);
	}
	if (preempt_tx) {
		tal_free(st->preempt_tx);
		st->preempt_tx = clone_bitcoin_tx(st, preempt_tx);
		st->preempt_commit_num = commit_num;
		/* A clean advance disarms. */
		st->armed = false;
		st->armed_commit_num = 0;
	}
	return write_state(ld, channel, st);
}

bool wt_store_put_sweeps(struct lightningd *ld,
			 const struct channel *channel,
			 u64 current_commit_num,
			 struct watchtower_blob *const *blobs)
{
	return wt_store_put_advance(ld, channel, current_commit_num, blobs, NULL);
}

bool wt_store_put_preempt(struct lightningd *ld,
			  const struct channel *channel,
			  u64 commit_num,
			  const struct bitcoin_tx *signed_commit_tx)
{
	return wt_store_put_advance(ld, channel, commit_num, NULL,
				    signed_commit_tx);
}

bool wt_store_set_preempt_armed(struct lightningd *ld,
				const struct channel *channel,
				bool armed)
{
	char *chandir = channel_store_dir(tmpctx, ld, channel, NULL);
	struct wt_state *st;

	if (!chandir)
		return false;
	st = load_state(tmpctx, channel, chandir);
	st->armed = armed;
	st->armed_commit_num = armed && channel->next_index[LOCAL]
		? channel->next_index[LOCAL] - 1 : 0;
	return write_state(ld, channel, st);
}

struct watchtower_blob **wt_store_load_sweeps(const tal_t *ctx,
					      struct lightningd *ld,
					      const struct channel *channel)
{
	char *chandir = channel_dir_path(tmpctx, ld, channel);
	struct wt_state *st = load_state(tmpctx, channel, chandir);

	return tal_steal(ctx, st->sweeps);
}

/* ---- justice sets --------------------------------------------------------- */

bool wt_store_put_justice(struct lightningd *ld,
			  const struct channel *channel,
			  const struct bitcoin_txid *commitment_txid,
			  u64 commitment_num,
			  struct watchtower_blob *const *blobs)
{
	char *justice = channel_store_dir(tmpctx, ld, channel, "justice");
	char *locator;
	u8 *enc = tal_arr(tmpctx, u8, 0);

	if (!justice)
		return false;
	locator = fmt_bitcoin_txid(tmpctx, commitment_txid);
	encode_blob_set(&enc, blobs);
	if (!write_durable(justice, locator, enc, tal_bytelen(enc))) {
		log_broken(channel->log,
			   "watchtower store: failed writing %s/%s: %s",
			   justice, locator, strerror(errno));
		return false;
	}
	log_debug(channel->log,
		  "watchtower store: persisted %zu justice blobs for "
		  "commit %"PRIu64" (%s)",
		  tal_count(blobs), commitment_num, locator);
	return true;
}

struct watchtower_blob **wt_store_load_justice(const tal_t *ctx,
					       struct lightningd *ld,
					       const struct channel *channel)
{
	struct watchtower_blob **out = tal_arr(ctx, struct watchtower_blob *, 0);
	char *chandir = channel_dir_path(tmpctx, ld, channel);
	char *justice = path_join(tmpctx, chandir, "justice");
	DIR *d = opendir(justice);
	struct dirent *ent;

	if (!d)
		return out;
	while ((ent = readdir(d)) != NULL) {
		char *path;
		struct stat st;
		struct watchtower_blob **set;

		if (ent->d_name[0] == '.')
			continue;
		path = path_join(tmpctx, justice, ent->d_name);
		if (stat(path, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			/* A commitment stored before justice sets were files. */
			set = load_blob_dir(ctx, channel, path);
		} else {
			u8 *contents = grab_file_str(tmpctx, path);
			const u8 *cursor = contents;
			size_t max;

			if (!contents) {
				log_broken(channel->log,
					   "watchtower store: cannot read %s",
					   path);
				continue;
			}
			max = tal_count(contents) - 1;
			set = decode_blob_set(ctx, channel, path, &cursor, &max);
		}
		for (size_t i = 0; i < tal_count(set); i++)
			tal_arr_expand(&out, set[i]);
	}
	closedir(d);
	return out;
}
