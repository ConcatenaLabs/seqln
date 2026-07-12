/* speculad -- the Specula keyless watchtower broadcaster (Phase C).
 *
 * A standalone, always-on, device-INDEPENDENT daemon (its own systemd unit, NOT
 * a CLN plugin, NOT spawned by lightningd).  It loads NO secret and runs NO
 * crypto.  It:
 *   1. reads the fsync-durable, secret-free watchtower store written by Phase B
 *      (documented on-disk format in lightningd/watchtower_store.h), reaching
 *      defensive posture purely from disk with no hsm_init (survives cold boot);
 *   2. watches the chain via elements-cli RPC (mirroring plugins/bcli.c: shell
 *      out to the configured CLI over the box's elementsd);
 *   3. on seeing a REVOKED commitment confirm on-chain (a breach), broadcasts
 *      the matching device-pre-signed CLASS-A justice blob(s) via
 *      sendrawtransaction, while the signing device is offline.
 *
 * REORG MODEL (see keyless-watchtower-design-specula): every blob binds only its
 * input outpoint, never a height, so a reorg never expires a blob -- it only
 * changes which stored blob is live and resets the depth clock.  speculad simply
 * re-polls every stored revoked-commitment txid each round: a re-confirm rebroad-
 * casts byte-identically (idempotent); a DIFFERENT revoked commitment surfacing
 * is matched to its own justice dir; the deadline is recomputed as confirmation
 * depth every round.  No finality timelock is ever used (anchoring supremacy).
 *
 * FEE (SINGLE|ACP): the CLASS-A justice blobs are SIGHASH_SINGLE|ANYONECANPAY
 * (Phase A) -- output 0 carries the full swept value and pays NO fee, so
 * speculad appends its OWN per-asset fee input (+ change) from a box-owned
 * fee-UTXO wallet in the channel asset and RBF-escalates toward the deadline,
 * never needing the device.  That coin selection needs the box fee wallet
 * (infra, not present on testnet), so it is the single documented SEAM below
 * (attach_fee_and_rbf()); this daemon otherwise runs the breach path end to end.
 *
 * CLASS-B honest-force-close sweeps + HTLC 2nd-stage: Phase B left store slots
 * (sweeps/) but no producer yet; speculad already loads them and is structured
 * so the CLASS-B broadcast drops into the same watch/broadcast loop.
 */
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <ccan/compiler/compiler.h>
#include <ccan/err/err.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/str.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <common/setup.h>
#include <common/utils.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <wire/wire.h>

/* ---- Decoupled store reader ---------------------------------------------- *
 * Byte-identical to lightningd/watchtower_store.c:wt_blob_decode's on-disk
 * layout (u8 kind, u64 commit_num, u32 output_index, amount_sat amount, u32
 * deadline_delta, u16 wscript_len, u8 wscript[], bitcoin_tx tx).  speculad
 * carries its own decoder so it needs ZERO lightningd/channel coupling. */
struct spd_blob {
	u8 kind;
	u64 commit_num;
	u32 output_index;
	struct amount_sat amount;
	u32 deadline_delta;
	u8 *wscript;
	struct bitcoin_tx *tx;
};

/* One revoked commitment we defend: its justice dir is named by the full
 * commitment txid hex (the locator we poll elementsd for). */
struct revoked_commit {
	char *locator;		/* 64-char commitment txid hex == dir name */
	char *dir;		/* <chandir>/justice/<locator> */
	struct spd_blob **blobs;/* CLASS-A justice set for this commitment */
	long confirmations;	/* recomputed each poll (depth clock) */
};

struct watched_channel {
	u64 dbid;
	char *chandir;			/* <netdir>/watchtower/<dbid> */
	u64 current_commit_num;		/* from meta (broadcast guard reference) */
	struct revoked_commit **revoked;/* CLASS-A, all revoked states */
	struct spd_blob **sweeps;	/* CLASS-B, current-state honest sweeps */
};

/* ---- Globals (config; all box-owned, no secrets) ------------------------- */
static const char **g_cli_base;	/* argv prefix: elements-cli + connection flags */
static volatile sig_atomic_t g_stop;

static void handle_sig(int s UNUSED)
{
	g_stop = 1;
}

static struct spd_blob *spd_blob_decode(const tal_t *ctx,
					const u8 **cursor, size_t *max)
{
	struct spd_blob *b = tal(ctx, struct spd_blob);
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

/* Load every blob_* file under dir (mirrors watchtower_store.c:load_blob_dir). */
static struct spd_blob **load_blob_dir(const tal_t *ctx, const char *dir)
{
	struct spd_blob **out = tal_arr(ctx, struct spd_blob *, 0);
	DIR *d = opendir(dir);
	struct dirent *ent;

	if (!d)
		return out;

	while ((ent = readdir(d)) != NULL) {
		char *path;
		u8 *contents;
		const u8 *cursor;
		size_t max;
		struct spd_blob *blob;

		if (strncmp(ent->d_name, "blob_", 5) != 0)
			continue;
		path = path_join(tmpctx, dir, ent->d_name);
		contents = grab_file_str(tmpctx, path);
		if (!contents) {
			fprintf(stderr, "speculad: cannot read %s\n", path);
			continue;
		}
		/* grab_file NUL-terminates; real length is tal_count-1. */
		cursor = contents;
		max = tal_count(contents) - 1;
		blob = spd_blob_decode(ctx, &cursor, &max);
		if (!blob) {
			fprintf(stderr, "speculad: corrupt blob %s\n", path);
			continue;
		}
		tal_arr_expand(&out, blob);
	}
	closedir(d);
	return out;
}

/* meta = LE u64 version, u64 dbid, u64 current_commit_num. */
static u64 read_meta_commit_num(const char *chandir)
{
	char *path = path_join(tmpctx, chandir, "meta");
	u8 *contents = grab_file_str(tmpctx, path);
	const u8 *cursor;
	size_t max;
	u64 version, dbid, commit_num;

	if (!contents)
		return 0;
	cursor = contents;
	max = tal_count(contents) - 1;
	version = fromwire_u64(&cursor, &max);
	dbid = fromwire_u64(&cursor, &max);
	commit_num = fromwire_u64(&cursor, &max);
	if (!cursor || version != 1)
		return 0;
	(void)dbid;
	return commit_num;
}

/* Enumerate <netdir>/watchtower/<dbid>/ into watched_channel records. */
static struct watched_channel **load_channels(const tal_t *ctx,
					      const char *netdir)
{
	struct watched_channel **chans
		= tal_arr(ctx, struct watched_channel *, 0);
	char *base = path_join(tmpctx, netdir, "watchtower");
	DIR *d = opendir(base);
	struct dirent *ent;

	if (!d)
		return chans;

	while ((ent = readdir(d)) != NULL) {
		char *chandir, *justice, *sweepsdir;
		struct stat st;
		struct watched_channel *c;
		DIR *jd;
		struct dirent *je;

		if (ent->d_name[0] == '.')
			continue;
		chandir = path_join(tmpctx, base, ent->d_name);
		if (stat(chandir, &st) != 0 || !S_ISDIR(st.st_mode))
			continue;

		c = tal(chans, struct watched_channel);
		c->dbid = strtoull(ent->d_name, NULL, 10);
		c->chandir = tal_strdup(c, chandir);
		c->current_commit_num = read_meta_commit_num(chandir);
		c->revoked = tal_arr(c, struct revoked_commit *, 0);

		sweepsdir = path_join(tmpctx, chandir, "sweeps");
		c->sweeps = load_blob_dir(c, sweepsdir);

		justice = path_join(tmpctx, chandir, "justice");
		jd = opendir(justice);
		if (jd) {
			while ((je = readdir(jd)) != NULL) {
				struct revoked_commit *rc;
				char *cdir;

				if (je->d_name[0] == '.')
					continue;
				cdir = path_join(tmpctx, justice, je->d_name);
				rc = tal(c, struct revoked_commit);
				rc->locator = tal_strdup(rc, je->d_name);
				rc->dir = tal_strdup(rc, cdir);
				rc->blobs = load_blob_dir(rc, cdir);
				rc->confirmations = 0;
				tal_arr_expand(&c->revoked, rc);
			}
			closedir(jd);
		}
		tal_arr_expand(&chans, c);
	}
	closedir(d);
	return chans;
}

/* ---- elements-cli RPC (fork/exec/pipe; no shell, box-controlled argv) ----- */
static char *run_cliv(const tal_t *ctx, const char **args)
{
	int pipefd[2];
	pid_t pid;
	char *out;
	char buf[4096];
	ssize_t n;
	int status;

	if (pipe(pipefd) != 0)
		return NULL;
	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return NULL;
	}
	if (pid == 0) {
		int dn;
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[1]);
		dn = open("/dev/null", O_WRONLY);
		if (dn >= 0) {
			dup2(dn, STDERR_FILENO);
			close(dn);
		}
		execvp(args[0], (char *const *)args);
		_exit(127);
	}
	close(pipefd[1]);
	out = tal_arr(ctx, char, 0);
	while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
		size_t old = tal_count(out);
		tal_resize(&out, old + n);
		memcpy(out + old, buf, n);
	}
	close(pipefd[0]);
	waitpid(pid, &status, 0);
	tal_resize(&out, tal_count(out) + 1);
	out[tal_count(out) - 1] = '\0';
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return tal_free(out);
	return out;
}

/* Build [cli_base..., method, extra..., NULL] and run it. */
static char *run_cli(const tal_t *ctx, const char *method,
		     const char **extra)
{
	const char **args = tal_arr(tmpctx, const char *, 0);
	size_t i;

	for (i = 0; i < tal_count(g_cli_base); i++)
		tal_arr_expand(&args, g_cli_base[i]);
	tal_arr_expand(&args, method);
	for (i = 0; extra && i < tal_count(extra); i++)
		tal_arr_expand(&args, extra[i]);
	tal_arr_expand(&args, (const char *)NULL);
	return run_cliv(ctx, args);
}

/* Minimal JSON scalar scrape: find "key" then the following integer. */
static long json_find_int(const char *s, const char *key)
{
	char *needle = tal_fmt(tmpctx, "\"%s\"", key);
	const char *p = s ? strstr(s, needle) : NULL;

	if (!p)
		return -1;
	p += strlen(needle);
	while (*p == ' ' || *p == ':')
		p++;
	if (*p != '-' && !isdigit((unsigned char)*p))
		return -1;
	return strtol(p, NULL, 10);
}

/* Confirmations of a txid (>=1 == confirmed; -1 == unknown/unconfirmed). */
static long rpc_tx_confirmations(const tal_t *ctx, const char *txid_hex)
{
	const char **extra = tal_arr(tmpctx, const char *, 2);
	char *res;
	long confs;

	extra[0] = txid_hex;
	extra[1] = "true";	/* verbose */
	res = run_cli(ctx, "getrawtransaction", extra);
	if (!res)
		return -1;
	confs = json_find_int(res, "confirmations");
	return confs;
}

static char *rpc_getbestblockhash(const tal_t *ctx)
{
	char *res = run_cli(ctx, "getbestblockhash", NULL);
	if (res) {
		/* strip trailing whitespace/newline */
		size_t len = strlen(res);
		while (len && (res[len - 1] == '\n' || res[len - 1] == '\r'
			       || res[len - 1] == ' '))
			res[--len] = '\0';
	}
	return res;
}

/* ---- Fee attach + RBF (the single documented box-fee-wallet SEAM) --------- *
 * Under SIGHASH_SINGLE|ANYONECANPAY the blob's output 0 already carries the
 * full swept value and pays no fee.  Production speculad here:
 *   (a) selects a per-asset fee UTXO (in the channel asset) from the box-owned,
 *       per-channel-reserved, rate-limited fee wallet;
 *   (b) appends it as input index >= 1 (+ change back to the fee wallet);
 *   (c) re-broadcasts at an escalating feerate keyed to the deadline
 *       (recomputed as confirmation depth after every reorg).
 * The fee wallet is box infra not present on testnet, so this returns the blob
 * unchanged (broadcast as-is) and the escalation is a no-op; the coin selection
 * is the ONLY missing piece of the end-to-end breach path.  Kept as a seam so
 * the SINGLE|ACP invariant (append only OWN inputs, never touch a user output)
 * lives in exactly one place. */
static const struct bitcoin_tx *attach_fee_and_rbf(const struct spd_blob *b,
						   long confirmations UNUSED)
{
	return b->tx;
}

static bool broadcast_blob(const struct spd_blob *b, long confirmations)
{
	const struct bitcoin_tx *tx = attach_fee_and_rbf(b, confirmations);
	u8 *raw = linearize_tx(tmpctx, tx);
	char *hex = tal_hexstr(tmpctx, raw, tal_bytelen(raw));
	const char **extra = tal_arr(tmpctx, const char *, 1);
	char *res;

	extra[0] = hex;
	res = run_cli(tmpctx, "sendrawtransaction", extra);
	/* Idempotent: elementsd returns the txid on accept AND on "already in
	 * mempool/chain"; a byte-identical rebroadcast on reorg re-confirm is
	 * therefore safe and expected.  We only warn on a hard reject. */
	if (!res)
		fprintf(stderr, "speculad: sendrawtransaction rejected for "
			"kind %u output %u\n", b->kind, b->output_index);
	return res != NULL;
}

/* ---- Sole-broadcaster lease (heartbeat, not a static lockfile) ------------ *
 * A standby speculad refuses to broadcast while a peer's heartbeat is fresh, so
 * two instances never double-RBF one fee input.  Heartbeat = atomically rewrite
 * <leasefile> with our pid each loop (bumping its mtime); a peer treats the
 * lease as free only once mtime is older than stale_secs, then takes over.
 * (Production: a fenced lease / quorum lock service; this file lease is the
 * single-box default.) */
static bool acquire_or_refresh_lease(const char *leasefile, unsigned stale_secs)
{
	struct stat st;
	char *tmp, *body;
	int fd;

	if (stat(leasefile, &st) == 0) {
		time_t now = time(NULL);
		char *owner = grab_file_str(tmpctx, leasefile);
		pid_t opid = owner ? (pid_t)atol(owner) : 0;

		if (opid != getpid() && (now - st.st_mtime) < (time_t)stale_secs)
			return false;	/* someone else holds a fresh lease */
	}

	tmp = tal_fmt(tmpctx, "%s.tmp.%d", leasefile, (int)getpid());
	body = tal_fmt(tmpctx, "%d\n", (int)getpid());
	fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0)
		return false;
	if (!write_all(fd, body, strlen(body))) {
		close_noerr(fd);
		unlink_noerr(tmp);
		return false;
	}
	if (close(fd) != 0) {
		unlink_noerr(tmp);
		return false;
	}
	if (rename(tmp, leasefile) != 0) {
		unlink_noerr(tmp);
		return false;
	}
	return true;
}

static void usage_and_exit(const char *argv0)
{
	fprintf(stderr,
		"usage: %s --netdir=DIR [--network=NET] [--poll-interval=SECS]\n"
		"          [--lease-file=PATH] [--lease-stale=SECS]\n"
		"          --cli=elements-cli [--cli=-datadir=/path] [--cli=...] ...\n"
		"\n"
		"speculad watches the Phase-B watchtower store under\n"
		"DIR/watchtower/<dbid>/ and, on a revoked commitment confirming,\n"
		"broadcasts the pre-signed justice blob(s) via the given CLI.\n"
		"Repeat --cli to build the full elements-cli invocation (path +\n"
		"connection flags).\n",
		argv0);
	exit(2);
}

int main(int argc, char *argv[])
{
	const char *netdir = NULL;
	const char *network = "sequentia-testnet";
	const char *leasefile = NULL;
	unsigned poll_interval = 15;
	unsigned lease_stale = 60;
	char *last_tip = NULL;
	const tal_t *top;

	common_setup(argv[0]);
	top = tal(NULL, char);
	g_cli_base = tal_arr(top, const char *, 0);

	for (int i = 1; i < argc; i++) {
		if (strstarts(argv[i], "--netdir="))
			netdir = argv[i] + strlen("--netdir=");
		else if (strstarts(argv[i], "--network="))
			network = argv[i] + strlen("--network=");
		else if (strstarts(argv[i], "--lease-file="))
			leasefile = argv[i] + strlen("--lease-file=");
		else if (strstarts(argv[i], "--poll-interval="))
			poll_interval = atoi(argv[i] + strlen("--poll-interval="));
		else if (strstarts(argv[i], "--lease-stale="))
			lease_stale = atoi(argv[i] + strlen("--lease-stale="));
		else if (strstarts(argv[i], "--cli="))
			tal_arr_expand(&g_cli_base,
				       tal_strdup(top, argv[i] + strlen("--cli=")));
		else
			usage_and_exit(argv[0]);
	}

	if (!netdir)
		usage_and_exit(argv[0]);
	if (tal_count(g_cli_base) == 0)
		tal_arr_expand(&g_cli_base, "elements-cli");
	if (!leasefile)
		leasefile = tal_fmt(top, "%s/watchtower/speculad.lease", netdir);

	chainparams = chainparams_for_network(network);
	if (!chainparams)
		errx(1, "speculad: unknown --network=%s (known: %s)",
		     network, chainparams_get_network_names(tmpctx));

	signal(SIGINT, handle_sig);
	signal(SIGTERM, handle_sig);
	signal(SIGPIPE, SIG_IGN);

	fprintf(stderr, "speculad: watching %s/watchtower (network %s), "
		"poll %us, lease %s\n", netdir, network, poll_interval,
		leasefile);

	while (!g_stop) {
		char *tip;
		bool may_broadcast, reorg_or_new;
		struct watched_channel **chans;

		clean_tmpctx();

		/* Reorg / new-tip detection: a best-block-hash change resets the
		 * depth clock; we re-poll every revoked txid regardless, so a
		 * reorg that surfaces a DIFFERENT revoked commitment is handled
		 * by matching that commitment's own justice dir. */
		tip = rpc_getbestblockhash(tmpctx);
		reorg_or_new = (!last_tip || !tip || !streq(last_tip, tip));
		if (reorg_or_new && tip) {
			tal_free(last_tip);
			last_tip = tal_strdup(top, tip);
		}

		/* Sole-broadcaster gate (failover via heartbeat staleness). */
		may_broadcast = acquire_or_refresh_lease(leasefile, lease_stale);

		chans = load_channels(tmpctx, netdir);
		for (size_t i = 0; i < tal_count(chans); i++) {
			struct watched_channel *c = chans[i];

			for (size_t j = 0; j < tal_count(c->revoked); j++) {
				struct revoked_commit *rc = c->revoked[j];
				long confs = rpc_tx_confirmations(tmpctx,
								  rc->locator);

				if (confs < 1)
					continue;	/* not (yet) on-chain */

				/* BREACH: a revoked commitment is confirmed.
				 * justice/ never holds the CURRENT state, so any
				 * confirmed locator here is provably a cheat. */
				rc->confirmations = confs;
				fprintf(stderr, "speculad: BREACH dbid=%"PRIu64
					" commit=%s confs=%ld -> broadcasting "
					"%zu justice blob(s)%s\n",
					c->dbid, rc->locator, confs,
					tal_count(rc->blobs),
					may_broadcast ? "" : " (SKIPPED: no lease)");
				if (!may_broadcast)
					continue;
				for (size_t k = 0; k < tal_count(rc->blobs); k++)
					broadcast_blob(rc->blobs[k], confs);
			}
		}

		if (g_stop)
			break;
		sleep(poll_interval);
	}

	fprintf(stderr, "speculad: shutting down\n");
	tal_free(top);
	common_shutdown();
	return 0;
}
