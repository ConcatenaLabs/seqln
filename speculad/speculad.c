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
 * CLASS-B honest-force-close sweeps + HTLC 2nd-stage: Phase E2 added the
 * producer -- lightningd/onchain_presign.c device-master-signs the current-state
 * honest-close set (kind 3 to_local-delayed + kind 4 offered-HTLC-timeout) at
 * every commitment advance, and the kind 5 HTLC-success sweep at fulfill (the
 * JBA fulfill hard-gate), writing them to the sweeps/ store slot this daemon
 * already loads.  It drops into the same watch/broadcast loop as the justice
 * set.  STILL A SEAM: kind 6 (remote_htlc_to_us, peer-honest-close HTLC sweep)
 * needs the remote-commitment HTLC outpoints threaded from channeld's
 * SENDING_COMMITSIG path first (lightningd lacks the remote commitment tx).
 */
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/compiler/compiler.h>
#include <ccan/err/err.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <ccan/str/str.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <common/presign_templates.h>	/* enum wt_tmpl_kind (stable on-disk u8) */
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
	/* Phase E (seam #3), from meta v2 (0 when meta is v1/absent): */
	struct bitcoin_outpoint funding;   /* funding outpoint (preempt funding-watch) */
	u32 remote_to_self_delay;	   /* exact RBF deadline window (CSV) */
	/* Phase F preemptive close (withhold-revoke / JBA defense): */
	struct bitcoin_tx *preempt_tx;	   /* OUR fully-signed current commitment */
	u64 preempt_commit_num;		   /* the commitment num it names */
	bool preempt_armed;		   /* device-down-mid-round flag present */
	u64 preempt_armed_commit_num;	   /* the commit_num the arm was set for */
};

/* ---- Globals (config; all box-owned, no secrets) ------------------------- */
static const char **g_cli_base;	/* argv prefix: elements-cli + connection flags */
static const char **g_fee_cli_base;	/* g_cli_base + -rpcwallet=<fee wallet> */
static const char *g_fee_wallet;	/* NULL == no fee wallet on this box (seam) */
static volatile sig_atomic_t g_stop;

/* Fee / RBF policy (all overridable on the command line). */
static u32 g_fee_base_perkw = FEERATE_FLOOR;	/* ~1 unit/vB floor */
static u32 g_fee_max_perkw  = 25000;		/* ceiling as the deadline nears */
static u32 g_assumed_csv    = 144;		/* deadline window when meta lacks
						 * remote to_self_delay (SEAM) */

/* Opt-in RBF (BIP125) on the tower's own fee input so each escalating re-fund
 * replaces the prior broadcast. */
#define SPD_RBF_SEQUENCE 0xFFFFFFFDU
/* Never leave a change output below this (drop-to-fee handled by caller). */
#define SPD_DUST_SAT AMOUNT_SAT(1000)

/* Persistent (cross-poll) per-blob state: the chosen fee UTXO (reused across
 * RBF rungs so each replacement keeps the SAME inputs and only raises the fee),
 * the escalation rung, the last broadcast txid, and the confirmed flag (once the
 * justice tx confirms we STOP re-broadcasting -- the broadcast de-dup). */
struct justice_state {
	char *key;			/* "<locator>:<output_index>:<kind>" */
	bool have_feeutxo;
	struct bitcoin_outpoint feeutxo;
	u64 feeutxo_val;		/* satoshis (exact) */
	u8 *feeutxo_spk;		/* fee UTXO scriptPubKey (change goes back here) */
	u32 rung;			/* RBF escalation counter */
	char *broadcast_txid;		/* last justice txid we broadcast */
};
static struct justice_state **g_states;	/* persistent registry */
static const tal_t *g_state_ctx;	/* owns g_states + entries (== top) */

static void handle_sig(int s UNUSED)
{
	g_stop = 1;
}

static struct justice_state *spd_get_state(const char *key)
{
	struct justice_state *st;

	for (size_t i = 0; i < tal_count(g_states); i++)
		if (streq(g_states[i]->key, key))
			return g_states[i];

	st = tal(g_state_ctx, struct justice_state);
	st->key = tal_strdup(st, key);
	st->have_feeutxo = false;
	st->feeutxo_val = 0;
	st->feeutxo_spk = NULL;
	st->rung = 0;
	st->broadcast_txid = NULL;
	tal_arr_expand(&g_states, st);
	return st;
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

/* A blob set as watchtower_store.c writes it: u64 version, u64 count, then
 * the blobs. */
#define WT_BLOB_SET_VERSION 1
#define WT_BLOB_SET_FILE "blobs"
#define WT_STATE_VERSION 3
#define WT_STATE_FILE "state"

static struct spd_blob **decode_blob_set(const tal_t *ctx, const char *what,
					 const u8 **cursor, size_t *max)
{
	struct spd_blob **out = tal_arr(ctx, struct spd_blob *, 0);
	u64 version = fromwire_u64(cursor, max);
	u64 count = fromwire_u64(cursor, max);

	if (!*cursor || version != WT_BLOB_SET_VERSION) {
		fprintf(stderr, "speculad: %s: unknown blob set version %"PRIu64"\n",
			what, version);
		*cursor = NULL;
		return out;
	}
	for (u64 i = 0; i < count; i++) {
		struct spd_blob *blob = spd_blob_decode(ctx, cursor, max);

		if (!blob) {
			fprintf(stderr, "speculad: corrupt blob set %s\n", what);
			break;
		}
		tal_arr_expand(&out, blob);
	}
	return out;
}

/* Load a blob-set FILE. */
static struct spd_blob **load_blob_file(const tal_t *ctx, const char *path)
{
	u8 *contents = grab_file_str(tmpctx, path);
	const u8 *cursor = contents;
	size_t max;

	if (!contents) {
		fprintf(stderr, "speculad: cannot read %s\n", path);
		return tal_arr(ctx, struct spd_blob *, 0);
	}
	/* grab_file NUL-terminates; real length is tal_count-1. */
	max = tal_count(contents) - 1;
	return decode_blob_set(ctx, path, &cursor, &max);
}

/* Load a blob set kept as a DIRECTORY (the layouts before justice sets were
 * files, mirrors watchtower_store.c:load_blob_dir): its `blobs` set file when
 * present, else every blob_* file. */
static struct spd_blob **load_blob_dir(const tal_t *ctx, const char *dir)
{
	struct spd_blob **out;
	char *setpath = path_join(tmpctx, dir, WT_BLOB_SET_FILE);
	DIR *d;
	struct dirent *ent;

	if (access(setpath, R_OK) == 0)
		return load_blob_file(ctx, setpath);

	out = tal_arr(ctx, struct spd_blob *, 0);
	d = opendir(dir);
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

/* The current-state bundle <chandir>/state (watchtower_store.h): meta fields,
 * the sweep set, the preempt commitment, the armed flag.  Fills the channel's
 * fields; returns false when there is no bundle (an earlier layout, read by
 * the caller's fallbacks) or it does not decode. */
static bool read_state(struct watched_channel *c, const char *chandir)
{
	char *path = path_join(tmpctx, chandir, WT_STATE_FILE);
	u8 *contents = grab_file_str(tmpctx, path);
	const u8 *cursor;
	size_t max;
	u64 version, dbid;
	u16 to_self_delay;

	if (!contents)
		return false;
	cursor = contents;
	max = tal_count(contents) - 1;
	version = fromwire_u64(&cursor, &max);
	dbid = fromwire_u64(&cursor, &max);
	c->current_commit_num = fromwire_u64(&cursor, &max);
	fromwire_bitcoin_outpoint(&cursor, &max, &c->funding);
	to_self_delay = fromwire_u16(&cursor, &max);
	if (!cursor || version != WT_STATE_VERSION || dbid != c->dbid) {
		fprintf(stderr, "speculad: %s: bad state file (version %"PRIu64
			", dbid %"PRIu64")\n", path, version, dbid);
		return false;
	}
	c->remote_to_self_delay = to_self_delay;
	c->sweeps = decode_blob_set(c, path, &cursor, &max);
	c->preempt_tx = NULL;
	c->preempt_commit_num = 0;
	if (fromwire_bool(&cursor, &max)) {
		c->preempt_commit_num = fromwire_u64(&cursor, &max);
		c->preempt_tx = fromwire_bitcoin_tx(c, &cursor, &max);
	}
	c->preempt_armed = fromwire_bool(&cursor, &max);
	c->preempt_armed_commit_num = c->preempt_armed
		? fromwire_u64(&cursor, &max) : 0;
	if (!cursor) {
		fprintf(stderr, "speculad: %s: truncated state file\n", path);
		return false;
	}
	return true;
}

/* meta = LE u64 version, u64 dbid, u64 current_commit_num[, v2: bitcoin_outpoint
 * funding, u16 remote_to_self_delay].  Fills *funding / *to_self_delay from a v2
 * meta (left zeroed for v1/absent).  Returns current_commit_num (0 on absence). */
static u64 read_meta(const char *chandir, struct bitcoin_outpoint *funding,
		     u32 *to_self_delay)
{
	char *path = path_join(tmpctx, chandir, "meta");
	u8 *contents = grab_file_str(tmpctx, path);
	const u8 *cursor;
	size_t max;
	u64 version, dbid, commit_num;

	memset(funding, 0, sizeof(*funding));
	*to_self_delay = 0;

	if (!contents)
		return 0;
	cursor = contents;
	max = tal_count(contents) - 1;
	version = fromwire_u64(&cursor, &max);
	dbid = fromwire_u64(&cursor, &max);
	commit_num = fromwire_u64(&cursor, &max);
	if (!cursor || (version != 1 && version != 2))
		return 0;
	(void)dbid;
	if (version >= 2) {
		fromwire_bitcoin_outpoint(&cursor, &max, funding);
		*to_self_delay = fromwire_u16(&cursor, &max);
		if (!cursor) {		/* truncated v2 -> treat as bare */
			memset(funding, 0, sizeof(*funding));
			*to_self_delay = 0;
		}
	}
	return commit_num;
}

/* Phase F: read the preempt slot <chandir>/preempt/commit = LE u64 commit_num +
 * bitcoin_tx (OUR fully-signed current commitment).  Fills *commit_num + *tx
 * (tal'd off ctx); returns true iff decoded. */
static bool read_preempt(const tal_t *ctx, const char *chandir,
			 u64 *commit_num, struct bitcoin_tx **tx)
{
	char *path = path_join(tmpctx, chandir, "preempt/commit");
	u8 *contents = grab_file_str(tmpctx, path);
	const u8 *cursor;
	size_t max;

	*tx = NULL;
	if (!contents)
		return false;
	cursor = contents;
	max = tal_count(contents) - 1;
	*commit_num = fromwire_u64(&cursor, &max);
	*tx = fromwire_bitcoin_tx(ctx, &cursor, &max);
	if (!cursor) {
		*tx = tal_free(*tx);
		return false;
	}
	return true;
}

/* Phase F: read the preempt "armed" flag <chandir>/preempt/armed (presence ==
 * armed; the file's LE u64 records the commit_num it was armed for). */
static bool read_preempt_armed(const char *chandir, u64 *armed_commit_num)
{
	char *path = path_join(tmpctx, chandir, "preempt/armed");
	u8 *contents = grab_file_str(tmpctx, path);
	const u8 *cursor;
	size_t max;

	*armed_commit_num = 0;
	if (!contents)
		return false;
	cursor = contents;
	max = tal_count(contents) - 1;
	*armed_commit_num = fromwire_u64(&cursor, &max);
	return cursor != NULL;
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
		c->revoked = tal_arr(c, struct revoked_commit *, 0);
		if (!read_state(c, chandir)) {
			/* The layout before the state bundle: meta beside
			 * sweeps/ and preempt/. */
			c->current_commit_num = read_meta(chandir, &c->funding,
							  &c->remote_to_self_delay);
			/* Phase F preempt slot + arm flag (both inert when absent). */
			c->preempt_tx = NULL;
			c->preempt_commit_num = 0;
			if (read_preempt(c, chandir, &c->preempt_commit_num,
					 &c->preempt_tx))
				c->preempt_tx = tal_steal(c, c->preempt_tx);
			c->preempt_armed = read_preempt_armed(chandir,
							      &c->preempt_armed_commit_num);
			sweepsdir = path_join(tmpctx, chandir, "sweeps");
			c->sweeps = load_blob_dir(c, sweepsdir);
		}

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
				/* One set file per revoked commitment; a
				 * directory is the earlier layout. */
				if (stat(cdir, &st) == 0 && S_ISDIR(st.st_mode))
					rc->blobs = load_blob_dir(rc, cdir);
				else
					rc->blobs = load_blob_file(rc, cdir);
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

static char *json_find_string(const tal_t *ctx, const char *s, const char *key);

/* Tri-state of a specific outpoint in the CONFIRMED UTXO set (gettxout with
 * include_mempool=false). */
enum spd_txout_state {
	SPD_TXOUT_UNSPENT,	/* still in the confirmed UTXO set */
	SPD_TXOUT_SPENT,	/* gone (spent or never existed): gettxout -> null */
	SPD_TXOUT_UNKNOWN,	/* RPC error: be conservative, keep defending */
};

/* Phase E (seam #2): reorg-safe de-dup gate.  gettxout [txid, vout, false]
 * queries ONLY the confirmed UTXO set: a non-null result means the outpoint is
 * still unspent (justice not landed, or a reorg re-exposed it -> keep/resume
 * broadcasting); the literal 'null' (exit 0) means spent/absent -> done for THIS
 * round only, NEVER latched, so a later reorg re-exposing it auto-resumes.  An
 * RPC error (run_cli -> NULL) is UNKNOWN -> conservatively keep defending. */
static enum spd_txout_state rpc_txout_state(const tal_t *ctx,
					    const char *txid_hex, u32 vout)
{
	const char **extra = tal_arr(tmpctx, const char *, 3);
	char *res, *best;

	extra[0] = txid_hex;
	extra[1] = tal_fmt(tmpctx, "%u", vout);
	extra[2] = "false";		/* include_mempool=false: confirmed set only */
	res = run_cli(ctx, "gettxout", extra);
	if (!res)
		return SPD_TXOUT_UNKNOWN;
	/* An unspent txout prints an object carrying "bestblock"/"scriptPubKey";
	 * a spent/absent one prints the bare literal 'null'. */
	best = json_find_string(tmpctx, res, "bestblock");
	if (best)
		return SPD_TXOUT_UNSPENT;
	return SPD_TXOUT_SPENT;
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

/* Current chain tip height (elementsd getblockcount prints a bare integer).
 * Returns -1 on RPC failure (callers then skip the CLTV pre-check and let the
 * mempool be the nLocktime authority). */
static long rpc_getblockcount(const tal_t *ctx)
{
	char *res = run_cli(ctx, "getblockcount", NULL);
	long h;

	if (!res)
		return -1;
	while (*res == ' ' || *res == '\n' || *res == '\r')
		res++;
	if (*res != '-' && !isdigit((unsigned char)*res))
		return -1;
	h = strtol(res, NULL, 10);
	return h;
}

/* Build [fee_cli_base..., method, extra..., NULL] and run it.  fee_cli_base is
 * g_cli_base plus -rpcwallet=<fee wallet>; falls back to g_cli_base when no fee
 * wallet is configured (only ever reached by callers guarded on g_fee_wallet). */
static char *run_cli_wallet(const tal_t *ctx, const char *method,
			    const char **extra)
{
	const char **args = tal_arr(tmpctx, const char *, 0);
	const char **base = g_fee_cli_base ? g_fee_cli_base : g_cli_base;
	size_t i;

	for (i = 0; i < tal_count(base); i++)
		tal_arr_expand(&args, base[i]);
	tal_arr_expand(&args, method);
	for (i = 0; extra && i < tal_count(extra); i++)
		tal_arr_expand(&args, extra[i]);
	tal_arr_expand(&args, (const char *)NULL);
	return run_cliv(ctx, args);
}

/* Extract the string value following "key":"..." (txid / scriptPubKey / hex). */
static char *json_find_string(const tal_t *ctx, const char *s, const char *key)
{
	char *needle = tal_fmt(tmpctx, "\"%s\"", key);
	const char *p = s ? strstr(s, needle) : NULL;
	const char *start;

	if (!p)
		return NULL;
	p += strlen(needle);
	while (*p == ' ' || *p == ':')
		p++;
	if (*p != '"')
		return NULL;
	start = ++p;
	while (*p && *p != '"')
		p++;
	if (*p != '"')
		return NULL;
	return tal_strndup(ctx, start, p - start);
}

/* Parse the BTC-decimal number after "key": into satoshis, EXACTLY (string
 * parse, no float rounding -- an off-by-one sat makes the elements tx invalid).
 * Returns false if absent, negative (unblindable) or malformed. */
static bool json_find_btc_sat(const char *s, const char *key, u64 *sat_out)
{
	char *needle = tal_fmt(tmpctx, "\"%s\"", key);
	const char *p = s ? strstr(s, needle) : NULL;
	u64 whole = 0, frac = 0;
	int fracdigits = 0;

	if (!p)
		return false;
	p += strlen(needle);
	while (*p == ' ' || *p == ':')
		p++;
	if (*p == '-')
		return false;
	if (!isdigit((unsigned char)*p))
		return false;
	while (isdigit((unsigned char)*p))
		whole = whole * 10 + (*p++ - '0');
	if (*p == '.') {
		p++;
		while (isdigit((unsigned char)*p)) {
			if (fracdigits < 8)
				frac = frac * 10 + (*p - '0');
			fracdigits++;
			p++;
		}
	}
	while (fracdigits < 8) {		/* pad to 8 decimals == satoshis */
		frac *= 10;
		fracdigits++;
	}
	*sat_out = whole * 100000000ULL + frac;
	return true;
}

/* Look for "key": true within a (bounded) JSON fragment. */
static bool json_bool_true(const char *s, const char *key)
{
	char *needle = tal_fmt(tmpctx, "\"%s\"", key);
	const char *p = s ? strstr(s, needle) : NULL;

	if (!p)
		return false;
	p += strlen(needle);
	while (*p == ' ' || *p == ':')
		p++;
	return strncmp(p, "true", 4) == 0;
}

/* The RPC-display asset hex (reversed 32-byte tag) of the 33-byte version+tag. */
static char *asset33_to_rpchex(const tal_t *ctx, const u8 asset33[33])
{
	u8 tag[32];

	memcpy(tag, asset33 + 1, 32);
	reverse_bytes(tag, 32);		/* internal (wally) -> display order */
	return tal_hexstr(ctx, tag, 32);
}

/* Select one spendable, confirmed fee UTXO in @asset_hex with value >= min_sat
 * from the fee wallet (listunspent asset-filtered).  Confirmed-only keeps RBF
 * replacements from adding new *unconfirmed* inputs (BIP125). */
static bool pick_fee_utxo(const tal_t *ctx, const char *asset_hex, u64 min_sat,
			  struct bitcoin_outpoint *out_op, u64 *out_val,
			  u8 **out_spk)
{
	const char **extra = tal_arr(tmpctx, const char *, 5);
	char *res;
	const char *p;

	extra[0] = "1";			/* minconf: confirmed only */
	extra[1] = "9999999";		/* maxconf */
	extra[2] = "[]";		/* addresses */
	extra[3] = "false";		/* include_unsafe */
	extra[4] = tal_fmt(tmpctx, "{\"asset\":\"%s\"}", asset_hex);
	res = run_cli_wallet(tmpctx, "listunspent", extra);
	if (!res)
		return false;

	/* Walk each result object (each begins with its "txid" field). */
	p = res;
	while ((p = strstr(p, "\"txid\"")) != NULL) {
		const char *nextobj = strstr(p + 6, "\"txid\"");
		size_t objlen = nextobj ? (size_t)(nextobj - p) : strlen(p);
		char *obj = tal_strndup(tmpctx, p, objlen);
		char *txid_hex = json_find_string(tmpctx, obj, "txid");
		char *spk_hex = json_find_string(tmpctx, obj, "scriptPubKey");
		long vout = json_find_int(obj, "vout");
		bool spendable = json_bool_true(obj, "spendable");
		u64 val = 0;
		bool haveval = json_find_btc_sat(obj, "amount", &val);

		p = nextobj ? nextobj : (p + strlen(p));

		if (!txid_hex || !spk_hex || vout < 0 || !haveval || !spendable)
			continue;
		if (val < min_sat)
			continue;
		if (!bitcoin_txid_from_hex(txid_hex, strlen(txid_hex),
					   &out_op->txid))
			continue;
		out_op->n = (u32)vout;
		*out_val = val;
		*out_spk = tal_hexdata(ctx, spk_hex, strlen(spk_hex));
		if (!*out_spk)
			continue;
		return true;
	}
	return false;
}

/* Escalating feerate: base -> max as the breach ages toward its deadline
 * window, plus a per-rung bump so each RBF round strictly out-fees the last.
 * Deadline window = the blob's stored deadline_delta, or the assumed remote
 * to_self_delay (SEAM: not yet threaded into meta). */
static u32 spd_feerate_perkw(const struct spd_blob *b, long breach_confs,
			     u32 rung, u32 remote_to_self_delay)
{
	/* Deadline window: the blob's own stored delta if present; else the
	 * channel's real remote to_self_delay from meta v2 (Phase E, seam #3);
	 * else the assumed-CSV fallback (v1/absent meta). */
	u32 window = b->deadline_delta ? b->deadline_delta
		: (remote_to_self_delay ? remote_to_self_delay : g_assumed_csv);
	double urgency;
	u64 fr;

	if (breach_confs < 0)
		breach_confs = 0;
	if (window && (u32)breach_confs > window)
		breach_confs = window;
	urgency = window ? (double)breach_confs / (double)window : 1.0;

	fr = (u64)g_fee_base_perkw
		+ (u64)(urgency * (double)(g_fee_max_perkw - g_fee_base_perkw))
		+ (u64)rung * (g_fee_base_perkw / 4 + 1);
	if (fr > g_fee_max_perkw)
		fr = g_fee_max_perkw;
	if (fr < FEERATE_FLOOR)
		fr = FEERATE_FLOOR;
	return (u32)fr;
}

/* ---- Fee attach + sign (the SINGLE|ACP append; box fee wallet) ------------ *
 * A CLASS-A justice blob is SIGHASH_SINGLE|ANYONECANPAY: input 0 (the revoked
 * outpoint, DEVICE-signed) + output 0 (full swept value to the user, no fee).
 * sendrawtransaction rejects it (no fee / unbalanced), so we must append our OWN
 * fee input (+ change + the elements explicit fee output) WITHOUT disturbing
 * input 0 or output 0, then sign ONLY the appended input with the fee-wallet
 * key.  ACP means input 0's signature survives the append.
 *
 * RPC CHOICE (verified against Sequentia-Core src/):
 *  - fundrawtransaction / walletcreatefundedpsbt CANNOT be used: they re-run
 *    CreateTransaction to balance the tx, but input 0 is EXTERNAL to the fee
 *    wallet (its key is on the device), so the wallet can't value it and would
 *    massively over-fund.  (converttopsbt is separately unusable: it CLEARS
 *    scriptSig + witness -- rawtransaction.cpp:2293/2299 -- destroying the
 *    SINGLE|ACP signature.)
 *  - So we balance the tx OURSELVES (we know input 0's value == output 0's
 *    value, and the fee UTXO's value) and hand it to signrawtransactionwithwallet,
 *    which signs input 1 (a wallet UTXO) and LEAVES input 0 untouched: for an
 *    input whose prevout the wallet doesn't own, ::SignTransaction sets an
 *    input error and `continue`s -- it never rewrites that input's witness
 *    (script/sign.cpp:645).  So input 0's SINGLE|ACP witness is preserved.
 *
 * Requires: fee-wallet UTXOs are segwit-v0 (bech32 p2wpkh) so signing input 1
 * needs only its own BIP143 amount (the taproot sighash would need input 0's
 * spent-output, which we don't feed the wallet).  Returns the fully-signed hex
 * (child of ctx) or NULL (no fee wallet / no suitable UTXO / RPC failure). */
static char *attach_fee_and_sign(const tal_t *ctx, const struct spd_blob *b,
				 struct justice_state *st, long breach_confs,
				 u32 remote_to_self_delay)
{
	struct amount_asset oa;
	u8 asset33[33];
	char *asset_hex, *hex, *signed_hex, *res;
	struct bitcoin_tx *tx;
	struct amount_sat out0, feeamt, minfee, maxfee, changeamt;
	u32 feerate;
	size_t weight;
	const char **extra;
	u64 uval;
	u8 *raw;
	int change_idx;

	if (!g_fee_wallet)
		return NULL;			/* no fee wallet on this box (SEAM) */

	/* Asset the blob output is denominated in (Fix B2 set it = channel asset). */
	oa = bitcoin_tx_output_get_amount(b->tx, 0);
	memcpy(asset33, oa.asset, sizeof(asset33));
	asset_hex = asset33_to_rpchex(ctx, asset33);
	out0 = bitcoin_tx_output_get_amount_sat(b->tx, 0);

	/* Choose the fee UTXO once, then REUSE it for every RBF rung so each
	 * replacement keeps the same inputs (only fee/change move). */
	if (!st->have_feeutxo) {
		struct bitcoin_outpoint op;
		u8 *spk;
		u64 v;
		struct amount_sat need;

		if (!amount_sat_add(&need, amount_tx_fee(g_fee_base_perkw, 500),
				    SPD_DUST_SAT))
			return NULL;
		if (!pick_fee_utxo(ctx, asset_hex, need.satoshis, &op, &v, &spk))
			return NULL;
		st->feeutxo = op;
		st->feeutxo_val = v;
		st->feeutxo_spk = tal_steal(g_state_ctx, spk);
		st->have_feeutxo = true;
	}
	uval = st->feeutxo_val;

	/* Clone: never mutate the loaded blob; we only append at index >= 1. */
	tx = clone_bitcoin_tx(ctx, b->tx);
	bitcoin_tx_set_output_asset(tx, asset33);	/* change+fee in blob asset */
	bitcoin_tx_add_input(tx, &st->feeutxo, SPD_RBF_SEQUENCE, NULL,
			     amount_sat(uval), st->feeutxo_spk, NULL);
	/* Change output back to the fee wallet (placeholder amount; set below).
	 * output 0 (user recovery) is left strictly alone; the SINGLE|ACP blob
	 * already carries a zero-value elements fee output (index 1) that
	 * bitcoin_tx_finalize() will re-value to the real fee, so the change
	 * lands at whatever index add_output returns (append). */
	/* The clone allocates exactly the blob's own outputs; make room for the
	 * appended change output (else bitcoin_tx_add_output asserts). */
	bitcoin_tx_reserve_output(tx);
	change_idx = bitcoin_tx_add_output(tx, st->feeutxo_spk, NULL,
					   amount_sat(uval));

	/* Weight incl. the p2wpkh fee-input witness (~108wu), change + fee out. */
	weight = bitcoin_tx_weight(tx) + 4 + 1 + 108
		+ elements_tx_overhead(chainparams, 2, 3);
	feerate = spd_feerate_perkw(b, breach_confs, st->rung, remote_to_self_delay);
	feeamt = amount_tx_fee(feerate, weight);
	minfee = amount_tx_fee(FEERATE_FLOOR, weight);
	if (amount_sat_less(feeamt, minfee))
		feeamt = minfee;
	/* Cap the fee so change stays >= dust (a too-small UTXO caps the max
	 * feerate: the fee wallet must hold adequately-sized per-asset UTXOs). */
	if (!amount_sat_sub(&maxfee, amount_sat(uval), SPD_DUST_SAT))
		return NULL;
	if (amount_sat_greater(feeamt, maxfee))
		feeamt = maxfee;
	if (!amount_sat_sub(&changeamt, amount_sat(uval), feeamt))
		return NULL;
	bitcoin_tx_output_set_amount(tx, change_idx, changeamt);
	/* Re-values the existing explicit elements fee output (empty
	 * scriptPubKey) in the blob asset to sum(inputs) - sum(non-fee outputs)
	 * = feeamt.  Exactly one fee output either way. */
	bitcoin_tx_finalize(tx);

	/* NON-CUSTODY GUARD: the user recovery output 0 must be byte-unchanged. */
	{
		struct amount_sat now0 = bitcoin_tx_output_get_amount_sat(tx, 0);
		struct amount_asset a0 = bitcoin_tx_output_get_amount(tx, 0);
		if (!amount_sat_eq(now0, out0)
		    || memcmp(a0.asset, asset33, sizeof(asset33)) != 0) {
			fprintf(stderr, "speculad: REFUSING -- funding altered "
				"output 0 (user recovery)\n");
			return NULL;
		}
	}

	raw = linearize_tx(ctx, tx);		/* keeps input 0's SINGLE|ACP witness */
	hex = tal_hexstr(ctx, raw, tal_bytelen(raw));
	extra = tal_arr(tmpctx, const char *, 1);
	extra[0] = hex;
	res = run_cli_wallet(ctx, "signrawtransactionwithwallet", extra);
	if (!res)
		return NULL;
	/* "complete":false is EXPECTED (the wallet can't verify input 0, whose
	 * key is on the device). */
	signed_hex = json_find_string(ctx, res, "hex");
	if (!signed_hex)
		return NULL;

	/* Elements' signrawtransactionwithwallet re-serializes the tx and STRIPS
	 * the witness of input 0 (the device pre-signed SINGLE|ACP penalty it
	 * doesn't own) down to a single element, breaking the revocation spend.
	 * Re-parse the wallet-signed tx (which now carries our fee input's
	 * witness at index >= 1) and restore input 0's original pre-signed
	 * witness from the clone. */
	{
		struct bitcoin_tx *stx;

		stx = bitcoin_tx_from_hex(ctx, signed_hex, strlen(signed_hex));
		if (!stx)
			return NULL;
		bitcoin_tx_input_copy_witness(stx, 0, tx, 0);
		raw = linearize_tx(ctx, stx);
		signed_hex = tal_hexstr(ctx, raw, tal_bytelen(raw));
	}
	return signed_hex;
}

/* Defend one justice blob for a confirmed breach: de-dup (stop once our justice
 * tx confirmed), else attach a fee + (re-)broadcast, escalating the feerate each
 * round (RBF) toward the deadline. */
static void defend_blob(struct revoked_commit *rc, const struct spd_blob *b,
			long breach_confs, bool may_broadcast,
			u32 remote_to_self_delay)
{
	char *key = tal_fmt(tmpctx, "%s:%u:%u",
			    rc->locator, b->output_index, b->kind);
	struct justice_state *st = spd_get_state(key);
	char *signed_hex, *res;
	const char **extra;
	enum spd_txout_state ts;

	/* Phase E (seam #2): REORG-SAFE de-dup.  The de-dup gate is the confirmed
	 * UTXO-set status of the REVOKED outpoint this justice tx spends
	 * (rc->locator : b->output_index) -- NOT a persistent "confirmed" latch.
	 * If it is SPENT, justice has landed (our tx or the peer's honest close),
	 * so we skip THIS round only; a later reorg that re-exposes the outpoint
	 * flips this back to UNSPENT and broadcasting auto-resumes (principle #1,
	 * no finality).  UNKNOWN (RPC error) conservatively keeps defending.
	 *
	 * NOTE: current CLASS-A blobs all spend a commitment output, so
	 * (locator, output_index) is exactly the spent prevout.  A future
	 * steal_htlc_tx 2nd-stage blob spends the HTLC-tx, not the commitment,
	 * so it must instead query its OWN tx's input-0 prevout. */
	ts = rpc_txout_state(tmpctx, rc->locator, b->output_index);
	if (ts == SPD_TXOUT_SPENT) {
		if (st->broadcast_txid) {
			/* Secondary signal only (needs txindex=1); logged, not gating. */
			long c = rpc_tx_confirmations(tmpctx, st->broadcast_txid);
			fprintf(stderr, "speculad: revoked outpoint %s:%u SPENT "
				"(our justice %s confs %ld) -- done this round\n",
				rc->locator, b->output_index, st->broadcast_txid, c);
		} else {
			fprintf(stderr, "speculad: revoked outpoint %s:%u already "
				"SPENT -- nothing to defend this round\n",
				rc->locator, b->output_index);
		}
		return;
	}
	/* UNSPENT or UNKNOWN: the revoked output is (still) claimable -> defend. */
	if (!may_broadcast)
		return;

	signed_hex = attach_fee_and_sign(tmpctx, b, st, breach_confs,
					 remote_to_self_delay);
	if (!signed_hex) {
		/* Fee wallet absent (testnet) or no suitable UTXO: broadcast the
		 * raw zero-fee blob so the breach is still surfaced/logged.  It
		 * will typically be rejected below-min-relay; this is the SEAM. */
		u8 *raw = linearize_tx(tmpctx, b->tx);
		signed_hex = tal_hexstr(tmpctx, raw, tal_bytelen(raw));
	}

	extra = tal_arr(tmpctx, const char *, 1);
	extra[0] = signed_hex;
	res = run_cli(tmpctx, "sendrawtransaction", extra);
	if (res) {
		size_t n = strlen(res);
		while (n && (res[n - 1] == '\n' || res[n - 1] == '\r'
			     || res[n - 1] == ' '))
			res[--n] = '\0';
		tal_free(st->broadcast_txid);
		st->broadcast_txid = tal_strdup(g_state_ctx, res);
		st->rung++;		/* next poll escalates the feerate (RBF) */
		fprintf(stderr, "speculad: broadcast justice %s -> txid %s "
			"(rung %u, feerate ~%u perkw)\n", key, res, st->rung,
			spd_feerate_perkw(b, breach_confs, st->rung - 1,
					  remote_to_self_delay));
	} else {
		fprintf(stderr, "speculad: sendrawtransaction rejected for %s "
			"(kind %u output %u)\n", key, b->kind, b->output_index);
		/* Re-select the fee UTXO next round: the cached one may have been
		 * spent / reorged away, or the RBF bump was rejected as too small. */
		st->have_feeutxo = false;
	}
}

/* Phase F: preemptive close (withhold-revoke / JBA defense).  If the signing
 * device dropped while lightningd was mid-commitment-round, lightningd sets the
 * preempt "armed" flag; speculad then broadcasts OUR CURRENT already-signed
 * commitment to grab the funding outpoint FIRST, so a later peer breach becomes a
 * double-spend.
 *
 * NON-CUSTODY: the broadcast is OUR OWN current commitment == a legitimate
 * unilateral (force) close returning funds to the user on-chain (subject to
 * to_self_delay), NEVER a revoked state.  The airtight guard is the equality
 * preempt_commit_num == meta.current_commit_num: lightningd bumps the preempt
 * slot + meta ATOMICALLY on every advance (BEFORE the prior state's secret is
 * revealed), so a superseded/revoked commitment is never equal-and-armed.  This
 * is exactly what separated Specula (safe) from the disqualified Vigilia design;
 * speculad enforces the equality as defense-in-depth and REFUSES on mismatch. */
static bool outpoint_is_zero(const struct bitcoin_outpoint *o)
{
	struct bitcoin_outpoint zero;
	memset(&zero, 0, sizeof(zero));
	return memcmp(o, &zero, sizeof(zero)) == 0;
}

static void maybe_preempt_close(struct watched_channel *c, bool may_broadcast)
{
	enum spd_txout_state ts;
	char *txid_hex, *hex, *res;
	const char **extra;
	u8 *raw;

	/* (a) only mid-round-device-down channels are armed. */
	if (!c->preempt_armed)
		return;

	/* (b) THE GUARD: never broadcast anything but the CURRENT, non-revoked
	 * local commitment.  A mismatch means the slot is stale/torn (or a revoked
	 * state) -> REFUSE. */
	if (!c->preempt_tx
	    || c->preempt_commit_num != c->current_commit_num
	    || c->preempt_armed_commit_num != c->current_commit_num) {
		fprintf(stderr, "speculad: REFUSING preempt dbid=%"PRIu64
			" (commit_num mismatch: preempt=%"PRIu64" armed=%"PRIu64
			" meta=%"PRIu64") -- stale/revoked, not broadcasting\n",
			c->dbid, c->preempt_commit_num, c->preempt_armed_commit_num,
			c->current_commit_num);
		return;
	}

	/* (c) FUNDING WATCH: only broadcast while the funding outpoint is still
	 * unspent.  SPENT -> a close already happened (our preempt confirmed, or
	 * the peer beat us -> the justice path handles a breach); reorg-safe, no
	 * latch (auto-resumes if a reorg re-exposes the funding outpoint). */
	if (outpoint_is_zero(&c->funding))
		return;		/* v1/absent meta: cannot watch funding */
	txid_hex = fmt_bitcoin_txid(tmpctx, &c->funding.txid);
	ts = rpc_txout_state(tmpctx, txid_hex, c->funding.n);
	if (ts == SPD_TXOUT_SPENT)
		return;		/* channel already closed on-chain */

	/* (d) need the sole-broadcaster lease. */
	if (!may_broadcast)
		return;

	/* Broadcast OUR current commitment (a complete 2-of-2 unilateral close: it
	 * carries its own baked-in fee, so NO fee attach, unlike the SINGLE|ACP
	 * sweeps).  Idempotent: re-broadcasting an already-in-mempool/confirmed
	 * commitment each poll is a harmless duplicate; the funding-SPENT gate stops
	 * it once it confirms. */
	raw = linearize_tx(tmpctx, c->preempt_tx);
	hex = tal_hexstr(tmpctx, raw, tal_bytelen(raw));
	extra = tal_arr(tmpctx, const char *, 1);
	extra[0] = hex;
	res = run_cli(tmpctx, "sendrawtransaction", extra);
	if (res) {
		size_t n = strlen(res);
		while (n && (res[n - 1] == '\n' || res[n - 1] == '\r'
			     || res[n - 1] == ' '))
			res[--n] = '\0';
		fprintf(stderr, "speculad: PREEMPT close dbid=%"PRIu64
			" commit=%"PRIu64" -> txid %s\n",
			c->dbid, c->preempt_commit_num, res);
	} else {
		fprintf(stderr, "speculad: preempt sendrawtransaction rejected "
			"dbid=%"PRIu64" commit=%"PRIu64" (likely already in "
			"mempool/confirmed)\n", c->dbid, c->preempt_commit_num);
	}
}

/* Specula Phase G (Task 1): broadcast one stored CLASS-B honest-close sweep.
 *
 * The commitment this sweep spends is recoverable from the blob itself: input 0's
 * prevout IS commitment_txid:output_index (kinds 3/4/5 spend an output of OUR
 * current commitment; kind 6 spends an output of the PEER's current commitment),
 * so speculad needs NO extra locator and lightningd need not hold the peer tx.
 *
 * MATCH gate ("this sweep belongs to a CONFIRMED commitment, and it is an HONEST
 * close, not a breach"): rpc_tx_confirmations(commit_txid) >= 1.  An honest close
 * confirms its commitment; a REVOKED close's txid is a justice locator that no
 * honest sweep references, so on a breach every honest sweep's commitment is not
 * confirmed -- and, belt-and-braces, we additionally skip any sweep whose confirmed
 * commitment IS a revoked locator (the justice path owns it).  No double broadcast.
 *
 * De-dup + reorg-safety: gate on rpc_txout_state(commit_txid, output_index) --
 * the same non-latched confirmed-UTXO gate defend_blob uses.  SPENT -> our sweep
 * (or the peer) already consumed that commitment output, skip THIS round only; a
 * reorg re-exposing it auto-resumes (principle #1, no finality latch).
 *
 * Timelocks: kind 3 (to_local-delayed) is CSV-encumbered -- broadcastable only
 * once the commitment has >= to_self_delay confirmations.  kind 4 and the kind-6
 * timeout leg carry an absolute nLocktime (== cltv_expiry) -- broadcastable only
 * once tip_height >= nLocktime.  kind 5 and the kind-6 preimage leg have nLocktime
 * 0 -> mature as soon as the commitment confirms.  We pre-gate on maturity to
 * avoid burning a fee-UTXO/RBF rung, but the mempool is the ultimate authority.
 *
 * Fee: kind 3 is SINGLE|ACP -> reuse attach_fee_and_sign (the exact non-custody
 * path, incl. the output-0-unchanged guard, that justice uses).  kinds 4/5/6 are
 * SIGHASH_ALL with a frozen self-deducting fee already baked in -> broadcast the
 * device-signed tx byte-for-byte AS-IS (no tower mutation, no RBF). */
static void defend_sweep(struct watched_channel *c, const struct spd_blob *b,
			 long tip_height, bool may_broadcast)
{
	struct bitcoin_outpoint commit_op;
	char *commit_txid_hex, *key, *signed_hex, *res;
	struct justice_state *st;
	enum spd_txout_state ts;
	long confs;
	const char **extra;

	/* (1) The commitment this blob spends == its input-0 prevout. */
	bitcoin_tx_input_get_outpoint(b->tx, 0, &commit_op);
	commit_txid_hex = fmt_bitcoin_txid(tmpctx, &commit_op.txid);
	/* Defensive: the stored output_index must equal the spent prevout n, so
	 * the gettxout de-dup below queries the correct commitment output. */
	if (commit_op.n != b->output_index) {
		fprintf(stderr, "speculad: sweep kind %u output_index %u != "
			"input-0 prevout n %u (%s) -- skipping malformed blob\n",
			b->kind, b->output_index, commit_op.n, commit_txid_hex);
		return;
	}

	/* (2) MATCH: only defend a sweep whose commitment is CONFIRMED.  <1 means
	 * this is not the on-chain close (a stale prior-state sweep, or a breach
	 * the justice path owns). */
	confs = rpc_tx_confirmations(tmpctx, commit_txid_hex);
	if (confs < 1)
		return;

	/* (3) Breach guard (belt-and-braces): if the confirmed commitment is a
	 * REVOKED locator, the justice path defends it -- never the honest sweep. */
	for (size_t j = 0; j < tal_count(c->revoked); j++) {
		if (streq(c->revoked[j]->locator, commit_txid_hex)) {
			fprintf(stderr, "speculad: sweep commitment %s is a "
				"REVOKED locator -- leaving it to the justice "
				"path\n", commit_txid_hex);
			return;
		}
	}

	/* (4) REORG-SAFE de-dup: if the swept commitment output is no longer in
	 * the confirmed UTXO set, our sweep (or the peer) already claimed it --
	 * skip this round only, no latch. */
	ts = rpc_txout_state(tmpctx, commit_txid_hex, b->output_index);
	if (ts == SPD_TXOUT_SPENT)
		return;
	if (!may_broadcast)
		return;

	/* (5) Timelock maturity gate (avoid wasting an RBF rung; the mempool is
	 * the final nLocktime/BIP68 authority either way). */
	if (b->kind == WT_TMPL_TO_LOCAL_DELAYED_SWEEP) {
		u32 window = b->deadline_delta ? b->deadline_delta
			: (c->remote_to_self_delay ? c->remote_to_self_delay
			   : g_assumed_csv);
		if (confs < (long)window) {
			fprintf(stderr, "speculad: to_local sweep %s:%u not CSV-"
				"mature (%ld/%u confs)\n", commit_txid_hex,
				b->output_index, confs, window);
			return;
		}
	} else {
		u32 lt = b->tx->wtx->locktime;
		if (lt != 0 && tip_height >= 0 && (u32)tip_height < lt) {
			fprintf(stderr, "speculad: HTLC sweep %s:%u not CLTV-"
				"mature (tip %ld < locktime %u)\n",
				commit_txid_hex, b->output_index, tip_height, lt);
			return;
		}
	}

	/* (6) Build the broadcastable hex per fee policy. */
	key = tal_fmt(tmpctx, "sweep:%s:%u:%u", commit_txid_hex, b->output_index,
		      b->kind);
	st = spd_get_state(key);
	if (b->kind == WT_TMPL_TO_LOCAL_DELAYED_SWEEP) {
		/* SINGLE|ACP: append our own fee input (+ change + fee output),
		 * RBF, non-custody output-0 guard -- reused verbatim from justice. */
		signed_hex = attach_fee_and_sign(tmpctx, b, st, confs,
						 c->remote_to_self_delay);
		if (!signed_hex) {
			/* No fee wallet (testnet) / no suitable UTXO: surface the
			 * raw zero-fee blob (below-min-relay), same seam as justice. */
			u8 *raw = linearize_tx(tmpctx, b->tx);
			signed_hex = tal_hexstr(tmpctx, raw, tal_bytelen(raw));
		}
	} else {
		/* kinds 4/5/6: SIGHASH_ALL frozen self-deducting fee -> broadcast
		 * byte-for-byte as the device signed it (NO fee attach, NO RBF). */
		u8 *raw = linearize_tx(tmpctx, b->tx);
		signed_hex = tal_hexstr(tmpctx, raw, tal_bytelen(raw));
	}

	extra = tal_arr(tmpctx, const char *, 1);
	extra[0] = signed_hex;
	res = run_cli(tmpctx, "sendrawtransaction", extra);
	if (res) {
		size_t n = strlen(res);
		while (n && (res[n - 1] == '\n' || res[n - 1] == '\r'
			     || res[n - 1] == ' '))
			res[--n] = '\0';
		tal_free(st->broadcast_txid);
		st->broadcast_txid = tal_strdup(g_state_ctx, res);
		if (b->kind == WT_TMPL_TO_LOCAL_DELAYED_SWEEP)
			st->rung++;	/* next round escalates the feerate (RBF) */
		fprintf(stderr, "speculad: HONEST-CLOSE SWEEP kind %u %s -> txid "
			"%s\n", b->kind, key, res);
	} else {
		fprintf(stderr, "speculad: sweep sendrawtransaction rejected for "
			"%s (kind %u; not yet mature / below-min-relay?)\n",
			key, b->kind);
		if (b->kind == WT_TMPL_TO_LOCAL_DELAYED_SWEEP)
			st->have_feeutxo = false;   /* re-pick the fee UTXO next round */
	}
}

/* Specula Phase G (Task 1): per-round funding-outpoint watch.  When a channel's
 * funding outpoint leaves the confirmed UTXO set, a force-close has confirmed on-
 * chain -> try to broadcast every stored CLASS-B honest-close sweep (each blob
 * self-selects its own confirmed commitment + honest-vs-breach inside
 * defend_sweep).  Non-latched, reorg-safe, exactly like maybe_preempt_close's
 * funding gate. */
static void defend_honest_close(struct watched_channel *c, long tip_height,
				bool may_broadcast)
{
	char *txid_hex;
	enum spd_txout_state ts;

	if (tal_count(c->sweeps) == 0)
		return;
	if (outpoint_is_zero(&c->funding))
		return;		/* v1/absent meta: cannot watch the funding outpoint */

	txid_hex = fmt_bitcoin_txid(tmpctx, &c->funding.txid);
	ts = rpc_txout_state(tmpctx, txid_hex, c->funding.n);
	if (ts == SPD_TXOUT_UNSPENT)
		return;		/* channel still open -> nothing force-closed yet */

	/* SPENT (a close confirmed) or UNKNOWN (RPC error -> be conservative):
	 * run each sweep; defend_sweep's own commitment-confirmed + de-dup gates
	 * make a stale/wrong-commitment sweep a no-op. */
	for (size_t k = 0; k < tal_count(c->sweeps); k++)
		defend_sweep(c, c->sweeps[k], tip_height, may_broadcast);
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
		"          [--fee-wallet=NAME] [--fee-base-perkw=N] [--fee-max-perkw=N]\n"
		"          [--assumed-csv=BLOCKS]\n"
		"          --cli=elements-cli [--cli=-datadir=/path] [--cli=...] ...\n"
		"\n"
		"speculad watches the Phase-B watchtower store under\n"
		"DIR/watchtower/<dbid>/ and, on a revoked commitment confirming,\n"
		"broadcasts the pre-signed justice blob(s) via the given CLI.\n"
		"Repeat --cli to build the full elements-cli invocation (path +\n"
		"connection flags).\n"
		"\n"
		"--fee-wallet names the box-owned elementsd wallet holding per-asset\n"
		"fee UTXOs (bech32/p2wpkh) that speculad appends to SINGLE|ACP justice\n"
		"blobs (+ change + explicit fee output) and RBFs.  Requires the node\n"
		"to run with txindex=1 (breach + confirmation detection use\n"
		"getrawtransaction).  Without --fee-wallet the zero-fee blob is\n"
		"broadcast as-is (typically below-min-relay: the documented seam).\n",
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
	g_state_ctx = top;
	g_states = tal_arr(top, struct justice_state *, 0);

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
		else if (strstarts(argv[i], "--fee-wallet="))
			g_fee_wallet = tal_strdup(top,
					argv[i] + strlen("--fee-wallet="));
		else if (strstarts(argv[i], "--fee-base-perkw="))
			g_fee_base_perkw = atoi(argv[i]
					+ strlen("--fee-base-perkw="));
		else if (strstarts(argv[i], "--fee-max-perkw="))
			g_fee_max_perkw = atoi(argv[i]
					+ strlen("--fee-max-perkw="));
		else if (strstarts(argv[i], "--assumed-csv="))
			g_assumed_csv = atoi(argv[i] + strlen("--assumed-csv="));
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

	/* Fee-wallet CLI = base + -rpcwallet=<name>, so the fee-input coin
	 * selection / signing targets the dedicated fee wallet only. */
	if (g_fee_wallet) {
		g_fee_cli_base = tal_arr(top, const char *, 0);
		for (size_t i = 0; i < tal_count(g_cli_base); i++)
			tal_arr_expand(&g_fee_cli_base, g_cli_base[i]);
		tal_arr_expand(&g_fee_cli_base,
			       tal_fmt(top, "-rpcwallet=%s", g_fee_wallet));
	}

	chainparams = chainparams_for_network(network);
	if (!chainparams)
		errx(1, "speculad: unknown --network=%s (known: %s)",
		     network, chainparams_get_network_names(tmpctx));

	signal(SIGINT, handle_sig);
	signal(SIGTERM, handle_sig);
	signal(SIGPIPE, SIG_IGN);

	fprintf(stderr, "speculad: watching %s/watchtower (network %s), "
		"poll %us, lease %s, fee-wallet %s\n", netdir, network,
		poll_interval, leasefile, g_fee_wallet ? g_fee_wallet : "(none)");

	while (!g_stop) {
		char *tip;
		long tip_height;
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

		/* Chain tip height (once per round) for the CLTV maturity gate on
		 * kind-4/kind-6-timeout honest-close sweeps.  -1 on RPC failure ->
		 * defend_sweep skips the pre-check and lets the mempool enforce
		 * nLocktime. */
		tip_height = rpc_getblockcount(tmpctx);

		/* Sole-broadcaster gate (failover via heartbeat staleness). */
		may_broadcast = acquire_or_refresh_lease(leasefile, lease_stale);

		chans = load_channels(tmpctx, netdir);
		for (size_t i = 0; i < tal_count(chans); i++) {
			struct watched_channel *c = chans[i];

			/* Phase F: race the peer to the funding outpoint with OUR
			 * current commitment if the device dropped mid-round.  Run
			 * FIRST (before the revoked/justice loop) so an armed channel
			 * grabs the funding outpoint before anything else. */
			maybe_preempt_close(c, may_broadcast);

			/* Phase G (Task 1): honest-close sweeps.  A confirmed
			 * commitment is exactly one of honest-or-revoked, so this
			 * and the justice loop below never collide (defend_sweep
			 * skips a commitment that is a revoked locator). */
			defend_honest_close(c, tip_height, may_broadcast);

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
					" commit=%s confs=%ld -> defending "
					"%zu justice blob(s)%s\n",
					c->dbid, rc->locator, confs,
					tal_count(rc->blobs),
					may_broadcast ? "" : " (no lease: de-dup only)");
				/* Per blob: attach a fee + (re-)broadcast with RBF
				 * escalation, or stop once the justice tx confirmed
				 * (de-dup).  defend_blob is safe without the lease
				 * (it only reads confirmations then). */
				for (size_t k = 0; k < tal_count(rc->blobs); k++)
					defend_blob(rc, rc->blobs[k], confs,
						    may_broadcast,
						    c->remote_to_self_delay);
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
