/* speculad -- the Specula keyless watchtower broadcaster (Phase C).
 *
 * A standalone, always-on, device-INDEPENDENT daemon (its own systemd unit, NOT
 * a CLN plugin, NOT spawned by lightningd).  It loads NO secret and signs
 * nothing (the fee input aside, which the fee wallet signs); its only
 * cryptography is public, the hashes and tweaks that rebuild a symmetric
 * channel's state outputs.  It:
 *   1. reads the fsync-durable, secret-free watchtower store written by Phase B
 *      (documented on-disk format in lightningd/watchtower_store.h), reaching
 *      defensive posture purely from disk with no hsm_init (survives cold boot);
 *   2. watches the chain via the node's CLI (mirroring plugins/bcli.c: shell
 *      out to the configured CLI over the box's node);
 *   3. on seeing a REVOKED commitment confirm on-chain (a breach), broadcasts
 *      the matching device-pre-signed CLASS-A justice blobs via
 *      sendrawtransaction, while the signing device is offline: one for the
 *      cheater's to_local output, one per HTLC output, and, once the cheater
 *      has won the race for an HTLC output with its HTLC-timeout or
 *      HTLC-success transaction, one for that transaction's output.
 *
 * COST PER ROUND: a revoked commitment can only be on chain once its channel's
 * funding output is spent, so each round looks at each channel's funding
 * output (gettxout) and polls the stored revoked commitments only while it is
 * spent.  A justice file is read only when its commitment is on chain.  A
 * round therefore costs a few calls per channel, however many states the
 * channel has revoked; lightningd removes a channel's store when it forgets
 * the closed channel.
 *
 * REORG MODEL (see keyless-watchtower-design-specula): every blob binds only its
 * input outpoint, never a height, so a reorg never expires a blob -- it only
 * changes which stored blob is live and resets the depth clock.  Every round
 * re-reads the UTXO set: a re-confirm rebroadcasts (idempotent); a DIFFERENT
 * revoked commitment surfacing is matched to its own justice file; the
 * deadline is recomputed as confirmation depth every round.  No finality
 * timelock is ever used (anchoring supremacy).
 *
 * FEE (SINGLE|ACP): the CLASS-A justice blobs are SIGHASH_SINGLE|ANYONECANPAY
 * (Phase A) -- output 0 carries the full swept value and pays NO fee.  speculad
 * puts every still-unspent blob of one breach into ONE transaction (blob k's
 * input and output at index k) and appends its OWN fee input (+ change) from a
 * box-owned wallet (--fee-wallet), then RBF-escalates toward the deadline,
 * never needing the device.  The fee coin is in the channel asset when the
 * node accepts that for fees and the wallet holds it, else in the accepted
 * asset whose largest coin covers the most fees (choose_fee_coin), as a wallet
 * chooses an exit's fee coin; the fee is converted at the node's exchange rate
 * for that asset (getfeeexchangerates): the feerates are in reference atoms,
 * the fee in the asset's own atoms.
 *
 * CLASS-B honest-force-close sweeps + HTLC 2nd-stage: lightningd/onchain_presign.c
 * device-master-signs the current-state honest-close set (kind 3 to_local-delayed
 * + kind 4 offered-HTLC-timeout) at every commitment advance, the kind 5
 * HTLC-success sweep at fulfill (the JBA fulfill hard-gate) and the kind 6
 * remote_htlc_to_us sweeps of the peer's commitment, writing them to the state
 * file's sweep set this daemon loads.  They drop into the same watch/broadcast
 * loop as the justice set.
 *
 * SYMMETRIC CHANNELS (common/sym_scripts.h): nothing to punish; the store is
 * one `sym` record per channel, and the tower replaces an older state by the
 * stored best one and settles the latest after the shared delay (defend_sym,
 * near the end of this file).
 */
#include "config.h"
#include <assert.h>
#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/compiler/compiler.h>
#include <ccan/err/err.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <ccan/str/str.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <common/json_parse_simple.h>
#include <common/presign_templates.h>	/* enum wt_tmpl_kind (stable on-disk u8) */
#include <common/setup.h>
#include <common/sym_factory.h>
#include <common/sym_scripts.h>
#include <common/sym_state.h>
#include <common/utils.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
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

struct spd_sym {
	u64 dbid;
	struct bitcoin_blkid genesis;
	struct bitcoin_outpoint funding;
	u32 funding_height;
	struct amount_sat funding_sats;
	u8 asset[33];
	u16 delay;
	struct pubkey key[2];
	bool we_opened;
	struct sym_state *best, *pending;
	struct sym_channel sc;
	/* A factory channel's factory (common/sym_factory.h), or NULL:
	 * `funding` is then its id, and its output the factory output until
	 * the split, its KO after it. */
	struct sym_factory *factory;
};

/* The output the walk starts from: the funding, or the factory output. */
static const struct bitcoin_outpoint *sym_anchor(const struct spd_sym *s)
{
	return s->factory ? &s->factory->out : &s->funding;
}

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
	/* A symmetric channel's record (the `sym` file), or NULL. */
	struct spd_sym *sym;
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
	char *key;			/* "<locator>:justice" for a breach,
					 * "sweep:<txid>:<output>:<kind>" */
	bool have_feeutxo;
	struct bitcoin_outpoint feeutxo;
	u64 feeutxo_val;		/* satoshis (exact) */
	u8 *feeutxo_spk;		/* fee UTXO scriptPubKey (change goes back here) */
	u8 fee_asset33[33];		/* the fee UTXO's asset */
	char *fee_asset_hex;		/* the same, display order */
	char *no_fee_coin;		/* why no fee coin was found, as last said */
	u32 rung;			/* RBF escalation counter */
	char *broadcast_txid;		/* last justice txid we broadcast */
	struct amount_sat fee_paid;	/* its fee, in atoms of fee_asset33 */
};
static struct justice_state **g_states;	/* persistent registry */
static struct spd_sym *read_sym(const tal_t *ctx, const char *chandir);
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
	st->fee_asset_hex = NULL;
	st->no_fee_coin = NULL;
	st->fee_paid = AMOUNT_SAT(0);
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
	if (!*cursor || !b->tx || b->tx->wtx->num_outputs == 0)
		return tal_free(b);
	/* A parsed transaction is denominated in the policy asset until told
	 * otherwise; a blob's is the asset of the output it sweeps to (the
	 * channel asset), and every amount read from it below is in that. */
	{
		struct amount_asset a = bitcoin_tx_output_get_amount(b->tx, 0);
		bitcoin_tx_set_output_asset(b->tx, a.asset);
	}
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
		c->sym = read_sym(c, chandir);
		if (c->sym) {
			c->sweeps = tal_arr(c, struct spd_blob *, 0);
			c->preempt_tx = NULL;
			c->preempt_armed = false;
			c->funding = *sym_anchor(c->sym);
			tal_arr_expand(&chans, c);
			continue;
		}
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
				/* Read only when this commitment is on chain
				 * (load_justice): a round costs the same
				 * however many states the channel revoked. */
				rc->blobs = NULL;
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

/* The justice set of a revoked commitment: one set file, or a directory in
 * the earlier layout. */
static void load_justice(struct revoked_commit *rc)
{
	struct stat st;

	if (rc->blobs)
		return;
	if (stat(rc->dir, &st) == 0 && S_ISDIR(st.st_mode))
		rc->blobs = load_blob_dir(rc, rc->dir);
	else
		rc->blobs = load_blob_file(rc, rc->dir);
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

/* The RPC-display asset hex (reversed 32-byte tag) of the 33-byte version+tag. */
static char *asset33_to_rpchex(const tal_t *ctx, const u8 asset33[33])
{
	u8 tag[32];

	memcpy(tag, asset33 + 1, 32);
	reverse_bytes(tag, 32);		/* internal (wally) -> display order */
	return tal_hexstr(ctx, tag, 32);
}

/* One spendable, confirmed coin of the fee wallet.  Confirmed-only keeps RBF
 * replacements from adding new *unconfirmed* inputs (BIP125). */
struct fee_coin {
	u8 asset33[33];			/* 0x01 + id, internal byte order */
	char *asset_hex;		/* display order, as the RPC shows it */
	struct bitcoin_outpoint op;
	u64 value;			/* atoms of asset33 */
	u8 *spk;
};

/* The 33-byte version+tag of a display-hex asset id. */
static bool asset_from_rpchex(const char *hex, u8 asset33[33])
{
	if (strlen(hex) != 64 || !hex_decode(hex, 64, asset33 + 1, 32))
		return false;
	reverse_bytes(asset33 + 1, 32);
	asset33[0] = 0x01;
	return true;
}

/* Every spendable, confirmed coin of the fee wallet, in any asset. */
static struct fee_coin *list_fee_coins(const tal_t *ctx)
{
	const char **extra = tal_arr(tmpctx, const char *, 4);
	struct fee_coin *coins = tal_arr(ctx, struct fee_coin, 0);
	const jsmntok_t *toks, *t;
	char *res;
	size_t i;

	extra[0] = "1";			/* minconf: confirmed only */
	extra[1] = "9999999";		/* maxconf */
	extra[2] = "[]";		/* addresses */
	extra[3] = "false";		/* include_unsafe */
	res = run_cli_wallet(tmpctx, "listunspent", extra);
	if (!res)
		return coins;
	toks = json_parse_simple(tmpctx, res, strlen(res));
	if (!toks || toks[0].type != JSMN_ARRAY)
		return coins;
	json_for_each_arr(i, t, toks) {
		const jsmntok_t *txid = json_get_member(res, t, "txid");
		const jsmntok_t *vout = json_get_member(res, t, "vout");
		const jsmntok_t *spk = json_get_member(res, t, "scriptPubKey");
		const jsmntok_t *asset = json_get_member(res, t, "asset");
		const jsmntok_t *spendable = json_get_member(res, t, "spendable");
		const char *obj = json_strdup(tmpctx, res, t);
		struct fee_coin c;
		char *hex;
		u32 n;
		bool can_spend;

		if (!txid || !vout || !spk || !asset || !spendable
		    || !json_to_bool(res, spendable, &can_spend) || !can_spend
		    || !json_to_u32(res, vout, &n)
		    || !json_find_btc_sat(obj, "amount", &c.value))
			continue;
		hex = json_strdup(tmpctx, res, txid);
		if (!bitcoin_txid_from_hex(hex, strlen(hex), &c.op.txid))
			continue;
		c.op.n = n;
		c.asset_hex = json_strdup(coins, res, asset);
		if (!asset_from_rpchex(c.asset_hex, c.asset33))
			continue;
		hex = json_strdup(tmpctx, res, spk);
		c.spk = tal_hexdata(coins, hex, strlen(hex));
		if (!c.spk)
			continue;
		tal_arr_expand(&coins, c);
	}
	return coins;
}

static u64 asset_rate(const char *asset_hex);

/* The fee of 1,000 vbytes at the base feerate in an asset at @rate, at
 * least one atom: what one kvB of this tower's transactions costs in it. */
static u64 per_kvb(u64 rate)
{
	u64 f = amount_tx_fee(feerate_in_asset(g_fee_base_perkw, rate),
			      4000).satoshis;	/* Raw: an atom count */
	return f ? f : 1;
}

/* The fee coin of a justice or sweep transaction in @channel_asset33, chosen
 * as a wallet chooses the fee coin of an exit: in the channel's own asset
 * when the node accepts it for fees and the wallet holds it, otherwise in the
 * accepted asset whose largest coin covers the most fees (its value over the
 * fee of a kvB in it), no asset preferred for what it is; ties go to the
 * lower asset id.  The coin is the largest of that asset, and must cover
 * @need of it (a function of the asset's rate).  Returns false, with *why
 * saying so, when the wallet holds no such coin. */
static bool choose_fee_coin(const tal_t *ctx, const u8 channel_asset33[33],
			    size_t weight, struct fee_coin *out,
			    const char **why)
{
	struct fee_coin *coins = list_fee_coins(tmpctx);
	const struct fee_coin *best = NULL, *own = NULL;
	u64 best_cover = 0;
	struct amount_sat need;

	/* The largest coin of each accepted asset. */
	for (size_t i = 0; i < tal_count(coins); i++) {
		const struct fee_coin *c = &coins[i];
		bool largest = true;

		if (asset_rate(c->asset_hex) == 0)
			continue;
		for (size_t j = 0; j < tal_count(coins); j++)
			if (j != i
			    && memcmp(coins[j].asset33, c->asset33, 33) == 0
			    && (coins[j].value > c->value
				|| (coins[j].value == c->value && j < i)))
				largest = false;
		if (!largest)
			continue;
		if (memcmp(c->asset33, channel_asset33, 33) == 0)
			own = c;
		{
			u64 cover = c->value / per_kvb(asset_rate(c->asset_hex));
			if (!best || cover > best_cover
			    || (cover == best_cover
				&& memcmp(c->asset33, best->asset33, 33) < 0)) {
				best = c;
				best_cover = cover;
			}
		}
	}
	if (own)
		best = own;
	if (!best) {
		char *held = tal_strdup(tmpctx, "");

		for (size_t i = 0; i < tal_count(coins); i++)
			tal_append_fmt(&held, "%s%"PRIu64" atoms of %s",
				       i ? ", " : "", coins[i].value,
				       coins[i].asset_hex);
		*why = tal_fmt(ctx, "the fee wallet holds no coin in an asset "
			       "this node accepts for fees%s (it holds: %s)",
			       asset_rate(asset33_to_rpchex(tmpctx, channel_asset33)) == 0
			       ? ", nor is the channel asset accepted" : "",
			       tal_count(coins) ? held : "nothing");
		return false;
	}
	if (!amount_sat_add(&need,
			    amount_tx_fee(feerate_in_asset(g_fee_base_perkw,
							   asset_rate(best->asset_hex)),
					  weight),
			    SPD_DUST_SAT)
	    || best->value < need.satoshis) {	/* Raw: an atom count */
		*why = tal_fmt(ctx, "the fee wallet's largest coin of asset %s "
			       "(%"PRIu64" atoms) does not cover %s of fee and "
			       "change", best->asset_hex, best->value,
			       fmt_amount_sat(tmpctx, need));
		return false;
	}
	*out = *best;
	out->asset_hex = tal_strdup(ctx, best->asset_hex);
	out->spk = tal_dup_talarr(ctx, u8, best->spk);
	return true;
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

/* ---- Fee exchange rates ---------------------------------------------------- *
 * A justice or sweep transaction pays its fee in the asset of its fee coin, and
 * every node values that fee through its own exchange rate for the asset (the
 * open fee market).  The feerates above are in reference atoms per kw; the fee is
 * the same value in atoms of the asset: feerate_in_asset() (common/amount.h).
 * The node's whitelist is read once per round, keys resolved from ticker
 * labels to display-hex ids as plugins/bcli.c does. */
struct spd_rate {
	char *asset_hex;	/* display-hex id */
	u64 rate;		/* EXCHANGE_RATE_SCALE == par */
};
/* NULL until the node has answered once; then the last answer. */
static struct spd_rate *g_rates;

static void refresh_rates(void)
{
	char *res, *labels;
	const jsmntok_t *toks, *ltoks = NULL, *key;
	struct spd_rate *rates;
	size_t i;

	res = run_cli(tmpctx, "getfeeexchangerates", NULL);
	if (!res) {
		fprintf(stderr, "speculad: getfeeexchangerates failed; "
			"keeping the last rates\n");
		return;
	}
	toks = json_parse_simple(tmpctx, res, strlen(res));
	if (!toks || toks[0].type != JSMN_OBJECT) {
		fprintf(stderr, "speculad: cannot parse getfeeexchangerates\n");
		return;
	}
	labels = run_cli(tmpctx, "dumpassetlabels", NULL);
	if (labels) {
		ltoks = json_parse_simple(tmpctx, labels, strlen(labels));
		if (ltoks && ltoks[0].type != JSMN_OBJECT)
			ltoks = NULL;
	}

	rates = tal_arr(g_state_ctx, struct spd_rate, 0);
	json_for_each_obj(i, key, toks) {
		struct spd_rate r;
		const jsmntok_t *hex;

		if (!json_to_u64(res, key + 1, &r.rate))
			continue;
		hex = ltoks ? json_get_member(labels, ltoks,
					      json_strdup(tmpctx, res, key))
			: NULL;
		r.asset_hex = hex ? json_strdup(rates, labels, hex)
			: json_strdup(rates, res, key);
		tal_arr_expand(&rates, r);
	}
	tal_free(g_rates);
	g_rates = rates;
}

/* The node's rate for an asset: 0 when the node does not accept it for fees.
 * Par when the node has never answered (a backend without the RPC). */
static u64 asset_rate(const char *asset_hex)
{
	if (!g_rates)
		return EXCHANGE_RATE_SCALE;
	for (size_t i = 0; i < tal_count(g_rates); i++)
		if (streq(g_rates[i].asset_hex, asset_hex))
			return g_rates[i].rate;
	return 0;
}

/* ---- Fee attach + sign (the SINGLE|ACP append; box fee wallet) ------------ *
 * A CLASS-A justice blob is SIGHASH_SINGLE|ANYONECANPAY: input 0 (the revoked
 * outpoint, DEVICE-signed) + output 0 (full swept value to the user, no fee).
 * Such a signature covers its own input and the output at the same index and
 * nothing else, so the blobs of one breach go into ONE transaction: blob k's
 * input at index k, its output at index k, then OUR fee input, a change output
 * and the explicit fee output, those three in the fee coin's asset (which may
 * not be the blobs').  One fee input pays for the whole breach, so a fee
 * wallet with a single UTXO in an accepted asset defends every output, and the
 * replacements of a later round replace the whole set at once.  Only the fee
 * input is signed here, with the fee-wallet key.
 *
 * RPC CHOICE (verified against Sequentia-Core src/):
 *  - fundrawtransaction / walletcreatefundedpsbt CANNOT be used: they re-run
 *    CreateTransaction to balance the tx, but the blob inputs are EXTERNAL to
 *    the fee wallet (their key is on the device), so the wallet can't value
 *    them and would massively over-fund.  (converttopsbt is separately
 *    unusable: it CLEARS scriptSig + witness -- rawtransaction.cpp:2293/2299 --
 *    destroying the SINGLE|ACP signatures.)
 *  - So we balance the tx OURSELVES (each blob input's value == its output's
 *    value, plus the fee UTXO's value) and hand it to
 *    signrawtransactionwithwallet, which signs the fee input (a wallet UTXO)
 *    and does not sign the inputs whose prevout the wallet doesn't own
 *    (script/sign.cpp:645); their witnesses are restored from the blobs below.
 *
 * Requires: fee-wallet UTXOs are segwit-v0 (bech32 p2wpkh) so signing the fee
 * input needs only its own BIP143 amount.  Every blob must sweep in one asset
 * under one nVersion and nLocktime (all justice blobs do).  Returns the
 * fully-signed hex (child of ctx) or NULL (no fee wallet / no suitable UTXO /
 * RPC failure / blobs that cannot share a transaction). */
static char *attach_fee_and_sign(const tal_t *ctx,
				 struct spd_blob *const *blobs,
				 struct justice_state *st, long breach_confs,
				 u32 remote_to_self_delay)
{
	size_t n = tal_count(blobs);
	struct amount_asset oa;
	u8 asset33[33];
	char *asset_hex, *hex, *signed_hex, *res;
	struct bitcoin_tx *tx;
	struct amount_sat feeamt, minfee, maxfee, changeamt;
	u32 feerate;
	u64 rate;
	size_t weight;
	const char **extra;
	u64 uval;
	u8 *raw;
	int change_idx, fee_idx;
	struct spd_blob *b;

	if (!g_fee_wallet || n == 0)
		return NULL;			/* no fee wallet on this box (SEAM) */

	/* Asset the blob outputs are denominated in (the channel asset). */
	b = blobs[0];
	oa = bitcoin_tx_output_get_amount(b->tx, 0);
	memcpy(asset33, oa.asset, sizeof(asset33));
	asset_hex = asset33_to_rpchex(ctx, asset33);
	for (size_t k = 0; k < n; k++) {
		struct amount_asset ok = bitcoin_tx_output_get_amount(blobs[k]->tx, 0);
		if (memcmp(ok.asset, asset33, sizeof(asset33)) != 0
		    || blobs[k]->tx->wtx->locktime != b->tx->wtx->locktime
		    || blobs[k]->tx->wtx->version != b->tx->wtx->version
		    || blobs[k]->tx->wtx->num_inputs != 1
		    || !amount_sat_eq(bitcoin_tx_output_get_amount_sat(blobs[k]->tx, 0),
				      blobs[k]->amount)) {
			fprintf(stderr, "speculad: blob for output %u cannot "
				"share a transaction with output %u\n",
				blobs[k]->output_index, b->output_index);
			return NULL;
		}
	}

	/* A chosen fee coin whose asset the node no longer accepts is given
	 * up: the next one is chosen afresh. */
	if (st->have_feeutxo && asset_rate(st->fee_asset_hex) == 0) {
		fprintf(stderr, "speculad: %s: fee asset %s is no longer "
			"accepted for fees by this node; choosing again\n",
			st->key, st->fee_asset_hex);
		st->have_feeutxo = false;
	}

	/* Choose the fee coin once, then REUSE it for every RBF rung so each
	 * replacement keeps the same fee input (only fee/change move).  The
	 * fee is paid in the coin's asset, which is the channel asset only
	 * when the node accepts that for fees and the wallet holds it. */
	if (!st->have_feeutxo) {
		struct fee_coin coin;
		const char *why;

		if (!choose_fee_coin(tmpctx, asset33, 500 * (n + 1), &coin,
				     &why)) {
			/* Said once until it changes; every round tries again. */
			if (!st->no_fee_coin || !streq(st->no_fee_coin, why)) {
				fprintf(stderr, "speculad: %s: cannot fund the "
					"justice for %zu output(s) in asset %s: "
					"%s; trying again every round\n",
					st->key, n, asset_hex, why);
				tal_free(st->no_fee_coin);
				st->no_fee_coin = tal_strdup(g_state_ctx, why);
			}
			return NULL;
		}
		st->no_fee_coin = tal_free(st->no_fee_coin);
		st->feeutxo = coin.op;
		st->feeutxo_val = coin.value;
		tal_free(st->feeutxo_spk);
		st->feeutxo_spk = tal_steal(g_state_ctx, coin.spk);
		memcpy(st->fee_asset33, coin.asset33, 33);
		tal_free(st->fee_asset_hex);
		st->fee_asset_hex = tal_strdup(g_state_ctx, coin.asset_hex);
		st->have_feeutxo = true;
	}
	uval = st->feeutxo_val;
	rate = asset_rate(st->fee_asset_hex);

	tx = bitcoin_tx(ctx, chainparams, n + 1, n + 2, b->tx->wtx->locktime);
	tx->wtx->version = b->tx->wtx->version;
	/* Blob k's input and output, in the channel asset. */
	bitcoin_tx_set_output_asset(tx, asset33);
	for (size_t k = 0; k < n; k++) {
		struct bitcoin_outpoint op;
		const struct wally_tx_output *o = &blobs[k]->tx->wtx->outputs[0];

		bitcoin_tx_input_get_outpoint(blobs[k]->tx, 0, &op);
		if (blobs[k]->kind == WT_TMPL_TCOV_REVOKE)
			/* Its wscript is the spent output's scriptPubKey. */
			bitcoin_tx_add_input(tx, &op,
					     blobs[k]->tx->wtx->inputs[0].sequence,
					     NULL, blobs[k]->amount,
					     blobs[k]->wscript, NULL);
		else
			bitcoin_tx_add_input(tx, &op,
					     blobs[k]->tx->wtx->inputs[0].sequence,
					     NULL, blobs[k]->amount, NULL,
					     blobs[k]->wscript);
		bitcoin_tx_input_copy_witness(tx, k, blobs[k]->tx, 0);
		bitcoin_tx_add_output(tx, tal_dup_arr(tmpctx, u8, o->script,
						      o->script_len, 0),
				      NULL, blobs[k]->amount);
	}
	/* The fee input, its change and the explicit fee output, all in the
	 * fee coin's asset: the blobs balance among themselves, so the fee
	 * is the fee input less its change. */
	bitcoin_tx_set_output_asset(tx, st->fee_asset33);
	bitcoin_tx_add_input(tx, &st->feeutxo, SPD_RBF_SEQUENCE, NULL,
			     amount_sat(uval), st->feeutxo_spk, NULL);
	change_idx = bitcoin_tx_add_output(tx, st->feeutxo_spk, NULL,
					   amount_sat(uval));
	fee_idx = -1;
	if (chainparams->is_elements)
		fee_idx = bitcoin_tx_add_output(tx, NULL, NULL, AMOUNT_SAT(0));

	/* Weight incl. the p2wpkh fee-input witness (~108wu). */
	weight = bitcoin_tx_weight(tx) + 108;
	feerate = feerate_in_asset(spd_feerate_perkw(b, breach_confs, st->rung,
						     remote_to_self_delay),
				   rate);
	feeamt = amount_tx_fee(feerate, weight);
	minfee = amount_tx_fee(feerate_in_asset(FEERATE_FLOOR, rate), weight);
	if (amount_sat_less(feeamt, minfee))
		feeamt = minfee;
	/* Cap the fee so change stays >= dust (a too-small UTXO caps the max
	 * feerate: the fee wallet must hold adequately-sized UTXOs). */
	if (!amount_sat_sub(&maxfee, amount_sat(uval), SPD_DUST_SAT))
		return NULL;
	if (amount_sat_greater(feeamt, maxfee))
		feeamt = maxfee;
	if (!amount_sat_sub(&changeamt, amount_sat(uval), feeamt))
		return NULL;
	bitcoin_tx_output_set_amount(tx, change_idx, changeamt);
	if (fee_idx >= 0)
		bitcoin_tx_output_set_amount(tx, fee_idx, feeamt);
	st->fee_paid = feeamt;
	assert(bitcoin_tx_check(tx));

	/* NON-CUSTODY GUARD: output k is byte-for-byte blob k's output 0. */
	for (size_t k = 0; k < n; k++) {
		const struct wally_tx_output *want = &blobs[k]->tx->wtx->outputs[0];
		const struct wally_tx_output *got = &tx->wtx->outputs[k];

		if (got->script_len != want->script_len
		    || memcmp(got->script, want->script, want->script_len) != 0
		    || got->asset_len != want->asset_len
		    || memcmp(got->asset, want->asset, want->asset_len) != 0
		    || got->value_len != want->value_len
		    || memcmp(got->value, want->value, want->value_len) != 0) {
			fprintf(stderr, "speculad: REFUSING -- output %zu is not "
				"the pre-signed recovery output\n", k);
			return NULL;
		}
	}

	raw = linearize_tx(ctx, tx);
	hex = tal_hexstr(ctx, raw, tal_bytelen(raw));
	extra = tal_arr(tmpctx, const char *, 1);
	extra[0] = hex;
	res = run_cli_wallet(ctx, "signrawtransactionwithwallet", extra);
	if (!res)
		return NULL;
	/* "complete":false is EXPECTED (the wallet can't verify the blob
	 * inputs, whose key is on the device). */
	signed_hex = json_find_string(ctx, res, "hex");
	if (!signed_hex)
		return NULL;

	/* Elements' signrawtransactionwithwallet re-serializes the tx and STRIPS
	 * the witnesses of the inputs it doesn't own down to a single element.
	 * Re-parse the wallet-signed tx (which now carries our fee input's
	 * witness) and restore every blob's pre-signed witness. */
	{
		struct bitcoin_tx *stx;

		stx = bitcoin_tx_from_hex(ctx, signed_hex, strlen(signed_hex));
		if (!stx)
			return NULL;
		for (size_t k = 0; k < n; k++)
			bitcoin_tx_input_copy_witness(stx, k, blobs[k]->tx, 0);
		raw = linearize_tx(ctx, stx);
		signed_hex = tal_hexstr(ctx, raw, tal_bytelen(raw));
	}
	return signed_hex;
}

/* Strip trailing whitespace from a CLI answer. */
static char *trim(char *res)
{
	size_t n = strlen(res);
	while (n && (res[n - 1] == '\n' || res[n - 1] == '\r'
		     || res[n - 1] == ' '))
		res[--n] = '\0';
	return res;
}

/* SEQUENTIA: a WT_TMPL_TCOV_REVOKE blob (taproot-covenant channel) holds a
 * spend of the revoked to_local by its REVOKE leaf, which needs no
 * signature, and to_local's script.  Every claim the cheater makes from that
 * commitment pays an output with that script, which the same witness spends;
 * so the blobs to broadcast are one per unspent output paying it, found in
 * the UTXO set, each a copy of the template spending that output. */
static struct spd_blob **tcov_revoke_blobs(const tal_t *ctx,
					   const struct spd_blob *tmpl)
{
	struct spd_blob **out = tal_arr(ctx, struct spd_blob *, 0);
	const char **extra = tal_arr(tmpctx, const char *, 2);
	const jsmntok_t *toks, *unspents, *t;
	char *res;
	size_t i;

	extra[0] = "start";
	extra[1] = tal_fmt(extra, "[\"raw(%s)\"]",
			   tal_hex(tmpctx, tmpl->wscript));
	res = run_cli(tmpctx, "scantxoutset", extra);
	if (!res)
		return out;
	toks = json_parse_simple(tmpctx, res, strlen(res));
	if (!toks)
		return out;
	unspents = json_get_member(res, toks, "unspents");
	if (!unspents || unspents->type != JSMN_ARRAY)
		return out;
	json_for_each_arr(i, t, unspents) {
		const jsmntok_t *txid = json_get_member(res, t, "txid");
		const jsmntok_t *vout = json_get_member(res, t, "vout");
		const char *obj = json_strdup(tmpctx, res, t);
		struct spd_blob *b;
		struct bitcoin_outpoint op;
		u64 sat;
		char *hex;
		u8 *spk;
		struct amount_asset tmpl_out;

		if (!txid || !vout || !json_to_u32(res, vout, &op.n)
		    || !json_find_btc_sat(obj, "amount", &sat))
			continue;
		hex = json_strdup(tmpctx, res, txid);
		if (!bitcoin_txid_from_hex(hex, strlen(hex), &op.txid))
			continue;
		b = tal(out, struct spd_blob);
		b->kind = tmpl->kind;
		b->commit_num = tmpl->commit_num;
		b->output_index = op.n;
		b->amount = amount_sat(sat);
		b->deadline_delta = tmpl->deadline_delta;
		b->wscript = tal_dup_talarr(b, u8, tmpl->wscript);
		tmpl_out = bitcoin_tx_output_get_amount(tmpl->tx, 0);
		spk = tal_dup_arr(tmpctx, u8,
				  tmpl->tx->wtx->outputs[0].script,
				  tmpl->tx->wtx->outputs[0].script_len, 0);
		b->tx = bitcoin_tx(b, chainparams, 1, 1, 0);
		bitcoin_tx_set_output_asset(b->tx, tmpl_out.asset);
		bitcoin_tx_add_input(b->tx, &op, 0xFFFFFFFF, NULL, b->amount,
				     tmpl->wscript, NULL);
		bitcoin_tx_input_copy_witness(b->tx, 0, tmpl->tx, 0);
		bitcoin_tx_add_output(b->tx, spk, NULL, b->amount);
		bitcoin_tx_finalize(b->tx);
		tal_arr_expand(&out, b);
	}
	return out;
}

/* Defend a confirmed breach: one justice transaction for every output of the
 * revoked commitment that is still unspent in the confirmed UTXO set,
 * re-broadcast each round with a higher fee (RBF) until it confirms. */
static void defend_breach(struct revoked_commit *rc, long breach_confs,
			  bool may_broadcast, u32 remote_to_self_delay)
{
	char *key = tal_fmt(tmpctx, "%s:justice", rc->locator);
	struct justice_state *st = spd_get_state(key);
	struct spd_blob **live = tal_arr(tmpctx, struct spd_blob *, 0);
	char *signed_hex, *res;
	const char **extra;

	/* Phase E (seam #2): REORG-SAFE de-dup.  The gate is the confirmed
	 * UTXO-set status of the outpoint each blob spends (its input 0) --
	 * NOT a persistent "confirmed" latch.  A blob is live while that
	 * outpoint is unspent in the confirmed UTXO set: a revoked
	 * commitment's output (kinds 0 and 1) until our justice or the
	 * peer's own spend lands, and the output of the peer's second-stage
	 * HTLC transaction (kind 2) only once that transaction has confirmed,
	 * which is when the peer has won the race for the commitment's HTLC
	 * output.  Spent (or not yet created) leaves it out THIS round only; a
	 * later reorg that re-exposes the outpoint flips it back to UNSPENT
	 * and it rejoins the set (principle #1, no finality).  UNKNOWN (RPC
	 * error) conservatively keeps defending. */
	struct spd_blob **blobs = tal_arr(tmpctx, struct spd_blob *, 0);

	for (size_t k = 0; k < tal_count(rc->blobs); k++) {
		if (rc->blobs[k]->kind == WT_TMPL_TCOV_REVOKE) {
			struct spd_blob **found
				= tcov_revoke_blobs(tmpctx, rc->blobs[k]);
			fprintf(stderr, "speculad: %s: %zu unspent output(s)"
				" pay the revoked to_local's script\n",
				rc->locator, tal_count(found));
			for (size_t f = 0; f < tal_count(found); f++)
				tal_arr_expand(&blobs, found[f]);
		} else
			tal_arr_expand(&blobs, rc->blobs[k]);
	}

	for (size_t k = 0; k < tal_count(blobs); k++) {
		struct spd_blob *b = blobs[k];
		struct bitcoin_outpoint op;
		const char *op_txid;

		bitcoin_tx_input_get_outpoint(b->tx, 0, &op);
		op_txid = fmt_bitcoin_txid(tmpctx, &op.txid);
		if (rpc_txout_state(tmpctx, op_txid, op.n) == SPD_TXOUT_SPENT) {
			if (b->kind != WT_TMPL_STEAL_HTLC_TX_PENALTY)
				fprintf(stderr, "speculad: revoked outpoint "
					"%s:%u SPENT (our last justice %s) -- "
					"done this round\n", op_txid, op.n,
					st->broadcast_txid ? st->broadcast_txid
					: "none");
			continue;
		}
		if (b->kind == WT_TMPL_STEAL_HTLC_TX_PENALTY)
			fprintf(stderr, "speculad: the peer's second-stage HTLC "
				"transaction %s for output %u of %s is confirmed: "
				"punishing its output\n", op_txid,
				b->output_index, rc->locator);
		tal_arr_expand(&live, b);
	}
	if (tal_count(live) == 0 || !may_broadcast)
		return;

	signed_hex = attach_fee_and_sign(tmpctx, live, st, breach_confs,
					 remote_to_self_delay);
	extra = tal_arr(tmpctx, const char *, 1);
	if (!signed_hex) {
		/* Fee wallet absent or no suitable UTXO: broadcast the raw
		 * zero-fee blobs so the breach is still surfaced/logged.  They
		 * are typically rejected below-min-relay. */
		for (size_t k = 0; k < tal_count(live); k++) {
			u8 *raw = linearize_tx(tmpctx, live[k]->tx);
			extra[0] = tal_hexstr(tmpctx, raw, tal_bytelen(raw));
			if (!run_cli(tmpctx, "sendrawtransaction", extra))
				fprintf(stderr, "speculad: unfunded justice for "
					"%s:%u rejected\n", rc->locator,
					live[k]->output_index);
		}
		return;
	}

	extra[0] = signed_hex;
	res = run_cli(tmpctx, "sendrawtransaction", extra);
	if (res) {
		tal_free(st->broadcast_txid);
		st->broadcast_txid = tal_strdup(g_state_ctx, trim(res));
		st->rung++;		/* next poll escalates the feerate (RBF) */
		fprintf(stderr, "speculad: broadcast justice %s for %zu "
			"output(s) -> txid %s (rung %u, feerate ~%u reference "
			"atoms/kw, fee %"PRIu64" atoms of asset %s, %s)\n",
			key, tal_count(live), st->broadcast_txid,
			st->rung, spd_feerate_perkw(live[0], breach_confs,
						    st->rung - 1,
						    remote_to_self_delay),
			st->fee_paid.satoshis, /* Raw: an atom count */
			st->fee_asset_hex,
			memcmp(st->fee_asset33,
			       bitcoin_tx_output_get_amount(live[0]->tx, 0).asset,
			       33) == 0
			? "the channel asset"
			: asset_rate(asset33_to_rpchex(tmpctx,
				bitcoin_tx_output_get_amount(live[0]->tx, 0).asset)) == 0
			? "the channel asset is not accepted for fees by this node"
			: "the fee wallet holds no coin of the channel asset");
	} else {
		fprintf(stderr, "speculad: sendrawtransaction rejected for "
			"%s (%zu output(s))\n", key, tal_count(live));
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
		struct spd_blob **one = tal_arr(tmpctx, struct spd_blob *, 1);
		one[0] = (struct spd_blob *)b;
		signed_hex = attach_fee_and_sign(tmpctx, one, st, confs,
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

/* ---- Symmetric channels (common/sym_scripts.h) ----------------------------- *
 * A symmetric channel has nothing to punish: an old state on chain is
 * replaced by a newer one, and the latest settles after the shared delay.
 * Its store is one record, `sym` (lightningd/watchtower_store.h): the
 * channel's constants and the best state the node holds with both update
 * signatures, plus the peer's newest, which the node signed alone.  That is
 * enough to answer ANY older state, because an update's witness publishes
 * the new state's number and R, from which the state output, its UPD leaf
 * and control block are rebuilt (sym_rebuild_state): public hashes and
 * tweaks, no key.
 *
 * Each round, while the funding output is spent, the tower follows the
 * chain of spends from it through the blocks: the kickoff to KO, each update
 * to its state output.  Over the state output that stands, it publishes an
 * update into the stored best state when that is newer; once the state that
 * stands is the stored one (or the peer's newest) and the delay has passed,
 * it publishes the settlement.  Either pays its fee from the fee wallet, as
 * a justice transaction does (choose_fee_coin), and is raised by replacement
 * at each new block until its input is spent.  A reorg below what was
 * scanned restarts the walk from the funding output, so the tower always acts
 * on the chain as it now stands.  HTLC outputs of the settlement are left to
 * the node: claiming them needs its key. */

/* Where the walk of one channel's spends stands (cross-round). */
struct sym_cursor {
	u64 dbid;
	struct bitcoin_outpoint funding;
	/* Last block scanned (0: none yet), and its hash. */
	u32 scanned;
	struct bitcoin_blkid scanned_hash;
	/* The output that stands: the funding (num -2), KO (-1) or state
	 * num's, created by a transaction confirmed at cur_height. */
	struct bitcoin_outpoint cur;
	s64 num;
	struct sha256 rest;
	struct amount_sat cur_sats;
	u8 *cur_spk;
	u32 cur_height;
	/* Spent by a settle or by something that is not a kickoff. */
	bool done;
	/* Tip height of our last broadcast over cur: one per block. */
	long bcast_tip;
	/* Last thing said, so a round says it once. */
	char *said;
};
static struct sym_cursor **g_sym_cursors;

#define SYM_FUNDING_NUM ((s64)-2)
/* Version 2 appends the factory; version 1 records still read. */
#define WT_SYM_VERSION 2

static struct spd_sym *read_sym(const tal_t *ctx, const char *chandir)
{
	char *path = path_join(tmpctx, chandir, "sym");
	u8 *contents = grab_file_str(tmpctx, path);
	const u8 *cursor;
	size_t max;
	struct spd_sym *s;
	u64 version;

	if (!contents)
		return NULL;
	cursor = contents;
	max = tal_bytelen(contents) - 1;	/* grab_file_str's NUL */
	s = tal(ctx, struct spd_sym);
	version = fromwire_u64(&cursor, &max);
	if (version != 1 && version != WT_SYM_VERSION) {
		fprintf(stderr, "speculad: %s: unknown version %"PRIu64"\n",
			path, version);
		return tal_free(s);
	}
	s->dbid = fromwire_u64(&cursor, &max);
	fromwire_bitcoin_blkid(&cursor, &max, &s->genesis);
	fromwire_bitcoin_outpoint(&cursor, &max, &s->funding);
	s->funding_height = fromwire_u32(&cursor, &max);
	s->funding_sats = fromwire_amount_sat(&cursor, &max);
	fromwire_u8_array(&cursor, &max, s->asset, sizeof(s->asset));
	s->delay = fromwire_u16(&cursor, &max);
	fromwire_pubkey(&cursor, &max, &s->key[SYM_OPENER]);
	fromwire_pubkey(&cursor, &max, &s->key[SYM_ACCEPTER]);
	s->we_opened = fromwire_bool(&cursor, &max);
	s->best = fromwire_bool(&cursor, &max)
		? fromwire_sym_state(s, &cursor, &max) : NULL;
	s->pending = fromwire_bool(&cursor, &max)
		? fromwire_sym_state(s, &cursor, &max) : NULL;
	s->factory = NULL;
	if (version >= 2 && fromwire_bool(&cursor, &max)) {
		s->factory = fromwire_sym_factory(s, &cursor, &max);
		if (s->factory && s->factory->slot >= tal_count(s->factory->slots))
			s->factory = tal_free(s->factory);
		if (!s->factory)
			fromwire_fail(&cursor, &max);
	}
	if (!cursor) {
		fprintf(stderr, "speculad: %s does not decode\n", path);
		return tal_free(s);
	}
	sym_channel_init(&s->sc, &s->genesis, &s->funding,
			 &s->key[SYM_OPENER], &s->key[SYM_ACCEPTER],
			 s->asset, s->delay);
	return s;
}

static void sym_say(struct sym_cursor *k, const char *fmt, ...)
	PRINTF_FMT(2, 3);

static void sym_say(struct sym_cursor *k, const char *fmt, ...)
{
	va_list ap;
	char *msg;

	va_start(ap, fmt);
	msg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);
	if (k->said && streq(k->said, msg))
		return;
	fprintf(stderr, "speculad: sym dbid=%"PRIu64": %s\n", k->dbid, msg);
	tal_free(k->said);
	k->said = tal_strdup(k, msg);
}

static void sym_cursor_reset(struct sym_cursor *k)
{
	k->scanned = 0;
	k->cur = k->funding;
	k->num = SYM_FUNDING_NUM;
	k->cur_spk = tal_free(k->cur_spk);
	k->cur_height = 0;
	k->done = false;
	k->bcast_tip = -1;
}

static struct sym_cursor *sym_cursor_get(const struct spd_sym *s)
{
	struct sym_cursor *k;

	for (size_t i = 0; i < tal_count(g_sym_cursors); i++)
		if (g_sym_cursors[i]->dbid == s->dbid
		    && bitcoin_outpoint_eq(&g_sym_cursors[i]->funding,
					   sym_anchor(s)))
			return g_sym_cursors[i];
	k = tal(g_state_ctx, struct sym_cursor);
	k->dbid = s->dbid;
	k->funding = *sym_anchor(s);
	k->cur_spk = NULL;
	k->said = NULL;
	sym_cursor_reset(k);
	tal_arr_expand(&g_sym_cursors, k);
	return k;
}

/* The block at @height, and its hash; NULL on RPC failure. */
static struct bitcoin_block *sym_block_at(const tal_t *ctx, u32 height,
					  struct bitcoin_blkid *hash)
{
	const char **extra = tal_arr(tmpctx, const char *, 1);
	char *hex, *res;

	extra[0] = tal_fmt(extra, "%u", height);
	hex = run_cli(tmpctx, "getblockhash", extra);
	if (!hex)
		return NULL;
	hex = trim(hex);
	if (!bitcoin_blkid_from_hex(hex, strlen(hex), hash))
		return NULL;
	extra = tal_arr(tmpctx, const char *, 2);
	extra[0] = hex;
	extra[1] = "0";
	res = run_cli(tmpctx, "getblock", extra);
	if (!res)
		return NULL;
	res = trim(res);
	return bitcoin_block_from_hex(ctx, chainparams, res, strlen(res));
}

static bool sym_block_hash_is(u32 height, const struct bitcoin_blkid *hash)
{
	const char **extra = tal_arr(tmpctx, const char *, 1);
	struct bitcoin_blkid h;
	char *hex;

	extra[0] = tal_fmt(extra, "%u", height);
	hex = run_cli(tmpctx, "getblockhash", extra);
	if (!hex)
		return true;	/* unknown: keep what we have */
	hex = trim(hex);
	return bitcoin_blkid_from_hex(hex, strlen(hex), &h)
		&& bitcoin_blkid_eq(&h, hash);
}

static u8 **sym_input_witness(const tal_t *ctx, const struct wally_tx_input *in)
{
	u8 **items;

	if (!in->witness)
		return tal_arr(ctx, u8 *, 0);
	items = tal_arr(ctx, u8 *, in->witness->num_items);
	for (size_t i = 0; i < in->witness->num_items; i++)
		items[i] = tal_dup_arr(items, u8, in->witness->items[i].witness,
				       in->witness->items[i].witness_len, 0);
	return items;
}

/* @tx's input @i spends k->cur: move the walk on. */
static void sym_follow(const struct spd_sym *s, struct sym_cursor *k,
		       const struct bitcoin_tx *tx,
		       const struct bitcoin_txid *txid, size_t i, u32 height)
{
	const struct wally_tx_output *o = i < tx->wtx->num_outputs
		? &tx->wtx->outputs[i] : NULL;
	u8 **wit = sym_input_witness(tmpctx, &tx->wtx->inputs[i]);
	struct amount_asset a;
	u8 *spk;
	s64 n;
	struct sha256 rest;

	if (k->num == SYM_FUNDING_NUM) {
		struct sym_tree ko;

		/* A factory's split pays the channel's KO at the output
		 * numbered as its slot, whatever input spends F. */
		if (s->factory) {
			i = s->factory->slot;
			o = i < tx->wtx->num_outputs ? &tx->wtx->outputs[i]
				: NULL;
		}
		sym_kickoff_tree(tmpctx, &s->sc, &ko);
		spk = sym_tree_spk(tmpctx, &ko);
		if (s->factory && (!o || !memeq(o->script, o->script_len, spk,
						 tal_bytelen(spk)))) {
			sym_say(k, "factory output spent by %s, which does not"
				" pay this channel's KO: nothing to watch",
				fmt_bitcoin_txid(tmpctx, txid));
			k->done = true;
			return;
		}
		if (!o || !memeq(o->script, o->script_len, spk, tal_bytelen(spk))) {
			sym_say(k, "funding spent by %s, not a kickoff (a mutual"
				" close): nothing to watch",
				fmt_bitcoin_txid(tmpctx, txid));
			k->done = true;
			return;
		}
		n = -1;
	} else if (sym_witness_len((const u8 **)wit) == 2) {
		/* A settle (an annex, which whoever mined it may have added,
		 * left out). */
		sym_say(k, "state %"PRId64" settled by %s", k->num,
			fmt_bitcoin_txid(tmpctx, txid));
		k->done = true;
		return;
	} else {
		u8 *leaf, *cb;

		if (!sym_parse_update_witness((const u8 **)wit, &n, &rest)) {
			sym_say(k, "state %"PRId64" spent by %s, neither an"
				" update nor a settle", k->num,
				fmt_bitcoin_txid(tmpctx, txid));
			k->done = true;
			return;
		}
		sym_rebuild_state(tmpctx, &s->sc, n, &rest, &spk, &leaf, &cb);
		if (!o || !memeq(o->script, o->script_len, spk, tal_bytelen(spk))) {
			sym_say(k, "update %s does not pay state %"PRId64"'s"
				" output at %zu", fmt_bitcoin_txid(tmpctx, txid),
				n, i);
			k->done = true;
			return;
		}
		k->rest = rest;
	}
	a = wally_tx_output_get_amount(o);
	k->cur.txid = *txid;
	k->cur.n = i;
	k->num = n;
	k->cur_sats = amount_sat(a.value);
	tal_free(k->cur_spk);
	k->cur_spk = tal_dup_talarr(k, u8, spk);
	k->cur_height = height;
	k->bcast_tip = -1;
	fprintf(stderr, "speculad: sym dbid=%"PRIu64": %s %s:%zu at height %u\n",
		k->dbid, n == -1 ? "kickoff, KO" : tal_fmt(tmpctx, "state %"PRId64,
							   n),
		fmt_bitcoin_txid(tmpctx, txid), i, height);
}

/* Scan blocks up to @tip, following the spends.  False on RPC failure. */
static bool sym_scan(const struct spd_sym *s, struct sym_cursor *k, long tip)
{
	if (k->scanned && !sym_block_hash_is(k->scanned, &k->scanned_hash)) {
		fprintf(stderr, "speculad: sym dbid=%"PRIu64": reorg below"
			" height %u: following the spends again\n", k->dbid,
			k->scanned);
		sym_cursor_reset(k);
	}
	if (!k->scanned) {
		u32 from = s->funding_height;
		if (!from)
			from = tip > 2016 ? tip - 2016 : 1;
		k->scanned = from - 1;
	}
	while (!k->done && (long)k->scanned < tip) {
		u32 h = k->scanned + 1;
		struct bitcoin_blkid hash;
		struct bitcoin_block *b = sym_block_at(tmpctx, h, &hash);

		if (!b)
			return false;
		for (size_t t = 0; t < tal_count(b->tx) && !k->done; t++) {
			const struct bitcoin_tx *tx = b->tx[t];

			for (size_t i = 0; i < tx->wtx->num_inputs; i++) {
				if (!wally_tx_input_spends(&tx->wtx->inputs[i],
							   &k->cur))
					continue;
				sym_follow(s, k, tx, &b->txids[t], i, h);
				break;
			}
		}
		k->scanned = h;
		k->scanned_hash = hash;
	}
	return true;
}

/* The state stored under @num, or NULL. */
static const struct sym_state *sym_stored(const struct spd_sym *s, s64 num)
{
	if (s->best && s->best->num == num)
		return s->best;
	if (s->pending && s->pending->num == num)
		return s->pending;
	return NULL;
}

/* Input 0 spends k->cur with @witness and @sequence into @outs; the fee
 * input, its change and the fee follow, in the fee coin's asset.  Signed by
 * the fee wallet, input 0's witness restored after. */
static char *sym_fund(const tal_t *ctx, const struct spd_sym *s,
		      const struct sym_cursor *k, struct justice_state *st,
		      u8 **witness, u32 sequence,
		      const struct sym_state_out *outs, u32 feerate_perkw)
{
	struct bitcoin_tx *tx, *stx;
	struct amount_sat feeamt, minfee, maxfee, changeamt;
	int change_idx, fee_idx = -1;
	char *hex, *signed_hex, *res;
	const char **extra;
	size_t weight;
	u64 rate;
	u8 *raw;

	if (!g_fee_wallet)
		return NULL;
	if (st->have_feeutxo && asset_rate(st->fee_asset_hex) == 0)
		st->have_feeutxo = false;
	if (!st->have_feeutxo) {
		struct fee_coin coin;
		const char *why;

		if (!choose_fee_coin(tmpctx, s->asset, 2000, &coin, &why)) {
			fprintf(stderr, "speculad: %s: cannot fund it: %s\n",
				st->key, why);
			return NULL;
		}
		st->feeutxo = coin.op;
		st->feeutxo_val = coin.value;
		tal_free(st->feeutxo_spk);
		st->feeutxo_spk = tal_steal(g_state_ctx, coin.spk);
		memcpy(st->fee_asset33, coin.asset33, 33);
		tal_free(st->fee_asset_hex);
		st->fee_asset_hex = tal_strdup(g_state_ctx, coin.asset_hex);
		st->have_feeutxo = true;
	}
	rate = asset_rate(st->fee_asset_hex);

	tx = bitcoin_tx(ctx, chainparams, 2, tal_count(outs) + 2, 0);
	bitcoin_tx_set_output_asset(tx, s->asset);
	bitcoin_tx_add_input(tx, &k->cur, sequence, NULL, k->cur_sats,
			     k->cur_spk, NULL);
	bitcoin_tx_input_set_witness(tx, 0, witness);
	for (size_t i = 0; i < tal_count(outs); i++)
		bitcoin_tx_add_output(tx, outs[i].spk, NULL, outs[i].amount);
	bitcoin_tx_set_output_asset(tx, st->fee_asset33);
	bitcoin_tx_add_input(tx, &st->feeutxo, SPD_RBF_SEQUENCE, NULL,
			     amount_sat(st->feeutxo_val), st->feeutxo_spk, NULL);
	change_idx = bitcoin_tx_add_output(tx, st->feeutxo_spk, NULL,
					   amount_sat(st->feeutxo_val));
	if (chainparams->is_elements)
		fee_idx = bitcoin_tx_add_output(tx, NULL, NULL, AMOUNT_SAT(0));

	weight = bitcoin_tx_weight(tx) + 108;
	feeamt = amount_tx_fee(feerate_in_asset(feerate_perkw, rate), weight);
	minfee = amount_tx_fee(feerate_in_asset(FEERATE_FLOOR, rate), weight);
	if (amount_sat_less(feeamt, minfee))
		feeamt = minfee;
	if (!amount_sat_sub(&maxfee, amount_sat(st->feeutxo_val), SPD_DUST_SAT))
		return NULL;
	if (amount_sat_greater(feeamt, maxfee))
		feeamt = maxfee;
	if (!amount_sat_sub(&changeamt, amount_sat(st->feeutxo_val), feeamt))
		return NULL;
	bitcoin_tx_output_set_amount(tx, change_idx, changeamt);
	if (fee_idx >= 0)
		bitcoin_tx_output_set_amount(tx, fee_idx, feeamt);
	st->fee_paid = feeamt;

	raw = linearize_tx(tmpctx, tx);
	hex = tal_hexstr(tmpctx, raw, tal_bytelen(raw));
	extra = tal_arr(tmpctx, const char *, 1);
	extra[0] = hex;
	res = run_cli_wallet(tmpctx, "signrawtransactionwithwallet", extra);
	if (!res)
		return NULL;
	signed_hex = json_find_string(tmpctx, res, "hex");
	if (!signed_hex)
		return NULL;
	/* The wallet strips the witness of the input it does not own. */
	stx = bitcoin_tx_from_hex(tmpctx, signed_hex, strlen(signed_hex));
	if (!stx)
		return NULL;
	bitcoin_tx_input_copy_witness(stx, 0, tx, 0);
	/* NON-CUSTODY GUARD: what the state pays, and nothing else, in
	 * outputs 0 .. m-1. */
	for (size_t i = 0; i < tal_count(outs); i++) {
		const struct wally_tx_output *got = &stx->wtx->outputs[i];
		struct amount_asset a = wally_tx_output_get_amount(got);

		if (!memeq(got->script, got->script_len, outs[i].spk,
			   tal_bytelen(outs[i].spk))
		    || !amount_asset_is(&a, s->asset)
		    || a.value != outs[i].amount.satoshis) { /* Raw: compare */
			fprintf(stderr, "speculad: REFUSING -- output %zu is not"
				" the state's\n", i);
			return NULL;
		}
	}
	raw = linearize_tx(tmpctx, stx);
	return tal_hexstr(ctx, raw, tal_bytelen(raw));
}

/* Feerate: from the base toward the ceiling as the deadline (the delay
 * after the stale state confirmed) nears, plus a step per replacement. */
static u32 sym_feerate(long elapsed, u32 window, u32 rung)
{
	double urgency;
	u64 fr;

	if (elapsed < 0)
		elapsed = 0;
	if (window && (u32)elapsed > window)
		elapsed = window;
	urgency = window ? (double)elapsed / (double)window : 0;
	fr = (u64)g_fee_base_perkw
		+ (u64)(urgency * (double)(g_fee_max_perkw - g_fee_base_perkw))
		+ (u64)rung * (g_fee_base_perkw / 4 + 1);
	if (fr > g_fee_max_perkw)
		fr = g_fee_max_perkw;
	if (fr < FEERATE_FLOOR)
		fr = FEERATE_FLOOR;
	return (u32)fr;
}

static void defend_sym(const struct spd_sym *s, long tip, bool may_broadcast)
{
	struct sym_cursor *k = sym_cursor_get(s);
	enum spd_txout_state fs;
	const struct sym_state *st;
	const struct bip340sig *sig_op, *sig_acc;
	struct sym_tree tree;
	struct sym_state_out *outs;
	u8 **witness;
	u32 sequence, feerate;
	bool update;
	struct justice_state *js;
	const char **extra;
	char *hex, *res;

	if (tip < 0)
		return;
	if (!bitcoin_blkid_eq(&s->genesis, &chainparams->genesis_blockhash)) {
		sym_say(k, "its record is for another chain: ignored");
		return;
	}
	fs = rpc_txout_state(tmpctx,
			     fmt_bitcoin_txid(tmpctx, &sym_anchor(s)->txid),
			     sym_anchor(s)->n);
	if (fs == SPD_TXOUT_UNKNOWN)
		return;
	if (fs == SPD_TXOUT_UNSPENT) {
		if (k->scanned)
			sym_cursor_reset(k);
		return;
	}
	if (!sym_scan(s, k, tip) || k->done || k->num == SYM_FUNDING_NUM)
		return;
	/* Spent in a block this round's scan has not reached: the next
	 * round follows it. */
	if (rpc_txout_state(tmpctx, fmt_bitcoin_txid(tmpctx, &k->cur.txid),
			    k->cur.n) != SPD_TXOUT_UNSPENT)
		return;

	update = s->best && s->best->num > k->num
		&& sym_state_signed(s->best, s->we_opened ? LOCAL : REMOTE,
				    &sig_op, &sig_acc);
	if (update) {
		u8 *prev_leaf, *prev_cb, *spk;
		struct sym_tree prev;

		if (k->num == -1) {
			sym_kickoff_tree(tmpctx, &s->sc, &prev);
			prev_leaf = prev.upd;
			prev_cb = sym_tree_control_block(tmpctx, &prev,
							 SYM_LEAF_UPD);
		} else
			sym_rebuild_state(tmpctx, &s->sc, k->num, &k->rest,
					  &spk, &prev_leaf, &prev_cb);
		sym_state_tree_of(tmpctx, &s->sc, s->best, &tree);
		witness = sym_update_witness(tmpctx, sig_op, sig_acc, &tree,
					     prev_leaf, prev_cb);
		outs = tal_arr(tmpctx, struct sym_state_out, 1);
		outs[0].amount = k->cur_sats;
		outs[0].spk = sym_tree_spk(outs, &tree);
		sequence = SYM_SEQUENCE;
		sym_say(k, "%s %"PRId64" stands: replacing it by state %"PRId64,
			k->num == -1 ? "KO" : "state", k->num, s->best->num);
	} else {
		u8 *spk;

		st = sym_stored(s, k->num);
		if (!st) {
			sym_say(k, "state %"PRId64" stands and its settlement is"
				" not stored here: its holder settles it",
				k->num);
			return;
		}
		sym_state_tree_of(tmpctx, &s->sc, st, &tree);
		spk = sym_tree_spk(tmpctx, &tree);
		if (!memeq(spk, tal_bytelen(spk), k->cur_spk,
			   tal_bytelen(k->cur_spk))) {
			sym_say(k, "state %"PRId64" stands with another"
				" settlement than the one stored", k->num);
			return;
		}
		/* CSV: the settle may be mined at cur_height + delay. */
		if (tip + 1 < (long)k->cur_height + s->delay) {
			sym_say(k, "state %"PRId64" stands: settling it at height"
				" %u", k->num, k->cur_height + s->delay);
			return;
		}
		witness = sym_settle_witness(tmpctx, &tree);
		outs = st->outs;
		sequence = s->delay;
	}
	if (!may_broadcast || k->bcast_tip == tip)
		return;

	js = spd_get_state(tal_fmt(tmpctx, "sym:%"PRIu64":%s:%u:%s", s->dbid,
				   fmt_bitcoin_txid(tmpctx, &k->cur.txid),
				   k->cur.n, update ? "update" : "settle"));
	feerate = update
		? sym_feerate(tip - k->cur_height + 1, s->delay, js->rung)
		: sym_feerate(0, 0, js->rung);
	hex = sym_fund(tmpctx, s, k, js, witness, sequence, outs, feerate);
	if (!hex)
		return;
	extra = tal_arr(tmpctx, const char *, 1);
	extra[0] = hex;
	res = run_cli(tmpctx, "sendrawtransaction", extra);
	if (!res) {
		fprintf(stderr, "speculad: %s: sendrawtransaction rejected\n",
			js->key);
		js->have_feeutxo = false;
		return;
	}
	k->bcast_tip = tip;
	js->rung++;
	tal_free(js->broadcast_txid);
	js->broadcast_txid = tal_strdup(g_state_ctx, trim(res));
	fprintf(stderr, "speculad: sym dbid=%"PRIu64": broadcast %s over %s"
		" %"PRId64" -> txid %s (rung %u, ~%u reference atoms/kw, fee %"
		PRIu64" atoms of asset %s)\n", s->dbid,
		update ? tal_fmt(tmpctx, "the update to state %"PRId64,
				 s->best->num) : "the settlement",
		k->num == -1 ? "KO" : "state", k->num, js->broadcast_txid,
		js->rung, feerate,
		js->fee_paid.satoshis, /* Raw: an atom count */
		js->fee_asset_hex);
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
		"--fee-wallet names the box-owned node wallet holding fee UTXOs\n"
		"(bech32/p2wpkh) that speculad appends to SINGLE|ACP justice blobs\n"
		"(+ change + explicit fee output) and RBFs; the fee is paid in the\n"
		"channel asset when the node accepts it and the wallet holds it, else\n"
		"in the accepted asset whose largest coin covers the most fees,\n"
		"converted at the node's exchange rate for it.\n"
		"--fee-base-perkw and --fee-max-perkw are in reference atoms.\n"
		"Requires the node to run with txindex=1 (breach + confirmation\n"
		"detection use getrawtransaction).  Without --fee-wallet the zero-fee\n"
		"blob is broadcast as-is (below the relay minimum, so refused).\n",
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
	g_sym_cursors = tal_arr(top, struct sym_cursor *, 0);

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

		/* The fee whitelist, for fees paid in a channel asset. */
		refresh_rates();

		chans = load_channels(tmpctx, netdir);
		for (size_t i = 0; i < tal_count(chans); i++) {
			struct watched_channel *c = chans[i];

			/* A symmetric channel: nothing to punish, an old state
			 * to replace and the latest to settle. */
			if (c->sym) {
				defend_sym(c->sym, tip_height, may_broadcast);
				continue;
			}

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

			/* A revoked commitment can only be on chain once the
			 * funding output is spent: while it is unspent there
			 * is no breach to look for, and the round costs one
			 * call per channel, not one per revoked state. */
			if (!outpoint_is_zero(&c->funding)
			    && rpc_txout_state(tmpctx,
					       fmt_bitcoin_txid(tmpctx,
								&c->funding.txid),
					       c->funding.n) == SPD_TXOUT_UNSPENT)
				continue;

			for (size_t j = 0; j < tal_count(c->revoked); j++) {
				struct revoked_commit *rc = c->revoked[j];
				long confs = rpc_tx_confirmations(tmpctx,
								  rc->locator);

				if (confs < 1)
					continue;	/* not (yet) on-chain */
				load_justice(rc);

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
				/* One funded justice tx for every output still
				 * unspent, (re-)broadcast with RBF escalation;
				 * outputs already spent drop out (de-dup).
				 * defend_breach is safe without the lease (it
				 * only reads the UTXO set then). */
				defend_breach(rc, confs, may_broadcast,
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
