/*~ SeqLN Tier-2 out-of-process signer (milestone M1).
 *
 * `signerd` owns the hsm_secret and drives libhsmd.  It is NOT a lightningd
 * subdaemon: it is fork/exec'd by `hsmd-proxy` (see hsmd/hsmd_proxy.c) with one
 * socket, over which it speaks the framed request/response protocol defined in
 * hsmd/signer_frame.h.  Because the proxy fork()s us, we inherit its working
 * directory (the lightning network dir) and load/create `hsm_secret` from there.
 *
 * This process is the "hosted, in-C" stand-in for the future Rust/WASM device
 * signer: it proves the transport, framing and the "fd-multiplex-stays-local"
 * split end to end while still reusing libhsmd for the actual crypto.
 */
#include "config.h"
#include <ccan/err/err.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/bip32.h>
#include <common/hsm_secret.h>
#include <common/node_id.h>
#include <common/randbytes.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <fcntl.h>
#include <hsmd/libhsmd.h>
#include <hsmd/permissions.h>
#include <hsmd/signer_frame.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wire/wire.h>

/* Our root secret, loaded from the working dir at WIRE_HSMD_INIT time. */
static struct hsm_secret *hsm_secret;

/* Human-readable log for this process (in the working dir); also mirrored to
 * stderr, which the parent proxy inherits. */
static FILE *slog;

static void signerd_log(const char *fmt, ...) PRINTF_FMT(1, 2);
static void signerd_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (slog) {
		va_list ap2;
		va_copy(ap2, ap);
		vfprintf(slog, fmt, ap2);
		fputc('\n', slog);
		fflush(slog);
		va_end(ap2);
	}
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

/*~ libhsmd requires the embedding process to provide these three callbacks.
 * In the monolithic hsmd they talk to lightningd over the status socket; here
 * we simply log, since signerd is a leaf process. */
u8 *hsmd_status_bad_request(struct hsmd_client *client, const u8 *msg,
			    const char *error)
{
	signerd_log("signerd: bad request: %s", error);
	/* NULL propagates up as the zero-length error reply frame. */
	return NULL;
}

void hsmd_status_fmt(enum log_level level, const struct node_id *peer,
		     const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);
	signerd_log("signerd[%s]: %s", log_level_name(level), str);
}

void hsmd_status_failed(enum status_failreason reason, const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);
	signerd_log("signerd: FATAL (%d): %s", reason, str);
	/* Exit closes our socket; the proxy sees EOF and reports up. */
	exit(2);
}

/*~ Create a fresh mnemonic-format hsm_secret (mirrors hsmd.c:create_hsm). */
static void create_hsm(int fd, const char *passphrase)
{
	u8 *hsm_secret_data;
	int ret;
	u8 entropy[BIP39_ENTROPY_LEN_128];
	char *mnemonic = NULL;
	struct sha256 seed_hash;
	u8 bip32_seed[BIP39_SEED_LEN_512];
	size_t bip32_seed_len;

	randbytes(entropy, sizeof(entropy));

	tal_wally_start();
	ret = bip39_mnemonic_from_bytes(NULL, entropy, sizeof(entropy),
					&mnemonic);
	tal_wally_end(tmpctx);
	if (ret != WALLY_OK || !mnemonic) {
		unlink_noerr("hsm_secret");
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Failed to generate mnemonic from entropy");
	}

	if (!derive_seed_hash(mnemonic, passphrase, &seed_hash)) {
		unlink_noerr("hsm_secret");
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Failed to derive seed hash from mnemonic");
	}

	hsm_secret_data = tal_arr(tmpctx, u8, 0);
	towire_sha256(&hsm_secret_data, &seed_hash);
	towire(&hsm_secret_data, mnemonic, strlen(mnemonic));

	tal_wally_start();
	ret = bip39_mnemonic_to_seed(mnemonic, passphrase, bip32_seed,
				     sizeof(bip32_seed), &bip32_seed_len);
	tal_wally_end(tmpctx);
	if (ret != WALLY_OK) {
		unlink_noerr("hsm_secret");
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Failed to derive seed from mnemonic");
	}

	if (!write_all(fd, hsm_secret_data, tal_count(hsm_secret_data))) {
		unlink_noerr("hsm_secret");
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR, "writing: %s",
				   strerror(errno));
	}
}

/*~ Mirrors hsmd.c:maybe_create_new_hsm. */
static void maybe_create_new_hsm(const char *passphrase)
{
	int fd = open("hsm_secret", O_CREAT | O_EXCL | O_WRONLY, 0400);
	if (fd < 0) {
		if (errno == EEXIST)
			return;
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR, "creating: %s",
				   strerror(errno));
	}
	create_hsm(fd, passphrase);
	if (fsync(fd) != 0) {
		unlink_noerr("hsm_secret");
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR, "fsync: %s",
				   strerror(errno));
	}
	if (close(fd) != 0) {
		unlink_noerr("hsm_secret");
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR, "closing: %s",
				   strerror(errno));
	}
	fd = open(".", O_RDONLY);
	if (fd < 0)
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR, "opening: %s",
				   strerror(errno));
	if (fsync(fd) != 0) {
		unlink_noerr("hsm_secret");
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR, "fsyncdir: %s",
				   strerror(errno));
	}
	close(fd);
	signerd_log("signerd: created new hsm_secret file");
}

/*~ Load the hsm_secret from the working dir (mirrors hsmd.c:load_hsm).  On a
 * wrong-passphrase error we return an init_reply_failure message (so the proxy
 * relays it to lightningd); other errors are fatal. */
static u8 *load_hsm(const tal_t *ctx, const char *passphrase)
{
	u8 *hsm_secret_contents;
	struct hsm_secret *hsms;
	enum hsm_secret_error err;

	hsm_secret_contents = grab_file_raw(tmpctx, "hsm_secret");
	if (!hsm_secret_contents)
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Could not read hsm_secret: %s",
				   strerror(errno));

	hsms = extract_hsm_secret(tmpctx, hsm_secret_contents,
				  tal_bytelen(hsm_secret_contents), passphrase,
				  &err);
	if (!hsms) {
		if (err == HSM_SECRET_ERR_WRONG_PASSPHRASE)
			return towire_hsmd_init_reply_failure(
			    ctx, err,
			    tal_fmt(tmpctx, "Failed to load hsm_secret: %s",
				    hsm_secret_error_str(err)));
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Failed to load hsm_secret: %s",
				   hsm_secret_error_str(err));
	}

	hsm_secret = tal(NULL, struct hsm_secret);
	hsm_secret->secret_data = tal_steal(hsm_secret, hsms->secret_data);
	hsm_secret->type = hsms->type;
	hsm_secret->mnemonic = tal_steal(hsm_secret, hsms->mnemonic);
	mlock_tal_memory(hsm_secret->secret_data);
	return NULL;
}

/*~ Handle WIRE_HSMD_INIT (mirrors hsmd.c:init_hsm, minus the ccan/io wrapper).
 * Parses the init message (which also sets the global `chainparams`), loads the
 * secret and returns the init reply for the proxy to relay. */
static u8 *signerd_init(const tal_t *ctx, const u8 *msg_in)
{
	struct secret *hsm_encryption_key;
	struct bip32_key_version bip32_key_version;
	u32 minversion, maxversion;
	struct tlv_hsmd_init_tlvs *tlvs;
	const u32 our_minversion = 4, our_maxversion = 6;
	const char *hsm_passphrase;
	u8 *fail;

	if (!fromwire_hsmd_init(NULL, msg_in, &bip32_key_version, &chainparams,
				&hsm_encryption_key, &dev_force_privkey,
				&dev_force_bip32_seed, &dev_force_channel_secrets,
				&dev_force_channel_secrets_shaseed, &minversion,
				&maxversion, &tlvs)) {
		signerd_log("signerd: could not parse init message");
		return NULL;
	}

	if (our_minversion > maxversion || our_maxversion < minversion)
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "Version %u-%u not valid: we need %u-%u",
				   minversion, maxversion, our_minversion,
				   our_maxversion);

	hsm_passphrase = tlvs->hsm_passphrase ? tlvs->hsm_passphrase : NULL;

	maybe_create_new_hsm(hsm_passphrase);
	fail = load_hsm(ctx, hsm_passphrase);
	if (fail)
		return fail;

	hsmd_mutual_version = maxversion < our_maxversion ? maxversion
							 : our_maxversion;
	signerd_log("signerd: initialized (mnemonic HSM secret, hsmd version %"
		    PRIu64 ", network %s)",
		    hsmd_mutual_version,
		    chainparams ? chainparams->network_name : "?");
	tal_free(tlvs);
	return hsmd_init(hsm_secret->secret_data,
			 tal_bytelen(hsm_secret->secret_data), hsmd_mutual_version,
			 bip32_key_version, hsm_secret->type);
}

/*~ WIRE_HSMD_CHECK_BIP86_PUBKEY is handled outside libhsmd in the monolithic
 * hsmd; replicate it here (mirrors hsmd.c:handle_check_bip86_pubkey). */
static u8 *signerd_check_bip86_pubkey(const tal_t *ctx, const u8 *msg_in)
{
	u32 index;
	struct pubkey their_pubkey, our_pubkey;
	struct privkey our_privkey;

	if (!fromwire_hsmd_check_bip86_pubkey(msg_in, &index, &their_pubkey)) {
		signerd_log("signerd: could not parse check_bip86_pubkey");
		return NULL;
	}
	if (!use_bip86_derivation(tal_bytelen(hsm_secret->secret_data))) {
		signerd_log("signerd: BIP86 derivation requires mnemonic secret");
		return NULL;
	}
	bip86_key(&our_privkey, &our_pubkey, index);
	if (!pubkey_eq(&our_pubkey, &their_pubkey))
		hsmd_status_failed(STATUS_FAIL_INTERNAL_ERROR,
				   "BIP86 derivation index %u differed", index);
	return towire_hsmd_check_bip86_pubkey_reply(ctx, true);
}

/*~ Dispatch one framed request to libhsmd. */
static u8 *signerd_handle(const tal_t *ctx, bool is_main,
			  const struct node_id *id, u64 dbid, u64 capabilities,
			  const u8 *msg)
{
	enum hsmd_wire t = fromwire_peektype(msg);
	struct hsmd_client *client;

	if (t == WIRE_HSMD_INIT)
		return signerd_init(ctx, msg);

	if (t == WIRE_HSMD_CHECK_BIP86_PUBKEY)
		return signerd_check_bip86_pubkey(ctx, msg);

	/* Reconstruct the libhsmd client context exactly as hsmd would. */
	if (is_main)
		client = hsmd_client_new_main(ctx, capabilities, NULL);
	else
		client = hsmd_client_new_peer(ctx, capabilities, dbid, id, NULL);
	/* Peer clients need the chain params to (de)serialize elements txs;
	 * the global was set from the init message. */
	client->chainparams = chainparams;

	return hsmd_handle_client_message(ctx, client, msg);
}

int main(int argc, char *argv[])
{
	int fd, devnull;

	common_setup(argv[0]);
	signal(SIGPIPE, SIG_IGN);

	if (argc < 2)
		errx(1, "usage: %s <socket-fd>", argv[0]);
	fd = atoi(argv[1]);

	/* Route libcommon's own status_* chatter somewhere harmless; our real
	 * logging goes via signerd_log(). */
	devnull = open("/dev/null", O_WRONLY);
	if (devnull >= 0)
		status_setup_sync(devnull);

	slog = fopen("signerd.log", "a");
	signerd_log("signerd: started, transport fd %d, pid %d", fd, getpid());

	for (;;) {
		bool is_main;
		struct node_id id;
		u64 dbid, capabilities;
		u8 *msg, *reply;

		clean_tmpctx();

		msg = signer_read_request(tmpctx, fd, &is_main, &id, &dbid,
					  &capabilities);
		if (!msg) {
			signerd_log("signerd: transport closed, exiting");
			break;
		}

		reply = signerd_handle(tmpctx, is_main, &id, dbid, capabilities,
				       msg);
		/* NULL reply -> zero-length error sentinel frame. */
		if (!reply)
			reply = tal_arr(tmpctx, u8, 0);

		if (!signer_write_reply(fd, reply)) {
			signerd_log("signerd: transport write failed, exiting");
			break;
		}
	}

	common_shutdown();
	return 0;
}
