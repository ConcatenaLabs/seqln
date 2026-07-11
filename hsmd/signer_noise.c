/*~ SeqLN Tier-2: BOLT-8 Noise_XK secure transport for the remote signer link
 * (initiator side).  See signer_noise.h.
 *
 * This is a synchronous (blocking) port of connectd/handshake.c's INITIATOR
 * path: the exact same Noise_XK ops over the exact same primitives
 * (ccan/crypto/{sha256,hkdf_sha256}, secp256k1 ECDH, libsodium
 * ChaCha20-Poly1305-IETF).  After the handshake we reuse common/cryptomsg.c's
 * audited transport cipher (cryptomsg_encrypt_msg / cryptomsg_decrypt_*), so the
 * only bespoke code here is wiring, not crypto.  The device signer
 * (contrib/seqln-signer/src/noise.rs) is the byte-compatible responder.
 */
#include "config.h"
#include <assert.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/tal.h>
#include <common/crypto_state.h>
#include <common/cryptomsg.h>
#include <common/randbytes.h>
#include <common/status.h>
#include <common/utils.h>
#include <hsmd/signer_frame.h>
#include <hsmd/signer_noise.h>
#include <secp256k1_ecdh.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* One BOLT-8 transport message body is length-prefixed by a u16. */
#define NOISE_MAX_MSG 65535

struct signer_noise {
	int fd;
	struct crypto_state cs;
	/* Decrypted-but-unconsumed plaintext from the read stream. */
	u8 *rbuf;   /* tal array (may be NULL when empty) */
	size_t roff; /* bytes already consumed from rbuf */
};

/*~ The secure channel OWNS its socket: freeing it closes the fd.  This is what
 * lets the LISTEN-mode proxy tear down a dropped device connection cleanly
 * (`tal_free(signer_noise)`) instead of leaking it in CLOSE-WAIT, then loop
 * back to accept() a fresh device.  Callers must therefore NOT close the fd
 * themselves, even on handshake failure (we still own it and close it here). */
static void destroy_signer_noise(struct signer_noise *n)
{
	if (n->fd >= 0) {
		close(n->fd);
		n->fd = -1;
	}
}

/* h = SHA-256(h || data) */
static void sha_mix_in(struct sha256 *h, const void *data, size_t len)
{
	struct sha256_ctx shactx;
	sha256_init(&shactx);
	sha256_update(&shactx, h, sizeof(*h));
	sha256_update(&shactx, data, len);
	sha256_done(&shactx, h);
}

/* h = SHA-256(h || pub.serializeCompressed()) */
static void sha_mix_in_key(struct sha256 *h, const struct pubkey *key)
{
	u8 der[PUBKEY_CMPR_LEN];
	size_t len = sizeof(der);
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, der, &len, &key->pubkey,
				      SECP256K1_EC_COMPRESSED);
	assert(len == sizeof(der));
	sha_mix_in(h, der, sizeof(der));
}

/* out1, out2 = HKDF(salt=in1, ikm=in2) */
static void hkdf_two_keys(struct secret *out1, struct secret *out2,
			  const struct secret *in1,
			  const void *in2, size_t in2_size)
{
	struct secret okm[2];
	hkdf_sha256(okm, sizeof(okm), in1, sizeof(*in1), in2, in2_size, NULL, 0);
	*out1 = okm[0];
	*out2 = okm[1];
}

static void le64_nonce(unsigned char *npub, u64 nonce)
{
	le64 le_nonce = cpu_to_le64(nonce);
	const size_t zerolen = crypto_aead_chacha20poly1305_ietf_NPUBBYTES - sizeof(le_nonce);
	memset(npub, 0, zerolen);
	memcpy(npub + zerolen, &le_nonce, sizeof(le_nonce));
}

static void encrypt_ad(const struct secret *k, u64 nonce,
		       const void *ad, size_t ad_len,
		       const void *plaintext, size_t plaintext_len,
		       void *output, size_t outputlen)
{
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long clen;
	int ret;
	assert(outputlen == plaintext_len + crypto_aead_chacha20poly1305_ietf_ABYTES);
	le64_nonce(npub, nonce);
	ret = crypto_aead_chacha20poly1305_ietf_encrypt(output, &clen,
							plaintext, plaintext_len,
							ad, ad_len, NULL, npub,
							k->data);
	assert(ret == 0);
	assert(clen == plaintext_len + crypto_aead_chacha20poly1305_ietf_ABYTES);
}

static bool decrypt(const struct secret *k, u64 nonce,
		    const void *ad, size_t ad_len,
		    const void *ciphertext, size_t ciphertext_len,
		    void *output, size_t outputlen)
{
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long mlen;
	assert(outputlen == ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES);
	le64_nonce(npub, nonce);
	if (crypto_aead_chacha20poly1305_ietf_decrypt(output, &mlen, NULL,
						      ciphertext, ciphertext_len,
						      ad, ad_len, npub,
						      k->data) != 0)
		return false;
	assert(mlen == ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES);
	return true;
}

/*~ Run the Noise_XK initiator handshake synchronously.  On success fills
 * `cs`; on any failure returns false and NOTHING has been usefully exchanged. */
static bool initiator_handshake(int fd,
				const struct secret *my_privkey,
				const struct pubkey *their_pinned_pub,
				struct crypto_state *cs)
{
	struct sha256 h;
	struct secret ck, temp_k, ss;
	struct privkey e_priv;
	struct pubkey e_pub, my_pub, re;
	u8 act1[50], act2[50], act3[66];
	u8 spub[PUBKEY_CMPR_LEN];
	size_t len;

	/* Derive our own static pubkey from the privkey. */
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &my_pub.pubkey,
					my_privkey->data))
		return false;

	/* Init: h = SHA256(protocolName); ck = h; h = SHA256(h||prologue);
	 *       h = SHA256(h || responder_static.pub). */
	sha256(&h, "Noise_XK_secp256k1_ChaChaPoly_SHA256",
	       strlen("Noise_XK_secp256k1_ChaChaPoly_SHA256"));
	memcpy(&ck, &h, sizeof(ck));
	sha_mix_in(&h, "lightning", strlen("lightning"));
	sha_mix_in_key(&h, their_pinned_pub);

	/* --- Act One (send) --- */
	do {
		randbytes(e_priv.secret.data, sizeof(e_priv.secret.data));
	} while (!secp256k1_ec_pubkey_create(secp256k1_ctx, &e_pub.pubkey,
					     e_priv.secret.data));
	sha_mix_in_key(&h, &e_pub);
	/* es = ECDH(e.priv, rs) */
	if (!secp256k1_ecdh(secp256k1_ctx, ss.data, &their_pinned_pub->pubkey,
			    e_priv.secret.data, NULL, NULL))
		return false;
	hkdf_two_keys(&ck, &temp_k, &ck, ss.data, sizeof(ss));
	act1[0] = 0;
	len = PUBKEY_CMPR_LEN;
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, act1 + 1, &len,
				      &e_pub.pubkey, SECP256K1_EC_COMPRESSED);
	encrypt_ad(&temp_k, 0, &h, sizeof(h), NULL, 0, act1 + 34, 16);
	sha_mix_in(&h, act1 + 34, 16);
	if (!write_all(fd, act1, sizeof(act1)))
		return false;

	/* --- Act Two (receive) --- */
	if (!read_all(fd, act2, sizeof(act2)))
		return false;
	if (act2[0] != 0)
		return false;
	if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &re.pubkey, act2 + 1,
				      PUBKEY_CMPR_LEN) != 1)
		return false;
	sha_mix_in_key(&h, &re);
	/* ee = ECDH(e.priv, re) */
	if (!secp256k1_ecdh(secp256k1_ctx, ss.data, &re.pubkey,
			    e_priv.secret.data, NULL, NULL))
		return false;
	hkdf_two_keys(&ck, &temp_k, &ck, ss.data, sizeof(ss));
	/* Authenticates the responder: fails unless it holds the pinned key. */
	if (!decrypt(&temp_k, 0, &h, sizeof(h), act2 + 34, 16, NULL, 0))
		return false;
	sha_mix_in(&h, act2 + 34, 16);

	/* --- Act Three (send our static key) --- */
	len = sizeof(spub);
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, spub, &len, &my_pub.pubkey,
				      SECP256K1_EC_COMPRESSED);
	act3[0] = 0;
	encrypt_ad(&temp_k, 1, &h, sizeof(h), spub, sizeof(spub), act3 + 1, 49);
	sha_mix_in(&h, act3 + 1, 49);
	/* se = ECDH(s.priv, re) */
	if (!secp256k1_ecdh(secp256k1_ctx, ss.data, &re.pubkey,
			    my_privkey->data, NULL, NULL))
		return false;
	hkdf_two_keys(&ck, &temp_k, &ck, ss.data, sizeof(ss));
	encrypt_ad(&temp_k, 0, &h, sizeof(h), NULL, 0, act3 + 50, 16);
	if (!write_all(fd, act3, sizeof(act3)))
		return false;

	/* Derive final transport keys (initiator split: sk=okm[0], rk=okm[1]). */
	hkdf_two_keys(&cs->sk, &cs->rk, &ck, NULL, 0);
	cs->rn = cs->sn = 0;
	cs->r_ck = cs->s_ck = ck;
	return true;
}

struct signer_noise *signer_noise_connect(const tal_t *ctx, int fd,
					  const struct secret *my_privkey,
					  const struct pubkey *their_pinned_pub)
{
	struct signer_noise *n = tal(ctx, struct signer_noise);
	n->fd = fd;
	n->rbuf = NULL;
	n->roff = 0;
	tal_add_destructor(n, destroy_signer_noise);

	if (!initiator_handshake(fd, my_privkey, their_pinned_pub, &n->cs))
		return tal_free(n);
	return n;
}

/*~ Run the Noise_XK RESPONDER handshake synchronously — the SeqLN Tier-2
 * BROWSER topology.  A browser device cannot listen(), so it connects OUT and is
 * the initiator; the hosted proxy therefore BINDS/accepts and plays the
 * responder here.  This is the exact mirror of initiator_handshake (same
 * primitives), only the roles are swapped: we mix in OUR OWN static key as the
 * "responder static", answer Act One, send Act Two with a fresh ephemeral, and
 * in Act Three recover + PIN-CHECK the initiator's (device's) static key.  The
 * transport-key split is the responder one (rk=okm[0], sk=okm[1]), matching the
 * initiator's (sk=okm[0], rk=okm[1]) so the two directions line up.
 * contrib/seqln-signer/src/noise.rs's `Initiator` is the byte-compatible peer. */
/*~ SeqLN Tier-2 A2: bare-fd poll-gated exact read/write for the RESPONDER
 * HANDSHAKE.  The accepted device fd is O_NONBLOCK from its first byte (set in
 * signer_noise_accept BEFORE the handshake), so a connector that completes TCP
 * but then stalls (or dribbles) handshake bytes can NEVER block the proxy's
 * single-threaded io loop: every read/write is gated by poll() against a
 * per-handshake `deadline`.  No cipher, no watch-fd — a stalled handshake simply
 * times out and the connector is rejected (fail-closed), and the proxy keeps
 * listening.  Returns true once `len` bytes are moved, false on EOF/error/deadline. */
static bool hs_poll_exact(int fd, u8 *buf, size_t len, bool writing,
			  struct timemono deadline)
{
	size_t done = 0;

	while (done < len) {
		struct pollfd pfd;
		struct timemono now = time_mono();
		u64 msleft;
		int ms, pr;
		ssize_t n;

		if (!timemono_before(now, deadline))
			return false; /* handshake deadline exceeded */
		msleft = time_to_msec(timemono_between(deadline, now));
		if (msleft == 0)
			msleft = 1;
		if (msleft > 500)
			msleft = 500; /* slice so we re-check the deadline promptly */
		ms = (int)msleft;

		pfd.fd = fd;
		pfd.events = writing ? POLLOUT : POLLIN;
		pfd.revents = 0;
		pr = poll(&pfd, 1, ms);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		if (pr == 0)
			continue; /* slice elapsed; loop re-checks the deadline */

		if (writing)
			n = (pfd.revents & POLLOUT) ? write(fd, buf + done, len - done)
						   : -2;
		else
			n = (pfd.revents & POLLIN) ? read(fd, buf + done, len - done)
						  : -2;
		if (n == -2) {
			/* No I/O readiness; a HUP/ERR with nothing to read is dead. */
			if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
				return false;
			continue;
		}
		if (n > 0) {
			done += n;
			continue;
		}
		if (n == 0)
			return false; /* EOF */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			continue;
		return false;
	}
	return true;
}

/*~ Run the Noise_XK RESPONDER handshake, poll-driven with a per-handshake
 * deadline (SeqLN Tier-2 A2) so a stalled/half-open connector can never freeze
 * the proxy.  See hs_poll_exact.  The crypto is identical to a synchronous run;
 * only the raw fd I/O is now poll-gated. */
static bool responder_handshake(int fd,
				const struct secret *my_privkey,
				const struct pubkey *their_pinned_pub,
				struct crypto_state *cs,
				struct timemono deadline)
{
	struct sha256 h;
	struct secret ck, temp_k, ss;
	struct privkey e_priv;
	struct pubkey e_pub, my_pub, re, rs;
	u8 act1[50], act2[50], act3[66];
	u8 rs_der[PUBKEY_CMPR_LEN], pinned_der[PUBKEY_CMPR_LEN];
	size_t len;

	/* Our own static pubkey (the "responder static" mixed into the hash). */
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &my_pub.pubkey,
					my_privkey->data))
		return false;

	sha256(&h, "Noise_XK_secp256k1_ChaChaPoly_SHA256",
	       strlen("Noise_XK_secp256k1_ChaChaPoly_SHA256"));
	memcpy(&ck, &h, sizeof(ck));
	sha_mix_in(&h, "lightning", strlen("lightning"));
	sha_mix_in_key(&h, &my_pub);

	/* --- Act One (receive) --- */
	if (!hs_poll_exact(fd, act1, sizeof(act1), false, deadline))
		return false;
	if (act1[0] != 0)
		return false;
	if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &re.pubkey, act1 + 1,
				      PUBKEY_CMPR_LEN) != 1)
		return false;
	sha_mix_in_key(&h, &re);
	/* es = ECDH(s.priv, re) */
	if (!secp256k1_ecdh(secp256k1_ctx, ss.data, &re.pubkey,
			    my_privkey->data, NULL, NULL))
		return false;
	hkdf_two_keys(&ck, &temp_k, &ck, ss.data, sizeof(ss));
	/* Authenticates: fails unless the initiator knew our static key. */
	if (!decrypt(&temp_k, 0, &h, sizeof(h), act1 + 34, 16, NULL, 0))
		return false;
	sha_mix_in(&h, act1 + 34, 16);

	/* --- Act Two (send our ephemeral + authenticating tag) --- */
	do {
		randbytes(e_priv.secret.data, sizeof(e_priv.secret.data));
	} while (!secp256k1_ec_pubkey_create(secp256k1_ctx, &e_pub.pubkey,
					     e_priv.secret.data));
	sha_mix_in_key(&h, &e_pub);
	/* ee = ECDH(e.priv, re) */
	if (!secp256k1_ecdh(secp256k1_ctx, ss.data, &re.pubkey,
			    e_priv.secret.data, NULL, NULL))
		return false;
	hkdf_two_keys(&ck, &temp_k, &ck, ss.data, sizeof(ss));
	act2[0] = 0;
	len = PUBKEY_CMPR_LEN;
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, act2 + 1, &len,
				      &e_pub.pubkey, SECP256K1_EC_COMPRESSED);
	encrypt_ad(&temp_k, 0, &h, sizeof(h), NULL, 0, act2 + 34, 16);
	sha_mix_in(&h, act2 + 34, 16);
	if (!hs_poll_exact(fd, act2, sizeof(act2), true, deadline))
		return false;

	/* --- Act Three (receive the initiator's static key, then pin-check) --- */
	if (!hs_poll_exact(fd, act3, sizeof(act3), false, deadline))
		return false;
	if (act3[0] != 0)
		return false;
	/* rs = decrypt(c) — the initiator's (device's) static pubkey. */
	if (!decrypt(&temp_k, 1, &h, sizeof(h), act3 + 1, 49, rs_der, sizeof(rs_der)))
		return false;
	if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &rs.pubkey, rs_der,
				      sizeof(rs_der)) != 1)
		return false;
	/* PIN CHECK: this is where the responder authenticates WHICH device.
	 * Reject any static key that is not the pinned device signer. */
	len = sizeof(pinned_der);
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, pinned_der, &len,
				      &their_pinned_pub->pubkey,
				      SECP256K1_EC_COMPRESSED);
	if (memcmp(rs_der, pinned_der, sizeof(rs_der)) != 0)
		return false;
	sha_mix_in(&h, act3 + 1, 49);
	/* se = ECDH(e.priv, rs) */
	if (!secp256k1_ecdh(secp256k1_ctx, ss.data, &rs.pubkey,
			    e_priv.secret.data, NULL, NULL))
		return false;
	hkdf_two_keys(&ck, &temp_k, &ck, ss.data, sizeof(ss));
	if (!decrypt(&temp_k, 0, &h, sizeof(h), act3 + 50, 16, NULL, 0))
		return false;

	/* Final transport keys (responder split: rk=okm[0], sk=okm[1]). */
	hkdf_two_keys(&cs->rk, &cs->sk, &ck, NULL, 0);
	cs->rn = cs->sn = 0;
	cs->r_ck = cs->s_ck = ck;
	return true;
}

struct signer_noise *signer_noise_accept(const tal_t *ctx, int fd,
					 const struct secret *my_privkey,
					 const struct pubkey *their_pinned_pub)
{
	struct signer_noise *n = tal(ctx, struct signer_noise);
	struct timemono hs_deadline;
	const char *e;
	int hs_ms = 4000; /* per-handshake budget; env-overridable (tests shorten) */

	n->fd = fd;
	n->rbuf = NULL;
	n->roff = 0;
	tal_add_destructor(n, destroy_signer_noise);

	/*~ A2: the BROWSER/LISTEN topology drives this fd with the poll-driven,
	 * reconnect-aware I/O below (never the blocking calls) — AND the handshake
	 * itself is now poll-driven — so a half-dead or stalled connector can never
	 * freeze the proxy's single-threaded io loop.  Flip it non-blocking BEFORE
	 * the handshake (the old code did this only AFTER, leaving the handshake
	 * reads as a second unbounded blocking-wedge site). */
	{
		int fl = fcntl(fd, F_GETFL, 0);
		if (fl != -1)
			fcntl(fd, F_SETFL, fl | O_NONBLOCK);
	}
	e = getenv("SEQLN_SIGNER_HS_TIMEOUT_MS");
	if (e && e[0]) {
		int v = atoi(e);
		if (v > 0)
			hs_ms = v;
	}
	hs_deadline = timemono_add(time_mono(), time_from_msec(hs_ms));

	if (!responder_handshake(fd, my_privkey, their_pinned_pub, &n->cs,
				 hs_deadline))
		return tal_free(n);
	return n;
}

/* Encrypt+send arbitrary bytes as one or more BOLT-8 transport messages. */
static bool noise_stream_write_all(struct signer_noise *n,
				   const u8 *data, size_t len)
{
	while (len > 0) {
		size_t chunk = len > NOISE_MAX_MSG ? NOISE_MAX_MSG : len;
		u8 *pt = tal_dup_arr(tmpctx, u8, data, chunk, 0);
		u8 *rec = cryptomsg_encrypt_msg(tmpctx, &n->cs, take(pt));
		bool ok = write_all(n->fd, rec, tal_bytelen(rec));
		tal_free(rec);
		if (!ok)
			return false;
		data += chunk;
		len -= chunk;
	}
	return true;
}

/* Fill `dst` with exactly `len` decrypted plaintext bytes from the stream. */
static bool noise_stream_read_all(struct signer_noise *n, u8 *dst, size_t len)
{
	size_t got = 0;

	while (got < len) {
		size_t avail;

		/* Drain buffered plaintext first. */
		if (n->rbuf && n->roff < tal_bytelen(n->rbuf)) {
			avail = tal_bytelen(n->rbuf) - n->roff;
			if (avail > len - got)
				avail = len - got;
			memcpy(dst + got, n->rbuf + n->roff, avail);
			n->roff += avail;
			got += avail;
			continue;
		}

		/* Need a fresh BOLT-8 message: 18-byte header then body. */
		{
			u8 hdr[CRYPTOMSG_HDR_SIZE];
			u8 *body, *pt;
			u16 bodylen;

			n->rbuf = tal_free(n->rbuf);
			n->roff = 0;

			if (!read_all(n->fd, hdr, sizeof(hdr)))
				return false;
			if (!cryptomsg_decrypt_header(&n->cs, hdr, &bodylen))
				return false;
			body = tal_arr(tmpctx, u8, (size_t)bodylen + CRYPTOMSG_BODY_OVERHEAD);
			if (!read_all(n->fd, body, tal_bytelen(body)))
				return false;
			pt = cryptomsg_decrypt_body(n, &n->cs, body);
			tal_free(body);
			if (!pt)
				return false;
			n->rbuf = pt;
			n->roff = 0;
			/* Empty record: loop and read the next. */
		}
	}
	return true;
}

bool signer_noise_write_request(struct signer_noise *n, bool is_main,
				const struct node_id *id,
				u64 dbid, u64 capabilities,
				const u8 *hsmd_msg)
{
	u8 *frame = signer_frame_build_request(tmpctx, is_main, id, dbid,
					       capabilities, hsmd_msg);
	return noise_stream_write_all(n, frame, tal_bytelen(frame));
}

u8 *signer_noise_read_reply(const tal_t *ctx, struct signer_noise *n)
{
	u8 lenbuf[4];
	u32 len;
	u8 *msg;

	if (!noise_stream_read_all(n, lenbuf, sizeof(lenbuf)))
		return NULL;
	len = sframe_get_u32(lenbuf);
	msg = tal_arr(ctx, u8, len);
	if (len && !noise_stream_read_all(n, msg, len))
		return tal_free(msg);
	return msg;
}

/* ------------------------------------------------------------------------- *
 * SeqLN Tier-2 ROBUST (poll-driven) LISTEN-mode I/O.  See signer_noise.h.
 *
 * The fd is O_NONBLOCK (set by signer_noise_accept).  We never let a syscall
 * block: every raw read()/write() is gated by poll() with a bounded per-op
 * DEADLINE, and while we wait we ALSO watch a caller-supplied listen socket so a
 * reconnecting device pre-empts a stuck one.  On any non-OK the caller discards
 * this whole channel, so bailing out mid-record (with a partly-advanced cipher
 * nonce) is safe — the request is re-sent fresh to the next device.
 * ------------------------------------------------------------------------- */

/* poll() budget per wait: bounded so we re-check the deadline promptly and stay
 * responsive to a newcomer even on a long total deadline. */
#define NOISE_POLL_SLICE_MS 500

/* Milliseconds until `deadline`, clamped to a poll slice; <=0 means expired. */
static int ms_until(struct timemono deadline)
{
	struct timemono now = time_mono();
	u64 ms;
	if (!timemono_before(now, deadline))
		return -1;
	ms = time_to_msec(timemono_between(deadline, now));
	if (ms == 0)
		ms = 1;
	if (ms > NOISE_POLL_SLICE_MS)
		ms = NOISE_POLL_SLICE_MS;
	return (int)ms;
}

/* Read EXACTLY len raw bytes into dst, poll-gated on n->fd (+ optional watch_fd),
 * honouring `deadline`.  Returns OK / DEVICE_DEAD / NEWCOMER / TIMEOUT. */
static enum signer_noise_status
poll_read_raw(struct signer_noise *n, u8 *dst, size_t len,
	      int watch_fd, struct timemono deadline)
{
	size_t got = 0;

	while (got < len) {
		struct pollfd pfd[2];
		int nfds = 1, ms, pr;

		pfd[0].fd = n->fd; pfd[0].events = POLLIN; pfd[0].revents = 0;
		if (watch_fd >= 0) {
			pfd[1].fd = watch_fd; pfd[1].events = POLLIN;
			pfd[1].revents = 0; nfds = 2;
		}
		ms = ms_until(deadline);
		if (ms < 0)
			return SIGNER_NOISE_TIMEOUT;

		pr = poll(pfd, nfds, ms);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			return SIGNER_NOISE_DEVICE_DEAD;
		}
		if (pr == 0)
			continue; /* slice elapsed; ms_until re-checks the deadline */

		/* Always drain a device that has data (finish a legit in-flight
		 * reply) BEFORE yielding to a newcomer. */
		if (pfd[0].revents & POLLIN) {
			ssize_t r = read(n->fd, dst + got, len - got);
			if (r > 0) {
				got += r;
				continue;
			}
			if (r == 0)
				return SIGNER_NOISE_DEVICE_DEAD; /* EOF */
			if (errno == EINTR || errno == EAGAIN
			    || errno == EWOULDBLOCK)
				continue;
			return SIGNER_NOISE_DEVICE_DEAD;
		}
		/* No device data: a pending newcomer means the browser
		 * reconnected — "newest wins", so yield to it. */
		if (nfds == 2 && (pfd[1].revents & POLLIN))
			return SIGNER_NOISE_NEWCOMER;
		if (pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL))
			return SIGNER_NOISE_DEVICE_DEAD;
	}
	return SIGNER_NOISE_OK;
}

/* Write EXACTLY len raw bytes from src, poll-gated on n->fd (+ optional
 * watch_fd), honouring `deadline`. */
static enum signer_noise_status
poll_write_raw(struct signer_noise *n, const u8 *src, size_t len,
	       int watch_fd, struct timemono deadline)
{
	size_t sent = 0;

	while (sent < len) {
		struct pollfd pfd[2];
		int nfds = 1, ms, pr;

		pfd[0].fd = n->fd; pfd[0].events = POLLOUT; pfd[0].revents = 0;
		if (watch_fd >= 0) {
			pfd[1].fd = watch_fd; pfd[1].events = POLLIN;
			pfd[1].revents = 0; nfds = 2;
		}
		ms = ms_until(deadline);
		if (ms < 0)
			return SIGNER_NOISE_TIMEOUT;

		pr = poll(pfd, nfds, ms);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			return SIGNER_NOISE_DEVICE_DEAD;
		}
		if (pr == 0)
			continue;

		if (pfd[0].revents & POLLOUT) {
			ssize_t w = write(n->fd, src + sent, len - sent);
			if (w > 0) {
				sent += w;
				continue;
			}
			if (w < 0 && (errno == EINTR || errno == EAGAIN
				      || errno == EWOULDBLOCK))
				continue;
			return SIGNER_NOISE_DEVICE_DEAD;
		}
		/* Can't make write progress (stuck send buffer) but a newcomer
		 * is waiting: the current link is wedged — yield to the newcomer. */
		if (nfds == 2 && (pfd[1].revents & POLLIN))
			return SIGNER_NOISE_NEWCOMER;
		if (pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL))
			return SIGNER_NOISE_DEVICE_DEAD;
	}
	return SIGNER_NOISE_OK;
}

/* Poll-gated variant of noise_stream_read_all: fill dst with len decrypted
 * plaintext bytes, reading fresh BOLT-8 records via poll_read_raw as needed. */
static enum signer_noise_status
noise_stream_read_all_poll(struct signer_noise *n, u8 *dst, size_t len,
			   int watch_fd, struct timemono deadline)
{
	size_t got = 0;

	while (got < len) {
		size_t avail;
		enum signer_noise_status st;

		/* Drain buffered plaintext first. */
		if (n->rbuf && n->roff < tal_bytelen(n->rbuf)) {
			avail = tal_bytelen(n->rbuf) - n->roff;
			if (avail > len - got)
				avail = len - got;
			memcpy(dst + got, n->rbuf + n->roff, avail);
			n->roff += avail;
			got += avail;
			continue;
		}

		/* Fresh BOLT-8 message: 18-byte header then body. */
		{
			u8 hdr[CRYPTOMSG_HDR_SIZE];
			u8 *body, *pt;
			u16 bodylen;

			n->rbuf = tal_free(n->rbuf);
			n->roff = 0;

			st = poll_read_raw(n, hdr, sizeof(hdr), watch_fd, deadline);
			if (st != SIGNER_NOISE_OK)
				return st;
			if (!cryptomsg_decrypt_header(&n->cs, hdr, &bodylen))
				return SIGNER_NOISE_DEVICE_DEAD;
			body = tal_arr(tmpctx, u8,
				       (size_t)bodylen + CRYPTOMSG_BODY_OVERHEAD);
			st = poll_read_raw(n, body, tal_bytelen(body),
					   watch_fd, deadline);
			if (st != SIGNER_NOISE_OK) {
				tal_free(body);
				return st;
			}
			pt = cryptomsg_decrypt_body(n, &n->cs, body);
			tal_free(body);
			if (!pt)
				return SIGNER_NOISE_DEVICE_DEAD;
			n->rbuf = pt;
			n->roff = 0;
		}
	}
	return SIGNER_NOISE_OK;
}

int signer_noise_fd(const struct signer_noise *n)
{
	return n->fd;
}

enum signer_noise_status
signer_noise_write_request_poll(struct signer_noise *n, bool is_main,
				const struct node_id *id, u64 dbid,
				u64 capabilities, const u8 *hsmd_msg,
				int watch_fd, struct timemono deadline)
{
	u8 *frame = signer_frame_build_request(tmpctx, is_main, id, dbid,
					       capabilities, hsmd_msg);
	size_t len = tal_bytelen(frame), off = 0;

	/* Encrypt + send as one or more BOLT-8 records (mirrors
	 * noise_stream_write_all, but each record is poll-gated). */
	while (off < len) {
		size_t chunk = len - off > NOISE_MAX_MSG ? NOISE_MAX_MSG
							 : len - off;
		u8 *pt = tal_dup_arr(tmpctx, u8, frame + off, chunk, 0);
		u8 *rec = cryptomsg_encrypt_msg(tmpctx, &n->cs, take(pt));
		enum signer_noise_status st =
		    poll_write_raw(n, rec, tal_bytelen(rec), watch_fd, deadline);
		tal_free(rec);
		if (st != SIGNER_NOISE_OK)
			return st;
		off += chunk;
	}
	return SIGNER_NOISE_OK;
}

enum signer_noise_status
signer_noise_read_reply_poll(const tal_t *ctx, struct signer_noise *n,
			     int watch_fd, struct timemono deadline,
			     u8 **reply)
{
	enum signer_noise_status st;
	u8 lenbuf[4];
	u32 len;
	u8 *msg;

	*reply = NULL;
	st = noise_stream_read_all_poll(n, lenbuf, sizeof(lenbuf),
					watch_fd, deadline);
	if (st != SIGNER_NOISE_OK)
		return st;
	len = sframe_get_u32(lenbuf);
	msg = tal_arr(ctx, u8, len);
	if (len) {
		st = noise_stream_read_all_poll(n, msg, len, watch_fd, deadline);
		if (st != SIGNER_NOISE_OK) {
			tal_free(msg);
			return st;
		}
	}
	*reply = msg;
	return SIGNER_NOISE_OK;
}
