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

	if (!initiator_handshake(fd, my_privkey, their_pinned_pub, &n->cs))
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
