#ifndef LIGHTNING_HSMD_SIGNER_FRAME_H
#define LIGHTNING_HSMD_SIGNER_FRAME_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/tal.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <string.h>

/*~ SeqLN Tier-2 signer-split transport (milestone M1).
 *
 * The `hsmd-proxy` process terminates the hsmd wire on fd 3 from lightningd and
 * forwards every request that needs the root secret to a separate `signerd`
 * process over ONE bidirectional socket.  fd-multiplexing (WIRE_HSMD_CLIENT_HSMFD)
 * is answered LOCALLY in the proxy and never crosses this transport, so the
 * signer only ever sees a pure request/response stream.
 *
 * This is deliberately a tiny, self-describing frame protocol so it can be
 * reimplemented byte-for-byte by a Rust/WASM device signer in M2.  ALL
 * multi-byte integers are LITTLE-ENDIAN.  There is exactly one request in
 * flight at a time (synchronous request/response).
 *
 * Request  (proxy -> signerd):
 *
 *     u32  len            byte length of everything after this field
 *     u8   is_main        1 = "main" client (dbid-0: lightningd/gossipd/connectd)
 *                         0 = per-peer client
 *     [33] node_id        compressed pubkey, present ONLY when is_main == 0
 *     u64  dbid           per-channel db id (0 for main clients)
 *     u64  capabilities   HSM_PERM_* bitmap for this client
 *     ...  hsmd_msg        the raw hsmd wire message (len - the fields above)
 *
 *   The signer reconstructs the libhsmd client context from {is_main, node_id,
 *   dbid, capabilities} exactly as the monolithic hsmd would, then hands
 *   `hsmd_msg` to libhsmd (with WIRE_HSMD_INIT / WIRE_HSMD_CHECK_BIP86_PUBKEY
 *   special-cased, mirroring hsmd.c).
 *
 * Reply    (signerd -> proxy):
 *
 *     u32  len            byte length of the reply message
 *     ...  hsmd_msg        the raw hsmd wire reply
 *
 *   A zero-length reply (len == 0) is the error sentinel: the signer could not
 *   satisfy the request (a real hsmd reply is always >= 2 bytes, the type).
 *   The proxy turns it into a normal hsmd "bad request" back to lightningd.
 */

/* Little-endian scalar codecs (host-endianness independent). */
static inline void sframe_put_u32(u8 buf[4], u32 v)
{
	buf[0] = v & 0xff;
	buf[1] = (v >> 8) & 0xff;
	buf[2] = (v >> 16) & 0xff;
	buf[3] = (v >> 24) & 0xff;
}

static inline u32 sframe_get_u32(const u8 buf[4])
{
	return (u32)buf[0] | ((u32)buf[1] << 8) | ((u32)buf[2] << 16)
		| ((u32)buf[3] << 24);
}

static inline void sframe_put_u64(u8 buf[8], u64 v)
{
	for (int i = 0; i < 8; i++)
		buf[i] = (v >> (8 * i)) & 0xff;
}

static inline u64 sframe_get_u64(const u8 buf[8])
{
	u64 v = 0;
	for (int i = 0; i < 8; i++)
		v |= (u64)buf[i] << (8 * i);
	return v;
}

/* PROXY side: build the full framed request buffer (4-byte len prefix +
 * payload) into a fresh tal array off `ctx`.  Factored out so both the raw-fd
 * path (signer_write_request) and the Noise-secured remote path
 * (signer_noise.c) emit byte-identical frames. */
static inline u8 *signer_frame_build_request(const tal_t *ctx, bool is_main,
					     const struct node_id *id,
					     u64 dbid, u64 capabilities,
					     const u8 *hsmd_msg)
{
	size_t msglen = tal_bytelen(hsmd_msg);
	size_t idlen = is_main ? 0 : PUBKEY_CMPR_LEN;
	size_t payload_len = 1 + idlen + 8 + 8 + msglen;
	u8 *frame = tal_arr(ctx, u8, 4 + payload_len);
	size_t off = 0;

	sframe_put_u32(frame + off, payload_len);
	off += 4;
	frame[off++] = is_main ? 1 : 0;
	if (!is_main) {
		memcpy(frame + off, id->k, PUBKEY_CMPR_LEN);
		off += PUBKEY_CMPR_LEN;
	}
	sframe_put_u64(frame + off, dbid);
	off += 8;
	sframe_put_u64(frame + off, capabilities);
	off += 8;
	if (msglen)
		memcpy(frame + off, hsmd_msg, msglen);
	return frame;
}

/* PROXY side: send a framed request.  Returns false on write error. */
static inline bool signer_write_request(int fd, bool is_main,
					const struct node_id *id,
					u64 dbid, u64 capabilities,
					const u8 *hsmd_msg)
{
	u8 *frame = signer_frame_build_request(NULL, is_main, id, dbid,
					       capabilities, hsmd_msg);
	bool ok = write_all(fd, frame, tal_bytelen(frame));
	tal_free(frame);
	return ok;
}

/* SIGNER side: read a framed request.  Returns the raw hsmd msg (tal off ctx)
 * and fills in the client context, or NULL on EOF / malformed frame. */
static inline u8 *signer_read_request(const tal_t *ctx, int fd,
				      bool *is_main, struct node_id *id,
				      u64 *dbid, u64 *capabilities)
{
	u8 lenbuf[4];
	u32 payload_len;
	u8 *payload, *msg;
	size_t off, header, msglen;

	if (!read_all(fd, lenbuf, sizeof(lenbuf)))
		return NULL;
	payload_len = sframe_get_u32(lenbuf);
	/* Smallest legal frame: is_main(1) + dbid(8) + caps(8). */
	if (payload_len < 1 + 8 + 8)
		return NULL;

	payload = tal_arr(ctx, u8, payload_len);
	if (!read_all(fd, payload, payload_len))
		return tal_free(payload);

	off = 0;
	*is_main = payload[off++] != 0;
	header = 1 + 8 + 8 + (*is_main ? 0 : PUBKEY_CMPR_LEN);
	if (payload_len < header)
		return tal_free(payload);

	if (!*is_main) {
		memcpy(id->k, payload + off, PUBKEY_CMPR_LEN);
		off += PUBKEY_CMPR_LEN;
	} else {
		memset(id, 0, sizeof(*id));
	}
	*dbid = sframe_get_u64(payload + off);
	off += 8;
	*capabilities = sframe_get_u64(payload + off);
	off += 8;

	msglen = payload_len - off;
	msg = tal_arr(ctx, u8, msglen);
	if (msglen)
		memcpy(msg, payload + off, msglen);
	tal_free(payload);
	return msg;
}

/* SIGNER side: send a framed reply (a zero-length msg is the error sentinel). */
static inline bool signer_write_reply(int fd, const u8 *msg)
{
	size_t msglen = tal_bytelen(msg);
	u8 lenbuf[4];

	sframe_put_u32(lenbuf, msglen);
	if (!write_all(fd, lenbuf, sizeof(lenbuf)))
		return false;
	if (msglen && !write_all(fd, msg, msglen))
		return false;
	return true;
}

/* PROXY side: read a framed reply (tal off ctx), or NULL on EOF.  A returned
 * zero-length array is the signer's error sentinel. */
static inline u8 *signer_read_reply(const tal_t *ctx, int fd)
{
	u8 lenbuf[4];
	u32 len;
	u8 *msg;

	if (!read_all(fd, lenbuf, sizeof(lenbuf)))
		return NULL;
	len = sframe_get_u32(lenbuf);
	msg = tal_arr(ctx, u8, len);
	if (len && !read_all(fd, msg, len))
		return tal_free(msg);
	return msg;
}

#endif /* LIGHTNING_HSMD_SIGNER_FRAME_H */
