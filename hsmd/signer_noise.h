#ifndef LIGHTNING_HSMD_SIGNER_NOISE_H
#define LIGHTNING_HSMD_SIGNER_NOISE_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/node_id.h>

/*~ SeqLN Tier-2: BOLT-8 Noise_XK secure transport for the REMOTE signer link.
 *
 * The hosted `hsmd-proxy` is the Noise INITIATOR: it connect()s to the device
 * signer (the responder) and runs the SAME authenticated handshake CLN uses for
 * peer links ("Noise_XK_secp256k1_ChaChaPoly_SHA256"), then tunnels the
 * signer-split frames (hsmd/signer_frame.h) through the resulting encrypted +
 * integrity-protected channel using common/cryptomsg.c's transport cipher.
 *
 * Mutual authentication from pinned long-term static keys:
 *   - the proxy holds its own transport static privkey and KNOWS the device's
 *     static pubkey up front (pinned), so a wrong device key fails Act Two;
 *   - the device recovers the proxy's static pubkey in Act Three and pin-checks
 *     it, rejecting a wrong proxy.
 * These transport static keys are SEPARATE from the node's fund-controlling HSM
 * key, so provisioning/rotating them never touches signing keys.
 */
struct signer_noise;

/*~ Run the initiator handshake over an already-connected socket `fd`.
 *
 *   my_privkey        : the proxy's own 32-byte transport static privkey.
 *   their_pinned_pub  : the device signer's pinned static pubkey (the ONLY one
 *                       we will talk to).
 *
 * Returns an opaque secure-channel handle (owning `fd`), or NULL if the
 * handshake fails (wrong/absent peer key, tampering, I/O error) — in which case
 * the caller must abort: no frames have been or will be exchanged.
 */
struct signer_noise *signer_noise_connect(const tal_t *ctx, int fd,
					  const struct secret *my_privkey,
					  const struct pubkey *their_pinned_pub);

/*~ Run the RESPONDER handshake over an already-accepted socket `fd` — the SeqLN
 * Tier-2 BROWSER topology.  A browser device can't listen(), so it connects OUT
 * as the initiator and the hosted proxy accepts + plays the responder.
 *
 *   my_privkey        : the proxy's own 32-byte transport static privkey.
 *   their_pinned_pub  : the device signer's pinned static pubkey (the ONLY one
 *                       we will authenticate + serve).
 *
 * Returns an opaque secure-channel handle (owning `fd`), or NULL if the
 * handshake fails (wrong/absent device key, tampering, I/O error) — in which
 * case the caller must serve NO frames on this connection. */
struct signer_noise *signer_noise_accept(const tal_t *ctx, int fd,
					 const struct secret *my_privkey,
					 const struct pubkey *their_pinned_pub);

/*~ Send a framed signer request through the secure channel (byte-identical to
 * signer_write_request, but encrypted).  Returns false on error. */
bool signer_noise_write_request(struct signer_noise *n, bool is_main,
				const struct node_id *id,
				u64 dbid, u64 capabilities,
				const u8 *hsmd_msg);

/*~ Read a framed signer reply from the secure channel (tal off `ctx`).  Returns
 * NULL on EOF/error; a zero-length array is the signer's error sentinel, exactly
 * as signer_read_reply. */
u8 *signer_noise_read_reply(const tal_t *ctx, struct signer_noise *n);

/*~ SeqLN Tier-2 ROBUST (poll-driven) LISTEN-mode I/O.
 *
 * The blocking read/write above freeze the whole single-threaded hsmd-proxy io
 * loop if the device link goes half-dead (a browser tab sleeps / the network
 * drops with no TCP RST, so the fronting relay holds an ESTAB-but-silent TCP).
 * That froze lightningd too (getinfo hangs, sync stalls) and defeated
 * evict-on-connect, since the loop never returned to the timer.  The functions
 * below make the device-link I/O poll-driven and reconnect-aware: they wait with
 * a per-op DEADLINE while ALSO watching a listen socket, so a reconnecting device
 * can pre-empt a stuck one, and a truly-dead link fails just the op — never the
 * node.  The proxy NEVER closes lightningd's hsmd fd; it only drops the device
 * side and re-sends the parked request once a device is back.
 *
 * These are used ONLY in the browser/LISTEN topology (the accepted fd is set
 * non-blocking after the handshake by signer_noise_accept); connect() and local
 * fork modes keep the blocking calls above unchanged. */
enum signer_noise_status {
	SIGNER_NOISE_OK = 0,       /* *reply filled (read) / bytes sent (write) */
	SIGNER_NOISE_DEVICE_DEAD,  /* EOF / error / HUP on the device link */
	SIGNER_NOISE_NEWCOMER,     /* a connection is pending on watch_fd */
	SIGNER_NOISE_TIMEOUT,      /* deadline exceeded; link up but silent */
};

/*~ The device link's raw fd, for the caller's own poll() bookkeeping. */
int signer_noise_fd(const struct signer_noise *n);

/*~ Poll-driven send of one framed request.  Waits (POLLOUT) until `deadline`,
 * also watching `watch_fd` (a listen socket; pass -1 to disable) for a pending
 * newcomer.  Returns OK once fully sent, or DEVICE_DEAD / NEWCOMER / TIMEOUT. */
enum signer_noise_status
signer_noise_write_request_poll(struct signer_noise *n, bool is_main,
				const struct node_id *id, u64 dbid,
				u64 capabilities, const u8 *hsmd_msg,
				int watch_fd, struct timemono deadline);

/*~ Poll-driven read of one framed reply (tal off `ctx`).  Waits (POLLIN) until
 * `deadline`, also watching `watch_fd` for a pending newcomer.  On OK, *reply is
 * the (possibly zero-length error-sentinel) reply; otherwise *reply is NULL and
 * the status says why.  A device with an in-flight reply is always drained in
 * preference to yielding to a newcomer. */
enum signer_noise_status
signer_noise_read_reply_poll(const tal_t *ctx, struct signer_noise *n,
			     int watch_fd, struct timemono deadline,
			     u8 **reply);

#endif /* LIGHTNING_HSMD_SIGNER_NOISE_H */
