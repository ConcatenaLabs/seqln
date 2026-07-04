#ifndef LIGHTNING_HSMD_SIGNER_NOISE_H
#define LIGHTNING_HSMD_SIGNER_NOISE_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/tal/tal.h>
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

#endif /* LIGHTNING_HSMD_SIGNER_NOISE_H */
