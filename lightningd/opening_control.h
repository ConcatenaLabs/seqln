#ifndef LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H
#define LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <lightningd/peer_control.h>

struct channel_id;
struct crypto_state;
struct json_stream;
struct lightningd;
struct peer_fd;
struct uncommitted_channel;

void NON_NULL_ARGS(2, 4) json_add_uncommitted_channel(struct command *cmd,
						      struct json_stream *response,
						      const struct uncommitted_channel *uc,
						      const struct peer *peer);

bool peer_start_openingd(struct peer *peer,
			 struct peer_fd *peer_fd);

struct subd *peer_get_owning_subd(struct peer *peer);

/* Parse a display asset id (32-byte hex) into the 33-byte elements asset
 * tag (0x01 || byte-reversed id). */
struct command_result *param_asset_tag(struct command *cmd,
				       const char *name,
				       const char *buffer,
				       const jsmntok_t *tok,
				       const u8 **asset);

#endif /* LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H */
