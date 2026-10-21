#include "config.h"
#include <bitcoin/script.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <channeld/channeld_wiregen.h>
#include <common/channel_type.h>
#include <common/credit_scripts.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/utils.h>
#include <connectd/connectd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/credit.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <onchaind/onchaind_wiregen.h>
#include <wallet/wallet.h>
#include <wire/wire.h>

static struct command_result *param_preimage(struct command *cmd,
					     const char *name,
					     const char *buffer,
					     const jsmntok_t *tok,
					     struct preimage **preimage)
{
	*preimage = tal(cmd, struct preimage);
	if (!hex_decode(buffer + tok->start, tok->end - tok->start,
			*preimage, sizeof(**preimage)))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be 64 hex digits");
	return NULL;
}

static struct command_result *param_bip340sig(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      struct bip340sig **sig)
{
	*sig = tal(cmd, struct bip340sig);
	if (!hex_decode(buffer + tok->start, tok->end - tok->start,
			(*sig)->u8, sizeof((*sig)->u8)))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be 128 hex digits");
	return NULL;
}

bool channel_has_credit(const struct channel *channel)
{
	return channel_type_has(channel->type, OPT_SEQ_CREDIT);
}

/* The opener provides. */
static enum side credit_provider(const struct channel *channel)
{
	return channel->opener;
}

static bool credit_params(const tal_t *ctx, const struct channel *channel,
			  struct credit_params *cp)
{
	const struct pubkey *provider_funding, *holder_payment;
	struct channel_id cid;

	if (credit_provider(channel) == LOCAL) {
		provider_funding = &channel->local_funding_pubkey;
		holder_payment = &channel->channel_info.theirbase.payment;
	} else {
		provider_funding = &channel->channel_info.remote_fundingkey;
		holder_payment = &channel->local_basepoints.payment;
	}
	/* The note's tag binds the channel by its funding outpoint, as
	 * channeld and onchaind compute it. */
	derive_channel_id(&cid, &channel->funding);
	return credit_params_init(ctx, &cid, provider_funding,
				  holder_payment, cp);
}

static bool credit_note_valid(const struct channel *channel,
			      const struct credit_note *n,
			      const char **why)
{
	struct credit_params cp;
	struct sha256 h;

	if (!credit_params(tmpctx, channel, &cp)) {
		*why = "no credit key for this channel";
		return false;
	}
	if (!credit_note_check(&cp.dtag, &cp.credit_key, n->credit,
			       &n->payment_hash, n->sig.u8)) {
		*why = "the signature is not the provider's on this note";
		return false;
	}
	if (n->preimage) {
		sha256(&h, n->preimage, sizeof(*n->preimage));
		if (!sha256_eq(&h, &n->payment_hash)) {
			*why = "the preimage is not the payment hash's";
			return false;
		}
	}
	return true;
}

struct credit_note *channel_credit_latest(const tal_t *ctx,
					  struct channel *channel)
{
	return wallet_credit_note_latest(ctx, channel->peer->ld->wallet,
					 channel->dbid,
					 credit_provider(channel) != LOCAL);
}

u64 channel_credit_owed(struct channel *channel)
{
	struct credit_note *n;

	if (!channel_has_credit(channel))
		return 0;
	n = channel_credit_latest(tmpctx, channel);
	return n ? n->credit : 0;
}

static u8 *towire_credit_msg(const tal_t *ctx, const struct channel *channel,
			     const struct credit_note *n)
{
	u8 *msg = tal_arr(ctx, u8, 0);

	towire_u16(&msg, SEQ_CREDIT_NOTE_MSG);
	towire_channel_id(&msg, &channel->cid);
	towire_u64(&msg, n->credit);
	towire_sha256(&msg, &n->payment_hash);
	towire_bip340sig(&msg, &n->sig);
	towire_bool(&msg, n->preimage != NULL);
	if (n->preimage)
		towire_preimage(&msg, n->preimage);
	return msg;
}

/* Provider: send a note to the holder, if it is connected. */
static void credit_send(struct channel *channel, const struct credit_note *n)
{
	struct lightningd *ld = channel->peer->ld;

	if (channel->peer->connected != PEER_CONNECTED)
		return;
	subd_send_msg(ld->connectd,
		      take(towire_connectd_custommsg_out(NULL, &channel->peer->id,
							 towire_credit_msg(tmpctx,
									   channel,
									   n))));
	log_debug(channel->log, "Sent credit note %"PRIu64" for %s",
		  n->credit, fmt_sha256(tmpctx, &n->payment_hash));
}

/* Hand the latest note to channeld or onchaind, whichever runs. */
static void credit_tell_owner(struct channel *channel)
{
	struct credit_note *n = channel_credit_latest(tmpctx, channel);

	if (!n || !channel->owner)
		return;
	if (streq(channel->owner->name, "channeld"))
		subd_send_msg(channel->owner,
			      take(towire_channeld_credit_note(NULL, n->credit,
							       &n->payment_hash,
							       &n->sig,
							       n->preimage)));
	else if (streq(channel->owner->name, "onchaind")
		 && credit_provider(channel) != LOCAL && n->preimage)
		subd_send_msg(channel->owner,
			      take(towire_onchaind_credit_note(NULL, n->credit,
							       &n->payment_hash,
							       &n->sig,
							       n->preimage)));
}

void credit_channel_started(struct channel *channel)
{
	struct credit_note *n;

	if (!channel_has_credit(channel))
		return;
	n = channel_credit_latest(tmpctx, channel);
	if (!n)
		return;
	if (credit_provider(channel) == LOCAL)
		credit_send(channel, n);
	credit_tell_owner(channel);
}

void credit_onchaind_started(struct channel *channel)
{
	if (channel_has_credit(channel))
		credit_tell_owner(channel);
}

/* Holder: a note from the provider (by peer message, or given by anyone
 * with addcreditnote).  Kept if it is valid; returns why not otherwise. */
static const char *credit_receive(struct channel *channel,
				  const struct credit_note *n)
{
	struct lightningd *ld = channel->peer->ld;
	struct credit_note *latest;
	const char *why;

	if (!channel_has_credit(channel))
		return "not a credit channel";
	if (credit_provider(channel) == LOCAL)
		return "this node provides the credit on that channel";
	if (!credit_note_valid(channel, n, &why))
		return why;

	latest = channel_credit_latest(tmpctx, channel);
	wallet_credit_note_save(ld->wallet, channel->dbid, false, n);
	log_info(channel->log, "Credit note: %"PRIu64" in all, for payment %s%s",
		 n->credit, fmt_sha256(tmpctx, &n->payment_hash),
		 n->preimage ? "" : " (its preimage not yet known)");
	/* A new highest enforceable note goes to whichever daemon runs. */
	if (n->preimage && (!latest || latest->credit < n->credit))
		credit_tell_owner(channel);
	return NULL;
}

static struct channel *credit_channel_by_cid(struct lightningd *ld,
					     const struct node_id *peer_id,
					     const struct channel_id *cid)
{
	struct channel *channel = channel_by_cid(ld, cid);

	if (!channel || (peer_id && !node_id_eq(&channel->peer->id, peer_id)))
		return NULL;
	return channel;
}

bool credit_handle_peer_msg(struct lightningd *ld,
			    const struct node_id *peer_id,
			    const u8 *msg)
{
	const u8 *cursor = msg;
	size_t max = tal_bytelen(msg);
	struct channel_id cid;
	struct credit_note n;
	struct channel *channel;
	const char *why;

	if (fromwire_peektype(msg) != SEQ_CREDIT_NOTE_MSG)
		return false;
	fromwire_u16(&cursor, &max);
	fromwire_channel_id(&cursor, &max, &cid);
	n.credit = fromwire_u64(&cursor, &max);
	fromwire_sha256(&cursor, &max, &n.payment_hash);
	fromwire_bip340sig(&cursor, &max, &n.sig);
	if (fromwire_bool(&cursor, &max)) {
		n.preimage = tal(tmpctx, struct preimage);
		fromwire_preimage(&cursor, &max, n.preimage);
	} else
		n.preimage = NULL;
	if (!cursor) {
		log_unusual(ld->log, "Malformed credit note from %s",
			    fmt_node_id(tmpctx, peer_id));
		return true;
	}
	channel = credit_channel_by_cid(ld, peer_id, &cid);
	if (!channel) {
		log_unusual(ld->log, "Credit note from %s for unknown channel %s",
			    fmt_node_id(tmpctx, peer_id),
			    fmt_channel_id(tmpctx, &cid));
		return true;
	}
	why = credit_receive(channel, &n);
	if (why)
		log_unusual(channel->log, "Refused a credit note from the peer:"
			    " %s", why);
	return true;
}

/* What the provider can still owe on top of @issued: its balance as the
 * holder's commitment pays it, less its HTLCs in flight, the commitment's
 * fee and the dust limit (CLAIM leaves the rest as an output). */
static bool credit_room(const struct channel *channel, u64 issued,
			u64 *room)
{
	struct amount_msat spendable = channel_amount_spendable(channel);
	u64 atoms = spendable.millisatoshis / 1000; /* Raw: atoms of the asset */
	u64 dust = channel->channel_info.their_config.dust_limit.satoshis /* Raw: atoms */
		> channel->our_config.dust_limit.satoshis /* Raw: atoms */
		? channel->channel_info.their_config.dust_limit.satoshis /* Raw: atoms */
		: channel->our_config.dust_limit.satoshis; /* Raw: atoms */

	if (atoms <= issued + dust)
		return false;
	*room = atoms - issued - dust;
	return true;
}

static void json_add_credit_note(struct json_stream *js,
				 const struct channel *channel,
				 const struct credit_note *n)
{
	json_object_start(js, NULL);
	json_add_node_id(js, "peer_id", &channel->peer->id);
	json_add_channel_id(js, "channel_id", &channel->cid);
	json_add_string(js, "role",
			credit_provider(channel) == LOCAL ? "provider" : "holder");
	json_add_u64(js, "credit", n->credit);
	json_add_sha256(js, "payment_hash", &n->payment_hash);
	json_add_bip340sig(js, "signature", &n->sig);
	if (n->preimage)
		json_add_preimage(js, "preimage", n->preimage);
	json_object_end(js);
}

/* The peer's credit channel in which we have @role, or a reason why not. */
static struct command_result *credit_channel_of(struct command *cmd,
						const struct node_id *id,
						const struct channel_id *cid,
						bool provider,
						struct channel **channel)
{
	struct peer *peer = peer_by_id(cmd->ld, id);
	struct channel *c, *found = NULL;

	if (!peer)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Unknown peer");
	list_for_each(&peer->channels, c, list) {
		if (!channel_has_credit(c)
		    || (credit_provider(c) == LOCAL) != provider)
			continue;
		if (cid && !channel_id_eq(&c->cid, cid))
			continue;
		if (found)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Several credit channels with that"
					    " peer: name one by channel_id");
		found = c;
	}
	if (!found)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "No credit channel with that peer in which"
				    " this node is the %s",
				    provider ? "provider" : "holder");
	*channel = found;
	return NULL;
}

static struct command_result *json_issuecredit(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct node_id *id;
	struct channel_id *cid;
	struct amount_msat *amount;
	struct sha256 *payment_hash;
	struct preimage *preimage;
	struct channel *channel;
	struct credit_note *latest, *n;
	struct command_result *res;
	struct json_stream *js;
	u64 add, room, issued;
	const u8 *msg;

	if (!param_check(cmd, buffer, params,
			 p_req("id", param_node_id, &id),
			 p_req("amount_msat", param_msat, &amount),
			 p_req("payment_hash", param_sha256, &payment_hash),
			 p_opt("preimage", param_preimage, &preimage),
			 p_opt("channel_id", param_channel_id, &cid),
			 NULL))
		return command_param_failed();

	res = credit_channel_of(cmd, id, cid, true, &channel);
	if (res)
		return res;
	if (preimage) {
		struct sha256 h;
		sha256(&h, preimage, sizeof(*preimage));
		if (!sha256_eq(&h, payment_hash))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "preimage is not payment_hash's");
	}

	/* Issuing again for a payment it already credited returns the note it
	 * issued then (a hook replayed after a restart asks twice). */
	n = wallet_credit_note_by_hash(cmd, cmd->ld->wallet, channel->dbid,
				       payment_hash);
	if (n) {
		if (preimage && !n->preimage) {
			n->preimage = tal_dup(n, struct preimage, preimage);
			wallet_credit_note_save(cmd->ld->wallet, channel->dbid,
						true, n);
		}
		goto done;
	}

	if (!channel_state_can_add_htlc(channel->state))
		return command_fail(cmd, LIGHTNINGD,
				    "Channel is %s: it cannot be credited",
				    channel_state_name(channel));

	latest = channel_credit_latest(tmpctx, channel);
	issued = latest ? latest->credit : 0;
	add = amount->millisatoshis / 1000; /* Raw: atoms of the asset */
	if (add == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Less than one atom to credit");
	if (!credit_room(channel, issued, &room) || add > room)
		return command_fail(cmd, LIGHTNINGD,
				    "This node's balance in the channel cannot"
				    " pay a credit of %"PRIu64" atoms more"
				    " (%"PRIu64" already owed)", add, issued);

	n = tal(cmd, struct credit_note);
	n->credit = issued + add;
	n->payment_hash = *payment_hash;
	n->preimage = tal_dup_or_null(n, struct preimage, preimage);
	{
		struct channel_id tagid;
		derive_channel_id(&tagid, &channel->funding);
		msg = towire_hsmd_sign_credit_note(NULL, &channel->peer->id,
						   channel->dbid, &tagid,
						   n->credit, payment_hash);
	}
	msg = hsm_sync_req(tmpctx, cmd->ld, take(msg));
	if (!fromwire_hsmd_sign_credit_note_reply(msg, &n->sig))
		fatal("Reading sign_credit_note_reply: %s",
		      tal_hex(tmpctx, msg));
	{
		const char *why;
		if (!credit_note_valid(channel, n, &why))
			return command_fail(cmd, LIGHTNINGD,
					    "The signer's note does not check: %s",
					    why);
	}
	wallet_credit_note_save(cmd->ld->wallet, channel->dbid, true, n);
	log_info(channel->log, "Issued credit note: %"PRIu64" in all, for"
		 " payment %s", n->credit, fmt_sha256(tmpctx, payment_hash));
	credit_send(channel, n);
	credit_tell_owner(channel);

done:
	js = json_stream_success(cmd);
	json_array_start(js, "notes");
	json_add_credit_note(js, channel, n);
	json_array_end(js);
	return command_success(cmd, js);
}

static const struct json_command issuecredit_command = {
	"issuecredit",
	json_issuecredit,
};
AUTODATA(json_command, &issuecredit_command);

static struct command_result *json_addcreditnote(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct node_id *id;
	struct channel_id *cid;
	u64 *credit;
	struct sha256 *payment_hash;
	struct preimage *preimage;
	struct bip340sig *sig;
	struct channel *channel;
	struct credit_note n;
	struct command_result *res;
	const char *why;
	struct json_stream *js;

	if (!param_check(cmd, buffer, params,
			 p_req("id", param_node_id, &id),
			 p_req("credit", param_u64, &credit),
			 p_req("payment_hash", param_sha256, &payment_hash),
			 p_req("signature", param_bip340sig, &sig),
			 p_opt("preimage", param_preimage, &preimage),
			 p_opt("channel_id", param_channel_id, &cid),
			 NULL))
		return command_param_failed();

	res = credit_channel_of(cmd, id, cid, false, &channel);
	if (res)
		return res;
	n.credit = *credit;
	n.payment_hash = *payment_hash;
	n.sig = *sig;
	n.preimage = preimage;
	why = credit_receive(channel, &n);
	if (why)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Credit note refused: %s", why);
	js = json_stream_success(cmd);
	json_array_start(js, "notes");
	json_add_credit_note(js, channel, &n);
	json_array_end(js);
	return command_success(cmd, js);
}

static const struct json_command addcreditnote_command = {
	"addcreditnote",
	json_addcreditnote,
};
AUTODATA(json_command, &addcreditnote_command);

static struct command_result *json_listcreditnotes(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *obj UNNEEDED,
						   const jsmntok_t *params)
{
	struct node_id *id;
	struct json_stream *js;
	struct peer *peer;
	struct peer_node_id_map_iter it;

	if (!param(cmd, buffer, params,
		   p_opt("id", param_node_id, &id),
		   NULL))
		return command_param_failed();

	js = json_stream_success(cmd);
	json_array_start(js, "notes");
	for (peer = peer_node_id_map_first(cmd->ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(cmd->ld->peers, &it)) {
		struct channel *c;

		if (id && !node_id_eq(&peer->id, id))
			continue;
		list_for_each(&peer->channels, c, list) {
			struct credit_note **notes;

			if (!channel_has_credit(c))
				continue;
			notes = wallet_credit_notes(tmpctx, cmd->ld->wallet,
						    c->dbid);
			for (size_t i = 0; i < tal_count(notes); i++)
				json_add_credit_note(js, c, notes[i]);
		}
	}
	json_array_end(js);
	return command_success(cmd, js);
}

static const struct json_command listcreditnotes_command = {
	"listcreditnotes",
	json_listcreditnotes,
};
AUTODATA(json_command, &listcreditnotes_command);
