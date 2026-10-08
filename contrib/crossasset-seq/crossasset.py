#!/usr/bin/env python3
"""SeqLN quoted cross-asset forwarding.

A node that holds channels in two assets can convert a payment between them:
it takes an incoming HTLC in asset A and forwards an outgoing HTLC in asset B,
under the same payment hash, at amounts it quoted and signed beforehand.
lightningd itself never forwards across an asset boundary (`forward_htlc()`
refuses it); this plugin takes the incoming HTLC off lightningd's hands on the
`htlc_accepted` hook, sends the onion's next hop with `sendonion` over the
channel the payer named, and resolves the incoming HTLC with the preimage the
outgoing one returns, or fails it back with the outgoing one's error.

Both roles run the same plugin.

Quoting node:
  crossassetsetrate asset_in asset_out rate [fee_base_msat] [fee_ppm]
                    [max_out_msat]   publish (or with rate=0 withdraw) a pair
  crossassetrates                    the published pairs and open forwards
  crossassetquote ...                (also answered for peers, see below)

Payer:
  crossassetrequestquote node_id payment_hash asset_in asset_out amount_out_msat
                    ask a peer for a quote over a custom message, and check it
  crossassetpay bolt11 node_id maxamount_in_msat [asset_in] [maxdelay]
                    pay an invoice in asset B with asset A, converted by node_id

A quote binds one payment hash, one amount in asset A and one amount out in
asset B, an expiry in seconds and the CLTV terms, signed by the quoting node's
key with `signmessage`.  The quoting node forwards one HTLC per quote, only
before its expiry, and only when the incoming HTLC's asset and amount, and the
outgoing channel's asset, amount and CLTV, are exactly the quote's.

README.md beside this file describes the protocol and its limits.
"""
import importlib.util
import json
import os
import secrets
import sys
import threading
import time
import types
from decimal import Decimal, InvalidOperation
from fractions import Fraction


# Load pyln.client.Plugin without pyln/client/__init__.py, which pulls in
# gossmap and a compiled dependency; plugin.py and lightning.py are
# stdlib-only.  The same loader as holdinvoice-seq.
def _find_pyln_client_dir():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        cand = os.path.join(d, "contrib", "pyln-client", "pyln", "client")
        if os.path.exists(os.path.join(cand, "plugin.py")):
            return cand
        d = os.path.dirname(d)
    raise RuntimeError("crossasset: no contrib/pyln-client above " + __file__)


def _load_pyln():
    base = _find_pyln_client_dir()
    pyln_root = os.path.dirname(os.path.dirname(base))
    for name, path in [("pyln", pyln_root), ("pyln.client", base)]:
        if name not in sys.modules:
            m = types.ModuleType(name)
            m.__path__ = [path]
            sys.modules[name] = m
    spec = importlib.util.spec_from_file_location("pyln.client.plugin",
                                                  base + "/plugin.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pyln.client.plugin"] = mod
    spec.loader.exec_module(mod)
    return mod.Plugin, sys.modules["pyln.client.lightning"].RpcError


Plugin, RpcError = _load_pyln()

# Custom message types (odd: a peer that does not know them ignores them).
MSG_QUOTE_REQUEST = 0xC0A1
MSG_QUOTE_REPLY = 0xC0A3

# The tag every signed quote starts with.  signmessage prefixes its own
# "Lightning Signed Message:", so a quote signature cannot be mistaken for any
# other message this node signs unless that message starts with this tag.
QUOTE_TAG = "seqln-crossasset-quote-v1:"

DATASTORE = "crossasset"

# Not dynamic: lightningd refuses to stop it at runtime.  While a forward is
# open, the incoming HTLC is held only by this plugin; without it lightningd
# would treat the HTLC as an ordinary forward, refuse it at the asset boundary
# and fail it back while the outgoing HTLC is still out.  Load it with
# important-plugin= so lightningd also stops if it dies.
plugin = Plugin(dynamic=False, custom_msgs=[])

# Quotes this node issued and that no HTLC has used yet, by payment hash.
# Kept in memory only: after a restart an unused quote is simply gone, and an
# HTLC that arrives for it is refused.
QUOTES = {}
# Forwards: a quote that an HTLC has used, by payment hash.  Persisted in the
# datastore before the outgoing HTLC is sent, so a restart neither forgets
# that the quote is spent nor sends the outgoing HTLC twice.
FORWARDS = {}
# Published pairs: (asset_in, asset_out) -> {rate, fee_base_msat, fee_ppm,
# max_out_msat}.  Persisted.
RATES = {}
LOCK = threading.RLock()
# Pending quote requests this node sent, by request id.
PENDING = {}
STATE = {"network": "", "node_id": "", "seconds": 30, "max_open": 4,
         "max_out_cltv": 432, "max_quotes": 1000}


# ---------------------------------------------------------------- helpers

def _hex32(v, what):
    v = str(v).lower()
    if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
        raise ValueError(f"{what} must be 32 bytes of hex")
    return v


def _msat(v):
    if isinstance(v, str) and v.endswith("msat"):
        v = v[:-4]
    return int(v)


def _rate(v):
    """A rate: atoms of the outgoing asset given per atom of the incoming
    one, as a positive decimal string.  Kept as text so it is signed and
    published exactly as set."""
    try:
        d = Decimal(str(v))
    except InvalidOperation:
        raise ValueError(f"rate {v!r} is not a decimal number")
    if not d.is_finite() or d < 0:
        raise ValueError("rate must be a positive decimal number")
    return format(d.normalize(), "f")


def amount_in_for(amount_out_msat, rate, fee_base_msat, fee_ppm):
    """What the quoting node asks in the incoming asset for amount_out_msat of
    the outgoing one: the converted amount, rounded up, plus the fee on it,
    rounded up.  Both sides compute it, so a payer can check a quote against
    the rate it is signed with."""
    r = Fraction(Decimal(rate))
    if r <= 0:
        raise ValueError("rate must be above zero")
    converted = -((-Fraction(amount_out_msat)) // r)  # ceil
    fee = -((-(converted * fee_ppm)) // 1000000) + fee_base_msat
    return int(converted + fee)


def quote_message(q):
    """The exact text a quote's signature covers: the tag, then every term as
    canonical JSON (sorted keys, no spaces)."""
    terms = {k: q[k] for k in ("network", "node_id", "quote_id", "payment_hash",
                               "asset_in", "amount_in_msat", "asset_out",
                               "amount_out_msat", "rate", "fee_base_msat",
                               "fee_ppm", "expiry", "cltv_delta", "max_out_cltv")}
    return QUOTE_TAG + json.dumps(terms, sort_keys=True, separators=(",", ":"))


def _channels(plugin, forwarding=False):
    """This node's channels: scid (and local alias) -> {asset, peer_id,
    state, spendable_msat}.  The asset comes from listfunds, which names
    every channel's asset, the policy asset included.  forwarding: the
    channels an onion may name, which for an unannounced channel is only its
    alias, as lightningd itself forwards (its real scid would tell a prober
    the channel exists)."""
    assets = {}
    for c in plugin.rpc.listfunds().get("channels", []):
        assets[(c.get("funding_txid"), c.get("funding_output"))] = c.get("asset")
    out = {}
    for c in plugin.rpc.listpeerchannels().get("channels", []):
        asset = assets.get((c.get("funding_txid"), c.get("funding_outnum")))
        if asset is None:
            asset = c.get("channel_asset")
        info = {"asset": asset, "peer_id": c.get("peer_id"),
                "state": c.get("state"),
                "spendable_msat": _msat(c.get("spendable_msat", 0)),
                "receivable_msat": _msat(c.get("receivable_msat", 0)),
                "scid": c.get("short_channel_id")}
        alias = (c.get("alias") or {}).get("local")
        names = [alias]
        if not (forwarding and c.get("private")):
            names.append(c.get("short_channel_id"))
        for k in names:
            if k:
                out[k] = info
    return out


def _persist_forward(plugin, ph):
    f = FORWARDS[ph]
    plugin.rpc.call("datastore", {"key": [DATASTORE, "forward", ph],
                                  "string": json.dumps(f),
                                  "mode": "create-or-replace"})


def _persist_rate(plugin, pair):
    key = [DATASTORE, "rate", pair[0] + "-" + pair[1]]
    if pair in RATES:
        plugin.rpc.call("datastore", {"key": key, "string": json.dumps(RATES[pair]),
                                      "mode": "create-or-replace"})
    else:
        try:
            plugin.rpc.call("deldatastore", {"key": key})
        except Exception:
            pass


def _open_forwards(asset_out):
    return sum(1 for f in FORWARDS.values()
               if f["state"] == "forwarding" and f["asset_out"] == asset_out)


# ---------------------------------------------------------------- startup

@plugin.init()
def init(options, configuration, plugin, **kwargs):
    info = plugin.rpc.getinfo()
    STATE["network"] = info.get("network", "")
    STATE["node_id"] = info["id"]
    STATE["seconds"] = int(options["crossasset-quote-seconds"])
    STATE["max_open"] = int(options["crossasset-max-open"])
    STATE["max_out_cltv"] = int(options["crossasset-max-out-cltv"])
    cfg = plugin.rpc.listconfigs("cltv-delta")["configs"]
    STATE["cltv_delta"] = int(cfg["cltv-delta"]["value_int"])
    # listdatastore lists one level below the key it is given.
    for kind in ("forward", "rate"):
        for d in plugin.rpc.call("listdatastore",
                                 {"key": [DATASTORE, kind]}).get("datastore", []):
            key = d.get("key", [])
            if len(key) != 3 or "string" not in d:
                continue
            rec = json.loads(d["string"])
            if kind == "forward":
                FORWARDS[key[2]] = rec
            else:
                a, b = key[2].split("-")
                RATES[(a, b)] = rec
    plugin.log(f"crossasset: {len(RATES)} published pair(s),"
               f" {_open_forwards_total()} open forward(s) restored", level="info")


def _open_forwards_total():
    return sum(1 for f in FORWARDS.values() if f["state"] == "forwarding")


plugin.add_option("crossasset-quote-seconds", "30",
                  "Longest life of a quote this node signs, in seconds", "int")
plugin.add_option("crossasset-max-open", "4",
                  "Most forwards this node keeps open at once in one outgoing"
                  " asset", "int")
plugin.add_option("crossasset-max-out-cltv", "432",
                  "Most blocks an outgoing HTLC of a quoted forward may lock"
                  " this node's funds for", "int")


# ---------------------------------------------------------------- quoting side

@plugin.method("crossassetsetrate")
def crossassetsetrate(plugin, asset_in, asset_out, rate, fee_base_msat=0,
                      fee_ppm=0, max_out_msat=0):
    """Publish the rate at which this node converts asset_in into asset_out:
    `rate` atoms of asset_out per atom of asset_in, a decimal.  The quote
    adds fee_base_msat plus fee_ppm on the converted amount, both in
    asset_in.  max_out_msat caps one quote's outgoing amount (0: no cap
    beyond the channel).  A rate of 0 withdraws the pair."""
    a = _hex32(asset_in, "asset_in")
    b = _hex32(asset_out, "asset_out")
    if a == b:
        raise ValueError("asset_in and asset_out are the same asset")
    r = _rate(rate)
    if int(fee_base_msat) < 0 or int(fee_ppm) < 0 or int(max_out_msat) < 0:
        raise ValueError("fee_base_msat, fee_ppm and max_out_msat cannot be negative")
    with LOCK:
        if Decimal(r) == 0:
            RATES.pop((a, b), None)
            _persist_rate(plugin, (a, b))
            return {"asset_in": a, "asset_out": b, "withdrawn": True}
        RATES[(a, b)] = {"rate": r, "fee_base_msat": int(fee_base_msat),
                         "fee_ppm": int(fee_ppm), "max_out_msat": int(max_out_msat)}
        _persist_rate(plugin, (a, b))
    plugin.log(f"crossasset: rate {a}->{b} set to {r}", level="info")
    return dict({"asset_in": a, "asset_out": b}, **RATES[(a, b)])


@plugin.method("crossassetrates")
def crossassetrates(plugin):
    """The pairs this node quotes, and its open forwards per outgoing asset."""
    with LOCK:
        pairs = [dict({"asset_in": a, "asset_out": b}, **v)
                 for (a, b), v in sorted(RATES.items())]
        open_by = {}
        for f in FORWARDS.values():
            if f["state"] == "forwarding":
                open_by[f["asset_out"]] = open_by.get(f["asset_out"], 0) + 1
    return {"node_id": STATE["node_id"], "pairs": pairs,
            "quote_seconds": STATE["seconds"], "max_open": STATE["max_open"],
            "max_out_cltv": STATE["max_out_cltv"], "cltv_delta": STATE["cltv_delta"],
            "open_forwards": open_by}


def make_quote(plugin, payment_hash, asset_in, asset_out, amount_out_msat,
               seconds=None):
    ph = _hex32(payment_hash, "payment_hash")
    a = _hex32(asset_in, "asset_in")
    b = _hex32(asset_out, "asset_out")
    amount_out = int(amount_out_msat)
    if amount_out <= 0:
        raise ValueError("amount_out_msat must be above zero")
    life = STATE["seconds"] if seconds is None else min(int(seconds), STATE["seconds"])
    if life <= 0:
        raise ValueError("seconds must be above zero")
    with LOCK:
        pair = RATES.get((a, b))
        if pair is None:
            raise ValueError(f"this node does not quote {a} for {b}")
        if pair["max_out_msat"] and amount_out > pair["max_out_msat"]:
            raise ValueError(f"amount_out_msat {amount_out} is above this pair's"
                             f" cap of {pair['max_out_msat']}")
        if ph in FORWARDS and FORWARDS[ph]["state"] != "failed":
            raise ValueError(f"a quote for payment hash {ph} has already been used")
        if _open_forwards(b) >= STATE["max_open"]:
            raise ValueError(f"this node has {STATE['max_open']} forwards open in"
                             f" asset {b}, its cap")
    chans = _channels(plugin).values()
    usable = [c for c in chans if c["state"] == "CHANNELD_NORMAL"]
    if not any(c["asset"] == a for c in usable):
        raise ValueError(f"this node holds no open channel in asset {a}")
    if not any(c["asset"] == b and c["spendable_msat"] >= amount_out for c in usable):
        raise ValueError(f"this node has no channel in asset {b} that can send"
                         f" {amount_out}msat")
    amount_in = amount_in_for(amount_out, pair["rate"], pair["fee_base_msat"],
                              pair["fee_ppm"])
    q = {"network": STATE["network"], "node_id": STATE["node_id"],
         "quote_id": secrets.token_hex(16), "payment_hash": ph,
         "asset_in": a, "amount_in_msat": amount_in,
         "asset_out": b, "amount_out_msat": amount_out,
         "rate": pair["rate"], "fee_base_msat": pair["fee_base_msat"],
         "fee_ppm": pair["fee_ppm"], "expiry": int(time.time()) + life,
         "cltv_delta": STATE["cltv_delta"], "max_out_cltv": STATE["max_out_cltv"]}
    q["signature"] = plugin.rpc.call("signmessage",
                                     {"message": quote_message(q)})["zbase"]
    with LOCK:
        now = time.time()
        for k in [k for k, v in QUOTES.items() if v["expiry"] < now]:
            del QUOTES[k]
        if len(QUOTES) >= STATE["max_quotes"] and ph not in QUOTES:
            raise ValueError("too many quotes outstanding; ask again shortly")
        # One live quote per payment hash: a new one replaces an unused one.
        QUOTES[ph] = q
    plugin.log(f"crossasset: quoted {q['quote_id']} for {ph}: {amount_in}msat of"
               f" {a} for {amount_out}msat of {b}, until {q['expiry']}", level="info")
    return q


@plugin.method("crossassetquote")
def crossassetquote(plugin, payment_hash, asset_in, asset_out, amount_out_msat,
                    seconds=None):
    """Quote, as this node, amount_out_msat of asset_out paid for in
    asset_in, for the payment with payment_hash.  A payer usually asks over
    the wire with crossassetrequestquote."""
    return make_quote(plugin, payment_hash, asset_in, asset_out,
                      amount_out_msat, seconds)


@plugin.hook("custommsg")
def on_custommsg(peer_id, payload, plugin, **kwargs):
    raw = bytes.fromhex(payload)
    if len(raw) < 2:
        return {"result": "continue"}
    mtype = int.from_bytes(raw[:2], "big")
    if mtype == MSG_QUOTE_REQUEST:
        threading.Thread(target=_answer_request, args=(plugin, peer_id, raw[2:]),
                         daemon=True).start()
    elif mtype == MSG_QUOTE_REPLY:
        try:
            body = json.loads(raw[2:].decode())
        except ValueError:
            return {"result": "continue"}
        with LOCK:
            waiter = PENDING.get(body.get("request_id"))
        if waiter is not None and waiter["peer_id"] == peer_id:
            waiter["reply"] = body
            waiter["event"].set()
    return {"result": "continue"}


def _answer_request(plugin, peer_id, body):
    try:
        req = json.loads(body.decode())
        rid = str(req.get("request_id", ""))[:64]
    except ValueError:
        return
    try:
        q = make_quote(plugin, req.get("payment_hash"), req.get("asset_in"),
                       req.get("asset_out"), req.get("amount_out_msat"),
                       req.get("seconds"))
        reply = {"request_id": rid, "quote": q}
    except Exception as e:
        reply = {"request_id": rid, "error": str(e)}
    msg = MSG_QUOTE_REPLY.to_bytes(2, "big") + json.dumps(reply).encode()
    try:
        plugin.rpc.call("sendcustommsg", {"node_id": peer_id, "msg": msg.hex()})
    except Exception as e:
        plugin.log(f"crossasset: could not answer {peer_id}: {e}", level="unusual")


# ---------------------------------------------------------------- the forward

def _fail_code(htlc, code="400f"):
    """A failure message with the HTLC's amount and the height, the form
    incorrect_or_unknown_payment_details (0x400f) takes."""
    if code != "400f":
        return code
    height = int(htlc["cltv_expiry"]) - int(htlc["cltv_expiry_relative"])
    return "400f" + _msat(htlc["amount_msat"]).to_bytes(8, "big").hex() \
        + height.to_bytes(4, "big").hex()


def _refuse(plugin, request, htlc, ph, why, code="400f"):
    plugin.log(f"crossasset: refused the htlc for {ph}: {why}", level="info")
    request.set_result({"result": "fail", "failure_message": _fail_code(htlc, code)})


def _check(q, onion, htlc, out):
    """Why an HTLC that would cross assets here does not match the quote, or
    None if it does."""
    if time.time() > q["expiry"]:
        return f"quote {q['quote_id']} expired at {q['expiry']}"
    if htlc.get("asset") != q["asset_in"]:
        return f"arrived in asset {htlc.get('asset')}, the quote takes {q['asset_in']}"
    if _msat(htlc["amount_msat"]) != q["amount_in_msat"]:
        return (f"arrived with {_msat(htlc['amount_msat'])}msat, the quote takes"
                f" {q['amount_in_msat']}msat")
    if out["asset"] != q["asset_out"]:
        return (f"the onion forwards over {out['scid']} in asset {out['asset']},"
                f" the quote pays {q['asset_out']}")
    if _msat(onion["forward_msat"]) != q["amount_out_msat"]:
        return (f"the onion forwards {_msat(onion['forward_msat'])}msat, the quote"
                f" pays {q['amount_out_msat']}msat")
    height = int(htlc["cltv_expiry"]) - int(htlc["cltv_expiry_relative"])
    out_cltv = int(onion["outgoing_cltv_value"])
    if out_cltv <= height:
        return f"the outgoing HTLC would expire at {out_cltv}, not above the tip {height}"
    if out_cltv - height > q["max_out_cltv"]:
        return (f"the outgoing HTLC would expire {out_cltv - height} blocks out,"
                f" the quote allows {q['max_out_cltv']}")
    if int(htlc["cltv_expiry"]) - out_cltv < q["cltv_delta"]:
        return (f"the incoming HTLC expires {int(htlc['cltv_expiry']) - out_cltv}"
                f" blocks after the outgoing one, the quote needs {q['cltv_delta']}")
    return None


def on_htlc_accepted(onion, htlc, request, plugin, **kwargs):
    ph = (htlc.get("payment_hash") or "").lower()
    key = [htlc.get("short_channel_id"), htlc.get("id")]
    with LOCK:
        fwd = FORWARDS.get(ph)
        if fwd is not None and fwd["in"] == key:
            # lightningd replays an HTLC it still holds after a restart.
            return _resume(plugin, request, htlc, ph)
        if fwd is not None and fwd["state"] == "failed" and ph in QUOTES:
            # A new quote for a payment whose last forward failed.
            fwd = None
        if fwd is None and ph not in QUOTES:
            return request.set_result({"result": "continue"})
    # Only an HTLC that would leave in another asset than it came in is an
    # attempt at a quote.  A payment to this node, or a forward in one asset
    # that happens to share a quoted hash, is lightningd's: refusing it here
    # would let anyone who knows an invoice's hash have its ordinary
    # forwards refused.
    scid = onion.get("short_channel_id")
    out = _channels(plugin, forwarding=True).get(scid) if scid else None
    if out is None or out["asset"] == htlc.get("asset"):
        return request.set_result({"result": "continue"})
    with LOCK:
        fwd = FORWARDS.get(ph)
        q = QUOTES.get(ph)
        if fwd is not None and not (fwd["state"] == "failed" and q is not None):
            return _refuse(plugin, request, htlc, ph,
                           f"quote {fwd['quote_id']} has already been used")
        if q is None:
            return request.set_result({"result": "continue"})
        why = _check(q, onion, htlc, out)
        if why is not None:
            return _refuse(plugin, request, htlc, ph, why)
        if _open_forwards(q["asset_out"]) >= STATE["max_open"]:
            # Temporary: the quote stays usable once a forward closes.
            return _refuse(plugin, request, htlc, ph,
                           f"{STATE['max_open']} forwards are open in asset"
                           f" {q['asset_out']}, the cap", code="2002")
        fwd = {"quote_id": q["quote_id"], "state": "forwarding", "in": key,
               "asset_in": q["asset_in"], "amount_in_msat": q["amount_in_msat"],
               "asset_out": q["asset_out"], "amount_out_msat": q["amount_out_msat"],
               "out_channel": out["scid"], "out_peer": out["peer_id"]}
        FORWARDS[ph] = fwd
        del QUOTES[ph]
        # On disk before anything is sent: the quote is spent.
        _persist_forward(plugin, ph)
    plugin.log(f"crossasset: forwarding {ph} under quote {q['quote_id']}:"
               f" {q['amount_in_msat']}msat of {q['asset_in']} in,"
               f" {q['amount_out_msat']}msat of {q['asset_out']} out over"
               f" {out['scid']}", level="info")
    try:
        # lightningd adds the delay to its tip when it sends: read the tip
        # now, so a block found since the HTLC arrived can only make the
        # outgoing expiry later than the onion asks, never earlier.
        height = plugin.rpc.getinfo()["blockheight"]
        plugin.rpc.call("sendonion", {
            "onion": onion["next_onion"],
            "first_hop": {"id": out["peer_id"], "channel": out["scid"],
                          "amount_msat": q["amount_out_msat"],
                          "delay": int(onion["outgoing_cltv_value"]) - height},
            "payment_hash": ph,
            "label": f"crossasset {q['quote_id']}"})
    except Exception as e:
        _finish(plugin, request, htlc, ph, None, None, f"sendonion: {e}")
        return
    threading.Thread(target=_wait_out, args=(plugin, request, htlc, ph),
                     daemon=True).start()


def _wait_out(plugin, request, htlc, ph):
    """Wait for the outgoing HTLC; resolve or fail the incoming one with it."""
    while True:
        try:
            res = plugin.rpc.call("waitsendpay", {"payment_hash": ph, "timeout": 60})
            return _finish(plugin, request, htlc, ph, res.get("payment_preimage"),
                           None, None)
        except RpcError as e:
            err = e.error if isinstance(getattr(e, "error", None), dict) else {}
            if err.get("code") == 200:      # still pending: wait again
                continue
            data = err.get("data") or {}
            return _finish(plugin, request, htlc, ph, None,
                           data.get("onionreply"), err.get("message", str(e)))
        except Exception as e:
            plugin.log(f"crossasset: waitsendpay {ph}: {e}; retrying", level="unusual")
            time.sleep(5)


def _finish(plugin, request, htlc, ph, preimage, onionreply, why):
    with LOCK:
        fwd = FORWARDS[ph]
        if preimage:
            fwd["state"] = "settled"
            fwd["preimage"] = preimage
        else:
            fwd["state"] = "failed"
            fwd["why"] = why
        _persist_forward(plugin, ph)
    if preimage:
        plugin.log(f"crossasset: {ph} settled: the outgoing HTLC returned the"
                   f" preimage; resolving the incoming one", level="info")
        request.set_result({"result": "resolve", "payment_key": preimage})
    elif onionreply:
        plugin.log(f"crossasset: {ph} failed downstream ({why}); failing the"
                   f" incoming HTLC with the downstream error", level="info")
        request.set_result({"result": "fail", "failure_onion": onionreply})
    else:
        plugin.log(f"crossasset: {ph} failed ({why}); failing the incoming HTLC",
                   level="info")
        request.set_result({"result": "fail", "failure_message": "2002"})


def _resume(plugin, request, htlc, ph):
    """The incoming HTLC of a forward, replayed after a restart: never send
    the outgoing one again; answer from what it became."""
    fwd = FORWARDS[ph]
    if fwd["state"] == "settled":
        return request.set_result({"result": "resolve", "payment_key": fwd["preimage"]})
    if fwd["state"] == "failed":
        return request.set_result({"result": "fail", "failure_message": "2002"})
    pays = plugin.rpc.call("listsendpays", {"payment_hash": ph}).get("payments", [])
    if not pays:
        # Spent and persisted, but the node stopped before sendonion: nothing
        # went out, so the incoming HTLC fails back.
        return _finish(plugin, request, htlc, ph, None, None,
                       "the outgoing HTLC was never sent")
    plugin.log(f"crossasset: resuming forward {ph} after a restart", level="info")
    threading.Thread(target=_wait_out, args=(plugin, request, htlc, ph),
                     daemon=True).start()


plugin.add_hook("htlc_accepted", on_htlc_accepted, background=True)


@plugin.method("crossassetforwards")
def crossassetforwards(plugin):
    """Every quote an HTLC has used, by payment hash, and what became of it."""
    with LOCK:
        return {"forwards": [dict({"payment_hash": k},
                                  **{x: y for x, y in v.items() if x != "preimage"})
                             for k, v in sorted(FORWARDS.items())]}


# ---------------------------------------------------------------- payer side

def check_quote(plugin, q, node_id, payment_hash, asset_in, asset_out,
                amount_out_msat):
    """Everything a payer checks before it relies on a quote.  Raises with
    the first term that fails."""
    want = {"node_id": node_id, "payment_hash": payment_hash,
            "asset_in": asset_in, "asset_out": asset_out,
            "amount_out_msat": int(amount_out_msat),
            "network": STATE["network"]}
    for k, v in want.items():
        if q.get(k) != v:
            raise ValueError(f"the quote's {k} is {q.get(k)!r}, asked for {v!r}")
    try:
        ok = plugin.rpc.call("checkmessage", {"message": quote_message(q),
                                              "zbase": q["signature"],
                                              "pubkey": node_id}).get("verified")
    except (RpcError, KeyError):
        ok = False
    if not ok:
        raise ValueError("the quote's signature is not the quoting node's")
    expect = amount_in_for(q["amount_out_msat"], q["rate"], int(q["fee_base_msat"]),
                           int(q["fee_ppm"]))
    if q["amount_in_msat"] != expect:
        raise ValueError(f"the quote asks {q['amount_in_msat']}msat, its own rate"
                         f" and fees give {expect}msat")
    if q["expiry"] <= time.time():
        raise ValueError(f"the quote expired at {q['expiry']}")
    return q


@plugin.method("crossassetcheckquote")
def crossassetcheckquote(plugin, quote, node_id, payment_hash, asset_in, asset_out,
                         amount_out_msat):
    """Check a quote as crossassetpay does before it pays against it."""
    return check_quote(plugin, quote, node_id, payment_hash, asset_in, asset_out,
                       amount_out_msat)


@plugin.method("crossassetquotemessage")
def crossassetquotemessage(plugin, quote):
    """The exact text a quote's signature covers."""
    return {"message": quote_message(quote)}


def _in_thread(request, fn, *args):
    """Run fn off the plugin's main loop, which must stay free to deliver
    the custom message that answers a quote request."""
    def run():
        try:
            request.set_result(fn(*args))
        except Exception as e:
            request.set_exception(e)
    threading.Thread(target=run, daemon=True).start()


@plugin.async_method("crossassetrequestquote")
def crossassetrequestquote_rpc(plugin, request, node_id, payment_hash, asset_in,
                               asset_out, amount_out_msat, seconds=None, timeout=30):
    """Ask peer node_id for a signed quote for amount_out_msat of asset_out,
    paid in asset_in, for the payment with payment_hash, and check it."""
    _in_thread(request, crossassetrequestquote, plugin, node_id, payment_hash,
               asset_in, asset_out, amount_out_msat, seconds, timeout)


def crossassetrequestquote(plugin, node_id, payment_hash, asset_in, asset_out,
                           amount_out_msat, seconds=None, timeout=30):
    """Ask peer node_id for a signed quote and check it: the terms are the
    ones asked for, the signature is node_id's, the amount in follows the
    signed rate and fees, and it has not expired."""
    rid = secrets.token_hex(8)
    req = {"request_id": rid, "payment_hash": _hex32(payment_hash, "payment_hash"),
           "asset_in": _hex32(asset_in, "asset_in"),
           "asset_out": _hex32(asset_out, "asset_out"),
           "amount_out_msat": int(amount_out_msat)}
    if seconds is not None:
        req["seconds"] = int(seconds)
    waiter = {"peer_id": node_id, "event": threading.Event(), "reply": None}
    with LOCK:
        PENDING[rid] = waiter
    try:
        msg = MSG_QUOTE_REQUEST.to_bytes(2, "big") + json.dumps(req).encode()
        plugin.rpc.call("sendcustommsg", {"node_id": node_id, "msg": msg.hex()})
        if not waiter["event"].wait(float(timeout)):
            raise ValueError(f"{node_id} sent no quote within {timeout}s")
    finally:
        with LOCK:
            PENDING.pop(rid, None)
    reply = waiter["reply"]
    if "error" in reply:
        raise ValueError(f"{node_id} refused to quote: {reply['error']}")
    return check_quote(plugin, reply.get("quote") or {}, node_id, req["payment_hash"],
                       req["asset_in"], req["asset_out"], req["amount_out_msat"])


def _route_after(plugin, inv, node_id, asset_out):
    """The path from the quoting node to the payee in asset_out: a route
    hint of the invoice that starts at the quoting node, else route finding
    from it."""
    payee, amount = inv["payee"], _msat(inv["amount_msat"])
    final = int(inv.get("min_final_cltv_expiry", 18))
    if payee == node_id:
        raise ValueError("the payee is the quoting node itself")
    for hint in inv.get("routes", []):
        if len(hint) == 1 and hint[0]["pubkey"] == node_id:
            return [{"id": payee, "channel": hint[0]["short_channel_id"],
                     "amount_msat": amount, "delay": final}]
    try:
        r = plugin.rpc.call("getroute", {"id": payee, "amount_msat": amount,
                                         "riskfactor": 1, "cltv": final,
                                         "fromid": node_id, "asset": asset_out})
    except Exception as e:
        raise ValueError(f"no route from {node_id} to the payee in asset"
                         f" {asset_out}: {e}")
    return [{"id": h["id"], "channel": h["channel"],
             "amount_msat": _msat(h["amount_msat"]), "delay": h["delay"]}
            for h in r["route"]]


@plugin.async_method("crossassetpay")
def crossassetpay_rpc(plugin, request, bolt11, node_id, maxamount_in_msat,
                      asset_in=None, maxdelay=1008, retry_for=60):
    """Pay bolt11, an invoice in one asset, with at most maxamount_in_msat of
    another asset, converted by node_id: see crossassetpay."""
    _in_thread(request, crossassetpay, plugin, bolt11, node_id, maxamount_in_msat,
               asset_in, maxdelay, retry_for)


def crossassetpay(plugin, bolt11, node_id, maxamount_in_msat, asset_in=None,
                  maxdelay=1008, retry_for=60):
    """Pay bolt11, an invoice in one asset, with another asset, converted by
    node_id, a peer that quotes the pair.  asset_in is the asset to pay in
    (default: the one asset this node's channels to node_id hold).  Nothing
    is sent if the quote asks more than maxamount_in_msat of it, the most
    this payer will give: only the payer can say what the conversion is
    worth to it.  Nor if the payer's HTLC would be locked for more than
    maxdelay blocks."""
    inv = plugin.rpc.call("decode", {"string": bolt11})
    if not inv.get("valid"):
        raise ValueError("the invoice does not decode")
    asset_out = inv.get("asset")
    if not asset_out:
        raise ValueError("the invoice names no asset")
    if "amount_msat" not in inv:
        raise ValueError("the invoice names no amount")
    if inv["created_at"] + inv["expiry"] <= time.time():
        raise ValueError("the invoice has expired")
    first = [c for c in _channels(plugin).values()
             if c["peer_id"] == node_id and c["state"] == "CHANNELD_NORMAL"]
    if asset_in is None:
        held = {c["asset"] for c in first}
        if len(held) != 1:
            raise ValueError(f"this node's channels to {node_id} hold"
                             f" {len(held)} assets: name asset_in")
        asset_in = held.pop()
    asset_in = _hex32(asset_in, "asset_in")
    if asset_in == asset_out:
        raise ValueError("the invoice is in asset_in already: use pay")
    first = [c for c in first if c["asset"] == asset_in]
    if not first:
        raise ValueError(f"this node has no open channel to {node_id} in {asset_in}")
    after = _route_after(plugin, inv, node_id, asset_out)
    q = crossassetrequestquote(plugin, node_id, inv["payment_hash"], asset_in,
                               asset_out, after[0]["amount_msat"])
    if q["amount_in_msat"] > int(maxamount_in_msat):
        raise ValueError(f"the quote asks {q['amount_in_msat']}msat of {asset_in},"
                         f" above maxamount_in_msat {maxamount_in_msat}")
    if after[0]["delay"] > q["max_out_cltv"]:
        raise ValueError(f"the payee needs {after[0]['delay']} blocks, the quote"
                         f" allows {q['max_out_cltv']}")
    if after[0]["delay"] + q["cltv_delta"] > int(maxdelay):
        raise ValueError(f"the quote's cltv_delta {q['cltv_delta']} would lock this"
                         f" payment for {after[0]['delay'] + q['cltv_delta']} blocks,"
                         f" above maxdelay {maxdelay}")
    chan = max(first, key=lambda c: c["spendable_msat"])
    if chan["spendable_msat"] < q["amount_in_msat"]:
        raise ValueError(f"this node can send {chan['spendable_msat']}msat of"
                         f" {asset_in} to {node_id}, the quote asks"
                         f" {q['amount_in_msat']}msat")
    route = [{"id": node_id, "channel": chan["scid"],
              "amount_msat": q["amount_in_msat"],
              "delay": after[0]["delay"] + q["cltv_delta"]}] + after
    plugin.rpc.call("sendpay", {"route": route, "payment_hash": inv["payment_hash"],
                                "payment_secret": inv.get("payment_secret"),
                                "bolt11": bolt11,
                                "amount_msat": _msat(inv["amount_msat"])})
    try:
        res = plugin.rpc.call("waitsendpay", {"payment_hash": inv["payment_hash"],
                                              "timeout": int(retry_for)})
    except RpcError as e:
        err = e.error if isinstance(getattr(e, "error", None), dict) else {}
        raise ValueError(f"the payment failed: {err.get('message', e)}"
                         f" (quote {q['quote_id']}, {json.dumps(err.get('data', {}))})")
    return {"payment_hash": inv["payment_hash"],
            "payment_preimage": res["payment_preimage"], "quote": q,
            "sent_msat": q["amount_in_msat"], "sent_asset": asset_in,
            "delivered_msat": _msat(inv["amount_msat"]), "delivered_asset": asset_out}


plugin.run()
