#!/usr/bin/env python3
"""SeqLN hold-invoice plugin.

Holds incoming HTLCs whose payment_hash has been registered via `holdinvoice`,
keeping them in the `accepted` state (off-chain HTLC locked but unsettled) until
`holdinvoicesettle <payment_hash> <preimage>` resolves them with the preimage or
`holdinvoicecancel <payment_hash>` fails them. This is the safety primitive the
pure-LN swap rests on: the maker's incoming leg is held until it learns the
preimage by paying the outgoing leg.

On a Sequentia network a hold is registered in one asset, and only HTLCs that
arrive in it count towards it: an HTLC in any other asset is refused, so the
holder never settles, and never reveals the preimage, for a payment in another
asset.

A hold registered with an amount is `accepted` only once the parts it holds
reach that amount.  Until then it stays `waiting`, cannot be settled, and the
parts it holds are failed back with `mpp_timeout` if the rest does not arrive
within the hold's `mpp_timeout` seconds of the first part.

Registrations are kept in lightningd's datastore, so a hold survives a restart
of the plugin or of the node: lightningd replays the HTLCs it still holds to the
`htlc_accepted` hook, and the plugin holds them again (or, once settled,
resolves them with the preimage).

RPC methods match what seqdex's clnLNLeg expects (holdinvoice / holdinvoicelookup
/ holdinvoicewait / holdinvoicesettle / holdinvoicecancel).
"""
import hashlib
import json
import os
import sys
import threading
import types
import importlib.util

# Load pyln.client.Plugin WITHOUT triggering pyln/client/__init__.py, which
# eagerly imports gossmap -> pyln.spec -> pyln.proto -> coincurve (a compiled
# dep not installed here). plugin.py + lightning.py are stdlib-only, so we load
# them directly with stub parent packages.
def _find_pyln_client_dir():
    import os
    # Search upward from this file for a CLN tree's contrib/pyln-client, then
    # fall back to the known laptop checkout.
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        cand = os.path.join(d, "contrib", "pyln-client", "pyln", "client")
        if os.path.exists(os.path.join(cand, "plugin.py")):
            return cand
        d = os.path.dirname(d)
    return "/home/aejkohl/seqln/contrib/pyln-client/pyln/client"


def _load_pyln_plugin():
    base = _find_pyln_client_dir()
    pyln_root = os.path.dirname(os.path.dirname(base))  # .../pyln-client/pyln
    for name, path in [("pyln", pyln_root),
                       ("pyln.client", base)]:
        if name not in sys.modules:
            m = types.ModuleType(name)
            m.__path__ = [path]
            sys.modules[name] = m
    spec = importlib.util.spec_from_file_location("pyln.client.plugin", base + "/plugin.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pyln.client.plugin"] = mod
    spec.loader.exec_module(mod)
    return mod.Plugin

Plugin = _load_pyln_plugin()

plugin = Plugin()

# The datastore key under which each hold is kept: [DATASTORE, payment_hash].
DATASTORE = "holdinvoice-seq"

# How a version of this plugin that predates listpeerchannels naming the
# policy asset recorded a hold in it, with no asset id.  Such a record is
# read back as the network's policy asset (POLICY_ASSETS).
LEGACY_POLICY = "policy"

# The policy asset (the Sequence token) of each Sequentia network, by display
# id, as bitcoin/chainparams.c has it: only to read LEGACY_POLICY records.
POLICY_ASSETS = {
    "sequentia-testnet": "c8eccacf0953e1931cd31e434d8319101cc36e6c38b0e2104d8687552fae3e40",
    "sequentia-regtest": "4d1b177ce67c24263c8a8f756b4e3525ec16fa5dd225e333c1d2d3d3ffe5e57f",
}

# payment_hash(hex) -> {state, preimage, amount_msat, received_msat,
#                        cltv_expiry, asset, label, description, cltv,
#                        mpp_timeout, htlcs: {(scid, id)}, requests: [Request],
#                        timer, waiters: [Request]}
HELD = {}
STATES = ("waiting", "accepted", "settled", "cancelled")

# BOLT #4: a final node SHOULD wait at least 60 seconds for the rest of a
# multi-part payment before failing the parts it holds with mpp_timeout.
MPP_TIMEOUT = 60

# Guards HELD's entries: the hook and the RPC methods run on the plugin's
# main thread, and a hold's timeout on a timer thread.
LOCK = threading.RLock()

# Guards `waiters`: a holdinvoicewait is answered either by the hook thread
# that holds the HTLC or by its own expiry timer, never both.
WAITERS_LOCK = threading.Lock()

# Whether this node is on a Sequentia network (assets in channels), set at
# init from getinfo.
ON_SEQUENTIA = {"value": False}


def _persist(plugin, ph):
    """Write what a restart needs to know about a hold to the datastore."""
    e = HELD[ph]
    rec = {k: e.get(k) for k in ("state", "preimage", "amount_msat", "asset",
                                 "label", "description", "cltv", "mpp_timeout")}
    plugin.rpc.call("datastore", {"key": [DATASTORE, ph],
                                  "string": json.dumps(rec),
                                  "mode": "create-or-replace"})


def _new_entry(state="waiting", preimage=None, amount_msat=0, asset=None,
               label="", description="", cltv=0, mpp_timeout=MPP_TIMEOUT):
    return {"state": state, "preimage": preimage,
            "amount_msat": int(amount_msat), "received_msat": 0,
            "cltv_expiry": None, "asset": asset, "label": label,
            "description": description, "cltv": cltv,
            "mpp_timeout": int(mpp_timeout), "htlcs": set(), "requests": [],
            "timer": None}


@plugin.init()
def init(options, configuration, plugin, **kwargs):
    network = plugin.rpc.getinfo().get("network", "")
    ON_SEQUENTIA["value"] = network.startswith("sequentia")
    policy = POLICY_ASSETS.get(network)
    restored = 0
    for d in plugin.rpc.call("listdatastore", {"key": [DATASTORE]}).get("datastore", []):
        key = d.get("key", [])
        if len(key) != 2 or "string" not in d:
            continue
        rec = json.loads(d["string"])
        state = rec.get("state", "waiting")
        # A hold that was accepted when the node stopped is waiting again
        # until lightningd replays the HTLCs it still holds.
        if state == "accepted":
            state = "waiting"
        asset = rec.get("asset")
        if asset == LEGACY_POLICY and policy:
            asset = policy
        HELD[key[1]] = _new_entry(state, rec.get("preimage"),
                                  rec.get("amount_msat", 0), asset,
                                  rec.get("label", ""), rec.get("description", ""),
                                  rec.get("cltv", 0),
                                  rec.get("mpp_timeout") or MPP_TIMEOUT)
        restored += 1
    plugin.log(f"holdinvoice: restored {restored} hold(s) from the datastore",
               level="info")


def _state_of(plugin, ph):
    """What a caller learns about a hold: the same for lookup and wait."""
    e = HELD.get(ph)
    if e is None:
        return {"payment_hash": ph, "state": "unknown"}
    res = {"payment_hash": ph, "state": e["state"],
           # amount_msat is the REGISTERED amount, received_msat the sum of the
           # held HTLCs in the hold's asset (others are refused, never counted).
           # The hold is accepted once received_msat reaches amount_msat.
           "amount_msat": e["amount_msat"],
           "received_msat": e.get("received_msat", 0),
           # cltv_expiry is the EARLIEST absolute expiry among the held HTLCs:
           # the payer chose it, and it is the hard deadline on everything the
           # holder does with the incoming leg (an outgoing payment it makes
           # against this hold must resolve before it). None until an HTLC is
           # held.
           "cltv_expiry": e.get("cltv_expiry"),
           # The tip the holder measures that expiry against, so it needs no
           # second round trip to learn it.
           "blockheight": plugin.rpc.getinfo().get("blockheight")}
    # The asset the hold is in (32-byte display id), the policy asset like
    # any other; absent off Sequentia networks.
    if e.get("asset"):
        res["asset"] = e["asset"]
    return res


def _wake_waiters(plugin, ph):
    """Answer every pending holdinvoicewait for ph with its current state."""
    e = HELD.get(ph)
    if e is None:
        return
    with WAITERS_LOCK:
        waiters = e.pop("waiters", [])
    result = _state_of(plugin, ph)
    for req in waiters:
        req.set_result(result)


def _default_asset(plugin):
    """The one asset this node's usable channels hold, or None."""
    held = set()
    for c in plugin.rpc.listpeerchannels().get("channels", []):
        if c.get("state") in ("CHANNELD_NORMAL", "CHANNELD_AWAITING_SPLICE"):
            held.add(c.get("channel_asset"))
    return held.pop() if len(held) == 1 and None not in held else None


@plugin.method("holdinvoice")
def holdinvoice(plugin, payment_hash, amount_msat=0, label="", description="",
                cltv=0, asset=None, mpp_timeout=MPP_TIMEOUT):
    """Register a payment_hash to be HELD when an HTLC for it arrives.

    On a Sequentia network the hold is in `asset` (32-byte hex id); without
    it, in the asset of this node's channels when they all hold one, and
    refused when they hold several or none.  The hold is accepted once the
    parts it holds reach amount_msat (with no amount, at the first part);
    parts short of it are failed back mpp_timeout seconds after the first.
    Does not create a BOLT11 (create-by-external-hash needs HSM invoice
    signing; the payer can pay the hash directly via sendpay). Returns the
    registered hash.
    """
    ph = str(payment_hash).lower()
    if ph in HELD and HELD[ph]["state"] in ("accepted", "settled"):
        return {"payment_hash": ph, "state": HELD[ph]["state"],
                "received_msat": HELD[ph]["received_msat"],
                "warning": "already registered"}
    mpp_timeout = int(mpp_timeout)
    if mpp_timeout <= 0:
        raise ValueError("mpp_timeout must be a positive number of seconds")
    if ON_SEQUENTIA["value"]:
        if asset:
            asset = str(asset).lower()
            if len(asset) != 64 or any(ch not in "0123456789abcdef" for ch in asset):
                raise ValueError("asset must be a 32-byte hex asset id")
        else:
            asset = _default_asset(plugin)
            if asset is None:
                raise ValueError("this node's channels hold several assets, or"
                                 " none: name the asset to hold the payment in")
    else:
        asset = None
    with LOCK:
        old = HELD.get(ph)
        if old is not None:
            _drop_parts(old, "2002")
        HELD[ph] = _new_entry(amount_msat=amount_msat, asset=asset, label=label,
                              description=description, cltv=cltv,
                              mpp_timeout=mpp_timeout)
        _persist(plugin, ph)
    plugin.log(f"holdinvoice: registered hash {ph} to hold"
               + (f" in asset {asset}" if asset else ""), level="info")
    res = {"payment_hash": ph, "state": "waiting", "received_msat": 0, "bolt11": None}
    if asset:
        res["asset"] = asset
    return res


@plugin.method("holdinvoicelookup")
def holdinvoicelookup(plugin, payment_hash):
    return _state_of(plugin, str(payment_hash).lower())


@plugin.async_method("holdinvoicewait")
def holdinvoicewait(plugin, request, payment_hash, timeout=60):
    """Block until the hold on payment_hash leaves `waiting` (the HTLC is
    held, or the hold was settled/cancelled) or `timeout` seconds pass, then
    answer as holdinvoicelookup would.

    Polling holdinvoicelookup put up to a poll interval between the HTLC
    landing and the holder acting on it; this answers the moment the hook
    holds it.
    """
    ph = str(payment_hash).lower()
    e = HELD.get(ph)
    if e is None or e["state"] != "waiting":
        request.set_result(_state_of(plugin, ph))
        return
    with WAITERS_LOCK:
        e.setdefault("waiters", []).append(request)

    def expire():
        with WAITERS_LOCK:
            waiters = e.get("waiters", [])
            if request not in waiters:
                return
            waiters.remove(request)
        request.set_result(_state_of(plugin, ph))

    t = threading.Timer(float(timeout), expire)
    t.daemon = True
    t.start()


@plugin.method("holdinvoicesettle")
def holdinvoicesettle(plugin, payment_hash, preimage):
    """Settle a held HTLC by revealing the preimage (must hash to payment_hash)."""
    ph = str(payment_hash).lower()
    with LOCK:
        e = HELD.get(ph)
        if e is None:
            raise ValueError(f"unknown held payment_hash {ph}")
        if hashlib.sha256(bytes.fromhex(str(preimage))).hexdigest() != ph:
            raise ValueError("preimage does not hash to payment_hash")
        # Parts held short of the amount: settling them would give the
        # preimage away for less than the hold asked.
        if e["state"] == "waiting" and e["requests"]:
            raise ValueError(f"the hold has received {e['received_msat']}msat of"
                             f" {e['amount_msat']}msat: it settles only once"
                             f" it holds the whole amount")
        _stop_timer(e)
        e["preimage"] = str(preimage).lower()
        e["state"] = "settled"
        # On disk before any HTLC is resolved: a restart replays them, and they
        # must then resolve with this preimage.
        _persist(plugin, ph)
        n = 0
        for req in e["requests"]:
            req.set_result({"result": "resolve", "payment_key": str(preimage).lower()})
            n += 1
        e["requests"] = []
        received = e["received_msat"]
    _wake_waiters(plugin, ph)
    plugin.log(f"holdinvoicesettle: resolved {n} htlc(s) for {ph}", level="info")
    return {"payment_hash": ph, "state": "settled", "resolved_htlcs": n,
            "received_msat": received}


@plugin.method("holdinvoicecancel")
def holdinvoicecancel(plugin, payment_hash):
    """Cancel a held HTLC (fail it back to the payer)."""
    ph = str(payment_hash).lower()
    with LOCK:
        e = HELD.get(ph)
        if e is None:
            raise ValueError(f"unknown held payment_hash {ph}")
        e["state"] = "cancelled"
        _persist(plugin, ph)
        received = e["received_msat"]
        # 0x2002 = temporary_node_failure
        n = _drop_parts(e, "2002")
    _wake_waiters(plugin, ph)
    plugin.log(f"holdinvoicecancel: failed {n} htlc(s) for {ph}", level="info")
    return {"payment_hash": ph, "state": "cancelled", "failed_htlcs": n,
            "received_msat": received}


def _stop_timer(e):
    if e.get("timer") is not None:
        e["timer"].cancel()
        e["timer"] = None


def _drop_parts(e, failure_message):
    """Fail every HTLC the hold holds with failure_message, and forget them.
    Returns how many there were.  Called with LOCK held."""
    _stop_timer(e)
    n = 0
    for req in e["requests"]:
        req.set_result({"result": "fail", "failure_message": failure_message})
        n += 1
    e["requests"] = []
    e["htlcs"] = set()
    e["received_msat"] = 0
    e["cltv_expiry"] = None
    return n


def _time_out(plugin, ph, e):
    """The hold's timeout: parts that have not reached its amount since the
    first arrived are failed back with mpp_timeout (BOLT #4, 0x0017), and
    the hold waits for a payment again."""
    with LOCK:
        if HELD.get(ph) is not e or e["state"] != "waiting" or not e["requests"]:
            return
        received = e["received_msat"]
        n = _drop_parts(e, "0017")
    plugin.log(f"holdinvoice: failed back {n} part(s) for {ph}: {received}msat of"
               f" {e['amount_msat']}msat after {e['mpp_timeout']}s", level="info")


def _msat(v):
    if isinstance(v, str) and v.endswith("msat"):
        v = v[:-4]
    return int(v)


def _wrong_payment(htlc):
    """incorrect_or_unknown_payment_details (0x400f) with the HTLC's amount
    and the current height, what a payee answers a payment it will not
    take."""
    height = int(htlc["cltv_expiry"]) - int(htlc["cltv_expiry_relative"])
    return "400f" + _msat(htlc["amount_msat"]).to_bytes(8, "big").hex() \
        + height.to_bytes(4, "big").hex()


def _asset_matches(plugin, e, htlc):
    """Whether the HTLC arrived in the hold's asset.  Returns (ok, what it
    arrived in, for the log)."""
    want = e.get("asset")
    if not want:
        return True, None
    # The hook names the asset of the channel the HTLC arrived on; an HTLC
    # without it cannot be judged, so it is refused.
    got = htlc.get("asset")
    return got == want, got


def on_htlc_accepted(onion, htlc, request, plugin, **kwargs):
    ph = (htlc.get("payment_hash") or "").lower()
    with LOCK:
        if HELD.get(ph) is None:
            # Not one of ours: let lightningd handle it normally.
            return request.set_result({"result": "continue"})
        return _on_held_htlc(plugin, ph, htlc, request)


def _on_held_htlc(plugin, ph, htlc, request):
    """An HTLC for a registered hash.  Called with LOCK held."""
    e = HELD[ph]
    ok, arrived = _asset_matches(plugin, e, htlc)
    if not ok:
        plugin.log(f"holdinvoice: refused an htlc for {ph} in asset {arrived}:"
                   f" the hold is in asset {e['asset']}", level="info")
        return request.set_result({"result": "fail",
                                   "failure_message": _wrong_payment(htlc)})
    if e["state"] == "settled":
        return request.set_result({"result": "resolve", "payment_key": e["preimage"]})
    if e["state"] == "cancelled":
        return request.set_result({"result": "fail", "failure_message": "2002"})
    # waiting/accepted -> HOLD: count the HTLC once (lightningd replays held
    # HTLCs after a restart), stash the request, defer.
    key = (htlc.get("short_channel_id"), htlc.get("id"))
    if key not in e["htlcs"]:
        e["htlcs"].add(key)
        try:
            e["received_msat"] = (e.get("received_msat") or 0) + _msat(htlc.get("amount_msat"))
        except (TypeError, ValueError):
            pass
    exp = htlc.get("cltv_expiry")
    try:
        exp = int(exp)
        if e.get("cltv_expiry") is None or exp < e["cltv_expiry"]:
            e["cltv_expiry"] = exp
    except (TypeError, ValueError):
        pass
    e["requests"].append(request)
    # No set_result -> the HTLC stays held until settle/cancel/timeout.
    if e["state"] == "accepted" or e["received_msat"] >= e["amount_msat"]:
        _stop_timer(e)
        e["state"] = "accepted"
        plugin.log(f"holdinvoice: HOLDING htlc for {ph} (now accepted:"
                   f" {e['received_msat']}msat of {e['amount_msat']}msat)", level="info")
        _wake_waiters(plugin, ph)
        return
    # Short of the amount: held while the rest may come, and failed back
    # at the hold's timeout if it does not.
    if e["timer"] is None:
        t = threading.Timer(float(e["mpp_timeout"]), _time_out, args=(plugin, ph, e))
        t.daemon = True
        e["timer"] = t
        t.start()
    plugin.log(f"holdinvoice: holding a part for {ph}: {e['received_msat']}msat of"
               f" {e['amount_msat']}msat, waiting for the rest", level="info")


plugin.add_hook("htlc_accepted", on_htlc_accepted, background=True)
plugin.run()
