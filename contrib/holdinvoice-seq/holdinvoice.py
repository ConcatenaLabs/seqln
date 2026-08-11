#!/usr/bin/env python3
"""SeqLN hold-invoice plugin (M0).

Holds incoming HTLCs whose payment_hash has been registered via `holdinvoice`,
keeping them in the `accepted` state (off-chain HTLC locked but unsettled) until
`holdinvoicesettle <payment_hash> <preimage>` resolves them with the preimage or
`holdinvoicecancel <payment_hash>` fails them. This is the safety primitive the
pure-LN swap rests on: the maker's incoming leg is held until it learns the
preimage by paying the outgoing leg.

RPC methods match what seqdex's clnLNLeg expects (holdinvoice / holdinvoicelookup
/ holdinvoicesettle / holdinvoicecancel). M0: in-memory state, no persistence.
"""
import hashlib
import os
import sys
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

# payment_hash(hex) -> {state, preimage, amount_msat, requests:[Request,...]}
HELD = {}
STATES = ("waiting", "accepted", "settled", "cancelled")


@plugin.method("holdinvoice")
def holdinvoice(plugin, payment_hash, amount_msat=0, label="", description="", cltv=0):
    """Register a payment_hash to be HELD when an HTLC for it arrives.

    Does not create a BOLT11 (create-by-external-hash needs HSM invoice signing;
    the payer can pay the hash directly via sendpay). Returns the registered hash.
    """
    ph = str(payment_hash).lower()
    if ph in HELD and HELD[ph]["state"] in ("accepted", "settled"):
        return {"payment_hash": ph, "state": HELD[ph]["state"],
                "warning": "already registered"}
    HELD[ph] = {"state": "waiting", "preimage": None,
                "amount_msat": int(amount_msat), "received_msat": 0,
                "requests": []}
    plugin.log(f"holdinvoice: registered hash {ph} to hold", level="info")
    return {"payment_hash": ph, "state": "waiting", "bolt11": None}


@plugin.method("holdinvoicelookup")
def holdinvoicelookup(plugin, payment_hash):
    ph = str(payment_hash).lower()
    e = HELD.get(ph)
    if e is None:
        return {"payment_hash": ph, "state": "unknown"}
    return {"payment_hash": ph, "state": e["state"],
            # amount_msat is the REGISTERED amount, received_msat the summed incoming
            # HTLCs. These used to be one accumulated field, so a lookup after the payer
            # paid reported registered+received (a 9999-sat hold read as 19998000 msat)
            # and looked like a double-pay in every audit that trusted it.
            "amount_msat": e["amount_msat"],
            "received_msat": e.get("received_msat", 0)}


@plugin.method("holdinvoicesettle")
def holdinvoicesettle(plugin, payment_hash, preimage):
    """Settle a held HTLC by revealing the preimage (must hash to payment_hash)."""
    ph = str(payment_hash).lower()
    e = HELD.get(ph)
    if e is None:
        raise ValueError(f"unknown held payment_hash {ph}")
    if hashlib.sha256(bytes.fromhex(str(preimage))).hexdigest() != ph:
        raise ValueError("preimage does not hash to payment_hash")
    e["preimage"] = str(preimage).lower()
    e["state"] = "settled"
    n = 0
    for req in e["requests"]:
        req.set_result({"result": "resolve", "payment_key": str(preimage).lower()})
        n += 1
    e["requests"] = []
    plugin.log(f"holdinvoicesettle: resolved {n} htlc(s) for {ph}", level="info")
    return {"payment_hash": ph, "state": "settled", "resolved_htlcs": n}


@plugin.method("holdinvoicecancel")
def holdinvoicecancel(plugin, payment_hash):
    """Cancel a held HTLC (fail it back to the payer)."""
    ph = str(payment_hash).lower()
    e = HELD.get(ph)
    if e is None:
        raise ValueError(f"unknown held payment_hash {ph}")
    e["state"] = "cancelled"
    n = 0
    for req in e["requests"]:
        # 0x2002 = temporary_node_failure
        req.set_result({"result": "fail", "failure_message": "2002"})
        n += 1
    e["requests"] = []
    plugin.log(f"holdinvoicecancel: failed {n} htlc(s) for {ph}", level="info")
    return {"payment_hash": ph, "state": "cancelled", "failed_htlcs": n}


def on_htlc_accepted(onion, htlc, request, plugin, **kwargs):
    ph = (htlc.get("payment_hash") or "").lower()
    e = HELD.get(ph)
    if e is None:
        # Not one of ours: let lightningd handle it normally.
        return request.set_result({"result": "continue"})
    if e["state"] == "settled":
        return request.set_result({"result": "resolve", "payment_key": e["preimage"]})
    if e["state"] == "cancelled":
        return request.set_result({"result": "fail", "failure_message": "2002"})
    # waiting/accepted -> HOLD: accumulate amount, stash the request, defer.
    amt = htlc.get("amount_msat")
    if isinstance(amt, str) and amt.endswith("msat"):
        amt = int(amt[:-4])
    try:
        e["received_msat"] = (e.get("received_msat") or 0) + int(amt)
    except (TypeError, ValueError):
        pass
    e["state"] = "accepted"
    e["requests"].append(request)
    plugin.log(f"holdinvoice: HOLDING htlc for {ph} (now accepted)", level="info")
    # No set_result -> the HTLC stays accepted until settle/cancel.


plugin.add_hook("htlc_accepted", on_htlc_accepted, background=True)
plugin.run()
