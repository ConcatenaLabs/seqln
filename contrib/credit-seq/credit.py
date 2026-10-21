#!/usr/bin/env python3
"""SeqLN credit plugin: invoices that credit a holder's channel.

On a credit channel (doc/sequentia-fork.md section 5d) the provider can
credit the holder while the holder cannot sign an update, for instance a
hosted user whose device is away.  This plugin runs on the provider's node:

  creditinvoice id amount_msat [label] [description]
      An invoice of this node, in the asset of its credit channel with peer
      `id`, whose payment credits that peer.

When such an invoice is paid, its `invoice_payment` hook asks lightningd to
issue a credit note for the amount (`issuecredit`), conditional on the
invoice's payment hash and carrying its preimage, before the payment is
accepted: the provider collects the payment only once the holder is owed it.
If the note cannot be issued (the provider's balance in the channel cannot
pay it), the payment is refused and fails back to the payer.
"""
import hashlib
import importlib.util
import os
import sys
import types


def _find_pyln_client_dir():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        cand = os.path.join(d, "contrib", "pyln-client", "pyln", "client")
        if os.path.exists(os.path.join(cand, "plugin.py")):
            return cand
        d = os.path.dirname(d)
    raise RuntimeError("contrib/pyln-client not found above " + __file__)


def _load_pyln_plugin():
    """pyln.client.Plugin without pyln/client/__init__.py, whose imports
    need compiled packages a node may lack (as contrib/holdinvoice-seq)."""
    base = _find_pyln_client_dir()
    pyln_root = os.path.dirname(os.path.dirname(base))
    for name, path in [("pyln", pyln_root), ("pyln.client", base)]:
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

PREFIX = "credit:"


def provider_channel(peer_id):
    """Our credit channel with `peer_id` in which this node provides."""
    chans = plugin.rpc.call("listpeerchannels", {"id": peer_id})["channels"]
    mine = [c for c in chans
            if "seq_credit/even" in c.get("channel_type", {}).get("names", [])
            and c.get("opener") == "local"]
    if len(mine) != 1:
        raise ValueError("{} credit channels with {} in which this node"
                         " provides".format(len(mine), peer_id))
    return mine[0]


@plugin.method("creditinvoice")
def creditinvoice(plugin, id, amount_msat, label=None, description=None):
    """An invoice whose payment credits peer `id`'s credit channel."""
    chan = provider_channel(id)
    label = label or hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    params = {"amount_msat": amount_msat,
              "label": "{}{}:{}".format(PREFIX, id, label),
              "description": description or "credit to {}".format(id)}
    if chan.get("channel_asset"):
        params["asset"] = chan["channel_asset"]
    inv = plugin.rpc.call("invoice", params)
    inv["credited"] = id
    inv["channel_id"] = chan["channel_id"]
    return inv


def _msat(v):
    if isinstance(v, int):
        return v
    return int(str(v).rstrip("msat"))


@plugin.hook("invoice_payment")
def on_payment(payment, plugin, **kwargs):
    label = payment.get("label", "")
    if not label.startswith(PREFIX):
        return {"result": "continue"}
    peer_id = label[len(PREFIX):].split(":")[0]
    preimage = payment["preimage"]
    payment_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    try:
        notes = plugin.rpc.call("issuecredit", {"id": peer_id,
                                                "amount_msat": _msat(payment["msat"]),
                                                "payment_hash": payment_hash,
                                                "preimage": preimage})["notes"]
    except Exception as e:
        plugin.log("Refusing payment {} for {}: no credit note: {}"
                   .format(payment_hash, peer_id, e), level="unusual")
        return {"result": "reject"}
    plugin.log("Credited {}: {} in all, for payment {}"
               .format(peer_id, notes[0]["credit"], payment_hash))
    return {"result": "continue"}


plugin.run()
