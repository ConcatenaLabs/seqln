#!/usr/bin/env python3
"""Hold every `askrene-remove-layer` for a few seconds before it runs.

xpay removes a payment's private layer as the very last step of a payment,
after the `xpay` command has returned: holding that call keeps the finished
payment in xpay's list of payments in progress for as long, which is the
window in which `listpays` is read in `test_listpays_finished_xpay`.
"""
from pyln.client import Plugin
import threading

plugin = Plugin()
HOLD_SECS = 3


@plugin.async_hook("rpc_command")
def on_rpc_command(plugin, rpc_command, request, **kwargs):
    if rpc_command['method'] == 'askrene-remove-layer':
        threading.Timer(HOLD_SECS, request.set_result,
                        [{'result': 'continue'}]).start()
    else:
        request.set_result({'result': 'continue'})


plugin.run()
