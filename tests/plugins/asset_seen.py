#!/usr/bin/env python3
"""Logs the asset lightningd names in the htlc_accepted and invoice_payment
hooks and in the forward_event and invoice_payment notifications, and lets
everything through."""
from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('htlc_accepted')
def on_htlc_accepted(onion, htlc, plugin, **kwargs):
    plugin.log("asset_seen htlc_accepted {} asset={}".format(
        htlc['payment_hash'], htlc.get('asset')))
    return {'result': 'continue'}


@plugin.hook('invoice_payment')
def on_invoice_payment(payment, plugin, **kwargs):
    plugin.log("asset_seen invoice_payment hook {} asset={}".format(
        payment['label'], payment.get('asset')))
    return {'result': 'continue'}


@plugin.subscribe('invoice_payment')
def on_invoice_paid(plugin, invoice_payment, **kwargs):
    plugin.log("asset_seen invoice_payment notification {} asset={}".format(
        invoice_payment['label'], invoice_payment.get('asset')))


@plugin.subscribe('forward_event')
def on_forward(plugin, forward_event, **kwargs):
    plugin.log("asset_seen forward_event {} {} asset={}".format(
        forward_event['payment_hash'], forward_event['status'],
        forward_event.get('asset')))


plugin.run()
