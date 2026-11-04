#!/usr/bin/env python3
"""Takes the swaps a peer asks for on a channel of several assets
(lightningd/sym_lanes.h), at a fixed price: it gives at most `price` of the
asset it gives for one of the asset it takes, and refuses the rest."""

from pyln.client import Plugin

plugin = Plugin()
plugin.add_option('sym-swap-price', '1',
                  'Most this node gives for one of what it takes', 'string')


@plugin.hook('sym_swap')
def on_sym_swap(sym_swap, plugin, **kwargs):
    price = float(plugin.get_option('sym-swap-price'))
    # The requester gives give_msat of give_asset, which this node takes,
    # and takes take_msat of take_asset, which this node gives.
    given = int(str(sym_swap['give_msat']).rstrip('msat'))
    taken = int(str(sym_swap['take_msat']).rstrip('msat'))
    if taken > price * given:
        plugin.log('Refusing swap {}: {} for {}'.format(
            sym_swap['id'], taken, given))
        return {'result': 'refuse', 'reason': 'price'}
    plugin.log('Taking swap {}: {} for {}'.format(sym_swap['id'], taken, given))
    return {'result': 'accept'}


plugin.run()
