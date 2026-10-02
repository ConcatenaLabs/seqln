"""Payments on nodes that hold channels in more than one asset.

An HTLC's amount is read in the atoms of whatever asset its channel holds:
nothing in an invoice or an onion names the asset.  So the payer must pick
channels of one asset, every forwarding node must keep a payment in the
asset it arrived in, and a payee must refuse an HTLC in an asset its invoice
was not issued in.  Run with TEST_NETWORK=sequentia-regtest (README.md,
"Testing").
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, wait_for

import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8


def fund(bitcoind, node, asset, atoms):
    addr = node.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send(addr, atoms, asset)
    return txid


def channel_in(node, peer, asset):
    return only_one([c for c in node.rpc.listpeerchannels(peer.info['id'])['channels']
                     if c.get('channel_asset') == asset])


def balance(node, peer, asset):
    return channel_in(node, peer, asset)['to_us_msat']


def two_asset_line(node_factory, bitcoind):
    """l1 -> l2 -> l3, with a GOLD and a SILV channel on each hop.  On the
    second hop the SILV channel is the larger, so a forwarding node that
    picks the channel with most room picks SILV."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: PAR})
    l1, l2, l3 = node_factory.get_nodes(3)

    txids = [fund(bitcoind, n, a, 10 * PAR) for n in (l1, l2) for a in (gold, silv)]
    bitcoind.generate_block(1, wait_for_mempool=txids)
    for n in (l1, l2):
        wait_for(lambda: len([o for o in n.rpc.listfunds()['outputs']
                              if o['status'] == 'confirmed']) == 2)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    for src, dst, asset, atoms in ((l1, l2, gold, PAR), (l1, l2, silv, PAR),
                                   (l2, l3, gold, PAR // 10), (l2, l3, silv, 5 * PAR)):
        res = src.rpc.call('fundchannel', {'id': dst.info['id'], 'amount': atoms,
                                           'asset': asset, 'announce': True})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])

    # Announce all four (anchors advance with each block).
    bitcoind.generate_block(6)
    for n in (l1, l2, l3):
        wait_for(lambda: len(n.rpc.listchannels()['channels']) == 8)
    return l1, l2, l3, gold, silv


def invoice(node, msat, label, asset):
    return node.rpc.call('invoice', {'amount_msat': msat, 'label': label,
                                     'description': label, 'asset': asset})['bolt11']


def test_routes_each_asset_over_its_own_channels(node_factory, bitcoind):
    """A node with channels in two assets to the same peer forwards each
    payment over the channel in the asset it arrived in, and the payee is
    paid in the asset its invoice asked for."""
    l1, l2, l3, gold, silv = two_asset_line(node_factory, bitcoind)

    before = {a: balance(l3, l2, a) for a in (gold, silv)}
    l1.rpc.call('pay', {'bolt11': invoice(l3, 1_000_000, 'gold', gold), 'asset': gold})
    wait_for(lambda: balance(l3, l2, gold) == before[gold] + 1_000_000)
    assert balance(l3, l2, silv) == before[silv]

    l1.rpc.call('pay', {'bolt11': invoice(l3, 2_000_000, 'silv', silv), 'asset': silv})
    wait_for(lambda: balance(l3, l2, silv) == before[silv] + 2_000_000)
    assert balance(l3, l2, gold) == before[gold] + 1_000_000


def test_payee_refuses_wrong_asset(node_factory, bitcoind):
    """An HTLC in an asset other than the one the invoice was issued in is
    refused, and the invoice stays unpaid."""
    l1, l2, l3, gold, silv = two_asset_line(node_factory, bitcoind)

    inv = invoice(l3, 1_000_000, 'wants-gold', gold)
    with pytest.raises(RpcError):
        l1.rpc.call('pay', {'bolt11': inv, 'asset': silv})
    assert only_one(l3.rpc.listinvoices('wants-gold')['invoices'])['status'] == 'unpaid'
    l3.daemon.wait_for_log(r'paid in asset {}, invoice wants {}'.format(silv, gold))

    # The same invoice, paid in its asset.
    l1.rpc.call('pay', {'bolt11': inv, 'asset': gold})
    assert only_one(l3.rpc.listinvoices('wants-gold')['invoices'])['status'] == 'paid'
    assert only_one(l3.rpc.listinvoices('wants-gold')['invoices'])['asset'] == gold


def test_no_asset_blind_first_hop(node_factory, bitcoind):
    """A payer holding channels in two assets must say which to pay in:
    `pay` without `asset=` and a first hop of "any channel" both refuse
    rather than pick one."""
    l1, l2, l3, gold, silv = two_asset_line(node_factory, bitcoind)

    inv = invoice(l2, 1_000_000, 'any', gold)
    with pytest.raises(RpcError, match=r'asset'):
        l1.rpc.pay(inv)

    # sendpay with an all-zero first hop: "any channel to this peer".
    decoded = l1.rpc.decode(inv)
    route = [{'id': l2.info['id'], 'channel': '0x0x0', 'amount_msat': 1_000_000,
              'delay': decoded['min_final_cltv_expiry'] + 5}]
    with pytest.raises(RpcError, match=r'asset'):
        l1.rpc.sendpay(route, decoded['payment_hash'],
                       payment_secret=decoded['payment_secret'])
    assert only_one(l2.rpc.listinvoices('any')['invoices'])['status'] == 'unpaid'

    # On a node with channels in several assets, an invoice that names none
    # does not pick one for the caller.
    l2.rpc.invoice(1_000_000, 'unnamed', 'unnamed')
    assert 'asset' not in only_one(l2.rpc.listinvoices('unnamed')['invoices'])


def test_one_asset_node_pays_without_asset(node_factory, bitcoind):
    """A node whose channels are all in one asset needs no `asset=`: that is
    the only asset it can pay in."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2 = node_factory.get_nodes(2)
    bitcoind.generate_block(1, wait_for_mempool=fund(bitcoind, l1, gold, 10 * PAR))
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': PAR, 'asset': gold})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    wait_for(lambda: channel_in(l1, l2, gold)['state'] == 'CHANNELD_NORMAL')

    # An invoice without `asset=` on a node with one asset records it.
    inv = l2.rpc.invoice(1_000_000, 'plain', 'plain')['bolt11']
    assert only_one(l2.rpc.listinvoices('plain')['invoices'])['asset'] == gold
    l1.rpc.pay(inv)
    wait_for(lambda: balance(l2, l1, gold) == 1_000_000)
