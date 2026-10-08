"""Route finding in the asset an invoice names.

A payer reads the asset from the invoice's `a` field and routes only over
channels in it; a payment in an asset the payer cannot send is refused
before any HTLC is offered.  Route finding learns the asset of an announced
channel from its funding output on chain, and of the node's own channels
(announced or not) from listpeerchannels.  Run with
TEST_NETWORK=sequentia-regtest (README.md, "Testing").
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
    return bitcoind.send(addr, atoms, asset)


def channel_in(node, peer, asset):
    return only_one([c for c in node.rpc.listpeerchannels(peer.info['id'])['channels']
                     if c.get('channel_asset') == asset])


def balance(node, peer, asset):
    return channel_in(node, peer, asset)['to_us_msat']


def no_htlcs_anywhere(*nodes):
    """No channel of any of these nodes carries or carried an HTLC, and the
    first sent no payment part."""
    for n in nodes:
        for c in n.rpc.listpeerchannels()['channels']:
            assert c['htlcs'] == [], c
    assert nodes[0].rpc.listsendpays()['payments'] == []
    for n in nodes:
        assert n.rpc.listforwards()['forwards'] == []


def line(node_factory, bitcoind, hops, announce=True):
    """Nodes in a line; hops[i] lists (asset, atoms) of the channels node i
    opens to node i+1.  Returns the nodes once every channel is usable and,
    if announced, in every node's gossip."""
    n = len(hops) + 1
    nodes = node_factory.get_nodes(n)
    txids = [fund(bitcoind, nodes[i], a, 10 * atoms)
             for i, chans in enumerate(hops) for a, atoms in chans]
    bitcoind.generate_block(1, wait_for_mempool=txids)
    for i, chans in enumerate(hops):
        wait_for(lambda: len([o for o in nodes[i].rpc.listfunds()['outputs']
                              if o['status'] == 'confirmed']) == len(chans))
    for i, chans in enumerate(hops):
        nodes[i].rpc.connect(nodes[i + 1].info['id'], 'localhost', nodes[i + 1].port)
        for asset, atoms in chans:
            res = nodes[i].rpc.call('fundchannel', {'id': nodes[i + 1].info['id'],
                                                    'amount': atoms, 'asset': asset,
                                                    'announce': announce})
            bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    total = sum(len(c) for c in hops)
    for i in range(n - 1):
        wait_for(lambda: len([c for c in nodes[i].rpc.listpeerchannels(nodes[i + 1].info['id'])['channels']
                              if c['state'] == 'CHANNELD_NORMAL']) == len(hops[i]))
    if announce:
        bitcoind.generate_block(6)
        for nd in nodes:
            wait_for(lambda: len(nd.rpc.listchannels()['channels']) == 2 * total)
    return nodes


def assets(bitcoind, k):
    out = [bitcoind.issue_asset(1000) for _ in range(k)]
    bitcoind.set_fee_rates(dict({bitcoind.POLICY_ASSET: PAR}, **{a: PAR for a in out}))
    return out


def inv(node, msat, label, asset, **kw):
    return node.rpc.call('invoice', dict({'amount_msat': msat, 'label': label,
                                          'description': label, 'asset': asset}, **kw))['bolt11']


def test_payer_reads_asset_from_invoice(node_factory, bitcoind):
    """A payer with channels in two assets pays each invoice in the asset
    it names, with no `asset=`, over that asset's channels only."""
    gold, silv = assets(bitcoind, 2)
    l1, l2, l3 = line(node_factory, bitcoind,
                      [[(gold, PAR), (silv, PAR)], [(gold, PAR // 10), (silv, 5 * PAR)]])

    before = {a: balance(l3, l2, a) for a in (gold, silv)}
    l1.rpc.pay(inv(l3, 1_000_000, 'g', gold))
    wait_for(lambda: balance(l3, l2, gold) == before[gold] + 1_000_000)
    assert balance(l3, l2, silv) == before[silv]
    assert only_one(l3.rpc.listinvoices('g')['invoices'])['status'] == 'paid'

    l1.rpc.pay(inv(l3, 2_000_000, 's', silv))
    wait_for(lambda: balance(l3, l2, silv) == before[silv] + 2_000_000)
    assert balance(l3, l2, gold) == before[gold] + 1_000_000

    # Each payment left l1 on the channel in its asset.
    wait_for(lambda: balance(l1, l2, gold) < PAR * 1000 and balance(l1, l2, silv) < PAR * 1000)

    # `asset=` may repeat the invoice's asset, never contradict it.
    i3 = inv(l3, 1_000_000, 'g2', gold)
    with pytest.raises(RpcError, match=r'The invoice is to be paid in asset {}, not {}'
                       .format(gold, silv)):
        l1.rpc.call('pay', {'bolt11': i3, 'asset': silv})
    l1.rpc.call('pay', {'bolt11': i3, 'asset': gold})

    # The gossip carries each channel's asset.
    chans = l1.rpc.listchannels()['channels']
    assert sorted(set(c['asset'] for c in chans)) == sorted([gold, silv])


def test_unsendable_asset_refused_before_htlc(node_factory, bitcoind):
    """An invoice in an asset the payer holds no channel in is refused
    before any HTLC is offered, naming the asset and the channels looked
    at, though a route in that asset exists beyond the payer."""
    gold, silv = assets(bitcoind, 2)
    l1, l2, l3 = line(node_factory, bitcoind,
                      [[(gold, PAR)], [(gold, PAR), (silv, PAR)]])
    scid = channel_in(l1, l2, gold)['short_channel_id']

    i_silv = inv(l3, 1_000_000, 's', silv)
    with pytest.raises(RpcError, match=r'This node cannot send asset {}: it has no open'
                       r' channel in it \(looked at: {} in {} \(CHANNELD_NORMAL\)\)'
                       .format(silv, scid, gold)) as err:
        l1.rpc.pay(i_silv)
    assert err.value.error['code'] == 215
    no_htlcs_anywhere(l1, l2, l3)
    assert only_one(l3.rpc.listinvoices('s')['invoices'])['status'] == 'unpaid'

    # Nor does naming another asset help.
    with pytest.raises(RpcError, match=r'The invoice is to be paid in asset {}, not {}'
                       .format(silv, gold)):
        l1.rpc.call('pay', {'bolt11': i_silv, 'asset': gold})
    no_htlcs_anywhere(l1, l2, l3)

    # A route in an asset the payer holds, which ends at the payee in
    # another, does not exist: getroute finds none in SILV from l1.
    with pytest.raises(RpcError, match=r'Could not find a route'):
        l1.rpc.call('getroute', {'id': l3.info['id'], 'amount_msat': 1000,
                                 'riskfactor': 1, 'asset': silv})

    # The same payer pays a GOLD invoice to the same payee.
    l1.rpc.pay(inv(l3, 1_000_000, 'g', gold))
    assert only_one(l3.rpc.listinvoices('g')['invoices'])['status'] == 'paid'


def test_getroute_in_one_asset(node_factory, bitcoind):
    """getroute routes in one asset: the one named, else the one this
    node's channels hold; with several it asks."""
    gold, silv = assets(bitcoind, 2)
    l1, l2, l3 = line(node_factory, bitcoind,
                      [[(gold, PAR), (silv, PAR)], [(gold, PAR), (silv, PAR)]])

    for a in (gold, silv):
        r = l1.rpc.call('getroute', {'id': l3.info['id'], 'amount_msat': 1000,
                                     'riskfactor': 1, 'asset': a})['route']
        assert [h['channel'] for h in r] == [channel_in(l1, l2, a)['short_channel_id'],
                                             channel_in(l2, l3, a)['short_channel_id']]

    with pytest.raises(RpcError, match=r'several assets: name the one to route in'):
        l1.rpc.getroute(l3.info['id'], 1000, 1)
    with pytest.raises(RpcError, match=r'A route from another node: name the asset'):
        l1.rpc.call('getroute', {'id': l3.info['id'], 'amount_msat': 1000,
                                 'riskfactor': 1, 'fromid': l2.info['id']})


def test_route_over_unannounced_first_hop(node_factory, bitcoind):
    """A payer's own unannounced channel carries its asset into route
    finding, so a payment leaves over it."""
    gold, silv = assets(bitcoind, 2)
    l1, l2, l3 = node_factory.get_nodes(3)
    # Announced GOLD and SILV channels l2 -> l3.
    txids = [fund(bitcoind, l2, a, 10 * PAR) for a in (gold, silv)]
    txids.append(fund(bitcoind, l1, gold, 10 * PAR))
    bitcoind.generate_block(1, wait_for_mempool=txids)
    wait_for(lambda: len(l2.rpc.listfunds()['outputs']) == 2)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    for a in (gold, silv):
        res = l2.rpc.call('fundchannel', {'id': l3.info['id'], 'amount': PAR, 'asset': a})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    # An unannounced GOLD channel l1 -> l2.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': PAR, 'asset': gold,
                                      'announce': False})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    wait_for(lambda: channel_in(l1, l2, gold)['state'] == 'CHANNELD_NORMAL')
    bitcoind.generate_block(6)
    wait_for(lambda: len(l1.rpc.listchannels(source=l2.info['id'])['channels']) == 2)
    wait_for(lambda: len(l1.rpc.listchannels(source=l3.info['id'])['channels']) == 2)

    r = l1.rpc.call('getroute', {'id': l3.info['id'], 'amount_msat': 1000,
                                 'riskfactor': 1, 'asset': gold})['route']
    assert r[0]['channel'] == channel_in(l1, l2, gold)['short_channel_id']
    assert r[1]['channel'] == channel_in(l2, l3, gold)['short_channel_id']
    # Without asset=: this node's channels hold one asset.
    assert l1.rpc.getroute(l3.info['id'], 1000, 1)['route'] == r

    before = balance(l3, l2, gold)
    l1.rpc.pay(inv(l3, 1_000_000, 'g', gold))
    wait_for(lambda: balance(l3, l2, gold) == before + 1_000_000)


def test_direct_peer_paid_in_invoice_asset(node_factory, bitcoind):
    """A payee that is a direct peer, over channels in two assets, is paid
    over the channel in the invoice's asset: the direct-channel shortcut
    keeps to the asset as route finding does."""
    gold, silv = assets(bitcoind, 2)
    l1, l2 = line(node_factory, bitcoind, [[(gold, PAR), (silv, PAR)]])

    for label, a, other in (('g', gold, silv), ('s', silv, gold)):
        before = {x: balance(l2, l1, x) for x in (gold, silv)}
        l1.rpc.pay(inv(l2, 3_000_000, label, a))
        wait_for(lambda: balance(l2, l1, a) == before[a] + 3_000_000)
        assert balance(l2, l1, other) == before[other]
        assert only_one(l2.rpc.listinvoices(label)['invoices'])['status'] == 'paid'
