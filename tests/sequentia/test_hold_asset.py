"""The asset of an HTLC, seen by plugins.

On a Sequentia network a node can hold channels in several assets, and an
HTLC's amount is in the asset of the channel it arrived on.  The htlc_accepted
hook, the invoice_payment hook and the forward_event and invoice_payment
notifications name that asset, and holdinvoice-seq holds a payment only in the
asset it was registered in.  Run with TEST_NETWORK=sequentia-regtest
(README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, wait_for

import hashlib
import os
import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
HOLD = os.path.join(os.path.dirname(__file__), '..', '..', 'contrib',
                    'holdinvoice-seq', 'holdinvoice.py')
ASSET_SEEN = os.path.join(os.path.dirname(__file__), '..', 'plugins', 'asset_seen.py')


def chan_in(node, peer, asset):
    return only_one([c for c in node.rpc.listpeerchannels(peer.info['id'])['channels']
                     if c.get('channel_asset') == asset])


def two_asset_channels(node_factory, bitcoind, opts):
    """l1 opens a GOLD and a SILV channel to l2; one SILV atom is worth a
    hundredth of a GOLD atom."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: PAR // 100})
    l1, l2 = node_factory.get_nodes(2, opts=opts)
    txids = [bitcoind.send(l1.rpc.newaddr('bech32')['bech32'], 10 * PAR, a)
             for a in (gold, silv)]
    bitcoind.generate_block(1, wait_for_mempool=txids)
    wait_for(lambda: len([o for o in l1.rpc.listfunds()['outputs']
                          if o['status'] == 'confirmed']) == 2)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    for a in (gold, silv):
        res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': PAR, 'asset': a})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a in (gold, silv):
        wait_for(lambda: chan_in(l2, l1, a)['state'] == 'CHANNELD_NORMAL')
    return l1, l2, gold, silv


def send_over(l1, l2, scid, h, amount):
    route = [{'id': l2.info['id'], 'channel': scid, 'amount_msat': amount, 'delay': 200}]
    l1.rpc.sendpay(route, h)


def test_hold_invoice_refuses_another_asset(node_factory, bitcoind):
    """A swap maker holds a hash for 5,000,000 GOLD atoms.  The payer routes
    the HTLC over its SILV channel instead: the hold refuses it, stays
    unpaid, and the maker has nothing to settle, so the preimage stays with
    it.  Sent again over the GOLD channel, the HTLC is held and settles."""
    l1, l2, gold, silv = two_asset_channels(node_factory, bitcoind, [{}, {'plugin': HOLD}])

    preimage = os.urandom(32)
    h = hashlib.sha256(preimage).hexdigest()
    amount = 5 * 10**6 * 1000  # 5,000,000 atoms, in GOLD
    # On a node with channels in two assets the hold must name one.
    with pytest.raises(RpcError, match='name the asset'):
        l2.rpc.call('holdinvoice', {'payment_hash': h, 'amount_msat': amount})
    reg = l2.rpc.call('holdinvoice', {'payment_hash': h, 'amount_msat': amount,
                                      'asset': gold})
    assert reg['asset'] == gold

    before = {a: chan_in(l2, l1, a)['to_us_msat'] for a in (gold, silv)}
    send_over(l1, l2, chan_in(l1, l2, silv)['short_channel_id'], h, amount)
    with pytest.raises(RpcError) as err:
        l1.rpc.waitsendpay(h)
    print("payer, SILV HTLC for a GOLD hold:", err.value.error['message'])
    assert err.value.error['data']['failcode'] == 0x400f
    look = l2.rpc.call('holdinvoicelookup', {'payment_hash': h})
    print("holdinvoicelookup after the SILV HTLC:", look)
    assert look['state'] == 'waiting'
    assert look['received_msat'] == 0
    assert l2.daemon.is_in_log('refused an htlc for {} in asset {}'.format(h, silv))
    after = {a: chan_in(l2, l1, a)['to_us_msat'] for a in (gold, silv)}
    assert after == before

    # The right asset: held, then settled.
    send_over(l1, l2, chan_in(l1, l2, gold)['short_channel_id'], h, amount)
    wait_for(lambda: l2.rpc.call('holdinvoicelookup', {'payment_hash': h})['state'] == 'accepted')
    look = l2.rpc.call('holdinvoicelookup', {'payment_hash': h})
    print("holdinvoicelookup after the GOLD HTLC:", look)
    assert look['received_msat'] == amount and look['asset'] == gold
    l2.rpc.call('holdinvoicesettle', {'payment_hash': h, 'preimage': preimage.hex()})
    assert l1.rpc.waitsendpay(h)['status'] == 'complete'
    wait_for(lambda: chan_in(l2, l1, gold)['htlcs'] == [])
    after = {a: chan_in(l2, l1, a)['to_us_msat'] for a in (gold, silv)}
    print("holder's balance change: GOLD {} msat, SILV {} msat".format(
        after[gold] - before[gold], after[silv] - before[silv]))
    assert after[gold] - before[gold] == amount
    assert after[silv] == before[silv]


def test_plugins_see_the_asset(node_factory, bitcoind):
    """A hook consumer sees the asset of the channel an HTLC arrived on, and
    so does a subscriber to the forward and payment notifications."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2, l3 = node_factory.line_graph(3, fundchannel=False, opts={'plugin': ASSET_SEEN})
    for a, b in ((l1, l2), (l2, l3)):
        addr = a.rpc.newaddr('bech32')['bech32']
        txid = bitcoind.send_and_mine_block(addr, 2 * PAR, gold)
        wait_for(lambda: any(o['txid'] == txid for o in a.rpc.listfunds()['outputs']))
        res = a.rpc.call('fundchannel', {'id': b.info['id'], 'amount': PAR,
                                         'asset': gold, 'announce': True})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1), (l2, l3), (l3, l2)):
        wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')
    bitcoind.generate_block(6)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 4)

    inv = l3.rpc.call('invoice', {'amount_msat': 10**6 * 1000, 'label': 'seen',
                                  'description': 'seen', 'asset': gold})
    l1.rpc.call('pay', {'bolt11': inv['bolt11'], 'asset': gold})
    h = inv['payment_hash']
    l2.daemon.wait_for_log('asset_seen htlc_accepted {} asset={}'.format(h, gold))
    l2.daemon.wait_for_log('asset_seen forward_event {} settled asset={}'.format(h, gold))
    l3.daemon.wait_for_log('asset_seen htlc_accepted {} asset={}'.format(h, gold))
    l3.daemon.wait_for_log('asset_seen invoice_payment hook seen asset={}'.format(gold))
    l3.daemon.wait_for_log('asset_seen invoice_payment notification seen asset={}'.format(gold))


def test_hold_survives_a_restart(node_factory, bitcoind):
    """A hold registered, and an HTLC held for it, before the holder's node
    restarts: after the restart lightningd replays the HTLC, the plugin holds
    it again in the registered asset, and the settle completes the payment.
    A hold registered before a restart, with no HTLC yet, still holds one
    that arrives after it."""
    l1, l2, gold, silv = two_asset_channels(node_factory, bitcoind,
                                            [{'may_reconnect': True},
                                             {'plugin': HOLD, 'may_reconnect': True}])
    # Large enough not to be dust in SILV at its feerate.
    amount = 5 * 10**6 * 1000

    p1 = os.urandom(32)
    h1 = hashlib.sha256(p1).hexdigest()
    l2.rpc.call('holdinvoice', {'payment_hash': h1, 'amount_msat': amount, 'asset': gold})
    send_over(l1, l2, chan_in(l1, l2, gold)['short_channel_id'], h1, amount)
    wait_for(lambda: l2.rpc.call('holdinvoicelookup', {'payment_hash': h1})['state'] == 'accepted')

    p2 = os.urandom(32)
    h2 = hashlib.sha256(p2).hexdigest()
    l2.rpc.call('holdinvoice', {'payment_hash': h2, 'amount_msat': amount, 'asset': gold})

    l2.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    assert l2.daemon.is_in_log('holdinvoice: restored 2 hold')
    wait_for(lambda: l2.rpc.call('holdinvoicelookup', {'payment_hash': h1})['state'] == 'accepted')
    look = l2.rpc.call('holdinvoicelookup', {'payment_hash': h1})
    print("after the restart, the held HTLC:", look)
    assert look['received_msat'] == amount and look['asset'] == gold
    l2.rpc.call('holdinvoicesettle', {'payment_hash': h1, 'preimage': p1.hex()})
    assert l1.rpc.waitsendpay(h1)['status'] == 'complete'

    assert l2.rpc.call('holdinvoicelookup', {'payment_hash': h2})['state'] == 'waiting'
    send_over(l1, l2, chan_in(l1, l2, silv)['short_channel_id'], h2, amount)
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(h2)
    assert l2.daemon.is_in_log('refused an htlc for {} in asset {}'.format(h2, silv))
    send_over(l1, l2, chan_in(l1, l2, gold)['short_channel_id'], h2, amount)
    wait_for(lambda: l2.rpc.call('holdinvoicelookup', {'payment_hash': h2})['state'] == 'accepted')
    l2.rpc.call('holdinvoicesettle', {'payment_hash': h2, 'preimage': p2.hex()})
    assert l1.rpc.waitsendpay(h2)['status'] == 'complete'


def test_hold_in_the_one_asset_of_the_node(node_factory, bitcoind):
    """On a node whose channels all hold one asset, a hold that names none is
    in that asset: here the Sequence token, the policy asset."""
    l1, l2 = node_factory.get_nodes(2, opts=[{}, {'plugin': HOLD}])
    addr = l1.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send_and_mine_block(addr, 2 * PAR)
    wait_for(lambda: any(o['txid'] == txid for o in l1.rpc.listfunds()['outputs']))
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.fundchannel(l2.info['id'], PAR)
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')
    p = os.urandom(32)
    h = hashlib.sha256(p).hexdigest()
    reg = l2.rpc.call('holdinvoice', {'payment_hash': h, 'amount_msat': 10**9})
    assert 'asset' not in reg
    scid = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['short_channel_id']
    send_over(l1, l2, scid, h, 10**9)
    wait_for(lambda: l2.rpc.call('holdinvoicelookup', {'payment_hash': h})['state'] == 'accepted')
    l2.rpc.call('holdinvoicesettle', {'payment_hash': h, 'preimage': p.hex()})
    assert l1.rpc.waitsendpay(h)['status'] == 'complete'


def test_payment_set_stays_in_one_asset(node_factory, bitcoind):
    """An invoice that names no asset, on a node with channels in two: the
    parts of one payment must all be in the asset of the first, or the node
    would add SILV atoms to GOLD ones at par."""
    l1, l2, gold, silv = two_asset_channels(node_factory, bitcoind, [{}, {}])
    part = 5 * 10**6 * 1000  # not dust in SILV at its feerate
    inv = l2.rpc.invoice(2 * part, 'mixed', 'mixed')
    assert 'asset' not in inv or inv.get('asset') is None
    h = inv['payment_hash']
    secret = inv['payment_secret']
    for i, a in enumerate((gold, silv)):
        scid = chan_in(l1, l2, a)['short_channel_id']
        route = [{'id': l2.info['id'], 'channel': scid, 'amount_msat': part, 'delay': 200}]
        l1.rpc.call('sendpay', {'route': route, 'payment_hash': h, 'payment_secret': secret,
                                'amount_msat': 2 * part, 'partid': i + 1, 'groupid': 1})
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(h, partid=2, groupid=1)
    assert l2.daemon.is_in_log('in asset {}, the payment set is in asset {}'.format(silv, gold))
    assert only_one(l2.rpc.listinvoices('mixed')['invoices'])['status'] == 'unpaid'
