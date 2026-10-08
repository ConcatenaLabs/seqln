"""How long a payer lets its payment be locked, by default.

`pay` and `keysend` refuse a route whose total CLTV delay is above
`maxdelay`.  Its default is the network's own cap on an HTLC's lock time,
the one lightningd enforces (`max_htlc_cltv`): 2016 blocks, two weeks, on Bitcoin, and 20,160
blocks, two weeks at Sequentia's one-minute blocks, on a Sequentia network.
An invoice whose final lock time is about 5,000 blocks (an Arca receive
invoice) is therefore paid by a default payer on Sequentia and refused on
Bitcoin.  askrene's `getroutes` takes the same cap as its default and its
limit.  `getroute` bounds no delay: it returns the route, and the payer
judges it.  Run with TEST_NETWORK=sequentia-regtest, and with
TEST_NETWORK=regtest for Bitcoin (README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, wait_for

import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK not in ('sequentia-regtest', 'regtest'),
                                reason='needs TEST_NETWORK=sequentia-regtest or regtest')

SEQ = TEST_NETWORK == 'sequentia-regtest'
FINAL = 5000          # the invoice's final lock time, in blocks
AMOUNT = 100_000_000  # msat
PAR = 10**8


def pair(node_factory, bitcoind, opts=None):
    """l1 with an announced channel to l2, in the Sequence token on Sequentia
    (the policy asset, funded like any other) and in bitcoin on Bitcoin."""
    if not SEQ:
        return node_factory.line_graph(2, wait_for_announce=True, opts=opts)
    l1, l2 = node_factory.get_nodes(2, opts=opts)
    txid = bitcoind.send_and_mine_block(l1.rpc.newaddr('bech32')['bech32'], 2 * PAR)
    wait_for(lambda: any(o['txid'] == txid and o['status'] == 'confirmed'
                         for o in l1.rpc.listfunds()['outputs']))
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.fundchannel(l2.info['id'], PAR)
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state']
                 == 'CHANNELD_NORMAL')
    bitcoind.generate_block(6)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)
    return l1, l2


def test_default_maxdelay_is_the_networks_cap(node_factory, bitcoind):
    l1, l2 = pair(node_factory, bitcoind)

    inv = l2.rpc.call('invoice', {'amount_msat': AMOUNT, 'label': 'long',
                                  'description': 'locked 5000 blocks', 'cltv': FINAL})
    assert l1.rpc.decode(inv['bolt11'])['min_final_cltv_expiry'] == FINAL

    # getroute bounds no delay: the route comes back, for the payer to judge.
    route = l1.rpc.getroute(l2.info['id'], AMOUNT, 1, cltv=FINAL)['route']
    print("getroute, cltv 5000:", route)
    assert only_one(route)['delay'] == FINAL

    # Bounded below the invoice's lock time, every network refuses it.
    with pytest.raises(RpcError) as err:
        l1.rpc.call('pay', {'bolt11': inv['bolt11'], 'maxdelay': FINAL - 1})
    print("pay maxdelay 4999:", err.value.error['message'])
    assert l1.rpc.listsendpays(payment_hash=inv['payment_hash'])['payments'] == []

    if not SEQ:
        # Bitcoin: the default, 2016, refuses a 5000-block lock.
        with pytest.raises(RpcError) as err:
            l1.rpc.call('pay', {'bolt11': inv['bolt11']})
        print("Bitcoin, pay with the default maxdelay:", err.value.error['message'])
        assert l1.rpc.listsendpays(payment_hash=inv['payment_hash'])['payments'] == []
        return

    # Sequentia: the default is the network's cap, so it pays.
    res = l1.rpc.call('pay', {'bolt11': inv['bolt11']})
    print("Sequentia, pay with the default maxdelay:", res['status'])
    assert res['status'] == 'complete'
    paid = only_one(l2.rpc.listinvoices('long')['invoices'])
    assert paid['status'] == 'paid'


def test_getroutes_takes_the_networks_cap(node_factory, bitcoind):
    """askrene's getroutes takes the network's cap as its default maxdelay
    and its limit."""
    l1, l2 = pair(node_factory, bitcoind)
    req = {'source': l1.info['id'], 'destination': l2.info['id'], 'amount_msat': AMOUNT,
           'layers': ['auto.localchans'], 'maxfee_msat': AMOUNT, 'final_cltv': FINAL}
    if SEQ:
        routes = l1.rpc.call('getroutes', req)['routes']
        print("getroutes, final_cltv 5000:", routes)
        assert only_one(routes)['final_cltv'] == FINAL
        l1.rpc.call('getroutes', dict(req, maxdelay=20160))
    else:
        with pytest.raises(RpcError, match='excessive delays') as err:
            l1.rpc.call('getroutes', req)
        print("getroutes, final_cltv 5000:", err.value.error['message'])
        with pytest.raises(RpcError, match='maximum delay allowed is 2016'):
            l1.rpc.call('getroutes', dict(req, maxdelay=20160))
