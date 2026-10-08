"""Multi-part payments and keysend in one asset.

The parts of a payment travel only over channels in the asset its invoice
names: a payment larger than what this node can send in that asset fails
without a part in any other asset, whatever it holds in them.  Keysend
takes the asset to pay in (`asset=`), routes only in it, and the payee's
backfilled invoice names the asset the HTLC arrived in.  Run with
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


def assets(bitcoind, k):
    out = [bitcoind.issue_asset(1000) for _ in range(k)]
    bitcoind.set_fee_rates(dict({bitcoind.POLICY_ASSET: PAR}, **{a: PAR for a in out}))
    return out


def open_channels(bitcoind, src, dst, chans, announce=True):
    """src opens to dst one channel per (asset, atoms) in chans."""
    txids = [fund(bitcoind, src, a, 10 * atoms) for a, atoms in chans]
    bitcoind.generate_block(1, wait_for_mempool=txids)
    wait_for(lambda: len([o for o in src.rpc.listfunds()['outputs']
                          if o['status'] == 'confirmed']) >= len(chans))
    src.rpc.connect(dst.info['id'], 'localhost', dst.port)
    for asset, atoms in chans:
        res = src.rpc.call('fundchannel', {'id': dst.info['id'], 'amount': atoms,
                                           'asset': asset, 'announce': announce})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    wait_for(lambda: len([c for c in src.rpc.listpeerchannels(dst.info['id'])['channels']
                          if c['state'] == 'CHANNELD_NORMAL']) == len(chans))


def chans_in(node, peer, asset):
    return [c for c in node.rpc.listpeerchannels(peer.info['id'])['channels']
            if c.get('channel_asset') == asset]


def no_htlcs_anywhere(*nodes):
    for n in nodes:
        for c in n.rpc.listpeerchannels()['channels']:
            assert c['htlcs'] == [], c
    assert nodes[0].rpc.listsendpays()['payments'] == []


def test_mpp_in_one_asset(node_factory, bitcoind):
    """A payment larger than any one channel splits over the payer's two
    GOLD channels and never touches its larger SILV channel; a payment
    larger than all its GOLD fails, with every part it offered in GOLD."""
    gold, silv = assets(bitcoind, 2)
    l1, l2 = node_factory.get_nodes(2)
    open_channels(bitcoind, l1, l2, [(gold, PAR), (gold, PAR), (silv, 5 * PAR)])

    silv_before = only_one(chans_in(l1, l2, silv))['to_us_msat']
    amount = 150_000_000_000  # 1.5 GOLD channels' worth
    inv = l2.rpc.call('invoice', {'amount_msat': amount, 'label': 'mpp',
                                  'description': 'mpp', 'asset': gold})['bolt11']
    res = l1.rpc.pay(inv)
    assert res['status'] == 'complete'
    assert res['parts'] >= 2
    assert len(chans_in(l1, l2, gold)) == 2

    def spent():
        return [PAR * 1000 - c['to_us_msat'] for c in chans_in(l1, l2, gold)]
    # Both GOLD channels carried a part, and together the whole amount.
    wait_for(lambda: sum(spent()) == amount)
    assert all(s > 0 for s in spent()), spent()
    assert only_one(chans_in(l1, l2, silv))['to_us_msat'] == silv_before
    paid = only_one(l2.rpc.listinvoices('mpp')['invoices'])
    assert paid['status'] == 'paid' and paid['asset'] == gold

    # More than all the GOLD l1 can still send, though less than its SILV:
    # it fails, and every part it offers is in GOLD.
    big = l2.rpc.call('invoice', {'amount_msat': 100_000_000_000, 'label': 'big',
                                  'description': 'big', 'asset': gold})['bolt11']
    gold_scids = set(c['short_channel_id'] for c in chans_in(l1, l2, gold))
    silv_scid = only_one(chans_in(l1, l2, silv))['short_channel_id']
    l1.daemon.logs_catchup()
    start = len(l1.daemon.logs)
    with pytest.raises(RpcError):
        l1.rpc.call('pay', {'bolt11': big, 'retry_for': 10})
    wait_for(lambda: all(c['htlcs'] == [] for c in l1.rpc.listpeerchannels()['channels']))

    def routes():
        l1.daemon.logs_catchup()
        return [ln.split('Created outgoing onion for route: ')[1].split()[0]
                for ln in l1.daemon.logs[start:]
                if 'Created outgoing onion for route: ' in ln]
    # The log may lag the RPC: wait for the parts' lines.
    wait_for(lambda: routes() != [])
    assert set(routes()) <= gold_scids, (routes(), silv_scid)
    assert only_one(chans_in(l1, l2, silv))['to_us_msat'] == silv_before
    assert only_one(l2.rpc.listinvoices('big')['invoices'])['status'] == 'unpaid'


def test_keysend_in_asset(node_factory, bitcoind):
    """keysend pays in the asset named, over its channels; the payee's
    invoice names that asset; a node with channels in two assets must name
    one, and an asset with no route is refused before any HTLC leaves."""
    gold, silv = assets(bitcoind, 2)
    l1, l2, l3 = node_factory.get_nodes(3)
    open_channels(bitcoind, l1, l2, [(gold, PAR), (silv, PAR)])
    # l2 -> l3 only in SILV.
    open_channels(bitcoind, l2, l3, [(silv, PAR)])
    bitcoind.generate_block(6)
    for n in (l1, l2, l3):
        wait_for(lambda: len(n.rpc.listchannels()['channels']) == 6)

    # With channels in two assets, the caller names one.
    with pytest.raises(RpcError, match=r'several assets: name the one to pay in'):
        l1.rpc.keysend(l2.info['id'], 5000)
    no_htlcs_anywhere(l1, l2, l3)

    before = {a: only_one(chans_in(l2, l1, a))['to_us_msat'] for a in (gold, silv)}
    res = l1.rpc.call('keysend', {'destination': l2.info['id'], 'amount_msat': 5000,
                                  'asset': gold})
    assert res['status'] == 'complete'
    wait_for(lambda: only_one(chans_in(l2, l1, gold))['to_us_msat'] == before[gold] + 5000)
    assert only_one(chans_in(l2, l1, silv))['to_us_msat'] == before[silv]
    ks = only_one([i for i in l2.rpc.listinvoices()['invoices']
                   if i['label'].startswith('keysend-')])
    assert ks['status'] == 'paid' and ks['asset'] == gold

    # Two hops in SILV.
    res = l1.rpc.call('keysend', {'destination': l3.info['id'], 'amount_msat': 7000,
                                  'asset': silv})
    assert res['status'] == 'complete'
    ks = only_one([i for i in l3.rpc.listinvoices()['invoices']
                   if i['label'].startswith('keysend-')])
    assert ks['asset'] == silv

    # GOLD to l3 would need a GOLD hop into SILV: no such route, and no
    # HTLC leaves.
    sendpays = len(l1.rpc.listsendpays()['payments'])
    with pytest.raises(RpcError):
        l1.rpc.call('keysend', {'destination': l3.info['id'], 'amount_msat': 7000,
                                'asset': gold})
    assert len(l1.rpc.listsendpays()['payments']) == sendpays
    for n in (l1, l2, l3):
        for c in n.rpc.listpeerchannels()['channels']:
            assert c['htlcs'] == [], c
    assert l2.rpc.listforwards(status='failed')['forwards'] == []
