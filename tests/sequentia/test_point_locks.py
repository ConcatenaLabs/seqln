"""Point-locked HTLCs (`option_seq_point_locks`, common/point_lock.h).

On a taproot-covenant channel an HTLC can be locked to a point L rather than
to a hash: its SUCCESS leaf takes the scalar t with t*G == L.  A payer locks
the first HTLC to L0 = T + c*G, T being the payment point in the payee's
invoice; every hop is told a tweak in its onion and forwards to its own point,
so no two hops see the same lock, and the payee opens its HTLC with its
invoice preimage plus the tweak it was told.  A payment through any node that
does not take point locks, or to a payee whose invoice has no point, stays
hash-locked under one hash end to end.
Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from pyln.testing.utils import TIMEOUT
from utils import TEST_NETWORK, only_one, wait_for

import hashlib
import json
import os
import pytest
import test_taproot_covenant as tc

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
POINT = {**tc.TCOV, **tc.SHORT, 'point-locks': None}
NOPOINT = {**tc.TCOV, **tc.SHORT}
POINT_BIT = 174


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def x_of(point_hex):
    return point_hex[2:]


def connect_channel(bitcoind, a, b, asset, atoms):
    """a opens an announced channel of `atoms` to b."""
    a.rpc.connect(b.info['id'], 'localhost', b.port)
    res = a.rpc.call('fundchannel', {'id': b.info['id'], 'amount': atoms,
                                     'asset': asset, 'announce': True})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for x, y in ((a, b), (b, a)):
        wait_for(lambda: only_one(x.rpc.listpeerchannels(y.info['id'])['channels'])['state']
                 == 'CHANNELD_NORMAL')
    return only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])


def announce(bitcoind, nodes, nchannels):
    """Bury the funding transactions and wait until every node sees every
    channel, both directions, and every node's features."""
    bitcoind.generate_block(6)
    for n in nodes:
        wait_for(lambda: len(n.rpc.listchannels()['channels']) == 2 * nchannels)
        wait_for(lambda: len([x for x in n.rpc.listnodes()['nodes'] if 'features' in x])
                 == len(nodes))


def htlc_of(node, peer):
    return only_one(only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])['htlcs'])


def unhold(node):
    open(os.path.join(node.daemon.lightning_dir, TEST_NETWORK, 'unhold'), 'w').close()


def gold_market(bitcoind):
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    return gold


def test_point_locks_two_hops_and_a_hash_lock_beside(node_factory, bitcoind, executor):
    """l1 pays l3 through l2, all three taking point locks: each HTLC is
    locked to its own point, none is the invoice's point or hash, and l1 ends
    with the invoice's preimage.  l2 restarts with both HTLCs in flight and
    still settles them.  Beside it l1 pays l4, which takes no point locks,
    through the same l2: l4's invoice has no point and the payment is
    hash-locked under the invoice's hash on both hops."""
    gold = gold_market(bitcoind)
    # After a restart lightningd has no onion payload for an incoming HTLC
    # it already forwarded, so it cannot count that forward's fee (as for
    # a hash-locked one): l2 logs it as broken.
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=[
        {**POINT, 'may_reconnect': True},
        {**POINT, 'may_reconnect': True,
         'broken_log': 'Unable to calculate fees collected'},
        {**POINT, 'plugin': tc.HOLD, 'may_reconnect': True},
        {**NOPOINT, 'plugin': tc.HOLD, 'may_reconnect': True}])
    tc.fund_node(bitcoind, l1, gold, 10 * PAR)
    tc.fund_node(bitcoind, l2, gold, 10 * PAR)
    connect_channel(bitcoind, l1, l2, gold, 2 * PAR)
    connect_channel(bitcoind, l2, l3, gold, 2 * PAR)
    connect_channel(bitcoind, l2, l4, gold, 2 * PAR)
    announce(bitcoind, [l1, l2, l3, l4], 3)
    for n in (l1, l2, l3):
        assert POINT_BIT + 1 in [i for i in range(512)
                                 if int(n.rpc.getinfo()['our_features']['init'], 16) >> i & 1]

    # --- point-locked, two hops
    inv = l3.rpc.call('invoice', {'amount_msat': 1_000_000_000, 'label': 'pt',
                                  'description': 'point', 'asset': gold})
    dec = l1.rpc.decode(inv['bolt11'])
    T, H = dec['payment_point'], dec['payment_hash']
    print("invoice: payment_point", T, "payment_hash", H)
    fut = executor.submit(l1.rpc.pay, inv['bolt11'])
    l3.daemon.wait_for_log('Calling invoice_payment hook')
    a = htlc_of(l1, l2)
    b_in, b_out = htlc_of(l2, l1), htlc_of(l2, l3)
    c = htlc_of(l3, l2)
    locks = {'l1 out': a['lock_point'], 'l2 in': b_in['lock_point'],
             'l2 out': b_out['lock_point'], 'l3 in': c['lock_point']}
    hashes = {'l1 out': a['payment_hash'], 'l2 in': b_in['payment_hash'],
              'l2 out': b_out['payment_hash'], 'l3 in': c['payment_hash']}
    print("locks:", json.dumps(locks, indent=1))
    print("payment hashes:", json.dumps(hashes, indent=1))
    assert locks['l1 out'] == locks['l2 in'] and locks['l2 out'] == locks['l3 in']
    assert locks['l2 in'] != locks['l2 out']
    for k in locks:
        assert locks[k] != T
        assert hashes[k] == x_of(locks[k])
        assert hashes[k] != H

    # l2 restarts with both HTLCs in flight: the locks and its tweak are
    # in its database.
    l2.restart()
    for x, y in ((l1, l2), (l2, l1), (l2, l3), (l3, l2)):
        wait_for(lambda: only_one(x.rpc.listpeerchannels(y.info['id'])['channels'])['peer_connected'])
    assert htlc_of(l2, l1)['lock_point'] == locks['l2 in']
    assert htlc_of(l2, l3)['lock_point'] == locks['l2 out']

    unhold(l3)
    res = fut.result(TIMEOUT)
    print("pay:", json.dumps({k: res[k] for k in ('status', 'payment_hash', 'payment_preimage')}))
    assert res['status'] == 'complete'
    assert res['payment_hash'] == H
    assert sha256(bytes.fromhex(res['payment_preimage'])) == H
    assert only_one(l3.rpc.listinvoices('pt')['invoices'])['status'] == 'paid'
    assert only_one(l3.rpc.listinvoices('pt')['invoices'])['payment_preimage'] == res['payment_preimage']
    fwd = only_one(l2.rpc.listforwards()['forwards'])
    assert fwd['status'] == 'settled'

    # --- hash-locked beside it: l4 takes no point locks
    inv4 = l4.rpc.call('invoice', {'amount_msat': 1_000_000_000, 'label': 'h',
                                   'description': 'hash', 'asset': gold})
    dec4 = l1.rpc.decode(inv4['bolt11'])
    assert 'payment_point' not in dec4
    fut = executor.submit(l1.rpc.pay, inv4['bolt11'])
    l4.daemon.wait_for_log('Calling invoice_payment hook')
    b_in, b_out = htlc_of(l2, l1), htlc_of(l2, l4)
    print("hash-locked: l2 in", b_in['payment_hash'], "l2 out", b_out['payment_hash'])
    assert 'lock_point' not in b_in and 'lock_point' not in b_out
    assert b_in['payment_hash'] == b_out['payment_hash'] == dec4['payment_hash']
    unhold(l4)
    res = fut.result(TIMEOUT)
    assert res['status'] == 'complete'
    assert sha256(bytes.fromhex(res['payment_preimage'])) == dec4['payment_hash']


def test_point_lock_falls_back_through_a_hop_without(node_factory, bitcoind, executor):
    """l3's invoice has a point, but the only route to it is through l5,
    which takes no point locks: l1 pays it hash-locked, under the invoice's
    hash on both hops."""
    gold = gold_market(bitcoind)
    l1, l5, l3 = node_factory.get_nodes(3, opts=[POINT, NOPOINT,
                                                 {**POINT, 'plugin': tc.HOLD}])
    tc.fund_node(bitcoind, l1, gold, 10 * PAR)
    tc.fund_node(bitcoind, l5, gold, 10 * PAR)
    connect_channel(bitcoind, l1, l5, gold, 2 * PAR)
    connect_channel(bitcoind, l5, l3, gold, 2 * PAR)
    announce(bitcoind, [l1, l5, l3], 2)
    inv = l3.rpc.call('invoice', {'amount_msat': 500_000_000, 'label': 'fb',
                                  'description': 'fallback', 'asset': gold})
    dec = l1.rpc.decode(inv['bolt11'])
    assert 'payment_point' in dec
    fut = executor.submit(l1.rpc.pay, inv['bolt11'])
    l3.daemon.wait_for_log('Calling invoice_payment hook')
    b_in, b_out = htlc_of(l5, l1), htlc_of(l5, l3)
    assert 'lock_point' not in b_in and 'lock_point' not in b_out
    assert b_in['payment_hash'] == b_out['payment_hash'] == dec['payment_hash']
    unhold(l3)
    res = fut.result(TIMEOUT)
    assert res['status'] == 'complete'
    assert sha256(bytes.fromhex(res['payment_preimage'])) == dec['payment_hash']
    l1.daemon.wait_for_log('Paying by hash lock, not point lock: no route through nodes'
                           ' that all take point locks')


def test_point_lock_claimed_on_chain(node_factory, bitcoind, executor):
    """l3 force-closes holding the point-locked HTLC l2 forwarded to it.
    Released, l3 claims it on chain with its SUCCESS leaf, which takes the
    scalar of the HTLC's point (and by covenant pays l3's delayed output);
    l2 reads the scalar from that witness, takes its tweak off, and settles
    l1's HTLC with it off chain: l1's payment completes with the invoice's
    preimage."""
    gold = gold_market(bitcoind)
    l1, l2, l3 = node_factory.get_nodes(3, opts=[
        POINT, POINT, {**POINT, 'plugin': tc.HOLD, 'may_fail': True}])
    tc.fund_node(bitcoind, l1, gold, 10 * PAR)
    tc.fund_node(bitcoind, l2, gold, 10 * PAR)
    tc.fund_node(bitcoind, l3, gold, 5 * PAR)
    connect_channel(bitcoind, l1, l2, gold, 2 * PAR)
    chan23 = connect_channel(bitcoind, l2, l3, gold, 2 * PAR)
    announce(bitcoind, [l1, l2, l3], 2)

    msat = 3_000_000_000
    inv = l3.rpc.call('invoice', {'amount_msat': msat, 'label': 'oc',
                                  'description': 'onchain', 'asset': gold})
    dec = l1.rpc.decode(inv['bolt11'])
    fut = executor.submit(l1.rpc.pay, inv['bolt11'])
    l3.daemon.wait_for_log('Calling invoice_payment hook')
    lock = htlc_of(l3, l2)['lock_point']

    commitment = only_one(l3.rpc.close(chan23['short_channel_id'], unilateraltimeout=1)['txids'])
    bitcoind.generate_block(1, wait_for_mempool=commitment)
    txd = bitcoind.rpc.getrawtransaction(commitment, 1)
    htlc_out = only_one([o['n'] for o in txd['vout']
                         if o['scriptPubKey']['type'] == 'witness_v1_taproot'
                         and int(Decimal(o['value']) * PAR) == msat // 1000])
    unhold(l3)
    tc.wait_spender(bitcoind, commitment, htlc_out)
    claim, i = tc.confirmed_spender(bitcoind, commitment, htlc_out)
    print("point success claim:", json.dumps({k: claim[k] for k in ('txid', 'vsize', 'weight')}))
    assert i == 0
    wit = claim['vin'][0]['txinwitness']
    # <sig> <scalar> <leaf> <control block>; the leaf opens with the point.
    assert len(wit) == 4 and len(wit[1]) == 64
    assert lock in wit[2]
    print("leaf bytes:", len(wit[2]) // 2)
    out0 = claim['vout'][0]
    assert out0['scriptPubKey']['type'] == 'witness_v1_taproot'
    assert int(Decimal(out0['value']) * PAR) == msat // 1000

    res = fut.result(TIMEOUT)
    assert res['status'] == 'complete'
    assert sha256(bytes.fromhex(res['payment_preimage'])) == dec['payment_hash']
    l2.daemon.wait_for_log('gave us scalar')
