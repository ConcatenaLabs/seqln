"""Channels of several assets (`option_seq_symmetric_lanes`, common/sym_lanes.h).

A symmetric channel (test_symmetric.py) holding a lane per asset: lane 0 is
the channel's own funding output, every other lane another output of the
same funding transaction, to the same 2-of-2 script, in its own asset.  An
HTLC belongs to one lane, and settles in its asset.  Every lane's state
output is the same program, whose settlement fixes every lane's outputs at
once, so one update signature per side covers every lane: a swap between
two lanes is one update, applied whole or not at all.
Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, wait_for

import os
import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
SYM_BIT = 178
LANES_BIT = 184
DELAY = 6
LANES = {'symmetric-channels': None, 'symmetric-delay': DELAY,
         'cltv-final': 40, 'cltv-delta': 40,
         'max-dust-htlc-exposure-msat': 10**12, 'may_reconnect': True}
GOLD_CAP = 40_000_000
SILV_CAP = 30_000_000
DEALER = os.path.join(os.path.dirname(__file__), '..', 'plugins',
                      'sym_swap_dealer.py')


def fund_node(bitcoind, node, asset, atoms):
    addr = node.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send(addr, atoms, asset)
    bitcoind.generate_block(1, wait_for_mempool=txid)
    wait_for(lambda: any(o['txid'] == txid and o['status'] == 'confirmed'
                         for o in node.rpc.listfunds()['outputs']))


def chan(node, peer):
    return only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])


def lanes(node, peer):
    """Our balance in each asset of the channel, msat, by asset."""
    return {lane['asset']: int(lane['to_us_msat'])
            for lane in chan(node, peer)['seq_lanes']}


def pay(src, dst, msat, asset):
    inv = dst.rpc.call('invoice', {'amount_msat': msat, 'label': 'l%d' % pay.n,
                                   'description': 'lanes', 'asset': asset})
    pay.n += 1
    return src.rpc.call('pay', {'bolt11': inv['bolt11']})


pay.n = 0


def lanes_pair(node_factory, bitcoind, opts=None, more=None):
    """l1 opens a channel holding GOLD (its own) and SILV to l2, whose
    dealer plugin takes swaps at one for one.  Every node accepts both for
    fees; SILV is worth two reference atoms an atom.  @more: further lanes,
    (asset, amount) each, funded by l1."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR,
                            silv: 2 * PAR})
    opts = opts or [{}, {}]
    l1, l2 = node_factory.get_nodes(2, opts=[
        dict(LANES, **opts[0]),
        dict(LANES, plugin=DEALER, **opts[1])])
    fund_node(bitcoind, l1, gold, PAR)
    fund_node(bitcoind, l1, silv, PAR)
    fund_node(bitcoind, l2, silv, PAR)
    for asset, amount in more or []:
        fund_node(bitcoind, l1, asset, 2 * amount)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.call('fundchannel', {
        'id': l2.info['id'], 'amount': GOLD_CAP, 'asset': gold,
        'lanes': [{'asset': silv, 'amount': SILV_CAP}]
        + [{'asset': a, 'amount': n} for a, n in more or []]})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    wait_for(lambda: chan(l1, l2)['state'] == 'CHANNELD_NORMAL')
    wait_for(lambda: chan(l2, l1)['state'] == 'CHANNELD_NORMAL')
    return l1, l2, gold, silv, res['txid']


def test_lanes_payments_and_swap(node_factory, bitcoind):
    """A channel holding two assets carries a payment in each, and swaps
    one for the other as one update."""
    l1, l2, gold, silv, ftxid = lanes_pair(node_factory, bitcoind)

    # One funding transaction, two outputs to the same 2-of-2, one per
    # asset.
    c = chan(l1, l2)
    assert LANES_BIT in c['channel_type']['bits']
    assert SYM_BIT in c['channel_type']['bits']
    ftx = bitcoind.rpc.getrawtransaction(ftxid, 1)
    outs = [o for o in ftx['vout'] if o['scriptPubKey']['type'] != 'fee'
            and o['scriptPubKey']['hex'] == ftx['vout'][c['funding_outnum']]['scriptPubKey']['hex']]
    assert sorted(o['asset'] for o in outs) == sorted([gold, silv])
    assert lanes(l1, l2) == {gold: GOLD_CAP * 1000, silv: SILV_CAP * 1000}
    assert lanes(l2, l1) == {gold: 0, silv: 0}

    # A payment in each asset, each carried by its own lane.
    pay(l1, l2, 5_000_000_000, gold)
    pay(l1, l2, 7_000_000_000, silv)
    wait_for(lambda: lanes(l2, l1) == {gold: 5_000_000_000,
                                       silv: 7_000_000_000})
    # And back, in SILV.
    pay(l2, l1, 1_000_000_000, silv)
    wait_for(lambda: lanes(l2, l1) == {gold: 5_000_000_000,
                                       silv: 6_000_000_000})
    l1_before = lanes(l1, l2)

    # l1 gives 2 GOLD-millions for 3 SILV-millions: l2's dealer takes it.
    res = l1.rpc.call('symswap', {'id': c['channel_id'],
                                  'give_asset': gold, 'give_msat': 2_000_000_000,
                                  'take_asset': silv, 'take_msat': 1_500_000_000})
    assert res['id']
    after = lanes(l1, l2)
    assert after == {gold: l1_before[gold] - 2_000_000_000,
                     silv: l1_before[silv] + 1_500_000_000}
    wait_for(lambda: lanes(l2, l1) == {gold: 7_000_000_000,
                                       silv: 4_500_000_000})
    l1.daemon.wait_for_log('Swap .* done: they gave')
    l2.daemon.wait_for_log('Swap .* done: we gave')

    # A swap the dealer does not like is refused, and nothing moves.
    with pytest.raises(RpcError, match='refused'):
        l1.rpc.call('symswap', {'id': c['channel_id'],
                                'give_asset': gold, 'give_msat': 1_000_000,
                                'take_asset': silv, 'take_msat': 5_000_000})
    # l1 has no dealer: it refuses every swap.
    with pytest.raises(RpcError, match='not taking swaps'):
        l2.rpc.call('symswap', {'id': c['channel_id'],
                                'give_asset': gold, 'give_msat': 1_000_000,
                                'take_asset': silv, 'take_msat': 1_000_000})
    assert lanes(l1, l2) == after

    # A swap that one side cannot pay is refused before anything is sent.
    with pytest.raises(RpcError, match='cannot give'):
        l1.rpc.call('symswap', {'id': c['channel_id'],
                                'give_asset': silv, 'give_msat': 1_000_000,
                                'take_asset': gold, 'take_msat': 10**12})

    # Restarts keep every lane's balance.
    l1.restart()
    l2.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    wait_for(lambda: chan(l1, l2)['peer_connected'])
    assert lanes(l1, l2) == after
    pay(l1, l2, 1_000_000_000, silv)
    wait_for(lambda: lanes(l2, l1)[silv] == 5_500_000_000)


def atoms(v):
    from decimal import Decimal
    return int(Decimal(v) * PAR)


def update_n(tx, i):
    """The state number an update's witness published (8 bytes LE)."""
    wit = tx['vin'][i]['txinwitness']
    assert len(wit) == 6, wit
    return int.from_bytes(bytes.fromhex(wit[2]), 'little', signed=True)


def mined_spender(bitcoind, txid, n, max_blocks=DELAY + 15):
    """The transaction a block holds spending txid:n, mining until one
    does, and the input that spends it."""
    import time
    for _ in range(max_blocks):
        h = bitcoind.rpc.getblockcount()
        for height in range(max(0, h - 60), h + 1):
            for t in bitcoind.rpc.getblock(bitcoind.rpc.getblockhash(height))['tx'][1:]:
                d = bitcoind.rpc.getrawtransaction(t, 1)
                for i, vin in enumerate(d['vin']):
                    if vin.get('txid') == txid and vin.get('vout') == n:
                        return d, i
        bitcoind.generate_block(1)
        time.sleep(1)
    raise ValueError('no block spends {}:{}'.format(txid, n))


def lane_outnums(bitcoind, ftxid, c, silv):
    ftx = bitcoind.rpc.getrawtransaction(ftxid, 1)
    spk = ftx['vout'][c['funding_outnum']]['scriptPubKey']['hex']
    silv_n = only_one([i for i, o in enumerate(ftx['vout'])
                       if o['scriptPubKey']['hex'] == spk
                       and o.get('asset') == silv])
    return c['funding_outnum'], silv_n


def follow_lane(bitcoind, txid, n):
    """From a lane's funding output: its kickoff, then every update over
    it, to the transaction that settles it (two witness items)."""
    spends = []
    while True:
        d, i = mined_spender(bitcoind, txid, n)
        spends.append((d, i))
        if len(d['vin'][i]['txinwitness']) == 2:
            return spends
        txid, n = d['txid'], i


def test_lanes_unilateral_close(node_factory, bitcoind):
    """Closing a channel of two assets kicks off each lane, puts the latest
    state over each, and settles both lanes in one transaction, every
    asset's outputs balanced against its own lane."""
    l1, l2, gold, silv, ftxid = lanes_pair(node_factory, bitcoind)
    c = chan(l1, l2)
    pay(l1, l2, 5_000_000_000, gold)
    pay(l1, l2, 7_000_000_000, silv)
    l1.rpc.call('symswap', {'id': c['channel_id'],
                            'give_asset': gold, 'give_msat': 2_000_000_000,
                            'take_asset': silv, 'take_msat': 1_000_000_000})
    wait_for(lambda: lanes(l2, l1) == {gold: 7_000_000_000,
                                       silv: 6_000_000_000})
    gold_n, silv_n = lane_outnums(bitcoind, ftxid, c, silv)

    # With the peer there, close would be mutual (test_lanes_mutual_close).
    l1.rpc.dev_fail(l2.info['id'])
    lane0 = follow_lane(bitcoind, ftxid, gold_n)
    lane1 = follow_lane(bitcoind, ftxid, silv_n)
    settle0, i0 = lane0[-1]
    settle1, i1 = lane1[-1]
    # One settle for both lanes, its two inputs with the same witness.
    assert settle0['txid'] == settle1['txid']
    assert settle0['vin'][i0]['txinwitness'] == settle1['vin'][i1]['txinwitness']
    # The settlement is outputs 0 .. 3, lane 0's then lane 1's; the fee
    # coin's change and the fee follow.
    outs = {}
    for o in settle0['vout'][:4]:
        outs.setdefault(o['asset'], []).append(atoms(o['value']))
    assert sorted(outs[gold]) == sorted([GOLD_CAP - 7_000_000, 7_000_000])
    assert sorted(outs[silv]) == sorted([SILV_CAP - 6_000_000, 6_000_000])
    print("settle of both lanes:",
          {x: settle0[x] for x in ('txid', 'vsize')})
    # Each update over a lane is the latest state.
    assert update_n(*lane0[-2]) == update_n(*lane1[-2])
    l1.daemon.wait_for_log('Settling state .* over its 2 lanes')
    for node, g, s in ((l2, 7_000_000_000, 6_000_000_000),
                       (l1, (GOLD_CAP - 7_000_000) * 1000,
                        (SILV_CAP - 6_000_000) * 1000)):
        wait_for(lambda: any(o['txid'] == settle0['txid'] and o['asset'] == gold
                             and o['amount_msat'] == g
                             for o in node.rpc.listfunds()['outputs']))
        wait_for(lambda: any(o['txid'] == settle0['txid'] and o['asset'] == silv
                             and o['amount_msat'] == s
                             for o in node.rpc.listfunds()['outputs']))


def test_lanes_keyless_watcher(node_factory, bitcoind, directory):
    """l1 keeps an old state, pays l2 more in both assets, and closes with
    the old one while l2 is offline: the stale state over each lane's KO.
    speculad, holding no key and only l2's store, replaces it on each lane
    with the latest, in that lane's asset, a fee coin in SILV from its own
    wallet.  Back online, l2 settles both lanes at once."""
    from test_watchtower import Speculad, fee_wallet
    l1, l2, gold, silv, ftxid = lanes_pair(node_factory, bitcoind,
                                           opts=[{}, {'watchtower-store': 'on'}])
    c = chan(l1, l2)
    pay(l1, l2, 5_000_000_000, gold)
    pay(l1, l2, 4_000_000_000, silv)
    stale = l1.rpc.call('dev-sym-snapshot', {'id': l2.info['id']})['state']
    pay(l1, l2, 6_000_000_000, gold)
    pay(l1, l2, 3_000_000_000, silv)
    wait_for(lambda: lanes(l2, l1) == {gold: 11_000_000_000,
                                       silv: 7_000_000_000})
    gold_n, silv_n = lane_outnums(bitcoind, ftxid, c, silv)

    l2.stop()
    wallet = fee_wallet(bitcoind, silv, [(silv, 1)])
    tower = Speculad(l2, bitcoind, wallet, directory)
    l1.rpc.close(l2.info['id'], unilateraltimeout=1)
    stale_over = []
    for n in (gold_n, silv_n):
        ko, _ = mined_spender(bitcoind, ftxid, n)
        first, j = mined_spender(bitcoind, ko['txid'], 0)
        assert update_n(first, j) == stale
        stale_over.append((first, j))
    tower.start()
    try:
        latest = []
        for first, j in stale_over:
            d, k = mined_spender(bitcoind, first['txid'], j)
            assert update_n(d, k) > stale
            assert only_one([o for o in d['vout']
                             if o['scriptPubKey']['type'] == 'fee'])['asset'] == silv
            latest.append((d, k))
        assert update_n(*latest[0]) == update_n(*latest[1])
        # Each replacement keeps its lane's asset.
        assert latest[0][0]['vout'][latest[0][1]]['asset'] == gold
        assert latest[1][0]['vout'][latest[1][1]]['asset'] == silv
        print("the tower replaced state", stale, "on both lanes by state",
              update_n(*latest[0]))
    finally:
        tower.stop()
        print(tower.output())
    assert 'replacing it by state {}'.format(update_n(*latest[0])) in tower.output()

    l2.start()
    settle, _ = mined_spender(bitcoind, latest[0][0]['txid'], latest[0][1])
    assert any(v['txid'] == latest[1][0]['txid'] for v in settle['vin'])
    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 11_000_000_000
                         for o in l2.rpc.listfunds()['outputs']))
    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == silv
                         and o['amount_msat'] == 7_000_000_000
                         for o in l2.rpc.listfunds()['outputs']))


def test_lanes_mutual_close(node_factory, bitcoind):
    """A channel of three assets closes cooperatively in one transaction:
    it spends every lane's funding output and pays each side its balance in
    each asset, the fee in the channel's own asset only.  No lane is kicked
    off."""
    third = bitcoind.POLICY_ASSET
    THIRD_CAP = 20_000_000
    l1, l2, gold, silv, ftxid = lanes_pair(node_factory, bitcoind,
                                           more=[(third, THIRD_CAP)])
    c = chan(l1, l2)
    pay(l1, l2, 5_000_000_000, gold)
    pay(l1, l2, 7_000_000_000, silv)
    pay(l1, l2, 3_000_000_000, third)
    l1.rpc.call('symswap', {'id': c['channel_id'],
                            'give_asset': gold, 'give_msat': 2_000_000_000,
                            'take_asset': silv, 'take_msat': 1_000_000_000})
    want = {gold: 7_000_000_000, silv: 6_000_000_000, third: 3_000_000_000}
    wait_for(lambda: lanes(l2, l1) == want)
    ftx = bitcoind.rpc.getrawtransaction(ftxid, 1)
    spk = ftx['vout'][c['funding_outnum']]['scriptPubKey']['hex']
    fundings = sorted((ftxid, i) for i, o in enumerate(ftx['vout'])
                      if o['scriptPubKey']['hex'] == spk)
    assert len(fundings) == 3

    res = l1.rpc.close(l2.info['id'])
    assert res['type'] == 'mutual'
    txid = only_one(res['txids'])
    bitcoind.generate_block(1, wait_for_mempool=txid)
    dec = bitcoind.rpc.getrawtransaction(txid, 1)
    # Every lane's funding output, and nothing else.
    assert sorted((v['txid'], v['vout']) for v in dec['vin']) == fundings
    fee = only_one([o for o in dec['vout'] if o['scriptPubKey']['type'] == 'fee'])
    assert fee['asset'] == gold
    paid = {}
    for o in dec['vout']:
        if o['scriptPubKey']['type'] != 'fee':
            paid.setdefault(o['asset'], []).append(atoms(o['value']))
    print("mutual close of three lanes:", {'txid': txid, 'vsize': dec['vsize'],
                                           'fee': atoms(fee['value'])})
    # Lane 0 pays the fee from the opener's share; the other lanes whole.
    assert sorted(paid[silv]) == sorted([SILV_CAP - 6_000_000, 6_000_000])
    assert sorted(paid[third]) == sorted([THIRD_CAP - 3_000_000, 3_000_000])
    assert 7_000_000 in paid[gold]
    assert sum(paid[gold]) + atoms(fee['value']) == GOLD_CAP
    for node, amounts in ((l2, {gold: 7_000_000, silv: 6_000_000,
                                third: 3_000_000}),
                          (l1, {silv: SILV_CAP - 6_000_000,
                                third: THIRD_CAP - 3_000_000})):
        for asset, amount in amounts.items():
            wait_for(lambda: any(o['txid'] == txid and o['asset'] == asset
                                 and o['amount_msat'] == amount * 1000
                                 for o in node.rpc.listfunds()['outputs']))
    assert not l1.daemon.is_in_log('Broadcasting the kickoff')
    assert not l2.daemon.is_in_log('Broadcasting the kickoff')
    bitcoind.generate_block(100)
    wait_for(lambda: l1.rpc.listpeerchannels()['channels'] == [])


def keyless_lanes_pair(node_factory, bitcoind, directory):
    """l2, a hub with the dealer, opens a channel of GOLD and SILV to l1, a
    keyless node whose keys are on a device in enforce mode, and pays it in
    each asset."""
    import test_keyless_close as kc
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR,
                            silv: 2 * PAR})
    # LANES holds may_reconnect, a harness setting, beside the options.
    opts = {k: v for k, v in LANES.items() if k != 'may_reconnect'}
    device, l1 = kc.keyless_node(node_factory, directory, broken_log='.*',
                                 options=opts, may_reconnect=True)
    l2 = node_factory.get_node(options=dict(opts, plugin=DEALER),
                               may_reconnect=True)
    fund_node(bitcoind, l2, gold, PAR)
    fund_node(bitcoind, l2, silv, PAR)
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    res = l2.rpc.call('fundchannel', {
        'id': l1.info['id'], 'amount': GOLD_CAP, 'asset': gold,
        'lanes': [{'asset': silv, 'amount': SILV_CAP}]})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    wait_for(lambda: chan(l1, l2)['state'] == 'CHANNELD_NORMAL')
    wait_for(lambda: chan(l2, l1)['state'] == 'CHANNELD_NORMAL')
    assert LANES_BIT in chan(l1, l2)['channel_type']['bits']
    pay(l2, l1, 9_000_000_000, gold)
    pay(l2, l1, 8_000_000_000, silv)
    wait_for(lambda: lanes(l1, l2) == {gold: 9_000_000_000, silv: 8_000_000_000})
    return device, l1, l2, gold, silv


def misstate_lane(node, lane, msat):
    """Move `msat` of the node's balance in further lane `lane` to its peer in
    its own database (channel_sym_lanes: a u16 count, then per lane its
    asset (33), output (4), value (8), our balance (8, big-endian) and two
    signatures), as a host lying to its device would."""
    import sqlite3
    path = os.path.join(node.daemon.lightning_dir, TEST_NETWORK, 'lightningd.sqlite3')
    db = sqlite3.connect(path)
    try:
        (blob,) = db.execute("SELECT lanes FROM channel_sym_lanes").fetchone()
        at = 2 + (lane - 1) * (45 + 8 + 128) + 45
        ours = int.from_bytes(blob[at:at + 8], 'big')
        blob = blob[:at] + (ours - msat).to_bytes(8, 'big') + blob[at + 8:]
        db.execute("UPDATE channel_sym_lanes SET lanes = ?", (blob,))
        db.commit()
    finally:
        db.close()
    return ours


@pytest.mark.skipif(not os.path.exists(os.environ.get('SEQLN_SIGNER', os.path.join(
    os.path.dirname(__file__), '..', '..', 'contrib', 'seqln-signer', 'target', 'release',
    'seqln-signer'))), reason='needs the seqln-signer binary')
def test_lanes_keyless_device(node_factory, bitcoind, directory):
    """A keyless node holds a channel of two assets.  Its device signs each
    lane's kickoff, then each state only after holding every lane's
    settlement to the channel and what it leaves this side in each lane to
    the payments and swaps it approved; it approves the swap the node asks
    for, and signs the mutual close, which pays the node its balance in each
    asset.  It refuses nothing."""
    device, l1, l2, gold, silv = keyless_lanes_pair(node_factory, bitcoind, directory)
    try:
        pay(l1, l2, 1_000_000_000, silv)
        res = l1.rpc.call('symswap', {'id': chan(l1, l2)['channel_id'],
                                      'give_asset': silv, 'give_msat': 2_000_000_000,
                                      'take_asset': gold, 'take_msat': 1_500_000_000})
        assert res['id']
        want = {gold: 10_500_000_000, silv: 5_000_000_000}
        wait_for(lambda: lanes(l1, l2) == want)
        assert 'POLICY REJECT' not in device.output()

        res = l1.rpc.close(l2.info['id'])
        assert res['type'] == 'mutual'
        txid = only_one(res['txids'])
        bitcoind.generate_block(1, wait_for_mempool=txid)
        for asset, msat in want.items():
            wait_for(lambda: any(o['txid'] == txid and o['asset'] == asset
                                 and o['amount_msat'] == msat
                                 for o in l1.rpc.listfunds()['outputs']))
        out = device.output()
        assert 'POLICY REJECT' not in out, out
        print("keyless lanes: payments, a swap and a mutual close, the device refusing nothing")
    finally:
        # The node first: a device that goes before it leaves the proxy
        # waiting for another.
        from test_keyless_close import answers
        if answers(l1, timeout=2):
            l1.stop()
        device.stop()


@pytest.mark.skipif(not os.path.exists(os.environ.get('SEQLN_SIGNER', os.path.join(
    os.path.dirname(__file__), '..', '..', 'contrib', 'seqln-signer', 'target', 'release',
    'seqln-signer'))), reason='needs the seqln-signer binary')
def test_lanes_keyless_misstated_lane_refused(node_factory, bitcoind, executor, directory):
    """The host takes 10,000 atoms of SILV off the keyless node's balance in
    its database, which the device was never asked to approve.  The next
    state it asks the device to sign, for an approved payment, is refused:
    it leaves this wallet less SILV than the device tracks."""
    device, l1, l2, gold, silv = keyless_lanes_pair(node_factory, bitcoind, directory)
    try:
        l1.stop()
        before = misstate_lane(l1, 1, 10_000_000)
        print("host database: our SILV {} msat, now {} msat".format(before, before - 10_000_000))
        l1.start()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        wait_for(lambda: chan(l1, l2)['state'] == 'CHANNELD_NORMAL'
                 and chan(l1, l2)['peer_connected'])
        inv = l2.rpc.call('invoice', {'amount_msat': 1_000_000_000, 'label': 'after',
                                      'description': 'after', 'asset': silv})['bolt11']
        executor.submit(l1.rpc.pay, inv)
        wait_for(lambda: 'POLICY REJECT' in device.output()
                 or l1.daemon.is_in_log('Bad commit_sig signature'))
        assert not l1.daemon.is_in_log('Bad commit_sig signature')
        refusal = only_one([line for line in device.output().splitlines()
                            if 'POLICY REJECT' in line][:1])
        print("device:", refusal)
        assert 'SIGN_SYM_LANES_STATE refused: lane 1' in refusal
        assert 'it leaves this wallet' in refusal
        assert l2.rpc.listinvoices('after')['invoices'][0]['status'] == 'unpaid'
    finally:
        # The node first: a device that goes before it leaves the proxy
        # waiting for another.
        from test_keyless_close import answers
        if answers(l1, timeout=2):
            l1.stop()
        device.stop()
