"""The symmetric channel type (`option_seq_symmetric`).

An old state is replaced by a newer one, never punished.  The funding output
is the usual 2-of-2; a unilateral close is the kickoff (both funding keys
signed it at open, SIGHASH_SINGLE|SIGHASH_ANYONECANPAY), then an update into
the best state a node holds whole, then the settlement once the shared delay
has passed.  Each pays its fee from a coin attached when it is broadcast, in
any asset the node accepts.  The scripts are in common/sym_scripts.h.
Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, wait_for

import json
import os
import pytest
import time

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
SYM_BIT = 178
DELAY = 6
# A short shared delay, and HTLC lifetimes above twice it plus the slack.
SYM = {'symmetric-channels': None, 'symmetric-delay': DELAY,
       'cltv-final': 40, 'cltv-delta': 40,
       'max-dust-htlc-exposure-msat': 10**12}
HOLD = os.path.join(os.path.dirname(__file__), '..', 'plugins', 'hold_invoice.py')


def fund_node(bitcoind, node, asset, atoms):
    addr = node.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send(addr, atoms, asset)
    bitcoind.generate_block(1, wait_for_mempool=txid)
    wait_for(lambda: any(o['txid'] == txid and o['status'] == 'confirmed'
                         for o in node.rpc.listfunds()['outputs']))


def open_channel(bitcoind, l1, l2, asset, atoms, **kwargs):
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.call('fundchannel', dict({'id': l2.info['id'], 'amount': atoms,
                                           'asset': asset}, **kwargs))
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state']
                 == 'CHANNELD_NORMAL')
    return only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])


def pay(src, dst, msat, asset):
    inv = dst.rpc.call('invoice', {'amount_msat': msat, 'label': 'l%d' % pay.n,
                                   'description': 'sym', 'asset': asset})
    pay.n += 1
    return src.rpc.pay(inv['bolt11'])


pay.n = 0


def sym_pair(node_factory, bitcoind, opts=({}, {})):
    """A GOLD channel of the new type, l1 -> l2.  SILV is another asset the
    nodes accept for fees, worth two reference atoms an atom.  l1 keeps no
    GOLD outside the channel: every fee it pays on chain is in SILV."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: 2 * PAR})
    l1, l2 = node_factory.get_nodes(2, opts=[{**SYM, **opts[0]},
                                             {**SYM, **opts[1]}])
    fund_node(bitcoind, l1, gold, PAR + 50_000)
    fund_node(bitcoind, l1, silv, 5 * PAR)
    fund_node(bitcoind, l2, silv, 5 * PAR)
    chan = open_channel(bitcoind, l1, l2, gold, PAR)
    assert SYM_BIT in chan['channel_type']['bits']
    # What change the funding left in GOLD goes elsewhere.
    for o in l1.rpc.listfunds()['outputs']:
        if o.get('asset') == gold and o['status'] == 'confirmed':
            l1.rpc.call('withdraw', {'destination': bitcoind.rpc.getnewaddress(),
                                     'satoshi': 'all', 'asset': gold})
            bitcoind.generate_block(1, wait_for_mempool=1)
            break
    return l1, l2, gold, silv, chan['short_channel_id']


def spender_of(bitcoind, txid, n, txids):
    for t in txids:
        d = bitcoind.rpc.getrawtransaction(t, 1)
        for i, vin in enumerate(d['vin']):
            if vin.get('txid') == txid and vin.get('vout') == n:
                return d, i
    return None, None


def recent_txids(bitcoind, blocks=40):
    txids = list(bitcoind.rpc.getrawmempool())
    h = bitcoind.rpc.getblockcount()
    for height in range(max(0, h - blocks), h + 1):
        txids += bitcoind.rpc.getblock(bitcoind.rpc.getblockhash(height))['tx'][1:]
    return txids


def mined_spender(bitcoind, txid, n, max_blocks=DELAY + 15):
    """The transaction a block holds spending txid:n, mining until one does
    (the one first in the mempool may be replaced by a higher fee)."""
    for _ in range(max_blocks):
        h = bitcoind.rpc.getblockcount()
        txids = []
        for height in range(max(0, h - 60), h + 1):
            txids += bitcoind.rpc.getblock(bitcoind.rpc.getblockhash(height))['tx'][1:]
        d, i = spender_of(bitcoind, txid, n, txids)
        if d:
            return d, i
        bitcoind.generate_block(1)
        time.sleep(1)
    raise ValueError('no block spends {}:{}'.format(txid, n))


def funding_outpoint(node, peer):
    c = only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])
    return c['funding_txid'], c['funding_outnum']


def fee_asset_of(tx):
    return only_one([o for o in tx['vout'] if o['scriptPubKey']['type'] == 'fee'])['asset']


def update_n(tx, i):
    """The state number an update's witness published (8 bytes LE)."""
    wit = tx['vin'][i]['txinwitness']
    assert len(wit) == 6, wit
    return int.from_bytes(bytes.fromhex(wit[2]), 'little', signed=True)


def test_sym_negotiated_and_pays_both_ways(node_factory, bitcoind):
    """Both peers offer the type: it is the channel's, and payments go both
    ways.  A peer that does not offer it gets an ordinary channel, and one
    asked for it explicitly refuses."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2, l3 = node_factory.get_nodes(3, opts=[SYM, SYM, {}])
    fund_node(bitcoind, l1, gold, 10 * PAR)
    chan = open_channel(bitcoind, l1, l2, gold, PAR)
    print("channel_type:", chan['channel_type'])
    assert SYM_BIT in chan['channel_type']['bits']
    assert 'seq_symmetric/even' in chan['channel_type']['names']
    for _ in range(3):
        pay(l1, l2, 4_000_000_000, gold)
        pay(l2, l1, 1_000_000_000, gold)
    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
             ['to_us_msat'] == 9_000_000_000)

    chan = open_channel(bitcoind, l1, l3, gold, PAR)
    assert SYM_BIT not in chan['channel_type']['bits']
    with pytest.raises(RpcError):
        l1.rpc.call('fundchannel', {'id': l3.info['id'], 'amount': PAR,
                                    'asset': gold, 'channel_type': [12, SYM_BIT]})


def test_sym_unilateral_close_settles(node_factory, bitcoind):
    """l1 closes unilaterally while l2 is away: the kickoff, l1's latest
    state over KO, and after the shared delay its settlement, each with a
    fee coin in SILV (l1 holds no GOLD outside the channel).  Each side's
    balance lands in its wallet; l2, back, sees its own."""
    l1, l2, gold, silv, scid = sym_pair(node_factory, bitcoind)
    pay(l1, l2, 30_000_000_000, gold)
    pay(l2, l1, 5_000_000_000, gold)
    l2.stop()
    l1.rpc.close(scid, unilateraltimeout=1)
    ftxid, fout = funding_outpoint(l1, l2)

    kickoff, i = mined_spender(bitcoind, ftxid, fout)
    print("kickoff:", json.dumps({k: kickoff[k] for k in ('txid', 'vsize')}))
    assert fee_asset_of(kickoff) == silv
    assert kickoff['vout'][i]['asset'] == gold
    assert int(Decimal(kickoff['vout'][i]['value']) * PAR) == PAR

    update, j = mined_spender(bitcoind, kickoff['txid'], i)
    print("update:", json.dumps({k: update[k] for k in ('txid', 'vsize')}),
          "state", update_n(update, j))
    assert fee_asset_of(update) == silv
    assert update['vout'][j]['asset'] == gold

    settle, _ = mined_spender(bitcoind, update['txid'], j)
    print("settle:", json.dumps({k: settle[k] for k in ('txid', 'vsize')}))
    assert fee_asset_of(settle) == silv
    # The settle waited the shared delay after the update.
    hu = bitcoind.rpc.getrawtransaction(update['txid'], 1)['blockhash']
    hs = bitcoind.rpc.getrawtransaction(settle['txid'], 1)['blockhash']
    assert (bitcoind.rpc.getblock(hs)['height']
            - bitcoind.rpc.getblock(hu)['height']) >= DELAY
    gold_out = sorted(int(Decimal(o['value']) * PAR) for o in settle['vout']
                      if o.get('asset') == gold)
    print("settlement (GOLD atoms):", gold_out)
    assert gold_out == [25_000_000, 75_000_000]

    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 75_000_000_000
                         for o in l1.rpc.listfunds()['outputs']))
    l2.start()
    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 25_000_000_000
                         for o in l2.rpc.listfunds()['outputs']))


def test_sym_stale_state_replaced(node_factory, bitcoind):
    """l1 keeps an old state, pays l2 most of the channel, and closes with
    the old one (dev-sym-snapshot) while l2 is away, so the stale state is
    mined.  l2, back within the shared delay, replaces it with the latest
    state it holds, and the settlement pays the latest split."""
    l1, l2, gold, silv, scid = sym_pair(node_factory, bitcoind,
                                        opts=({'may_reconnect': True},
                                              {'may_reconnect': True}))
    pay(l1, l2, 10_000_000_000, gold)
    stale = l1.rpc.call('dev-sym-snapshot', {'id': l2.info['id']})['state']
    pay(l1, l2, 60_000_000_000, gold)
    ftxid, fout = funding_outpoint(l1, l2)
    l2.stop()
    l1.rpc.close(scid, unilateraltimeout=1)

    kickoff, i = mined_spender(bitcoind, ftxid, fout)
    first, j = mined_spender(bitcoind, kickoff['txid'], i)
    assert update_n(first, j) == stale
    print("stale state", stale, "mined:",
          json.dumps({x: first[x] for x in ('txid', 'vsize')}))

    l2.start()
    l2.daemon.wait_for_log('Replacing state {} by our state'.format(stale))
    latest, k = mined_spender(bitcoind, first['txid'], j)
    assert latest['vin'][k]['txinwitness'] != first['vin'][j]['txinwitness']
    n_latest = update_n(latest, k)
    assert n_latest > stale
    hf = bitcoind.rpc.getrawtransaction(first['txid'], 1)['blockhash']
    hl = bitcoind.rpc.getrawtransaction(latest['txid'], 1)['blockhash']
    print("replaced by state", n_latest, "after",
          bitcoind.rpc.getblock(hl)['height'] - bitcoind.rpc.getblock(hf)['height'],
          "blocks:", json.dumps({x: latest[x] for x in ('txid', 'vsize')}))
    assert fee_asset_of(latest) == silv
    settle, _ = mined_spender(bitcoind, latest['txid'], k)
    gold_out = sorted(int(Decimal(o['value']) * PAR) for o in settle['vout']
                      if o.get('asset') == gold)
    print("settlement (GOLD atoms):", gold_out)
    assert gold_out == [30_000_000, 70_000_000]
    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 70_000_000_000
                         for o in l2.rpc.listfunds()['outputs']))


def held_htlc(l1, l2, executor, msat, gold):
    inv = l2.rpc.call('invoice', {'amount_msat': msat, 'label': 'held%d' % msat,
                                  'description': 'held', 'asset': gold})
    fut = executor.submit(l1.rpc.pay, inv['bolt11'])
    wait_for(lambda: [h['state'] for h in only_one(
        l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs']]
        == ['SENT_ADD_ACK_REVOCATION'])
    l2.daemon.wait_for_log('Calling invoice_payment hook')
    htlc = only_one(only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'])
    return fut, htlc


def test_sym_htlc_settled_on_chain(node_factory, bitcoind, executor):
    """An HTLC in flight when l2 closes: the settlement carries it as a
    taproot output, l2 learns the preimage and claims it by its SUCCESS
    leaf."""
    l1, l2, gold, silv, scid = sym_pair(node_factory, bitcoind,
                                        opts=({'may_fail': True}, {'plugin': HOLD}))
    msat = 3_000_000_000
    fut, htlc = held_htlc(l1, l2, executor, msat, gold)
    l1.stop()
    ftxid, fout = funding_outpoint(l2, l1)
    l2.rpc.close(scid, unilateraltimeout=1)
    kickoff, i = mined_spender(bitcoind, ftxid, fout)
    update, j = mined_spender(bitcoind, kickoff['txid'], i)
    settle, _ = mined_spender(bitcoind, update['txid'], j)
    htlc_out = only_one([o['n'] for o in settle['vout']
                         if o['scriptPubKey']['type'] == 'witness_v1_taproot'
                         and int(Decimal(o['value']) * PAR) == msat // 1000])
    open(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'unhold'), 'w').close()
    claim, c = mined_spender(bitcoind, settle['txid'], htlc_out)
    print("success claim:", json.dumps({k: claim[k] for k in ('txid', 'vsize')}))
    wit = claim['vin'][c]['txinwitness']
    assert len(wit) == 4 and len(wit[1]) == 64   # <sig> <preimage> <leaf> <cb>
    wait_for(lambda: any(o['txid'] == claim['txid'] and o['asset'] == gold
                         for o in l2.rpc.listfunds()['outputs']))


def test_sym_htlc_times_out(node_factory, bitcoind, executor):
    """An HTLC l1 offered, which l2 holds and never settles: l1 closes, the
    settlement carries it, and past its CLTV l1 takes it back by its
    TIMEOUT leaf, the fee from a SILV coin."""
    l1, l2, gold, silv, scid = sym_pair(node_factory, bitcoind,
                                        opts=({}, {'plugin': HOLD, 'may_fail': True}))
    msat = 2_000_000_000
    fut, htlc = held_htlc(l1, l2, executor, msat, gold)
    l2.stop()
    ftxid, fout = funding_outpoint(l1, l2)
    l1.rpc.close(scid, unilateraltimeout=1)
    kickoff, i = mined_spender(bitcoind, ftxid, fout)
    update, j = mined_spender(bitcoind, kickoff['txid'], i)
    settle, _ = mined_spender(bitcoind, update['txid'], j)
    htlc_out = only_one([o['n'] for o in settle['vout']
                         if o['scriptPubKey']['type'] == 'witness_v1_taproot'
                         and int(Decimal(o['value']) * PAR) == msat // 1000])
    print("HTLC expires at", htlc['expiry'], "settled at",
          bitcoind.rpc.getblockcount())
    while bitcoind.rpc.getblockcount() < htlc['expiry']:
        bitcoind.generate_block(1)
    claim, c = mined_spender(bitcoind, settle['txid'], htlc_out)
    print("timeout claim:", json.dumps({k: claim[k] for k in ('txid', 'vsize')}))
    wit = claim['vin'][c]['txinwitness']
    assert len(wit) == 3                         # <sig> <leaf> <cb>
    assert claim['locktime'] >= htlc['expiry']
    wait_for(lambda: any(o['txid'] == claim['txid'] and o['asset'] == gold
                         for o in l1.rpc.listfunds()['outputs']))


def test_sym_mutual_close(node_factory, bitcoind):
    """The funding output is the usual 2-of-2, so a symmetric channel closes
    cooperatively as any other: one transaction paying each its balance."""
    l1, l2, gold, silv, scid = sym_pair(node_factory, bitcoind)
    pay(l1, l2, 20_000_000_000, gold)
    res = l1.rpc.close(scid)
    assert res['type'] == 'mutual'
    txid = only_one(res['txids'])
    bitcoind.generate_block(1, wait_for_mempool=txid)
    dec = bitcoind.rpc.getrawtransaction(txid, 1)
    gold_out = sorted(int(Decimal(o['value']) * PAR) for o in dec['vout']
                      if o.get('asset') == gold and o['scriptPubKey']['type'] != 'fee')
    print("mutual close (GOLD atoms):", gold_out)
    assert gold_out[0] == 20_000_000
    wait_for(lambda: any(o['txid'] == txid and o['asset'] == gold
                         for o in l2.rpc.listfunds()['outputs']))


def test_sym_keyless_watcher(node_factory, bitcoind, directory):
    """l1 keeps an old state, pays l2 most of the channel, and closes with
    the old one while l2 is offline.  speculad, holding no key and only l2's
    store (the latest state l2 holds whole), replaces the stale state with
    the latest, then settles it once the shared delay has passed, each with a
    fee coin in SILV from its own wallet (the channel is in GOLD).  Back
    online, l2 finds its balance in its wallet."""
    from test_watchtower import Speculad, fee_wallet
    victim = {'watchtower-store': 'on', 'may_reconnect': True}
    l1, l2, gold, silv, scid = sym_pair(node_factory, bitcoind,
                                        opts=({'may_reconnect': True}, victim))
    pay(l1, l2, 10_000_000_000, gold)
    stale = l1.rpc.call('dev-sym-snapshot', {'id': l2.info['id']})['state']
    pay(l1, l2, 60_000_000_000, gold)
    store = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'watchtower')
    assert any(os.path.exists(os.path.join(store, d, 'sym')) for d in os.listdir(store))
    ftxid, fout = funding_outpoint(l1, l2)

    l2.stop()
    wallet = fee_wallet(bitcoind, silv, [(silv, 1)])
    tower = Speculad(l2, bitcoind, wallet, directory)
    tower.start()
    try:
        l1.rpc.close(scid, unilateraltimeout=1)
        kickoff, i = mined_spender(bitcoind, ftxid, fout)
        first, j = mined_spender(bitcoind, kickoff['txid'], i)
        assert update_n(first, j) == stale
        print("stale state", stale, "mined:",
              json.dumps({x: first[x] for x in ('txid', 'vsize')}))

        latest, k = mined_spender(bitcoind, first['txid'], j)
        n_latest = update_n(latest, k)
        assert n_latest > stale
        assert fee_asset_of(latest) == silv
        print("the tower replaced it by state", n_latest,
              json.dumps({x: latest[x] for x in ('txid', 'vsize')}))

        settle, _ = mined_spender(bitcoind, latest['txid'], k)
        assert fee_asset_of(settle) == silv
        hl = bitcoind.rpc.getrawtransaction(latest['txid'], 1)['blockhash']
        hs = bitcoind.rpc.getrawtransaction(settle['txid'], 1)['blockhash']
        waited = bitcoind.rpc.getblock(hs)['height'] - bitcoind.rpc.getblock(hl)['height']
        assert waited >= DELAY
        gold_out = sorted(int(Decimal(o['value']) * PAR) for o in settle['vout']
                          if o.get('asset') == gold)
        print("the tower settled after", waited, "blocks:",
              json.dumps({x: settle[x] for x in ('txid', 'vsize')}),
              "settlement (GOLD atoms):", gold_out)
        assert gold_out == [30_000_000, 70_000_000]
    finally:
        tower.stop()
        print(tower.output())
    out = tower.output()
    assert 'replacing it by state {}'.format(n_latest) in out
    assert 'broadcast the settlement' in out

    l2.start()
    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 70_000_000_000
                         for o in l2.rpc.listfunds()['outputs']))


def test_sym_keyless_device(node_factory, bitcoind, directory):
    """A keyless node, its keys on a device in enforce mode, opens a
    symmetric channel: the device signs the kickoff once, and each state only
    after holding its settlement to the channel and to the payments it
    approved.  The node pays and is paid, then closes unilaterally while the
    hub is away: the device signs only the fee coins of the kickoff, the
    update and the settlement, which pays the node its balance.  The device
    refuses nothing."""
    from test_keyless_close import keyless_node, channel, answers
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: 2 * PAR})
    device, l1 = keyless_node(node_factory, directory, options=dict(SYM))
    try:
        l2 = node_factory.get_node(options=SYM, may_reconnect=True)
        fund_node(bitcoind, l1, gold, PAR + 50_000)
        fund_node(bitcoind, l1, silv, 5 * PAR)
        chan = open_channel(bitcoind, l1, l2, gold, PAR)
        assert SYM_BIT in chan['channel_type']['bits']
        pay(l1, l2, 30_000_000_000, gold)
        pay(l2, l1, 5_000_000_000, gold)
        wait_for(lambda: channel(l1, l2)['htlcs'] == [])
        assert 'POLICY REJECT' not in device.output()

        l2.stop()
        l1.rpc.close(chan['short_channel_id'], unilateraltimeout=1)
        kickoff, i = mined_spender(bitcoind, chan['funding_txid'], chan['funding_outnum'])
        update, j = mined_spender(bitcoind, kickoff['txid'], i)
        settle, _ = mined_spender(bitcoind, update['txid'], j)
        fees = [fee_asset_of(tx) for tx in (kickoff, update, settle)]
        assert all(a in (gold, silv) for a in fees)
        gold_out = sorted(int(Decimal(o['value']) * PAR) for o in settle['vout']
                          if o.get('asset') == gold)
        print("keyless close: kickoff {} vB, update {} vB (state {}), settle {} vB,"
              " settlement (GOLD atoms) {}, fees in {}".format(
                  kickoff['vsize'], update['vsize'], update_n(update, j), settle['vsize'],
                  gold_out, ['GOLD' if a == gold else 'SILV' for a in fees]))
        assert gold_out == [25_000_000, 75_000_000]
        wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                             and o['amount_msat'] == 75_000_000_000
                             for o in l1.rpc.listfunds()['outputs']))
        assert 'POLICY REJECT' not in device.output()
    finally:
        # The node first: a device that goes before it leaves the proxy
        # waiting for another.
        if answers(l1, timeout=2):
            l1.stop()
        device.stop()


def test_sym_keyless_device_claims_htlc(node_factory, bitcoind, directory, executor):
    """A keyless node holds an HTLC it received when it closes: the settlement
    carries it, and once the node learns the preimage its device signs the
    claim by the SUCCESS leaf (SIGN_SYM_HTLC), to the node's own wallet."""
    from test_keyless_close import keyless_node, answers
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: 2 * PAR})
    device, l2 = keyless_node(node_factory, directory, options=dict(SYM, plugin=HOLD))
    try:
        l1 = node_factory.get_node(options=SYM, may_fail=True)
        fund_node(bitcoind, l1, gold, PAR + 50_000)
        fund_node(bitcoind, l2, silv, 5 * PAR)
        chan = open_channel(bitcoind, l1, l2, gold, PAR)
        assert SYM_BIT in chan['channel_type']['bits']
        msat = 3_000_000_000
        fut, htlc = held_htlc(l1, l2, executor, msat, gold)
        l1.stop()
        l2.rpc.close(chan['short_channel_id'], unilateraltimeout=1)
        kickoff, i = mined_spender(bitcoind, chan['funding_txid'], chan['funding_outnum'])
        update, j = mined_spender(bitcoind, kickoff['txid'], i)
        settle, _ = mined_spender(bitcoind, update['txid'], j)
        htlc_out = only_one([o['n'] for o in settle['vout']
                             if o['scriptPubKey']['type'] == 'witness_v1_taproot'
                             and int(Decimal(o['value']) * PAR) == msat // 1000])
        open(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'unhold'), 'w').close()
        claim, c = mined_spender(bitcoind, settle['txid'], htlc_out)
        wit = claim['vin'][c]['txinwitness']
        assert len(wit) == 4 and len(wit[1]) == 64   # <sig> <preimage> <leaf> <cb>
        print("keyless SUCCESS claim:", json.dumps({k: claim[k] for k in ('txid', 'vsize')}))
        wait_for(lambda: any(o['txid'] == claim['txid'] and o['asset'] == gold
                             for o in l2.rpc.listfunds()['outputs']))
        assert 'POLICY REJECT' not in device.output()
        assert l2.daemon.is_in_log('WIRE_HSMD_SIGN_SYM_HTLC')
    finally:
        if answers(l2, timeout=2):
            l2.stop()
        device.stop()
