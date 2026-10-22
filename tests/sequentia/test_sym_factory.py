"""Factory channels (`option_seq_symmetric_factory`, common/sym_factory.h).

One funding output, F, opens a symmetric channel (test_symmetric.py) between
a hub and each of its members.  F = tr(NUMS, SPLIT): no signature, and the
split pays every channel's KO at the output numbered as its slot.  A
channel's output on chain is F until the split and its KO after it; the
update signatures name neither, so a split moves every channel on without a
signature.  One member exits alone: the split, its best state over its KO,
the settlement; every other channel goes on, anchored on its KO.
Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK, only_one, wait_for

import json
import os
import pytest
import time

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
SYM_BIT = 178
FACTORY_BIT = 182
DELAY = 6
FAC = {'symmetric-channels': None, 'symmetric-delay': DELAY,
       'cltv-final': 40, 'cltv-delta': 40,
       'max-dust-htlc-exposure-msat': 10**12, 'may_reconnect': True}
# The four channels' capacities (GOLD atoms), slot by slot.
CAPS = [30_000_000, 30_000_000, 20_000_000, 20_000_000]


def fund_node(bitcoind, node, asset, atoms):
    addr = node.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send(addr, atoms, asset)
    bitcoind.generate_block(1, wait_for_mempool=txid)
    wait_for(lambda: any(o['txid'] == txid and o['status'] == 'confirmed'
                         for o in node.rpc.listfunds()['outputs']))


def pay(src, dst, msat, asset):
    inv = dst.rpc.call('invoice', {'amount_msat': msat, 'label': 'f%d' % pay.n,
                                   'description': 'factory', 'asset': asset})
    pay.n += 1
    return src.rpc.pay(inv['bolt11'])


pay.n = 0


def chan(node, peer):
    return only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])


def atoms(v):
    return int(Decimal(v) * PAR)


def fee_asset_of(tx):
    return only_one([o for o in tx['vout'] if o['scriptPubKey']['type'] == 'fee'])['asset']


def update_n(tx, i):
    """The state number an update's witness published (8 bytes LE)."""
    wit = tx['vin'][i]['txinwitness']
    assert len(wit) == 6, wit
    return int.from_bytes(bytes.fromhex(wit[2]), 'little', signed=True)


def mined_spender(bitcoind, txid, n, max_blocks=DELAY + 15):
    """The transaction a block holds spending txid:n, mining until one does."""
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


def factory(node_factory, bitcoind, opts=None):
    """A hub and four members, the hub's four channels opened as one
    factory in GOLD.  SILV is another asset every node accepts for fees,
    worth two reference atoms an atom; the members hold only SILV, so every
    fee they pay on chain is in SILV.  `opts`: each node's extra options,
    the hub's first."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: 2 * PAR})
    opts = opts or [{} for _ in range(5)]
    hub, *members = node_factory.get_nodes(5, opts=[dict(FAC, **o) for o in opts])
    fund_node(bitcoind, hub, gold, PAR + 50_000_000)
    for n in [hub] + members:
        fund_node(bitcoind, n, silv, 2 * PAR)
    for m in members:
        hub.rpc.connect(m.info['id'], 'localhost', m.port)
    res = hub.rpc.call('multifundchannel', {
        'destinations': [{'id': m.info['id'], 'amount': CAPS[i], 'asset': gold}
                         for i, m in enumerate(members)],
        'factory': True})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for m in members:
        wait_for(lambda: chan(hub, m)['state'] == 'CHANNELD_NORMAL')
        wait_for(lambda: chan(m, hub)['state'] == 'CHANNELD_NORMAL')
    # What change the funding left in GOLD goes elsewhere: the hub's fees
    # on chain are in SILV too.
    wait_for(lambda: any(o['asset'] == gold and o['status'] == 'confirmed'
                         for o in hub.rpc.listfunds()['outputs']))
    w = hub.rpc.call('withdraw', {'destination': bitcoind.rpc.getnewaddress(),
                                  'satoshi': 'all', 'asset': gold})
    bitcoind.generate_block(1, wait_for_mempool=w['txid'])
    return hub, members, gold, silv, res['txid']


def test_factory_four_channels_one_output(node_factory, bitcoind):
    """One output opens four channels; two are used while the other two
    members are offline; one member exits alone, and the others go on."""
    hub, members, gold, silv, ftxid = factory(node_factory, bitcoind)
    m0, m1, m2, m3 = members

    # One funding output holds the four channels: F, a taproot output of the
    # whole capacity, and no 2-of-2.
    ftx = bitcoind.rpc.getrawtransaction(ftxid, 1)
    gold_outs = [o for o in ftx['vout'] if o.get('asset') == gold
                 and o['scriptPubKey']['type'] != 'fee']
    f_out = only_one([o for o in gold_outs if atoms(o['value']) == sum(CAPS)])
    assert f_out['scriptPubKey']['type'] == 'witness_v1_taproot'
    print("factory funding:", json.dumps({'txid': ftxid, 'vsize': ftx['vsize'],
                                          'outputs': len(ftx['vout'])}))
    infos = []
    for slot, m in enumerate(members):
        c = chan(hub, m)
        assert FACTORY_BIT in c['channel_type']['bits']
        assert SYM_BIT in c['channel_type']['bits']
        assert 'seq_symmetric_factory/even' in c['channel_type']['names']
        f = c['seq_factory']
        assert (f['factory_txid'], f['factory_outnum']) == (ftxid, f_out['n'])
        assert f['slot'] == slot and f['size'] == 4
        assert 'ko_txid' not in f
        # The member holds the same factory and slot.
        assert chan(m, hub)['seq_factory'] == f
        infos.append(f)
    assert len({f['nonce'] for f in infos}) == 1
    print("channels:", [(f['slot'], c) for f, c in zip(infos, CAPS)])

    # Members 2 and 3 go offline; members 0 and 1 are paid and pay back.
    m2.stop()
    m3.stop()
    pay(hub, m0, 10_000_000_000, gold)
    pay(hub, m1, 7_000_000_000, gold)
    pay(m0, hub, 2_000_000_000, gold)
    pay(m1, hub, 1_000_000_000, gold)
    wait_for(lambda: chan(m0, hub)['to_us_msat'] == 8_000_000_000)
    wait_for(lambda: chan(m1, hub)['to_us_msat'] == 6_000_000_000)

    # Member 0 exits alone, unilaterally: the split (no signature), its best
    # state over its KO, the settlement after the shared delay, each with a
    # fee coin in SILV.
    res = m0.rpc.close(hub.info['id'])
    assert res['type'] == 'unilateral'
    split, si = mined_spender(bitcoind, ftxid, f_out['n'])
    print("split:", json.dumps({k: split[k] for k in ('txid', 'vsize')}))
    assert fee_asset_of(split) == silv
    for slot in range(4):
        o = split['vout'][slot]
        assert o['asset'] == gold and atoms(o['value']) == CAPS[slot]
        assert o['scriptPubKey']['type'] == 'witness_v1_taproot'
    update, ui = mined_spender(bitcoind, split['txid'], 0)
    print("member 0's update:", json.dumps({k: update[k] for k in ('txid', 'vsize')}),
          "state", update_n(update, ui))
    assert fee_asset_of(update) == silv
    settle, _ = mined_spender(bitcoind, update['txid'], ui)
    print("member 0's settle:", json.dumps({k: settle[k] for k in ('txid', 'vsize')}))
    hu = bitcoind.rpc.getrawtransaction(update['txid'], 1)['blockhash']
    hs = bitcoind.rpc.getrawtransaction(settle['txid'], 1)['blockhash']
    assert (bitcoind.rpc.getblock(hs)['height']
            - bitcoind.rpc.getblock(hu)['height']) >= DELAY
    assert fee_asset_of(settle) == silv
    gold_out = sorted(atoms(o['value']) for o in settle['vout'] if o.get('asset') == gold)
    print("member 0's settlement (GOLD atoms):", gold_out)
    assert gold_out == [8_000_000, 22_000_000]
    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 8_000_000_000
                         for o in m0.rpc.listfunds()['outputs']))

    # The other three channels go on, each anchored on its KO.
    for slot, m in ((1, m1), (2, m2), (3, m3)):
        c = chan(hub, m)
        assert c['state'] == 'CHANNELD_NORMAL', c['state']
        assert (c['seq_factory']['ko_txid'], c['seq_factory']['ko_outnum']) \
            == (split['txid'], slot)
    pay(hub, m1, 3_000_000_000, gold)
    wait_for(lambda: chan(m1, hub)['to_us_msat'] == 9_000_000_000)
    assert chan(m1, hub)['seq_factory']['ko_txid'] == split['txid']
    # The offline members' KOs stand, with no clock on them.
    bitcoind.generate_block(2 * DELAY)
    for slot in (1, 2, 3):
        assert bitcoind.rpc.gettxout(split['txid'], slot) is not None

    # Back, members 2 and 3 learn of the split and go on too.
    for m in (m2, m3):
        m.start()
        hub.rpc.connect(m.info['id'], 'localhost', m.port)
        wait_for(lambda: chan(m, hub)['state'] == 'CHANNELD_NORMAL'
                 and chan(m, hub)['peer_connected'])
        wait_for(lambda: chan(m, hub)['seq_factory'].get('ko_txid') == split['txid'])
    pay(hub, m2, 4_000_000_000, gold)
    pay(hub, m3, 5_000_000_000, gold)
    wait_for(lambda: chan(m2, hub)['to_us_msat'] == 4_000_000_000)
    wait_for(lambda: chan(m3, hub)['to_us_msat'] == 5_000_000_000)


def test_factory_stale_state_replaced(node_factory, bitcoind):
    """The hub keeps an old state of member 1's channel, pays member 1 most
    of it, and closes with the old one while member 1 is away: the split,
    then the stale state over KO 1, mined.  Member 1, back within the shared
    delay, finds F split and KO 1 spent, and replaces the stale state with
    its latest; the settlement pays the latest split.  The other channels
    stay open."""
    hub, members, gold, silv, ftxid = factory(node_factory, bitcoind)
    m0, m1, m2, m3 = members
    pay(hub, m1, 5_000_000_000, gold)
    stale = hub.rpc.call('dev-sym-snapshot', {'id': m1.info['id']})['state']
    pay(hub, m1, 15_000_000_000, gold)
    f = chan(hub, m1)['seq_factory']
    m1.stop()
    hub.rpc.close(m1.info['id'])

    split, _ = mined_spender(bitcoind, f['factory_txid'], f['factory_outnum'])
    first, j = mined_spender(bitcoind, split['txid'], 1)
    assert update_n(first, j) == stale
    print("stale state", stale, "mined:",
          json.dumps({x: first[x] for x in ('txid', 'vsize')}))

    m1.start()
    m1.daemon.wait_for_log('Replacing state {} by our state'.format(stale))
    latest, k = mined_spender(bitcoind, first['txid'], j)
    n_latest = update_n(latest, k)
    assert n_latest > stale
    assert fee_asset_of(latest) == silv
    hf = bitcoind.rpc.getrawtransaction(first['txid'], 1)['blockhash']
    hl = bitcoind.rpc.getrawtransaction(latest['txid'], 1)['blockhash']
    print("replaced by state", n_latest, "after",
          bitcoind.rpc.getblock(hl)['height'] - bitcoind.rpc.getblock(hf)['height'],
          "blocks:", json.dumps({x: latest[x] for x in ('txid', 'vsize')}))
    settle, _ = mined_spender(bitcoind, latest['txid'], k)
    gold_out = sorted(atoms(o['value']) for o in settle['vout'] if o.get('asset') == gold)
    print("settlement (GOLD atoms):", gold_out)
    assert gold_out == [10_000_000, 20_000_000]
    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 20_000_000_000
                         for o in m1.rpc.listfunds()['outputs']))
    for m in (m0, m2, m3):
        assert chan(hub, m)['state'] == 'CHANNELD_NORMAL'
    pay(hub, m2, 1_000_000_000, gold)


def test_factory_split_reorged(node_factory, bitcoind):
    """Member 0's split is mined in a Sequentia block anchored to a Bitcoin
    block the parent chain then reorganizes away: the Sequentia block goes
    with it, the split leaves the chain and comes back in a new block, and
    every channel, member 0's exit included, goes on from it."""
    hub, members, gold, silv, ftxid = factory(node_factory, bitcoind)
    m0, m1, m2, m3 = members
    pay(hub, m0, 6_000_000_000, gold)
    pay(hub, m1, 4_000_000_000, gold)
    f = chan(hub, m0)['seq_factory']

    # The split goes into a block anchored to a parent block about to go.
    orphan = bitcoind.mine_parent(1)[0]
    m0.rpc.close(hub.info['id'])
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) >= 1)
    split_txid = None
    for t in bitcoind.rpc.getrawmempool():
        d = bitcoind.rpc.getrawtransaction(t, 1)
        if any(v.get('txid') == f['factory_txid'] and v.get('vout') == f['factory_outnum']
               for v in d['vin']):
            split_txid = t
    assert split_txid
    base = bitcoind.rpc.getblockcount()
    gone = bitcoind.generate_block(1, advance_parent=False)
    for n in (hub, m1):
        wait_for(lambda: all(chan(n, m)['seq_factory'].get('ko_txid') == split_txid
                             for m in ([m0, m1, m2, m3] if n == hub else [hub])))

    # The parent drops that block for a longer branch: the Sequentia block
    # anchored to it goes, and the split with it.
    bitcoind.parent.rpc.invalidateblock(orphan)
    bitcoind.mine_parent(2)
    wait_for(lambda: bitcoind.rpc.getblockcount() == base)
    new = bitcoind.generate_block(3, advance_parent=False)
    assert not set(new) & set(gone)
    hub.daemon.wait_for_log(r'Removing stale block {}: {}'.format(base + 1, gone[0]))

    # The split is mined again (from the mempool, or rebroadcast), and the
    # exit runs to its settlement; the other channels go on.
    split, si = mined_spender(bitcoind, f['factory_txid'], f['factory_outnum'])
    print("split after the reorganization:",
          json.dumps({k: split[k] for k in ('txid', 'vsize')}))
    update, ui = mined_spender(bitcoind, split['txid'], 0)
    settle, _ = mined_spender(bitcoind, update['txid'], ui)
    gold_out = sorted(atoms(o['value']) for o in settle['vout'] if o.get('asset') == gold)
    print("member 0's settlement (GOLD atoms):", gold_out)
    assert gold_out == [6_000_000, 24_000_000]
    for slot, m in ((1, m1), (2, m2), (3, m3)):
        c = chan(hub, m)
        assert c['state'] == 'CHANNELD_NORMAL'
        assert (c['seq_factory']['ko_txid'], c['seq_factory']['ko_outnum']) \
            == (split['txid'], slot)
    pay(hub, m1, 2_000_000_000, gold)
    wait_for(lambda: chan(m1, hub)['to_us_msat'] == 6_000_000_000)


def test_factory_keyless_watcher(node_factory, bitcoind, directory):
    """The hub keeps an old state of member 1's channel, pays member 1 more,
    and closes with the old one while member 1 is offline: the split, then
    the stale state over KO 1.  speculad, holding no key and only member 1's
    store (its factory and the latest state it holds whole), walks from the
    factory output to KO 1, replaces the stale state with the latest, and
    settles it after the shared delay, each with a fee coin in SILV from its
    own wallet.  Back online, member 1 finds its balance in its wallet."""
    from test_watchtower import Speculad, fee_wallet
    victim = {'watchtower-store': 'on'}
    hub, members, gold, silv, ftxid = factory(node_factory, bitcoind,
                                               opts=[{}, {}, victim, {}, {}])
    m0, m1, m2, m3 = members
    pay(hub, m1, 5_000_000_000, gold)
    stale = hub.rpc.call('dev-sym-snapshot', {'id': m1.info['id']})['state']
    pay(hub, m1, 15_000_000_000, gold)
    store = os.path.join(m1.daemon.lightning_dir, TEST_NETWORK, 'watchtower')
    assert any(os.path.exists(os.path.join(store, d, 'sym')) for d in os.listdir(store))
    f = chan(hub, m1)['seq_factory']

    m1.stop()
    wallet = fee_wallet(bitcoind, silv, [(silv, 1)])
    tower = Speculad(m1, bitcoind, wallet, directory)
    # The tower starts once the stale state is mined over KO 1, so it is
    # that state the tower must answer (started sooner, it can put the
    # latest over KO 1 before the hub's stale update gets there).
    hub.rpc.close(m1.info['id'])
    split, _ = mined_spender(bitcoind, f['factory_txid'], f['factory_outnum'])
    first, j = mined_spender(bitcoind, split['txid'], f['slot'])
    assert update_n(first, j) == stale
    print("stale state", stale, "mined over KO", f['slot'], ":",
          json.dumps({x: first[x] for x in ('txid', 'vsize')}))
    tower.start()
    try:
        latest, k = mined_spender(bitcoind, first['txid'], j)
        n_latest = update_n(latest, k)
        assert n_latest > stale
        assert fee_asset_of(latest) == silv
        print("the tower replaced it by state", n_latest,
              json.dumps({x: latest[x] for x in ('txid', 'vsize')}))
        settle, _ = mined_spender(bitcoind, latest['txid'], k)
        assert fee_asset_of(settle) == silv
        gold_out = sorted(atoms(o['value']) for o in settle['vout'] if o.get('asset') == gold)
        print("settlement (GOLD atoms):", gold_out)
        assert gold_out == [10_000_000, 20_000_000]
    finally:
        tower.stop()
        print(tower.output())
    out = tower.output()
    assert 'replacing it by state {}'.format(n_latest) in out
    assert 'broadcast the settlement' in out

    m1.start()
    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 20_000_000_000
                         for o in m1.rpc.listfunds()['outputs']))
