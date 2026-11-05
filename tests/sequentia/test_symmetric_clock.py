"""The symmetric type's settle clock (`option_seq_symmetric_clock`).

The funding: the opener names a funding input in open_channel, and that
input issues one atom of a fresh asset, the marker, with no reissuance
token, into the seed beside the usual 2-of-2 (common/sym_scripts.h).  The
opener checks the funding before it signs it; the accepter, which puts
nothing into the channel, checks it once mined, before the channel locks
in, and forgets the channel if it is wrong (lightningd/sym_clock.h).

On chain: the kickoff spends the funding and the seed, and pays KO the
marker and the clock the capacity.  Each state output holds the marker, an
update has the lock time floor, and the settle spends the state output and
the clock, whose shared delay runs once, from the kickoff.
Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from test_symmetric import (SYM, PAR, DELAY, HOLD, fund_node, pay, mined_spender,
                            funding_outpoint, fee_asset_of, update_n, held_htlc)
from utils import TEST_NETWORK, only_one, wait_for

import json
import os
import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

SYM_BIT, CLOCK_BIT = 178, 180
CLOCK = dict(SYM, **{'dev-symmetric-clock': None})


def clock_nodes(node_factory, bitcoind, opts=({}, {})):
    """l1 and l2 offer the settle clock; l1 holds GOLD to open in and SILV
    for fees, l2 only SILV."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: 2 * PAR})
    l1, l2 = node_factory.get_nodes(2, opts=[{**CLOCK, **opts[0]},
                                             {**CLOCK, **opts[1]}])
    fund_node(bitcoind, l1, gold, PAR + 50_000)
    fund_node(bitcoind, l1, silv, 5 * PAR)
    fund_node(bitcoind, l2, silv, 5 * PAR)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    return l1, l2, gold, silv


def issuances(bitcoind, txid):
    d = bitcoind.rpc.getrawtransaction(txid, 1)
    return d, [v for v in d['vin'] if v.get('issuance')]


def test_sym_clock_funding_issues_the_marker(node_factory, bitcoind):
    """The funding's issuer input issues one atom of the marker, no token,
    and output `seed` pays it to the seed; the accepter finds it so once the
    funding is mined, and the channel opens, pays both ways and pays again
    after the accepter restarts."""
    l1, l2, gold, silv = clock_nodes(node_factory, bitcoind,
                                     opts=({'may_reconnect': True},
                                           {'may_reconnect': True}))
    res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': PAR,
                                      'asset': gold})
    assert {SYM_BIT, CLOCK_BIT} <= set(res['channel_type']['bits'])

    d, iss = issuances(bitcoind, res['txid'])
    issued = only_one(iss)['issuance']
    print("issuance:", issued)
    assert issued['isreissuance'] is False
    assert int(round(float(issued['assetamount']) * 10**8)) == 1
    assert not issued.get('tokenamount')
    marker = issued['asset']
    held = [o for o in d['vout'] if o.get('asset') == marker]
    seed = only_one(held)
    assert int(round(float(seed['value']) * 10**8)) == 1
    # The seed is a taproot output, beside the P2WSH funding output.
    assert seed['scriptPubKey']['hex'].startswith('5120')
    funding = d['vout'][res['outnum']]
    assert funding['scriptPubKey']['hex'].startswith('0020')
    print("funding", res['txid'], "vsize", d['vsize'], "seed output", seed['n'])

    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    l2.daemon.wait_for_log(r'Funding issues the marker into the seed,'
                           r' output {}'.format(seed['n']))
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state']
                 == 'CHANNELD_NORMAL')
    pay(l1, l2, 30_000_000_000, gold)
    pay(l2, l1, 10_000_000_000, gold)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])
             ['to_us_msat'] == (PAR - 20_000_000) * 1000)

    # The channel and its seed survive a restart.
    l2.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    pay(l1, l2, 5_000_000_000, gold)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])
             ['to_us_msat'] == (PAR - 25_000_000) * 1000)


def test_sym_clock_accepter_refuses_two_atoms(node_factory, bitcoind):
    """An opener whose funding issues two atoms of the marker (a spare one
    could later take the clock): the accepter, restarted before it is mined,
    finds it so once it is and forgets the channel, which never locks in.
    The opener,
    whose own check only logged it (--dev-symmetric-clock-bad-funding),
    finds it too and does not lock in either."""
    l1, l2, gold, silv = clock_nodes(
        node_factory, bitcoind,
        opts=({'dev-symmetric-clock-bad-funding': None,
               'broken_log': "is not this settle-clock channel"},
              {'broken_log': "is not this settle-clock channel"}))
    res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': PAR,
                                      'asset': gold})
    l1.daemon.wait_for_log(r'dev-symmetric-clock-bad-funding: funding anyway:'
                           r' the issuer.s input issues 2 atoms, not one')
    d, iss = issuances(bitcoind, res['txid'])
    assert int(round(float(only_one(iss)['issuance']['assetamount']) * 10**8)) == 2

    # l2 reads the issuer back from its database to check the funding.
    l2.restart()
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    l2.daemon.wait_for_log(r'is not this settle-clock channel.s: the issuer.s'
                           r' input issues 2 atoms, not one')
    l2.daemon.wait_for_log(r'forget channel')
    wait_for(lambda: l2.rpc.listpeerchannels(l1.info['id'])['channels'] == [])
    l1.daemon.wait_for_log(r'is not this settle-clock channel.s: the issuer.s'
                           r' input issues 2 atoms, not one')
    bitcoind.generate_block(3)
    for c in l1.rpc.listpeerchannels(l2.info['id'])['channels']:
        assert c['state'] != 'CHANNELD_NORMAL'


FLOOR = 500000001


def atoms(out):
    return int(round(Decimal(out['value']) * PAR))


def height_of(bitcoind, txid):
    return bitcoind.rpc.getblock(bitcoind.rpc.getrawtransaction(txid, 1)['blockhash'])['height']


def clock_pair(node_factory, bitcoind, opts=({}, {})):
    """A settle-clock GOLD channel l1 -> l2, l1 left without GOLD outside
    it (its fees on chain are in SILV); its marker and its seed outpoint."""
    l1, l2, gold, silv = clock_nodes(node_factory, bitcoind, opts)
    res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': PAR,
                                      'asset': gold})
    d, iss = issuances(bitcoind, res['txid'])
    marker = only_one(iss)['issuance']['asset']
    seed = (res['txid'], only_one([o for o in d['vout'] if o.get('asset') == marker])['n'])
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state']
                 == 'CHANNELD_NORMAL')
    for o in l1.rpc.listfunds()['outputs']:
        if o.get('asset') == gold and o['status'] == 'confirmed':
            l1.rpc.call('withdraw', {'destination': bitcoind.rpc.getnewaddress(),
                                     'satoshi': 'all', 'asset': gold})
            bitcoind.generate_block(1, wait_for_mempool=1)
            break
    scid = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['short_channel_id']
    return l1, l2, gold, silv, scid, marker, seed


def check_kickoff(bitcoind, l1, l2, gold, marker, seed):
    """The kickoff: funding and seed in, KO with the marker and the clock
    with the capacity out.  Returns it, KO's index and the clock's."""
    ftxid, fout = funding_outpoint(l1, l2)
    kickoff, i = mined_spender(bitcoind, ftxid, fout)
    print("kickoff:", json.dumps({k: kickoff[k] for k in ('txid', 'vsize')}))
    assert (kickoff['vin'][i + 1]['txid'], kickoff['vin'][i + 1]['vout']) == seed
    # The seed's KICK leaf: leaf and control block, no signature.
    assert len(kickoff['vin'][i + 1]['txinwitness']) == 2
    ko, clock = kickoff['vout'][i], kickoff['vout'][i + 1]
    assert ko['asset'] == marker and atoms(ko) == 1
    assert clock['asset'] == gold and atoms(clock) == PAR
    assert clock['scriptPubKey']['hex'].startswith('5120')
    return kickoff, i, i + 1


def check_update(update, j, marker):
    assert update['locktime'] == FLOOR
    assert update['vout'][j]['asset'] == marker and atoms(update['vout'][j]) == 1


def check_settle(bitcoind, settle, s, state_tx, j, kickoff, c, marker):
    """The settle: the state output and the clock in, the marker back to
    the state's script at its index, the settlement after it."""
    assert (settle['vin'][s + 1]['txid'], settle['vin'][s + 1]['vout']) == (kickoff['txid'], c)
    assert settle['vin'][s + 1]['sequence'] == DELAY
    assert settle['locktime'] == 0
    assert settle['vout'][s]['asset'] == marker and atoms(settle['vout'][s]) == 1
    assert (settle['vout'][s]['scriptPubKey']['hex']
            == state_tx['vout'][j]['scriptPubKey']['hex'])
    hk, hu, hs = (height_of(bitcoind, t['txid']) for t in (kickoff, state_tx, settle))
    print("settle:", json.dumps({k: settle[k] for k in ('txid', 'vsize')}),
          "{} blocks after the kickoff, {} after the last update".format(hs - hk, hs - hu))
    # The clock's delay runs from the kickoff.
    assert hs - hk >= DELAY


def test_sym_clock_unilateral_close_settles(node_factory, bitcoind):
    """l1 closes unilaterally while l2 is away: the kickoff with the seed,
    l1's latest state over KO, and the settle with the clock once its
    delay from the kickoff has passed, each with a fee coin in SILV.  Each
    side's balance lands in its wallet; l2, back, sees its own."""
    l1, l2, gold, silv, scid, marker, seed = clock_pair(node_factory, bitcoind)
    pay(l1, l2, 30_000_000_000, gold)
    pay(l2, l1, 5_000_000_000, gold)
    l2.stop()
    l1.rpc.close(scid, unilateraltimeout=1)

    kickoff, i, c = check_kickoff(bitcoind, l1, l2, gold, marker, seed)
    assert fee_asset_of(kickoff) == silv
    update, j = mined_spender(bitcoind, kickoff['txid'], i)
    print("update:", json.dumps({k: update[k] for k in ('txid', 'vsize')}),
          "state", update_n(update, j))
    check_update(update, j, marker)
    assert fee_asset_of(update) == silv
    settle, s = mined_spender(bitcoind, update['txid'], j)
    check_settle(bitcoind, settle, s, update, j, kickoff, c, marker)
    assert fee_asset_of(settle) == silv
    gold_out = sorted(atoms(o) for o in settle['vout'] if o.get('asset') == gold)
    print("settlement (GOLD atoms):", gold_out)
    assert gold_out == [25_000_000, 75_000_000]

    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 75_000_000_000
                         for o in l1.rpc.listfunds()['outputs']))
    l2.start()
    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 25_000_000_000
                         for o in l2.rpc.listfunds()['outputs']))


def test_sym_clock_stale_state_replaced(node_factory, bitcoind):
    """l1 closes with an old state (dev-sym-snapshot) while l2 is away, so
    the stale state is mined.  l2, back before the clock runs out, replaces
    it with the latest state it holds, and the settle pays the latest
    split."""
    l1, l2, gold, silv, scid, marker, seed = clock_pair(
        node_factory, bitcoind, opts=({'may_reconnect': True}, {'may_reconnect': True}))
    pay(l1, l2, 10_000_000_000, gold)
    stale = l1.rpc.call('dev-sym-snapshot', {'id': l2.info['id']})['state']
    pay(l1, l2, 60_000_000_000, gold)
    l2.stop()
    l1.rpc.close(scid, unilateraltimeout=1)

    kickoff, i, c = check_kickoff(bitcoind, l1, l2, gold, marker, seed)
    first, j = mined_spender(bitcoind, kickoff['txid'], i)
    assert update_n(first, j) == stale
    check_update(first, j, marker)
    print("stale state", stale, "mined:",
          json.dumps({x: first[x] for x in ('txid', 'vsize')}))

    l2.start()
    l2.daemon.wait_for_log('Replacing state {} by our state'.format(stale))
    latest, k = mined_spender(bitcoind, first['txid'], j)
    n_latest = update_n(latest, k)
    assert n_latest > stale
    check_update(latest, k, marker)
    print("replaced by state", n_latest, "after",
          height_of(bitcoind, latest['txid']) - height_of(bitcoind, first['txid']),
          "blocks:", json.dumps({x: latest[x] for x in ('txid', 'vsize')}))
    settle, s = mined_spender(bitcoind, latest['txid'], k)
    check_settle(bitcoind, settle, s, latest, k, kickoff, c, marker)
    gold_out = sorted(atoms(o) for o in settle['vout'] if o.get('asset') == gold)
    print("settlement (GOLD atoms):", gold_out)
    assert gold_out == [30_000_000, 70_000_000]
    wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                         and o['amount_msat'] == 70_000_000_000
                         for o in l2.rpc.listfunds()['outputs']))


def test_sym_clock_htlc_margin_is_one_delay(node_factory, bitcoind):
    """The clock runs the shared delay once, so an HTLC must outlive one
    delay plus the slack (6 + 12 blocks here), not the base type's two
    delays (24): one expiring 20 blocks out goes through, one expiring 10
    out is refused.  l2 takes a final expiry of 20 blocks."""
    l1, l2, gold, silv, scid, marker, seed = clock_pair(node_factory, bitcoind,
                                                        opts=({}, {'cltv-final': 20}))
    inv = l2.rpc.call('invoice', {'amount_msat': 1_000_000_000, 'label': 'soon',
                                  'description': 'sym', 'asset': gold, 'cltv': 10})
    with pytest.raises(RpcError):
        l1.rpc.pay(inv['bolt11'])
    l1.daemon.wait_for_log(r'Not offering an HTLC expiring at [0-9]+ on a symmetric'
                           r' channel: it must outlive 18 blocks')
    inv = l2.rpc.call('invoice', {'amount_msat': 1_000_000_000, 'label': 'later',
                                  'description': 'sym', 'asset': gold})
    assert l1.rpc.pay(inv['bolt11'])['status'] == 'complete'


def test_sym_clock_htlc_claimed_after_settle(node_factory, bitcoind, executor):
    """An HTLC in flight when l2 closes: the settle with the clock carries
    it, and l2, once it learns the preimage, claims it by its SUCCESS
    leaf."""
    l1, l2, gold, silv, scid, marker, seed = clock_pair(
        node_factory, bitcoind, opts=({'may_fail': True}, {'plugin': HOLD}))
    msat = 3_000_000_000
    fut, htlc = held_htlc(l1, l2, executor, msat, gold)
    l1.stop()
    l2.rpc.close(scid, unilateraltimeout=1)
    kickoff, i, c = check_kickoff(bitcoind, l2, l1, gold, marker, seed)
    update, j = mined_spender(bitcoind, kickoff['txid'], i)
    check_update(update, j, marker)
    settle, s = mined_spender(bitcoind, update['txid'], j)
    check_settle(bitcoind, settle, s, update, j, kickoff, c, marker)
    htlc_out = only_one([o['n'] for o in settle['vout']
                         if o['scriptPubKey']['type'] == 'witness_v1_taproot'
                         and o.get('asset') == gold and atoms(o) == msat // 1000])
    open(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'unhold'), 'w').close()
    claim, cl = mined_spender(bitcoind, settle['txid'], htlc_out)
    print("success claim:", json.dumps({k: claim[k] for k in ('txid', 'vsize')}))
    assert len(claim['vin'][cl]['txinwitness']) == 4
    wait_for(lambda: any(o['txid'] == claim['txid'] and o['asset'] == gold
                         for o in l2.rpc.listfunds()['outputs']))


def test_sym_clock_mutual_close(node_factory, bitcoind):
    """A settle-clock channel closes cooperatively from its 2-of-2 funding
    output, as any symmetric channel; the seed and its marker atom stay
    where they are."""
    l1, l2, gold, silv, scid, marker, seed = clock_pair(node_factory, bitcoind)
    pay(l1, l2, 20_000_000_000, gold)
    res = l1.rpc.close(scid)
    assert res['type'] == 'mutual'
    txid = only_one(res['txids'])
    bitcoind.generate_block(1, wait_for_mempool=txid)
    dec = bitcoind.rpc.getrawtransaction(txid, 1)
    assert seed not in [(v['txid'], v['vout']) for v in dec['vin']]
    gold_out = sorted(atoms(o) for o in dec['vout']
                      if o.get('asset') == gold and o['scriptPubKey']['type'] != 'fee')
    print("mutual close (GOLD atoms):", gold_out)
    assert gold_out[0] == 20_000_000
    assert bitcoind.rpc.gettxout(seed[0], seed[1]) is not None
    wait_for(lambda: any(o['txid'] == txid and o['asset'] == gold
                         for o in l2.rpc.listfunds()['outputs']))


def test_sym_clock_keyless_watcher(node_factory, bitcoind, directory):
    """l1 closes a settle-clock channel with an old state while l2 is
    offline.  speculad, holding no key and only l2's store, replaces the
    stale state with the latest, holding the marker at the lock time
    floor, and settles it with the clock once the delay since the kickoff
    has passed, each with a fee coin in SILV from its own wallet.  Back
    online, l2 finds its balance in its wallet."""
    from test_watchtower import Speculad, fee_wallet
    victim = {'watchtower-store': 'on', 'may_reconnect': True}
    l1, l2, gold, silv, scid, marker, seed = clock_pair(
        node_factory, bitcoind, opts=({'may_reconnect': True}, victim))
    pay(l1, l2, 10_000_000_000, gold)
    stale = l1.rpc.call('dev-sym-snapshot', {'id': l2.info['id']})['state']
    pay(l1, l2, 60_000_000_000, gold)
    store = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'watchtower')
    recs = [os.path.join(store, d, 'sym') for d in os.listdir(store)
            if os.path.exists(os.path.join(store, d, 'sym'))]
    # The record is version 4: it carries the clock.
    assert int.from_bytes(open(only_one(recs), 'rb').read()[:8], 'big') == 4

    l2.stop()
    wallet = fee_wallet(bitcoind, silv, [(silv, 1)])
    tower = Speculad(l2, bitcoind, wallet, directory)
    tower.start()
    try:
        l1.rpc.close(scid, unilateraltimeout=1)
        kickoff, i, c = check_kickoff(bitcoind, l1, l2, gold, marker, seed)
        first, j = mined_spender(bitcoind, kickoff['txid'], i)
        assert update_n(first, j) == stale
        print("stale state", stale, "mined:",
              json.dumps({x: first[x] for x in ('txid', 'vsize')}))

        latest, k = mined_spender(bitcoind, first['txid'], j)
        n_latest = update_n(latest, k)
        assert n_latest > stale
        check_update(latest, k, marker)
        assert fee_asset_of(latest) == silv
        print("the tower replaced it by state", n_latest,
              json.dumps({x: latest[x] for x in ('txid', 'vsize')}))

        settle, s = mined_spender(bitcoind, latest['txid'], k)
        check_settle(bitcoind, settle, s, latest, k, kickoff, c, marker)
        assert fee_asset_of(settle) == silv
        gold_out = sorted(atoms(o) for o in settle['vout'] if o.get('asset') == gold)
        print("the tower's settlement (GOLD atoms):", gold_out)
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


def test_sym_clock_keyless_device(node_factory, bitcoind, directory):
    """A keyless node, its keys on a device in enforce mode, accepts a
    settle-clock channel.  Its first state pays it nothing and names the
    issuer, which the device keeps; the kickoff's KO must hold one atom of
    that marker.  Once the funding is mined lightningd shows it to the
    device (CHECK_SYM_CLOCK_FUNDING), which checks the one marker atom in
    the seed, and only then signs states that pay the node.  The node is
    paid, then closes unilaterally over the clock while the opener is away;
    the device refuses nothing."""
    from test_keyless_close import keyless_node, answers
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: 2 * PAR})
    device, l2 = keyless_node(node_factory, directory, options=dict(CLOCK))
    try:
        l1 = node_factory.get_node(options=CLOCK, may_reconnect=True)
        fund_node(bitcoind, l1, gold, PAR + 50_000)
        fund_node(bitcoind, l1, silv, 5 * PAR)
        fund_node(bitcoind, l2, silv, 5 * PAR)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': PAR,
                                          'asset': gold})
        assert {SYM_BIT, CLOCK_BIT} <= set(res['channel_type']['bits'])
        d, iss = issuances(bitcoind, res['txid'])
        marker = only_one(iss)['issuance']['asset']
        seed = (res['txid'], only_one([o for o in d['vout'] if o.get('asset') == marker])['n'])
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        l2.daemon.wait_for_log(r'Funding issues the marker into the seed')
        for a, b in ((l1, l2), (l2, l1)):
            wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state']
                     == 'CHANNELD_NORMAL')
        pay(l1, l2, 30_000_000_000, gold)
        pay(l2, l1, 5_000_000_000, gold)
        wait_for(lambda: only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['htlcs'] == [])
        assert 'POLICY REJECT' not in device.output()
        assert l2.daemon.is_in_log('WIRE_HSMD_CHECK_SYM_CLOCK_FUNDING')
        assert l2.daemon.is_in_log('WIRE_HSMD_SIGN_SYM_CLOCK_STATE')

        l1.stop()
        scid = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['short_channel_id']
        l2.rpc.close(scid, unilateraltimeout=1)
        kickoff, i, c = check_kickoff(bitcoind, l2, l1, gold, marker, seed)
        update, j = mined_spender(bitcoind, kickoff['txid'], i)
        check_update(update, j, marker)
        settle, s = mined_spender(bitcoind, update['txid'], j)
        check_settle(bitcoind, settle, s, update, j, kickoff, c, marker)
        gold_out = sorted(atoms(o) for o in settle['vout'] if o.get('asset') == gold)
        print("keyless clock close: kickoff {} vB, update {} vB (state {}),"
              " settle {} vB, settlement (GOLD atoms) {}".format(
                  kickoff['vsize'], update['vsize'], update_n(update, j),
                  settle['vsize'], gold_out))
        assert gold_out == [25_000_000, 75_000_000]
        wait_for(lambda: any(o['txid'] == settle['txid'] and o['asset'] == gold
                             and o['amount_msat'] == 25_000_000_000
                             for o in l2.rpc.listfunds()['outputs']))
        assert 'POLICY REJECT' not in device.output()
    finally:
        if answers(l2, timeout=2):
            l2.stop()
        device.stop()


def test_sym_clock_keyless_opener(node_factory, bitcoind, directory):
    """A keyless node opens a settle-clock channel: its device is shown the
    funding before it signs a state that pays it, and signs the funding's
    wallet inputs, the one that issues the marker included (its signature
    hash covers the issuance), and the seed it checked.  The funding is
    mined and the channel pays both ways; the device refuses nothing."""
    from test_keyless_close import keyless_node, answers
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: 2 * PAR})
    device, l1 = keyless_node(node_factory, directory, options=dict(CLOCK))
    try:
        l2 = node_factory.get_node(options=CLOCK)
        fund_node(bitcoind, l1, gold, PAR + 50_000)
        fund_node(bitcoind, l1, silv, 5 * PAR)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': PAR,
                                          'asset': gold})
        assert {SYM_BIT, CLOCK_BIT} <= set(res['channel_type']['bits'])
        d, iss = issuances(bitcoind, res['txid'])
        assert int(round(float(only_one(iss)['issuance']['assetamount']) * 10**8)) == 1
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        l2.daemon.wait_for_log(r'Funding issues the marker into the seed')
        for a, b in ((l1, l2), (l2, l1)):
            wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state']
                     == 'CHANNELD_NORMAL')
        pay(l1, l2, 30_000_000_000, gold)
        pay(l2, l1, 5_000_000_000, gold)
        wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])
                 ['to_us_msat'] == (PAR - 25_000_000) * 1000)
        assert l1.daemon.is_in_log('WIRE_HSMD_CHECK_SYM_CLOCK_FUNDING')
        assert 'POLICY REJECT' not in device.output()
        print("keyless opener's funding:", res['txid'], "vsize", d['vsize'])
    finally:
        if answers(l1, timeout=2):
            l1.stop()
        device.stop()
