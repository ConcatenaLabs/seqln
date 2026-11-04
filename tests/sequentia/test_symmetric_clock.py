"""The symmetric type's settle clock (`option_seq_symmetric_clock`): its
funding.  The opener names a funding input in open_channel, and that input
issues one atom of a fresh asset, the marker, with no reissuance token, into
the seed beside the usual 2-of-2 (common/sym_scripts.h).  The opener checks
the funding before it signs it; the accepter, which puts nothing into the
channel, checks it once mined, before the channel locks in, and forgets the
channel if it is wrong (lightningd/sym_clock.h).
Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from test_symmetric import SYM, PAR, fund_node, pay
from utils import TEST_NETWORK, only_one, wait_for

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
    l1, l2, gold, silv = clock_nodes(node_factory, bitcoind)
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
