"""Dust limit and channel reserve in the channel's asset.

A node's dust limit is a reference amount, like its fee settings: 546 atoms
would be dust in a cheap asset and a large sum in a dear one.  Each node sets
a channel's dust limit at what the reference dust limit is worth in the
channel's asset by its exchange rate, so HTLCs are trimmed at the same value
whatever the asset, and the reserve, at least the dust limit, follows.  Run
with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, wait_for

import os
import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
# One atom of DEAR is worth 10 reference atoms; one of CHEAP, a tenth of one.
DEAR_RATE = 10**9
CHEAP_RATE = 10**7
FLOOR = (253, 253, 253, 253)
HOLD_TEST_PLUGIN = os.path.join(os.path.dirname(__file__), '..', 'plugins',
                                'hold_invoice.py')


def ref(atoms, rate):
    """What `atoms` of an asset at `rate` are worth in reference atoms."""
    return Decimal(atoms) * rate / PAR


def atoms_of(ref_atoms, rate):
    return ref_atoms * PAR // rate


def chan(node, peer):
    return only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])


def two_channels(node_factory, bitcoind, value, opts=None):
    """l1 opens a channel worth `value` reference atoms to l2 in DEAR and one
    of the same worth to l3 in CHEAP."""
    dear = bitcoind.issue_asset(1000)
    cheap = bitcoind.issue_asset(100000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, dear: DEAR_RATE,
                            cheap: CHEAP_RATE})
    l1, l2, l3 = node_factory.get_nodes(3, opts=opts)
    txids = []
    for asset, rate in ((dear, DEAR_RATE), (cheap, CHEAP_RATE)):
        addr = l1.rpc.newaddr('bech32')['bech32']
        txids.append(bitcoind.send(addr, 2 * atoms_of(value, rate), asset))
    bitcoind.generate_block(1, wait_for_mempool=txids)
    wait_for(lambda: len([o for o in l1.rpc.listfunds()['outputs']
                          if o['status'] == 'confirmed']) == 2)
    for peer, asset, rate in ((l2, dear, DEAR_RATE), (l3, cheap, CHEAP_RATE)):
        l1.rpc.connect(peer.info['id'], 'localhost', peer.port)
        res = l1.rpc.call('fundchannel', {'id': peer.info['id'],
                                          'amount': atoms_of(value, rate),
                                          'asset': asset, 'announce': False})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1), (l1, l3), (l3, l1)):
        wait_for(lambda: chan(a, b)['state'] == 'CHANNELD_NORMAL')
    return l1, l2, l3, dear, cheap


def htlc_outputs(bitcoind, tx, amounts):
    """The amounts (atoms) among `amounts` that `tx` carries as outputs."""
    vout = bitcoind.rpc.decoderawtransaction(tx)['vout']
    values = [int(Decimal(o['value']) * PAR) for o in vout
              if o['scriptPubKey']['type'] == 'witness_v0_scripthash']
    return sorted(a for a in amounts if a in values)


def test_htlcs_trimmed_at_the_same_value(node_factory, bitcoind, executor):
    """HTLCs worth 400, 600 and 1,500 reference atoms in flight on a DEAR
    channel and a CHEAP one: on both channels, on both commitments, the 400
    and the 600 are trimmed and the 1,500 is not, and every commitment
    relays.  A dust limit of 546 atoms in each asset trimmed all three in
    DEAR (worth 5,460), and in CHEAP (worth 54.6) only the 400, which its
    HTLC transaction's fee outweighed."""
    l1, l2, l3, dear, cheap = two_channels(
        node_factory, bitcoind, 10**8,
        opts=[{'feerates': FLOOR},
              {'plugin': HOLD_TEST_PLUGIN, 'feerates': FLOOR},
              {'plugin': HOLD_TEST_PLUGIN, 'feerates': FLOOR}])
    values = (400, 600, 1500)
    for peer, asset, rate in ((l2, dear, DEAR_RATE), (l3, cheap, CHEAP_RATE)):
        amounts = [atoms_of(v, rate) for v in values]
        for i, a in enumerate(amounts):
            inv = peer.rpc.invoice(a * 1000, 'h{}'.format(i), 'h')['bolt11']
            executor.submit(l1.rpc.pay, inv)
        wait_for(lambda: [h['state'] for h in chan(l1, peer)['htlcs']]
                 == ['SENT_ADD_ACK_REVOCATION'] * len(amounts))

    trimmed = {}
    for peer, asset, rate in ((l2, dear, DEAR_RATE), (l3, cheap, CHEAP_RATE)):
        amounts = [atoms_of(v, rate) for v in values]
        c = chan(l1, peer)
        print("{}: rate {} ({} reference atoms per atom), feerate {} per kw;"
              " dust limit {} atoms (worth {}) on l1, {} on the peer;"
              " reserves {} / {}".format(
                  'DEAR' if asset == dear else 'CHEAP', rate, ref(1, rate),
                  c['feerate']['perkw'],
                  c['dust_limit_msat'] // 1000,
                  ref(c['dust_limit_msat'] // 1000, rate),
                  chan(peer, l1)['dust_limit_msat'] // 1000,
                  c['our_reserve_msat'] // 1000, c['their_reserve_msat'] // 1000))
        for who, node, other in (('l1', l1, peer), ('peer', peer, l1)):
            commit = node.rpc.dev_sign_last_tx(other.info['id'])['tx']
            kept = htlc_outputs(bitcoind, commit, amounts)
            gone = [ref(a, rate) for a in amounts if a not in kept]
            relay = only_one(bitcoind.rpc.testmempoolaccept([commit]))
            print("  {}'s commitment: HTLCs {} atoms, outputs for {},"
                  " trimmed (reference atoms): {}; relays: {}".format(
                      who, amounts, kept, gone,
                      relay['allowed'] or relay.get('reject-reason')))
            trimmed[('DEAR' if asset == dear else 'CHEAP', who)] = (gone, relay['allowed'])
    assert trimmed == {(a, w): ([400, 600], True)
                       for a in ('DEAR', 'CHEAP') for w in ('l1', 'peer')}

    # The dust limit is worth the reference 546 in both assets (to the atom).
    for peer, rate in ((l2, DEAR_RATE), (l3, CHEAP_RATE)):
        for node, other in ((l1, peer), (peer, l1)):
            dust = chan(node, other)['dust_limit_msat'] // 1000
            assert dust == -(-546 * PAR // rate)

    for n in (l2, l3):
        open(os.path.join(n.daemon.lightning_dir, TEST_NETWORK, 'unhold'), 'w').close()


@pytest.mark.parametrize('value', [200000, 40000])
def test_reserve_refused_at_the_same_value(node_factory, bitcoind, value):
    """Channels worth `value` reference atoms in DEAR and in CHEAP.  The peer,
    paid 4,000 reference atoms, can pay back all but its reserve, and not one
    atom more, and the reserve is worth the same in both assets: 1% of the
    funding at 200,000, the dust limit at 40,000.  A reserve floored at 546
    atoms was worth 5,460 in DEAR and 54.6 in CHEAP, and a channel of 40,000
    in DEAR (4,000 atoms) was under the 10,000-atom minimum capacity."""
    l1, l2, l3, dear, cheap = two_channels(
        node_factory, bitcoind, value,
        opts=[{'feerates': FLOOR}] * 3)
    reserves = {}
    for peer, asset, rate in ((l2, dear, DEAR_RATE), (l3, cheap, CHEAP_RATE)):
        name = 'DEAR' if asset == dear else 'CHEAP'
        paid = atoms_of(4000, rate)
        inv = peer.rpc.invoice(paid * 1000, 'in', 'in')['bolt11']
        l1.rpc.pay(inv)
        wait_for(lambda: chan(peer, l1)['htlcs'] == [])
        c = chan(peer, l1)
        reserve = c['our_reserve_msat'] // 1000
        reserves[name] = ref(reserve, rate)
        print("{}: rate {}; the peer holds {} atoms and must keep {} atoms"
              " (worth {}); spendable {}msat".format(
                  name, rate, c['to_us_msat'] // 1000, reserve,
                  ref(reserve, rate), c['spendable_msat']))
        scid = c['short_channel_id'] if c.get('short_channel_id') else c['alias']['local']
        room = c['to_us_msat'] - reserve * 1000
        results = []
        for amount in (room + 1000, room):
            inv = l1.rpc.call('invoice', {'amount_msat': amount, 'asset': asset,
                                          'label': '{}{}'.format(name, amount),
                                          'description': 'out'})
            route = [{'amount_msat': amount, 'id': l1.info['id'],
                      'delay': 200, 'channel': scid}]
            try:
                peer.rpc.sendpay(route, inv['payment_hash'],
                                 payment_secret=inv['payment_secret'])
                peer.rpc.waitsendpay(inv['payment_hash'])
                results.append('paid')
            except RpcError as e:
                results.append('refused: {}'.format(e.error['message']))
        print("  paying back {} msat (one atom over the room above the reserve):"
              " {}".format(room + 1000, results[0]))
        print("  paying back {} msat: {}".format(room, results[1]))
        line = peer.daemon.wait_for_log(r'cannot afford htlc: would make balance .* below reserve')
        print("  peer's channeld: {}".format(line.split('DEBUG')[-1].strip()))
        assert results[0].startswith('refused')
        assert results[1] == 'paid'
        wait_for(lambda: chan(peer, l1)['to_us_msat'] == reserve * 1000)

    # The same value, to within an atom of DEAR.
    print("reserves in reference atoms:", reserves)
    assert abs(reserves['DEAR'] - reserves['CHEAP']) <= ref(1, DEAR_RATE)


def mock_rates(node, bitcoind, change):
    """Make `node` see the Sequentia node's fee whitelist with `change`
    applied: {asset hex: new rate}."""
    before = node.daemon.rpcproxy.mock_counts.get('getfeeexchangerates', 0)

    def fake(r):
        real = bitcoind.rpc.getfeeexchangerates()
        real.update(change)
        return {'id': r['id'], 'error': None, 'result': real}
    node.daemon.rpcproxy.mock_rpc('getfeeexchangerates', fake)
    wait_for(lambda: node.daemon.rpcproxy.mock_counts['getfeeexchangerates'] >= before + 3)


@pytest.mark.parametrize('fundee_rate,opens', [(9 * CHEAP_RATE // 10, True),
                                               (7 * CHEAP_RATE // 10, False)])
def test_fundee_meets_the_openers_reserve(node_factory, bitcoind, fundee_rate, opens):
    """A CHEAP channel worth 40,000 reference atoms, whose reserve is the
    opener's dust limit (5,460 atoms).  A fundee that values CHEAP 10% lower
    sets a dust limit of 6,067 atoms, above that reserve, which BOLT 2
    forbids: it lowers its dust limit to the reserve, and the channel opens.
    At 30% lower (7,800 atoms) the reserve is under four fifths of its dust
    limit: it refuses the channel."""
    cheap = bitcoind.issue_asset(100000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, cheap: CHEAP_RATE})
    l1, l2 = node_factory.get_nodes(2, opts=[{'feerates': FLOOR},
                                             {'feerates': FLOOR, 'may_reconnect': True}])
    mock_rates(l2, bitcoind, {cheap: fundee_rate})
    funding = atoms_of(40000, CHEAP_RATE)
    addr = l1.rpc.newaddr('bech32')['bech32']
    bitcoind.send_and_mine_block(addr, 2 * funding, cheap)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    args = {'id': l2.info['id'], 'amount': funding, 'asset': cheap, 'announce': False}
    if opens:
        res = l1.rpc.call('fundchannel', args)
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        wait_for(lambda: chan(l1, l2)['state'] == 'CHANNELD_NORMAL')
        line = l2.daemon.is_in_log(r'Lowering our dust limit')
        print("fundee at rate {}: {}".format(fundee_rate, line.split('DEBUG')[-1].strip()))
        print("opener: dust limit {} atoms, requires the fundee to keep {};"
              " fundee: dust limit {} atoms".format(
                  chan(l1, l2)['dust_limit_msat'] // 1000,
                  chan(l1, l2)['their_reserve_msat'] // 1000,
                  chan(l2, l1)['dust_limit_msat'] // 1000))
        assert chan(l2, l1)['dust_limit_msat'] == chan(l1, l2)['their_reserve_msat'] == 5460000
    else:
        with pytest.raises(RpcError, match=r'channel_reserve_satoshis 5460sat is below our dust limit 7800sat'):
            l1.rpc.call('fundchannel', args)
        print("fundee at rate {}: refused: {}".format(
            fundee_rate, l2.daemon.is_in_log(r'channel_reserve_satoshis .* is below').split('DEBUG')[-1].strip()))
