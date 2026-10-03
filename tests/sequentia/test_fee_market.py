"""Channel fees in the open fee market.

Every fee of a channel is paid in the channel asset, and each node values that
asset at its own exchange rate.  These tests hold the fees and the feerate
negotiation to that: a fee is never 0 atoms and always worth the floor; the
policy asset is priced like any other; two peers that value the asset
differently by an ordinary amount keep the channel, and peers that cannot agree
fail it after a second refusal by refreshed rates; a fundee that has no rate
for the asset keeps its limits.  Run
with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, sync_blockheight, wait_for

import os
import pytest
import re
import time

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
# One atom worth 10,000 reference atoms: the relay floor of 253 per kw is 1
# atom per kw, and a transaction under 1000 weight units paid 0 atoms when
# fees were rounded down.
DEAREST = 10**12
FLOOR = (253, 253, 253, 253)
HOLD_TEST_PLUGIN = os.path.join(os.path.dirname(__file__), '..', 'plugins',
                                'hold_invoice.py')


def chan(node, peer):
    return only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])


def fee_of(bitcoind, tx):
    dec = bitcoind.rpc.decoderawtransaction(tx)
    fee = only_one([o for o in dec['vout'] if o['scriptPubKey']['type'] == 'fee'])
    return fee['asset'], int(Decimal(fee['value']) * PAR), dec['vsize'], dec['weight']


def fund(bitcoind, node, atoms, asset=None):
    addr = node.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send_and_mine_block(addr, atoms, asset)
    wait_for(lambda: any(o['txid'] == txid for o in node.rpc.listfunds()['outputs']))


def open_chan(bitcoind, l1, l2, atoms, asset=None):
    fund(bitcoind, l1, 2 * atoms, asset)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    args = {'id': l2.info['id'], 'amount': atoms, 'announce': True}
    if asset:
        args['asset'] = asset
    res = l1.rpc.call('fundchannel', args)
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: chan(a, b)['state'] == 'CHANNELD_NORMAL')


def mock_rates(node, bitcoind, change):
    """Make `node` see the Sequentia node's fee whitelist with `change`
    applied: {asset hex: new rate, or None to drop it}."""
    before = node.daemon.rpcproxy.mock_counts.get('getfeeexchangerates', 0)

    def fake(r):
        real = bitcoind.rpc.getfeeexchangerates()
        for k, v in change.items():
            if v is None:
                real.pop(k, None)
            else:
                real[k] = v
        return {'id': r['id'], 'error': None, 'result': real}
    node.daemon.rpcproxy.mock_rpc('getfeeexchangerates', fake)
    wait_for(lambda: node.daemon.rpcproxy.mock_counts['getfeeexchangerates'] >= before + 3)


def confirm(bitcoind, txid):
    """Wait for `txid` to reach the mempool or a block, then see it in one."""
    def seen():
        try:
            return bitcoind.rpc.getrawtransaction(txid, True)
        except Exception:
            return None
    wait_for(lambda: seen() is not None)
    if not seen().get('confirmations'):
        bitcoind.generate_block(1, wait_for_mempool=txid)
    confs = seen().get('confirmations', 0)
    print("{} confirmed: {} confirmation(s)".format(txid, confs))
    assert confs >= 1


def pay(l1, l2, label, msat=10**6 * 1000):
    inv = l2.rpc.invoice(msat, label, label)['bolt11']
    try:
        l1.rpc.pay(inv)
        return 'paid'
    except RpcError as e:
        return 'failed: {}'.format(e.error.get('message'))


def test_dear_asset_sweep_fee(node_factory, bitcoind):
    """A channel in an asset whose atom is worth 10,000 reference atoms: its
    to_local sweep (807 weight units at 1 atom per kw) pays a fee of at least
    one atom, worth more than the floor, and confirms."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: DEAREST})
    l1, l2 = node_factory.get_nodes(2)
    open_chan(bitcoind, l1, l2, 10**9, gold)
    commit = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']
    asset, atoms, vsize, weight = fee_of(bitcoind, commit)
    print("commitment: fee {} atoms, vsize {}: {}".format(
        atoms, vsize, only_one(bitcoind.rpc.testmempoolaccept([commit]))))
    assert atoms >= 1

    commit_txid = chan(l1, l2)['scratch_txid']
    l1.rpc.dev_fail(l2.info['id'])
    bitcoind.generate_block(1, wait_for_mempool=commit_txid)
    line = l1.daemon.wait_for_log(r'Broadcast for onchaind tx [0-9a-f]+')
    sweep = re.search(r'Broadcast for onchaind tx ([0-9a-f]+)', line).group(1)
    asset, atoms, vsize, weight = fee_of(bitcoind, sweep)
    print("to_local sweep: asset {} fee {} atoms (worth {} reference atoms),"
          " vsize {}, weight {}".format(asset, atoms, atoms * DEAREST // PAR,
                                        vsize, weight))
    assert asset == gold
    assert atoms >= 1
    assert atoms * DEAREST // PAR >= vsize

    # Past to_self_delay the sweep (or onchaind's replacement of it, at a
    # higher feerate as its deadline nears) relays and confirms.
    delay = chan(l1, l2)['their_to_self_delay']
    bitcoind.generate_block(delay - 1, advance_parent=False)
    sync_blockheight(bitcoind, [l1])

    def spender():
        for txid in bitcoind.rpc.getrawmempool():
            d = bitcoind.rpc.getrawtransaction(txid, True)
            if any(v.get('txid') == commit_txid for v in d['vin']):
                return d
        return None
    wait_for(lambda: spender() is not None)
    relayed = spender()
    asset, atoms, vsize, weight = fee_of(bitcoind, relayed['hex'])
    print("sweep in the mempool after {} blocks: fee {} atoms, vsize {}"
          .format(delay - 1, atoms, vsize))
    assert atoms >= 1
    confirm(bitcoind, relayed['txid'])


def test_dear_asset_htlc_timeout_fee(node_factory, bitcoind, executor):
    """The HTLC-timeout transaction of a channel in that asset, at the floor
    feerate: 993 weight units at 1 atom per kw.  It pays at least one atom,
    relays past its locktime, and confirms."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: DEAREST})
    l1, l2 = node_factory.get_nodes(2, opts=[{'may_fail': True, 'broken_log': '.*',
                                              'feerates': FLOOR},
                                             {'plugin': HOLD_TEST_PLUGIN, 'may_fail': True,
                                              'broken_log': '.*', 'feerates': FLOOR}])
    open_chan(bitcoind, l1, l2, 10**9, gold)
    inv = l2.rpc.invoice(10**6 * 1000, 'held', 'held')['bolt11']
    executor.submit(l1.rpc.pay, inv)
    wait_for(lambda: [h['state'] for h in chan(l1, l2)['htlcs']] == ['SENT_ADD_ACK_REVOCATION'])
    l2.daemon.wait_for_log('Calling invoice_payment hook')

    expiry = only_one(chan(l1, l2)['htlcs'])['expiry']
    print("channel feerate:", chan(l1, l2)['feerate'], "HTLC expiry", expiry)
    commit_txid = chan(l1, l2)['scratch_txid']
    l1.rpc.dev_fail(l2.info['id'])
    bitcoind.generate_block(1, wait_for_mempool=commit_txid)
    commit = bitcoind.rpc.getrawtransaction(commit_txid, True)
    bitcoind.generate_block(expiry - bitcoind.rpc.getblockcount() + 1, advance_parent=False)
    sync_blockheight(bitcoind, [l1])
    htlc_n = [o['n'] for o in commit['vout']
              if o['scriptPubKey']['type'] == 'witness_v0_scripthash'
              and int(Decimal(o['value']) * PAR) == 10**6]
    htlc_tx = None
    deadline = time.time() + 120
    while htlc_tx is None and time.time() < deadline:
        l1.daemon.logs_catchup()
        for line in l1.daemon.logs:
            m = re.search(r'Broadcast for onchaind tx ([0-9a-f]+)', line)
            if not m:
                continue
            dec = bitcoind.rpc.decoderawtransaction(m.group(1))
            if any(v.get('txid') == commit_txid and v.get('vout') in htlc_n for v in dec['vin']):
                htlc_tx = m.group(1)
        time.sleep(1)
    assert htlc_tx
    dec = bitcoind.rpc.decoderawtransaction(htlc_tx)
    asset, atoms, vsize, weight = fee_of(bitcoind, htlc_tx)
    print("HTLC-timeout tx: locktime {}, fee {} atoms (worth {} reference atoms),"
          " vsize {}, weight {}".format(dec['locktime'], atoms,
                                        atoms * DEAREST // PAR, vsize, weight))
    assert atoms >= 1
    res = only_one(bitcoind.rpc.testmempoolaccept([htlc_tx]))
    print("HTLC-timeout tx past its locktime:", res)
    assert res['allowed'] or 'already' in res.get('reject-reason', ''), res
    confirm(bitcoind, dec['txid'])


def test_policy_asset_repriced(node_factory, bitcoind, executor):
    """The node prices the policy asset like any asset (open fee market).
    After it reprices the Sequence token to a thousandth of par, a channel in
    it moves its feerate to the new rate, and its commitment relays.  Each
    lightningd polls the rate on its own, so the fundee may judge the opener's
    new feerate by the old rate once: it then refreshes the rate and accepts
    the feerate when the opener sends it again."""
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR})
    l1, l2 = node_factory.get_nodes(2, opts={'may_reconnect': True})
    open_chan(bitcoind, l1, l2, 10**8)
    before = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']
    print("commitment at par:", fee_of(bitcoind, before)[1:3])

    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: 10**5})
    rates = l1.rpc.call('getfeeexchangerates')['rates']
    print("bcli's rates after the reprice:", rates)
    assert rates.get(bitcoind.POLICY_ASSET) == 10**5
    # The opener restates its feerate in the token's atoms at the new rate,
    # with the next commitment.
    executor.submit(pay, l1, l2, 'r1')
    wait_for(lambda: chan(l2, l1)['feerate']['perkw'] > 1000 * 7500, timeout=180)
    assert chan(l2, l1)['state'] == 'CHANNELD_NORMAL'
    print("fundee refusals on the way:",
          [line for line in l2.daemon.logs if 'Refused the peer' in line])
    after = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']
    asset, atoms, vsize, weight = fee_of(bitcoind, after)
    res = only_one(bitcoind.rpc.testmempoolaccept([after]))
    print("commitment after: fee {} atoms (= {} reference atoms at 1e5), vsize {}: {}"
          .format(atoms, atoms * 10**5 / PAR, vsize, res))
    assert res['allowed'], res


def test_rates_diverge_modestly(node_factory, bitcoind):
    """The fundee values the channel asset 20 percent lower than the opener,
    and both nodes' feerates sit at the relay floor, as on a Sequentia
    network.  The channel opens, its feerate moves, and payments go."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2 = node_factory.get_nodes(2, opts={'feerates': FLOOR, 'may_reconnect': True})
    mock_rates(l2, bitcoind, {gold: PAR * 8 // 10})
    open_chan(bitcoind, l1, l2, 10**8, gold)
    for i in range(2):
        assert pay(l1, l2, 'm{}'.format(i)) == 'paid'
    print("fundee feerate log:", [line for line in l2.daemon.logs
                                  if 'update_fee' in line or 'peer updated fee' in line])
    assert not l2.daemon.is_in_log('outside range')
    assert chan(l2, l1)['state'] == 'CHANNELD_NORMAL'


def test_rates_diverge_beyond_the_ceiling(node_factory, bitcoind, executor):
    """Mid-channel, the fundee comes to value the asset at 25 times the
    opener's rate: the opener's next feerate is far above the fundee's
    ceiling.  The fundee refuses it once and refreshes its rates; refused
    again by the fresh rate, it fails the channel, saying why, instead of
    refusing the same update_fee at every reconnect."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2 = node_factory.get_nodes(2, opts={'may_reconnect': True, 'may_fail': True})
    open_chan(bitcoind, l1, l2, 10**8, gold)
    mock_rates(l2, bitcoind, {gold: 25 * PAR})
    # The payment's commitment carries the opener's update_fee; its HTLC is
    # left in the failed channel, so do not wait for the payment.
    executor.submit(pay, l1, l2, 'x1')
    l2.daemon.wait_for_log('Refused the peer\'s update_fee 11005, outside range 11-6000')
    l2.daemon.wait_for_log('update_fee 11005 outside range 11-6000 again, judged by'
                           ' this node\'s fee exchange rates refreshed since the first'
                           ' refusal')
    wait_for(lambda: chan(l2, l1)['state'] != 'CHANNELD_NORMAL')
    time.sleep(20)
    judged = [line for line in l2.daemon.logs if re.search(r'update_fee [0-9]+, range', line)]
    print("fundee judged update_fee {} times: {}".format(len(judged), judged))
    print("states:", chan(l1, l2)['state'], chan(l2, l1)['state'])
    assert chan(l2, l1)['state'] in ('AWAITING_UNILATERAL', 'FUNDING_SPEND_SEEN', 'ONCHAIN')
    # Twice, then no more: the channel failed instead of looping.
    assert len(judged) == 2


def test_fundee_without_rate_keeps_its_limits(node_factory, bitcoind, executor):
    """The fundee no longer has a rate for the channel asset (dropped from its
    whitelist).  Reconnected, it still holds the opener's update_fee to the
    limits its last rate gave."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2 = node_factory.get_nodes(2, opts={'may_reconnect': True, 'may_fail': True})
    open_chan(bitcoind, l1, l2, 10**8, gold)
    assert pay(l1, l2, 'k1') == 'paid'
    mock_rates(l2, bitcoind, {gold: None})
    l2.rpc.disconnect(l1.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.daemon.wait_for_log('No fee exchange rate for the channel asset: holding'
                           ' the peer\'s feerate to the last limits')
    wait_for(lambda: chan(l2, l1)['peer_connected'] and chan(l2, l1).get('owner') == 'channeld')
    # The opener's estimates climb (smoothed) towards 1,500,000 per kw; it
    # restates its feerate as they do.
    l1.set_feerates((1500000, 1500000, 1500000, 1500000), wait_for_effect=False)
    executor.submit(pay, l1, l2, 'k2')
    l2.daemon.wait_for_log('outside range 253-150000 again')
    accepted = [int(m.group(1)) for m in
                (re.search(r'peer updated fee to ([0-9]+)', line) for line in l2.daemon.logs) if m]
    print("fundee accepted feerates {}, then refused: {}".format(
        accepted, [line for line in l2.daemon.logs if 'outside range' in line][:2]))
    assert max(accepted) <= 150000
    wait_for(lambda: chan(l2, l1)['state'] != 'CHANNELD_NORMAL')


def test_fundee_restarted_without_rate_holds_the_feerate(node_factory, bitcoind, executor):
    """Restarted with no rate for the channel asset, the fundee has no limits
    of its own to hold: it keeps the feerate where it is."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2 = node_factory.get_nodes(2, opts={'may_reconnect': True, 'may_fail': True})
    open_chan(bitcoind, l1, l2, 10**8, gold)
    assert pay(l1, l2, 'h1') == 'paid'
    current = chan(l2, l1)['feerate']['perkw']

    def no_gold(r):
        real = bitcoind.rpc.getfeeexchangerates()
        real.pop(gold, None)
        return {'id': r['id'], 'error': None, 'result': real}
    l2.daemon.rpcproxy.mock_rpc('getfeeexchangerates', no_gold)
    l2.restart()
    l2.daemon.logs_catchup()
    start = len(l2.daemon.logs)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.daemon.wait_for_log('No fee exchange rate for the channel asset: holding'
                           ' the feerate at {}'.format(current))
    l1.set_feerates((20000, 15000, 10000, 5000), wait_for_effect=False)
    executor.submit(pay, l1, l2, 'h2')
    l2.daemon.wait_for_log('outside range {}-{} again'.format(current, current))
    print("restarted fundee:", [line for line in l2.daemon.logs[start:] if 'outside range' in line][:2])
    moved = [int(m.group(1)) for m in
             (re.search(r'peer updated fee to ([0-9]+)', line) for line in l2.daemon.logs[start:]) if m]
    assert set(moved) <= {current}, moved
    wait_for(lambda: chan(l2, l1)['state'] != 'CHANNELD_NORMAL')
