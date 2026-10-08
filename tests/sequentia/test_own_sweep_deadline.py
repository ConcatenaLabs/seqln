"""The sweep of a node's own delayed output after a unilateral close.

The output cannot be spent before the delay (to_self_delay) has run, which on
a Sequentia network is about a day of blocks.  The sweeper aims at a deadline
past that, so its first attempt is made when the delay has run, at a low
feerate, and it raises the feerate block by block from there as the deadline
nears, rather than bidding the most for a block the output cannot be in.  Run
with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK, only_one, sync_blockheight, wait_for

import pytest
import re

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
FEERATE_LINE = re.compile(r'Feerate for target (\d+) \(([+-]\d+) blocks\) is (\d+)'
                          r' \((\d+) in the channel asset\), fee (\d+)sat of (\d+)sat')


def chan(node, peer):
    return only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])


def sweep_feerates(node, start):
    """(height, target, blocks to it, feerate) for each fee the sweeper
    priced since log line `start`."""
    node.daemon.logs_catchup()
    out = []
    for line in node.daemon.logs[start:]:
        m = FEERATE_LINE.search(line)
        if m:
            out.append((int(m.group(1)) - int(m.group(2)), int(m.group(1)),
                        int(m.group(2)), int(m.group(3))))
    return out


def test_own_delayed_sweep_waits_for_its_delay(node_factory, bitcoind):
    """l1 force-closes a GOLD channel.  Its to_local waits 1,440 blocks.  The
    sweep is priced at the floor when the delay has run, held out of the
    mempool for 281 blocks while its feerate rises toward the deadline, then
    confirms; it is never priced at the feerate for the next block."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2 = node_factory.get_nodes(2)
    addr = l1.rpc.newaddr('bech32')['bech32']
    bitcoind.send_and_mine_block(addr, 2 * 10**7, gold)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': 10**7,
                                      'asset': gold, 'announce': False})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    wait_for(lambda: chan(l1, l2)['state'] == 'CHANNELD_NORMAL')
    feerates = l1.rpc.feerates('perkw')['perkw']
    urgent = max(e['feerate'] for e in feerates['estimates'])
    print("node feerates (perkw):", [(e['blockcount'], e['feerate'])
                                     for e in feerates['estimates']],
          "floor", feerates['floor'])

    delay = chan(l1, l2)['their_to_self_delay']
    commit_txid = chan(l1, l2)['scratch_txid']
    l1.daemon.logs_catchup()
    start = len(l1.daemon.logs)
    l1.rpc.dev_fail(l2.info['id'])
    bitcoind.generate_block(1, wait_for_mempool=commit_txid)
    close_height = bitcoind.rpc.getblockcount()
    l1.daemon.wait_for_log(r'Deferring broadcast of txid [0-9a-f]+ until block')
    print("commitment confirmed at {}; to_local waits {} blocks, spendable"
          " in block {}".format(close_height, delay, close_height + delay))

    # Hold every transaction l1 sends out of the mempool, so the sweep stays
    # unconfirmed while the chain moves on.
    def held(r):
        return {'id': r['id'], 'result': None,
                'error': {'code': -26, 'message': 'held back by the test'}}
    l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', held)
    bitcoind.generate_block(delay - 2, advance_parent=False)
    sync_blockheight(bitcoind, [l1])
    # From the block before the output can be spent, ten blocks at a time,
    # each priced by the sweeper before the next.
    for _ in range(29):
        bitcoind.generate_block(10 if _ else 1, advance_parent=False)
        sync_blockheight(bitcoind, [l1])
        last = bitcoind.rpc.getblockcount()
        wait_for(lambda: any(s[0] >= last for s in sweep_feerates(l1, start)))
    l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', None)

    def spender():
        for txid in bitcoind.rpc.getrawmempool():
            d = bitcoind.rpc.getrawtransaction(txid, True)
            if any(v.get('txid') == commit_txid for v in d['vin']):
                return d
        return None
    bitcoind.generate_block(1, advance_parent=False)
    wait_for(lambda: spender() is not None)
    sweep = spender()
    fee = only_one([o for o in sweep['vout'] if o['scriptPubKey']['type'] == 'fee'])
    fee_atoms = int(Decimal(fee['value']) * PAR)
    bitcoind.generate_block(1, wait_for_mempool=sweep['txid'], advance_parent=False)
    assert bitcoind.rpc.getrawtransaction(sweep['txid'], True)['confirmations'] >= 1

    seq = sweep_feerates(l1, start)
    print("the sweeper's feerates (height, target, blocks to target, perkw):")
    for s in seq:
        print("  ", s)
    print("sweep {} confirmed: fee {} atoms, weight {} ({} perkw); the urgent"
          " feerate is {}".format(sweep['txid'], fee_atoms, sweep['weight'],
                                  fee_atoms * 1000 // sweep['weight'], urgent))

    spendable_from = close_height + delay - 1
    attempts = [s for s in seq if s[0] >= spendable_from]
    assert attempts, "no attempt once the delay had run"
    # The first attempt is at the floor, its deadline well ahead...
    assert attempts[0][2] > 200
    # ...the feerate only rises from there...
    assert all(b[3] >= a[3] for a, b in zip(attempts, attempts[1:]))
    assert attempts[-1][3] > attempts[0][3]
    # ...and is never the feerate for the next block.
    assert all(s[2] > 0 and s[3] < urgent for s in seq)
    assert fee_atoms * 1000 // sweep['weight'] < urgent
