"""What a peer's commitment pays this node is in the channel's asset.

When a channel closes with the peer's commitment, onchaind hands the output
that pays this node to the wallet itself (it is not to an address the wallet
watches).  On a Sequentia network that output is in the channel's asset, like
every output of the commitment: the wallet must record it so, list it so, and
spend it in that asset.  Run with TEST_NETWORK=sequentia-regtest (README.md,
"Testing").
"""
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK, only_one, sync_blockheight, wait_for

import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8


def test_peer_commitment_pays_in_channel_asset(node_factory, bitcoind):
    """l1 opens a channel in an issued asset to l2 and pays it.  l2 goes
    away; l1 closes with its commitment, which confirms.  Back, l2 lists the
    output that pays it in the asset, and spends it to an address in the
    asset."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, asset: PAR})
    l1, l2 = node_factory.get_nodes(2, opts={'may_reconnect': True})
    addr = l1.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send_and_mine_block(addr, 2 * PAR, asset)
    wait_for(lambda: any(o['txid'] == txid for o in l1.rpc.listfunds()['outputs']))
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': 10**7,
                                      'asset': asset, 'announce': True})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')
    inv = l2.rpc.invoice(3 * 10**6 * 1000, 'in', 'in')['bolt11']
    l1.rpc.pay(inv)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

    l2.stop()
    commitment = only_one(l1.rpc.close(l2.info['id'], unilateraltimeout=1)['txids'])
    bitcoind.generate_block(1, wait_for_mempool=commitment)
    l2.start()
    wait_for(lambda: only_one(l2.rpc.listpeerchannels()['channels'])['state'] == 'ONCHAIN')
    wait_for(lambda: any(o['txid'] == commitment for o in l2.rpc.listfunds()['outputs']))
    out = only_one([o for o in l2.rpc.listfunds()['outputs'] if o['txid'] == commitment])
    print('the commitment pays l2:', out)
    assert out['asset'] == asset
    assert out['amount_msat'] == 3 * 10**6 * 1000

    # The wallet spends it in the asset (fee and change in it too).
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l2])
    dest = bitcoind.getnewaddress()
    res = l2.rpc.call('fundpsbt', {'satoshi': 'all', 'feerate': 'normal',
                                   'startweight': 1000, 'asset': asset})
    psbt = l2.rpc.call('addpsbtoutput', {'satoshi': res['excess_msat'] // 1000,
                                         'initialpsbt': res['psbt'],
                                         'destination': dest, 'asset': asset})['psbt']
    spent = l2.rpc.sendpsbt(l2.rpc.signpsbt(psbt)['signed_psbt'])['txid']
    bitcoind.generate_block(1, wait_for_mempool=spent)
    tx = bitcoind.rpc.getrawtransaction(spent, True)
    assert any(i['txid'] == commitment for i in tx['vin'])
    paid = only_one([v for v in tx['vout'] if v['scriptPubKey'].get('address') == dest])
    assert paid['asset'] == asset
