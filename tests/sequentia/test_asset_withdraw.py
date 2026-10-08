"""The wallet moves a coin in any asset, paying the fee in that asset.

`withdraw`, `txprepare` and `utxopsbt` take the asset being moved (`asset`,
its display id); without it they move the asset of their inputs, never paying
the fee in another.  The coin here is what a peer's commitment paid this
node in the channel's asset, at a fee rate other than par, so the fee is
valued at that asset's rate.  A database whose close outputs were recorded
without their channel's asset is given it at the upgrade.

Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, sync_blockheight, wait_for

import os
import pytest
import sqlite3

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
# The issued asset's fee rate: worth twice the reference unit, so a fee in it
# is half as many atoms as the same fee in the policy asset.
RATE = 2 * PAR
CAP = 10**7
PAY = 3 * 10**6


def close_output(bitcoind, node_factory):
    """l1 opens a channel in an issued asset to l2 and pays it PAY; l1 closes
    with its commitment while l2 is away.  Returns (asset, l1, l2, the
    commitment's txid, the output it pays l2)."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, asset: RATE})
    l1, l2 = node_factory.get_nodes(2, opts={'may_reconnect': True})
    addr = l1.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send_and_mine_block(addr, 2 * CAP, asset)
    wait_for(lambda: any(o['txid'] == txid for o in l1.rpc.listfunds()['outputs']))
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': CAP,
                                      'asset': asset, 'announce': True})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')
    l1.rpc.pay(l2.rpc.invoice(PAY * 1000, 'in', 'in')['bolt11'])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])
    l2.stop()
    commitment = only_one(l1.rpc.close(l2.info['id'], unilateraltimeout=1)['txids'])
    bitcoind.generate_block(1, wait_for_mempool=commitment)
    l2.start()
    wait_for(lambda: any(o['txid'] == commitment for o in l2.rpc.listfunds()['outputs']))
    out = only_one([o for o in l2.rpc.listfunds()['outputs'] if o['txid'] == commitment])
    # The peer's commitment pays after one block (CSV 1) on an anchor channel.
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l2])
    return asset, l1, l2, commitment, out


def confirmed_in_asset(bitcoind, txid, dest, asset):
    bitcoind.generate_block(1, wait_for_mempool=txid)
    tx = bitcoind.rpc.getrawtransaction(txid, True)
    paid = only_one([v for v in tx['vout'] if v['scriptPubKey'].get('address') == dest])
    fee = only_one([v for v in tx['vout'] if v['scriptPubKey']['type'] == 'fee'])
    assert {v['asset'] for v in tx['vout']} == {asset}, tx['vout']
    return tx, paid, fee


def test_withdraw_in_the_asset(node_factory, bitcoind):
    """withdraw: with the asset named; with the coin named and no asset; and
    without either, which moves only the policy asset."""
    asset, l1, l2, commitment, out = close_output(bitcoind, node_factory)
    utxo = '{}:{}'.format(commitment, out['output'])

    # Named neither: the policy asset, of which l2 holds none.
    with pytest.raises(RpcError, match='Could not afford'):
        l2.rpc.withdraw(bitcoind.getnewaddress(), 'all')
    # Named an asset l2 does not hold the coin in.
    with pytest.raises(RpcError, match='is in asset {}, not {}'.format(asset, bitcoind.POLICY_ASSET)):
        l2.rpc.call('withdraw', {'destination': bitcoind.getnewaddress(), 'satoshi': 'all',
                                 'utxos': [utxo], 'asset': bitcoind.POLICY_ASSET})

    # The coin named: its asset.
    dest = bitcoind.getnewaddress()
    res = l2.rpc.call('withdraw', {'destination': dest, 'satoshi': 'all', 'utxos': [utxo]})
    tx, paid, fee = confirmed_in_asset(bitcoind, res['txid'], dest, asset)
    print('withdraw utxos=[close output] paid {} {} with a fee of {} atoms of it'
          .format(paid['value'], asset, round(fee['value'] * 10**8)))
    assert any(i['txid'] == commitment for i in tx['vin'])
    assert round((paid['value'] + fee['value']) * 10**8) == PAY


def test_txprepare_and_utxopsbt_in_the_asset(node_factory, bitcoind):
    """txprepare/txsend with the asset named, and utxopsbt, each spend the
    coin in its asset; utxopsbt refuses coins of two assets."""
    asset, l1, l2, commitment, out = close_output(bitcoind, node_factory)
    utxo = '{}:{}'.format(commitment, out['output'])

    # utxopsbt, no asset named: the coin's asset pays the fee.
    res = l2.rpc.call('utxopsbt', {'satoshi': 'all', 'feerate': 'normal', 'startweight': 1000,
                                   'utxos': [utxo], 'reserve': 0})
    outs = bitcoind.rpc.decodepsbt(res['psbt'])['outputs']
    print('utxopsbt of the close output: excess {}, outputs {}'.format(res['excess_msat'], outs))
    assert {o['asset'] for o in outs} == {asset}
    with pytest.raises(RpcError, match='is in asset {}, not {}'.format(asset, bitcoind.POLICY_ASSET)):
        l2.rpc.call('utxopsbt', {'satoshi': 'all', 'feerate': 'normal', 'startweight': 1000,
                                 'utxos': [utxo], 'asset': bitcoind.POLICY_ASSET})

    # A coin of another asset beside it: one transaction moves one asset.
    addr = l2.rpc.newaddr('bech32')['bech32']
    other = bitcoind.send_and_mine_block(addr, 10**6)
    wait_for(lambda: any(o['txid'] == other for o in l2.rpc.listfunds()['outputs']))
    o2 = only_one([o for o in l2.rpc.listfunds()['outputs'] if o['txid'] == other])
    with pytest.raises(RpcError, match='a transaction moves one asset'):
        l2.rpc.call('utxopsbt', {'satoshi': 'all', 'feerate': 'normal', 'startweight': 1000,
                                 'utxos': [utxo, '{}:{}'.format(other, o2['output'])]})

    # txprepare with the asset named, then txsend.
    dest = bitcoind.getnewaddress()
    prep = l2.rpc.call('txprepare', {'outputs': [{dest: 'all'}], 'asset': asset})
    sent = l2.rpc.txsend(prep['txid'])
    tx, paid, fee = confirmed_in_asset(bitcoind, sent['txid'], dest, asset)
    print('txprepare asset= paid {} with a fee of {} atoms'.format(
        paid['value'], round(fee['value'] * 10**8)))
    assert any(i['txid'] == commitment for i in tx['vin'])


def test_close_output_asset_migration(node_factory, bitcoind):
    """A database whose close output was recorded without its channel's
    asset (as before the wallet noted it) reads it back as the policy asset;
    the upgrade gives it the channel's asset, and the coin is spent in it."""
    asset, l1, l2, commitment, out = close_output(bitcoind, node_factory)
    assert out['asset'] == asset
    db_path = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'lightningd.sqlite3')

    def query(sql, *args):
        db = sqlite3.connect(db_path)
        try:
            r = db.execute(sql, args).fetchall()
            db.commit()
            return r
        finally:
            db.close()

    l2.stop()
    n = query("UPDATE outputs SET asset=NULL WHERE channel_id IS NOT NULL")
    assert query("SELECT count(*) FROM outputs WHERE asset IS NULL AND channel_id IS NOT NULL")[0][0] == 1
    l2.start()
    before = only_one([o for o in l2.rpc.listfunds()['outputs'] if o['txid'] == commitment])
    print('the row without an asset reads as', before['asset'])
    assert before['asset'] == bitcoind.POLICY_ASSET
    assert n == []

    # A database from before the upgrade: back to the version before the
    # migration that fills the asset in.  The migrations after it add the
    # penalty_htlcs second-stage columns, which such a database lacks too.
    l2.stop()
    version = query("SELECT version FROM version")[0][0]
    later = ('stage2_txid', 'stage2_amount')
    for column in later:
        query("ALTER TABLE penalty_htlcs DROP COLUMN {}".format(column))
    back = version - 1 - len(later)
    query("UPDATE version SET version=?", back)
    l2.daemon.opts['database-upgrade'] = 'true'
    l2.start()
    with open(os.path.join(l2.daemon.lightning_dir, 'log')) as f:
        log = f.read()
    assert 'Updating database from version {} to {}'.format(back, version) in log
    assert "Gave 1 close output(s) their channel's asset" in log
    assert query("SELECT version FROM version")[0][0] == version
    after = only_one([o for o in l2.rpc.listfunds()['outputs'] if o['txid'] == commitment])
    print('after the upgrade it reads as', after['asset'])
    assert after['asset'] == asset

    dest = bitcoind.getnewaddress()
    res = l2.rpc.call('withdraw', {'destination': dest, 'satoshi': 'all', 'asset': asset})
    confirmed_in_asset(bitcoind, res['txid'], dest, asset)
