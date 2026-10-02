"""On-chain fees of a channel in an asset not priced at par.

A channel's transactions pay their fee in the channel asset.  The fee must be
worth what the network asks, valued through the node's exchange rate for that
asset: fee_atoms = ceil(policy_fee * 10^8 / rate).  Run with
TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK, only_one, sync_blockheight, wait_for

import pytest
import re

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
# One atom of CHEAP is worth a thousandth of a reference atom; one atom of
# DEAR is worth a hundred.
CHEAP = 10**5
DEAR = 10**10


def asset_channel(node_factory, bitcoind, rate, atoms):
    """Two nodes with an announced channel of `atoms` in a fresh asset priced
    at `rate`, opened by l1."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, asset: rate})
    l1, l2 = node_factory.get_nodes(2)

    addr = l1.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send_and_mine_block(addr, 2 * atoms, asset)
    wait_for(lambda: any(o['txid'] == txid for o in l1.rpc.listfunds()['outputs']))

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': atoms,
                                      'asset': asset, 'announce': True})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')
    return l1, l2, asset


def fee_value(bitcoind, tx, asset, rate):
    """The explicit fee of `tx`, in the asset, and its value in reference
    atoms at `rate`; plus its virtual size."""
    dec = bitcoind.rpc.decoderawtransaction(tx)
    fee = only_one([o for o in dec['vout'] if o['scriptPubKey']['type'] == 'fee'])
    assert fee['asset'] == asset
    atoms = int(Decimal(fee['value']) * PAR)
    return atoms, atoms * rate / PAR, dec['vsize']


def policy_fee(node, vsize, kind):
    """What a transaction of `vsize` vbytes pays at the node's `kind`
    feerate, in reference atoms."""
    perkb = node.rpc.feerates('perkb')['perkb'][kind]
    return perkb * vsize / 1000


@pytest.mark.parametrize('rate', [CHEAP, DEAR], ids=['cheap', 'dear'])
def test_commitment_fee_follows_exchange_rate(node_factory, bitcoind, rate):
    """The commitment of an asset channel pays the network's fee in value: an
    asset worth little pays more atoms, an asset worth much pays fewer.  The
    node accepts it, and it does not overpay."""
    l1, l2, asset = asset_channel(node_factory, bitcoind, rate, 10**9)

    tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']
    atoms, value, vsize = fee_value(bitcoind, tx, asset, rate)
    want = policy_fee(l1, vsize, 'unilateral_close')
    print("commitment: {} vB, fee {} atoms = {} reference atoms, policy fee {}"
          .format(vsize, atoms, value, want))

    accept = only_one(bitcoind.rpc.testmempoolaccept([tx]))
    assert accept['allowed'], accept
    assert want / 2 <= value <= want * 2


def test_sweep_fee_follows_exchange_rate(node_factory, bitcoind):
    """A unilateral close of a cheap-asset channel reaches the chain, and the
    sweep of its delayed output after to_self_delay pays the network's fee in
    value too."""
    l1, l2, asset = asset_channel(node_factory, bitcoind, CHEAP, 10**9)

    commit_txid = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['scratch_txid']
    l1.rpc.dev_fail(l2.info['id'])
    bitcoind.generate_block(1, wait_for_mempool=commit_txid)

    # onchaind builds the sweep as soon as the commitment confirms and holds
    # it until to_self_delay has passed.
    line = l1.daemon.wait_for_log(r'Broadcast for onchaind tx [0-9a-f]+')
    sweep_tx = re.search(r'Broadcast for onchaind tx ([0-9a-f]+)', line).group(1)
    atoms, value, vsize = fee_value(bitcoind, sweep_tx, asset, CHEAP)
    # A sweep with a distant deadline may pay as little as the floor, but
    # never less, in value.
    floor = policy_fee(l1, vsize, 'floor')
    high = policy_fee(l1, vsize, 'unilateral_close')
    print("sweep: {} vB, fee {} atoms = {} reference atoms, floor {}, unilateral {}"
          .format(vsize, atoms, value, floor, high))
    assert floor <= value <= high * 2

    delay = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['their_to_self_delay']
    bitcoind.generate_block(delay, advance_parent=False)
    sync_blockheight(bitcoind, [l1])
    # By now the sweep is past its deadline and lightningd has replaced it
    # at a higher feerate, still in the asset: whichever version is in the
    # mempool, the node relayed it.
    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: any(o.get('asset') == asset and o['status'] == 'confirmed'
                         and o['amount_msat'] > 10**8 * 1000
                         for o in l1.rpc.listfunds()['outputs']))
