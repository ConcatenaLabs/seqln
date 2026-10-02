"""SeqLN on a Sequentia chain whose headers carry Bitcoin anchors.

Run with TEST_NETWORK=sequentia-regtest, with `sequentiad`/`sequentia-cli` and
a Bitcoin Core `bitcoind` on PATH (README.md, "Testing").  The `bitcoind`
fixture is then a SequentiaD: a committee-certified chain anchored to a
Bitcoin regtest node, `bitcoind.parent`.
"""
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK, only_one, sync_blockheight, wait_for

import pytest
import time

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8


def fund_asset(bitcoind, node, asset, atoms):
    """Send `atoms` of `asset` to `node`'s wallet and wait until it sees them."""
    addr = node.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send_and_mine_block(addr, atoms, asset)
    wait_for(lambda: any(o['txid'] == txid for o in node.rpc.listfunds()['outputs']))


def open_channel(bitcoind, l1, l2, atoms, asset=None, **kwargs):
    """Open an announced channel from l1 to l2 and confirm its funding in one
    block.  Returns the funding txid."""
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    args = {'id': l2.info['id'], 'amount': atoms, 'announce': True}
    if asset:
        args['asset'] = asset
    args.update(kwargs)
    res = l1.rpc.call('fundchannel', args)
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    return res['txid']


def channel(node, peer):
    return only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])


def test_sequentia_defaults(node_factory, bitcoind):
    """A node on a Sequentia network runs the network's timelock and rescan
    defaults, not Bitcoin's."""
    l1 = node_factory.get_node()
    configs = l1.rpc.listconfigs()['configs']
    assert configs['funding-confirms']['value_int'] == 1
    assert configs['watchtime-blocks']['value_int'] == 1440
    assert configs['cltv-delta']['value_int'] == 270
    assert configs['cltv-final']['value_int'] == 180
    assert configs['rescan']['value_int'] == -1
    assert l1.rpc.getinfo()['network'] == 'sequentia-regtest'


def test_asset_channel_pay_close(node_factory, bitcoind):
    """Two nodes open a channel in an issued asset, pay over it and close it.
    Every transaction of the channel is in the asset, its fee included."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    # Started after the rates are set, so their first read already has them.
    l1, l2 = node_factory.get_nodes(2)

    # The opener holds only the asset: nothing falls back to the policy asset.
    fund_asset(bitcoind, l1, gold, 20 * 10**8)
    funding_txid = open_channel(bitcoind, l1, l2, 10**8, asset=gold)

    wait_for(lambda: channel(l1, l2)['state'] == 'CHANNELD_NORMAL')
    wait_for(lambda: channel(l2, l1)['state'] == 'CHANNELD_NORMAL')
    assert channel(l1, l2)['channel_asset'] == gold
    assert channel(l2, l1)['channel_asset'] == gold
    # The network's to_self_delay, both ways.
    assert channel(l1, l2)['our_to_self_delay'] == 1440
    assert channel(l1, l2)['their_to_self_delay'] == 1440

    funding = bitcoind.rpc.getrawtransaction(funding_txid, True)
    assert {o['asset'] for o in funding['vout']} == {gold}

    inv = l2.rpc.invoice(5_000_000, 'pay-gold', 'gold payment')
    l1.rpc.call('pay', {'bolt11': inv['bolt11'], 'asset': gold})
    wait_for(lambda: l2.rpc.listinvoices('pay-gold')['invoices'][0]['status'] == 'paid')
    wait_for(lambda: channel(l2, l1)['to_us_msat'] == 5_000_000)

    res = l1.rpc.close(l2.info['id'])
    assert res['type'] == 'mutual'
    closing_txid = only_one(res['txids'])
    bitcoind.generate_block(1, wait_for_mempool=closing_txid)
    closing = bitcoind.rpc.getrawtransaction(closing_txid, True)
    assert {o['asset'] for o in closing['vout']} == {gold}
    # The payee's 5,000 atoms come back to its wallet in the asset.
    wait_for(lambda: any(o.get('asset') == gold and o['amount_msat'] == 5_000_000
                         and o['status'] == 'confirmed'
                         for o in l2.rpc.listfunds()['outputs']))


def test_burial_gate_holds_announcement(node_factory, bitcoind):
    """A channel is usable at certified depth 1, but its announcement waits
    until the funding block's Bitcoin anchor is buried by two parent blocks,
    however many certified Sequentia blocks pile up on top of it."""
    l1, l2 = node_factory.get_nodes(2)
    fund_asset(bitcoind, l1, bitcoind.POLICY_ASSET, 10**8)
    open_channel(bitcoind, l1, l2, 10**7)
    wait_for(lambda: channel(l1, l2)['state'] == 'CHANNELD_NORMAL')
    scid = channel(l1, l2)['short_channel_id']

    # Well past the announcement depth of 6, with the parent standing still.
    bitcoind.generate_block(10, advance_parent=False)
    sync_blockheight(bitcoind, [l1, l2])
    # One parent block buries the anchor by one: still not enough.
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2])
    time.sleep(5)
    assert l1.rpc.listchannels(scid)['channels'] == []
    assert l2.rpc.listchannels(scid)['channels'] == []

    # The payment path does not need the announcement.
    inv = l2.rpc.invoice(1_000_000, 'unannounced', 'paid before announcement')
    l1.rpc.pay(inv['bolt11'])

    # The second parent block buries it.
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listchannels(scid)['channels']) == 2)
    wait_for(lambda: len(l2.rpc.listchannels(scid)['channels']) == 2)


def test_certified_frontier_clamp(node_factory, bitcoind):
    """SeqLN counts only committee-certified blocks.  A block certified by
    fewer than quorum (accepted only under the escaping stall) is not part of
    the chain SeqLN sees until a certified block lands on top of it."""
    l1 = node_factory.get_node()

    # Fill the parent's median-time-past window at Bitcoin's cadence, anchor a
    # certified block to it, then advance the parent three more blocks: the
    # escaping stall now accepts a sub-quorum block.
    bitcoind.mine_parent(12, spacing=600)
    bitcoind.generate_block(1, advance_parent=False)
    certified = bitcoind.rpc.getblockcount()
    sync_blockheight(bitcoind, [l1])
    bitcoind.mine_parent(3, spacing=600)
    weak = bitcoind.generate_uncertified_block()
    hdr = bitcoind.rpc.getblockheader(weak)
    assert hdr['height'] == certified + 1
    assert hdr['poscertified'] is False

    # SeqLN polls every second; give it several polls.
    time.sleep(5)
    assert l1.rpc.getinfo()['blockheight'] == certified

    # A certified block on top moves the frontier past both.
    bitcoind.generate_block(1, advance_parent=False)
    wait_for(lambda: l1.rpc.getinfo()['blockheight'] == certified + 2)


def test_bitcoin_reorg_reorgs_sequentia(node_factory, bitcoind):
    """When the parent chain reorganizes away a block that Sequentia blocks
    anchor to, those Sequentia blocks go too, and SeqLN follows."""
    l1 = node_factory.get_node()
    bitcoind.generate_block(3)
    sync_blockheight(bitcoind, [l1])
    base = bitcoind.rpc.getblockcount()

    # Two Sequentia blocks anchored to a fresh parent block.
    orphan = bitcoind.mine_parent(1)[0]
    gone = bitcoind.generate_block(2, advance_parent=False)
    sync_blockheight(bitcoind, [l1])
    assert l1.rpc.getinfo()['blockheight'] == base + 2

    # The parent drops that block for a longer branch; the Sequentia node
    # discards both blocks anchored to it.
    bitcoind.parent.rpc.invalidateblock(orphan)
    bitcoind.mine_parent(2)
    wait_for(lambda: bitcoind.rpc.getblockcount() == base)

    # Once the new branch is longer, SeqLN unwinds the stale blocks.
    new = bitcoind.generate_block(3, advance_parent=False)
    assert not set(new) & set(gone)
    l1.daemon.wait_for_logs([r'Removing stale block {}: {}'.format(base + 2, gone[1]),
                             r'Removing stale block {}: {}'.format(base + 1, gone[0])])
    sync_blockheight(bitcoind, [l1])
