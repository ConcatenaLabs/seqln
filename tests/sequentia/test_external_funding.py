"""A channel funded by a transaction its opener's node did not build.

A web wallet opens its hosted node's channels with its own coins in one
transaction, not a deposit to the node followed by the node's own funding:
`fundchannel_start` on the node, a funding transaction the wallet builds and
blinds, `fundchannel_complete` with it UNSIGNED, so the peer's signature on
the first commitment (the way back) exists before any coin moves, and only
then the wallet signs and broadcasts.

On Elements the txid is fixed once the transaction is blinded: signing adds
witnesses only.  So the change can stay confidential; the output to the 2-of-2
is explicit, as every funding output is.

Elements gives `fundchannel_complete` nothing to check that output's amount
against, and it does not: a funder that pays the 2-of-2 less than it announced
gets commitments that can never spend it.  Whoever hands the node an outside
transaction must check the amount and the asset first.

Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK, only_one, wait_for

import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8


def channel(node, peer):
    return only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])


def segwit_coin(bitcoind, atoms):
    """A policy-asset coin of the outside wallet on a segwit address.  The
    regtest wallet's first coins are OP_TRUE outputs, whose spending txid is
    unknown until signed; a web wallet's coins are all segwit."""
    txid = bitcoind.send_and_mine_block(bitcoind.rpc.getnewaddress(), atoms)
    return only_one([{'txid': u['txid'], 'vout': u['vout']}
                     for u in bitcoind.rpc.listunspent()
                     if u['txid'] == txid and u['amount'] == atoms / PAR])


def outside_funding(bitcoind, addr, atoms, asset, fee_asset, inputs=None):
    """The outside wallet's funding transaction, blinded and unsigned: `atoms`
    of `asset` to `addr`, the change confidential, the fee in `fee_asset`."""
    # Confidential change, as a web wallet's always is (the regtest wallet's
    # addresses are explicit by default).
    change = bitcoind.rpc.getaddressinfo(bitcoind.rpc.getnewaddress())['confidential']
    opts = {'fee_asset': fee_asset, 'change_address': change}
    if inputs:
        opts['add_inputs'] = False
    funded = bitcoind.rpc.walletcreatefundedpsbt(
        inputs or [], [{addr: atoms / PAR, 'asset': asset}], 0, opts)
    return bitcoind.rpc.walletprocesspsbt(funded['psbt'], False)['psbt']


@pytest.mark.parametrize('issued', [False, True], ids=['policy-asset', 'issued-asset'])
def test_channel_funded_from_outside(node_factory, bitcoind, issued):
    if issued:
        asset = bitcoind.issue_asset(1000)
        bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, asset: PAR})
    else:
        asset = bitcoind.POLICY_ASSET
    l1, l2 = node_factory.get_nodes(2)

    # The opener's node holds nothing: every coin comes from the outside wallet.
    assert l1.rpc.listfunds()['outputs'] == []
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    atoms = PAR
    start = l1.rpc.call('fundchannel_start', {'id': l2.info['id'], 'amount': atoms,
                                              'asset': asset, 'announce': False})
    addr = start['funding_address']

    # An issued-asset channel's funding pays its fee in the asset too: the
    # outside wallet need not hold the policy asset at all.
    inputs = None if issued else [segwit_coin(bitcoind, 2 * atoms)]
    psbt = outside_funding(bitcoind, addr, atoms, asset, asset, inputs)
    decoded = bitcoind.rpc.decodepsbt(psbt)
    to_channel = [o for o in decoded['outputs']
                  if o.get('script', {}).get('address') == addr]
    assert len(to_channel) == 1
    assert to_channel[0]['amount'] == atoms / PAR
    assert to_channel[0]['asset'] == asset

    # The way back first: the node completes with the transaction unsigned.
    done = l1.rpc.call('fundchannel_complete', {'id': l2.info['id'], 'psbt': psbt})
    assert done['commitments_secured']
    txid = channel(l1, l2)['funding_txid']

    # Only now does the wallet sign and broadcast, and the txid is the one
    # the node already holds commitments for.
    signed = bitcoind.rpc.walletprocesspsbt(psbt)['psbt']
    final = bitcoind.rpc.finalizepsbt(signed)
    assert final['complete']
    assert bitcoind.rpc.sendrawtransaction(final['hex']) == txid
    # ...though its change was blinded: confidential, and the txid unmoved.
    vout = bitcoind.rpc.getrawtransaction(txid, True)['vout']
    assert any('valuecommitment' in o for o in vout)
    bitcoind.generate_block(1, wait_for_mempool=txid)

    wait_for(lambda: channel(l1, l2)['state'] == 'CHANNELD_NORMAL')
    wait_for(lambda: channel(l2, l1)['state'] == 'CHANNELD_NORMAL')
    assert channel(l1, l2)['channel_asset'] == asset
    assert channel(l1, l2)['total_msat'] == atoms * 1000

    # A channel like any other: a payment over it, then a close that pays
    # the opener's node, which held nothing before.
    inv = l2.rpc.call('invoice', {'amount_msat': 5_000_000, 'label': 'ext',
                                  'description': 'over an outside-funded channel',
                                  'asset': asset})
    l1.rpc.call('pay', {'bolt11': inv['bolt11'], 'asset': asset})
    wait_for(lambda: channel(l2, l1)['to_us_msat'] == 5_000_000)
    res = l1.rpc.close(l2.info['id'])
    assert res['type'] == 'mutual'
    closing = only_one(res['txids'])
    bitcoind.generate_block(1, wait_for_mempool=closing)
    wait_for(lambda: any(o['status'] == 'confirmed' and o.get('asset') == asset
                         and o['txid'] == closing
                         for o in l1.rpc.listfunds()['outputs']))
    wait_for(lambda: any(o['status'] == 'confirmed' and o.get('asset') == asset
                         and o['amount_msat'] == 5_000_000
                         for o in l2.rpc.listfunds()['outputs']))


def test_complete_does_not_check_the_amount(node_factory, bitcoind):
    """What the caller must check: the node completes with a funding output
    worth less than the channel it opened, so the amount is the funder's to
    verify, never the node's.  Cancelling before broadcast moves no coin."""
    l1, l2 = node_factory.get_nodes(2)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    start = l1.rpc.call('fundchannel_start', {'id': l2.info['id'], 'amount': PAR,
                                              'asset': bitcoind.POLICY_ASSET,
                                              'announce': False})
    short = outside_funding(bitcoind, start['funding_address'], PAR // 2,
                            bitcoind.POLICY_ASSET, bitcoind.POLICY_ASSET,
                            [segwit_coin(bitcoind, 2 * PAR)])
    try:
        done = l1.rpc.call('fundchannel_complete', {'id': l2.info['id'], 'psbt': short})
        accepted = bool(done.get('commitments_secured'))
    except Exception as e:  # if a later seqln checks it, all the better
        print('fundchannel_complete refused a short funding output:', e)
        accepted = False
    print('fundchannel_complete accepted a short funding output:', accepted)
    if accepted:
        l1.rpc.call('fundchannel_cancel', {'id': l2.info['id']})
        wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'] == []
                 or channel(l1, l2)['state'] != 'CHANNELD_AWAITING_LOCKIN')
