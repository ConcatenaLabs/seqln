"""A keyless node whose device comes off a store that validated nothing.

A hosted node's device keeps a store of its channels.  A store written by a
device that validated nothing (version 1, as the wallet's browser device wrote
it) records no commitment of a channel and no balance: the device that
imports it cannot tell a channel's current state from an old one, and does not
take the host's word for it.  It marks each of those channels as predating
validation, signs no commitment step for any of them (no commitment of either
side, no revocation, no close) and reports them.  Their peer closes them; what
the close pays the node, the device sends only to the node's own address.  A
channel opened afterwards is validated from its first commitment and pays
both ways.

Run with TEST_NETWORK=sequentia-regtest and with TEST_NETWORK=regtest;
SEQLN_DEVICE=wasm serves the node from the browser build (see
test_keyless_close.py).
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, sync_blockheight, wait_for

import os
import pytest
import re

import test_keyless_close as kc
import test_keyless_start as ks

pytestmark = pytest.mark.skipif(TEST_NETWORK not in ('sequentia-regtest', 'regtest'),
                                reason='needs TEST_NETWORK=sequentia-regtest or regtest')
needs_device = pytest.mark.skipif(
    not os.path.exists(kc.SIGNER) or (kc.DEVICE == 'wasm' and not os.path.exists(
        os.path.join(os.path.dirname(kc.WASM_DEVICE), '..', 'pkg', 'seqln_signer_wasm.js'))),
    reason='needs the seqln-signer binary (and the wasm package for SEQLN_DEVICE=wasm)')

SEQ = TEST_NETWORK == 'sequentia-regtest'
PREDATES = 'predates validation'
REFUSED_STEP = r'POLICY REJECT: (VALIDATE_COMMITMENT_TX|SIGN_REMOTE_COMMITMENT_TX|REVOKE_COMMITMENT_TX|SIGN_MUTUAL_CLOSE_TX|SIGN_COMMITMENT_TX) refused: channel \d+ of peer [0-9a-f]+ predates validation'


def withdraw_all(node, addr, asset):
    args = {'destination': addr, 'satoshi': 'all', 'feerate': 'normal'}
    if asset:
        args['asset'] = asset
    return node.rpc.call('withdraw', args)['txid']


def moved_to_own_address(bitcoind, node, device, txid, asset):
    """What `txid` paid the node: to another address the device refuses it;
    to the node's own address it signs, and the spend confirms."""
    with pytest.raises(RpcError, match='not finalizeable'):
        withdraw_all(node, bitcoind.getnewaddress(), asset)
    assert "which is not one of this device's own scripts" in device.output()
    addr = node.rpc.newaddr('bech32')['bech32']
    for _ in range(5):
        try:
            spent = withdraw_all(node, addr, asset)
            break
        except RpcError as e:
            # The peer's commitment pays us after one block (CSV 1).
            if 'csv locked' not in str(e) and 'could not afford' not in str(e).lower():
                raise
            bitcoind.generate_block(1)
            sync_blockheight(bitcoind, [node])
    bitcoind.generate_block(1, wait_for_mempool=spent)
    tx = bitcoind.rpc.getrawtransaction(spent, True)
    assert any(i['txid'] == txid for i in tx['vin'])
    paid = only_one([v for v in tx['vout'] if v['scriptPubKey'].get('address') == addr])
    if SEQ:
        assert paid['asset'] == asset
    wait_for(lambda: any(o['txid'] == spent and o['status'] == 'confirmed'
                         for o in node.rpc.listfunds()['outputs']))
    print('the hub close {} paid the node {}; its device moved it to the node\'s own address in {}'
          .format(txid, paid['value'], spent))
    return spent


def new_channel_pays_both_ways(bitcoind, hub, keyless, device, asset):
    """The hub opens a new channel to the node; it pays both ways, every
    commitment step validated by the device."""
    validated = device.requests(35)
    scid = ks.open_paid_channel(bitcoind, hub, keyless, asset)
    inv = hub.rpc.invoice(ks.PAY * 1000 // 4, 'back-' + scid, 'back')['bolt11']
    assert keyless.rpc.pay(inv)['status'] == 'complete'
    wait_for(lambda: ks.chan(keyless, scid)['htlcs'] == [])
    print('a channel opened after the upgrade, {}: paid both ways, {} commitments validated'
          .format(scid, device.requests(35) - validated))
    assert device.requests(35) > validated
    return scid


def onto_v1_store(device, node):
    """Stop the node and its device, and rewrite the device's store as a
    version-1 device wrote it."""
    node.stop()
    device.stop()
    assert ks.store_as_version(device, 1) >= 1


@needs_device
def test_hub_closes_a_channel_from_an_old_store(node_factory, bitcoind, directory):
    """The hub closes the channel unilaterally while the node is down (as the
    cutover does); the node starts on the old store, its device reports the
    channel and signs nothing for it, the node follows the close, and the
    device moves what it paid the node to the node's own address."""
    asset = ks.coin(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True,
                                 may_reconnect=True, broken_log='.*')
    try:
        l2 = node_factory.get_node(may_reconnect=True, broken_log=ks.HUB_BROKEN)
        ks.fund(bitcoind, l2, 3 * ks.CAP, asset)
        scid = ks.open_paid_channel(bitcoind, l2, l1, asset)
        onto_v1_store(device, l1)

        theirs = only_one(l2.rpc.close(scid, unilateraltimeout=1)['txids'])
        bitcoind.generate_block(1, wait_for_mempool=theirs)

        ks.restart_device(device)
        l1.start()
        wait_for(lambda: PREDATES in device.output())
        line = [ln for ln in device.output().splitlines() if PREDATES in ln][0]
        print('device:', line.split('seqln-signer: ', 1)[-1])
        wait_for(lambda: ks.chan(l1, scid)['state'] == 'ONCHAIN')
        out = ks.holds(bitcoind, l1, theirs, asset)
        assert out['amount_msat'] == ks.PAY * 1000
        moved_to_own_address(bitcoind, l1, device, theirs, asset)
        new_channel_pays_both_ways(bitcoind, l2, l1, device, asset)
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()


@needs_device
def test_old_channel_left_open_is_never_stepped(node_factory, bitcoind, directory):
    """The hub has not closed the channel: the node starts on the old store
    and its peer reconnects.  The device refuses every commitment step the
    channel asks for, so the channel moves no more.  The hub closes it, and
    the node's device moves what the close paid the node to its own address."""
    asset = ks.coin(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True,
                                 may_reconnect=True, broken_log='.*')
    try:
        l2 = node_factory.get_node(may_reconnect=True, broken_log=ks.HUB_BROKEN)
        ks.fund(bitcoind, l2, 3 * ks.CAP, asset)
        scid = ks.open_paid_channel(bitcoind, l2, l1, asset)
        onto_v1_store(device, l1)
        ks.restart_device(device)
        l1.start()
        try:
            l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        except RpcError:
            pass
        # The peers reestablish the channel: the device signs none of its
        # steps, so the node runs no channeld for it and it moves no more.
        wait_for(lambda: re.search(REFUSED_STEP, device.output()))
        steps = sorted(set(m.group(1) for m in re.finditer(REFUSED_STEP, device.output())))
        print('refused on the old channel:', steps)
        wait_for(lambda: 'channeld' not in (ks.chan(l1, scid).get('owner') or ''))
        assert ks.chan(l2, scid)['to_us_msat'] == (ks.CAP - ks.PAY) * 1000

        # The hub closes it: no mutual close (refused), so its commitment.
        theirs = only_one(l2.rpc.close(scid, unilateraltimeout=1)['txids'])
        bitcoind.generate_block(1, wait_for_mempool=theirs)
        wait_for(lambda: ks.chan(l1, scid)['state'] == 'ONCHAIN')
        ks.holds(bitcoind, l1, theirs, asset)
        moved_to_own_address(bitcoind, l1, device, theirs, asset)
        new_channel_pays_both_ways(bitcoind, l2, l1, device, asset)
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()
