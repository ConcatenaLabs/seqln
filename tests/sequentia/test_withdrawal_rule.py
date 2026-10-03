"""A keyless node's device moves the node's coins only to the node's own
scripts, or into a channel the node is opening.

The hub closes a channel to the keyless node.  What the close paid the node
is moved to the node's own address, as the hosted service's consolidation
does, and the coin that makes is an ordinary wallet coin.  The device still
refuses its spend to any other address (the second hop), and signs its spend
to the node's own address.  That coin then funds a channel from the node to
the hub, which pays both ways: the funding output is the one output beside
the node's own scripts the device signs to, because it is the funding of a
channel this side is opening, whose first commitment the device validated.

On Bitcoin regtest each negative is forced into a block, with the chain's
node checking scripts one at a time (-par=1) so the refusal names the
failure: the honest second hop with its output redirected, and the honest
funding transaction with its funding output redirected.  Both fail on the
device's signature, which commits to every output.

Run with TEST_NETWORK=sequentia-regtest and with TEST_NETWORK=regtest;
SEQLN_DEVICE=wasm serves the node from the browser build (see
test_keyless_close.py).
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from pyln.testing.utils import JSONRPCError
from utils import TEST_NETWORK, only_one, wait_for

import os
import pytest

import test_close_output_spend as cos
import test_keyless_close as kc
import test_keyless_start as ks
import test_predating_store as tps

pytestmark = pytest.mark.skipif(TEST_NETWORK not in ('sequentia-regtest', 'regtest'),
                                reason='needs TEST_NETWORK=sequentia-regtest or regtest')
needs_device = pytest.mark.skipif(
    not os.path.exists(kc.SIGNER) or (kc.DEVICE == 'wasm' and not os.path.exists(
        os.path.join(os.path.dirname(kc.WASM_DEVICE), '..', 'pkg', 'seqln_signer_wasm.js'))),
    reason='needs the seqln-signer binary (and the wasm package for SEQLN_DEVICE=wasm)')

SEQ = TEST_NETWORK == 'sequentia-regtest'
FOREIGN = ("which is not one of this device's own scripts nor the funding output of a "
           "channel it is opening")


def into_block(bitcoind, raw, script, other, what):
    """Bitcoin regtest: `raw`, with its output to `script` paid to `other`
    instead, forced into a block: refused on the device's signature."""
    if SEQ:
        return None
    assert raw.count(script) == 1 and len(script) == len(other)
    bad = raw.replace(script, other)
    with pytest.raises(JSONRPCError) as e:
        bitcoind.rpc.generateblock(bitcoind.rpc.getnewaddress(), [bad])
    msg = e.value.error['message']
    print('{} forced into a block: {}'.format(what, msg))
    assert 'mandatory-script-verify-flag-failed' in msg, e.value.error
    return msg


@needs_device
def test_close_payout_funds_a_channel(node_factory, bitcoind, directory):
    cos.checks_scripts_one_by_one(bitcoind)
    asset = ks.coin(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True,
                                 may_reconnect=True, broken_log='.*')
    try:
        l2 = node_factory.get_node(may_reconnect=True, broken_log=ks.HUB_BROKEN)
        ks.fund(bitcoind, l2, 3 * ks.CAP, asset)
        scid = ks.open_paid_channel(bitcoind, l2, l1, asset)

        # The hub closes: what its commitment pays the node is a close output.
        theirs = only_one(l2.rpc.close(scid, unilateraltimeout=1)['txids'])
        bitcoind.generate_block(1, wait_for_mempool=theirs)
        wait_for(lambda: ks.chan(l1, scid)['state'] == 'ONCHAIN')
        assert ks.holds(bitcoind, l1, theirs, asset)['amount_msat'] == ks.PAY * 1000

        # The consolidation: refused to another address, signed to the
        # node's own (`withdraw`, as the hosted service calls it).
        hop1 = tps.moved_to_own_address(bitcoind, l1, device, theirs, asset)

        # The second hop: the coin hop 1 made, to another address. Refused.
        before = device.output().count(cos.REFUSED)
        with pytest.raises(RpcError, match='not finalizeable'):
            tps.withdraw_all(l1, bitcoind.getnewaddress(), asset)
        wait_for(lambda: device.output().count(cos.REFUSED) > before)
        line = [ln for ln in device.output().splitlines() if cos.REFUSED in ln][-1]
        print('second hop to another address:', line.split('seqln-signer: ', 1)[-1])
        assert FOREIGN in line, line

        # To the node's own address it is signed; that transaction with its
        # output redirected does not enter a block.
        own = l1.rpc.newaddr('bech32')['bech32']
        hop2 = tps.withdraw_all(l1, own, asset)
        raw = bitcoind.rpc.getrawtransaction(hop2)
        own_spk = bitcoind.rpc.getaddressinfo(own)['scriptPubKey']
        into_block(bitcoind, raw, own_spk, '0014' + 'ee' * 20, 'the second hop, redirected')
        bitcoind.generate_block(1, wait_for_mempool=hop2)
        # The output at that address (on Bitcoin, lightningd keeps its emergency reserve
        # for anchor channels as a second output of its own).
        wait_for(lambda: any(o['txid'] == hop2 and o['address'] == own and o['status'] == 'confirmed'
                             for o in l1.rpc.listfunds()['outputs']))
        coin = only_one([o for o in l1.rpc.listfunds()['outputs'] if o['txid'] == hop2 and o['address'] == own])
        print('hop 1 {} and hop 2 {} to the node\'s own address: signed, {} left'
              .format(hop1, hop2, coin['amount_msat'] // 1000))

        # That coin funds a channel from the node to the hub.
        withdrawals = device.requests(7)
        try:
            l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        except RpcError:
            pass
        amount = coin['amount_msat'] // 1000 // 2
        args = {'id': l2.info['id'], 'amount': amount, 'announce': True, 'minconf': 0}
        if asset:
            args['asset'] = asset
        res = l1.rpc.call('fundchannel', args)
        assert device.requests(7) > withdrawals
        funding = bitcoind.rpc.getrawtransaction(res['txid'], True)
        fund_spk = only_one([v for v in funding['vout']
                             if v['scriptPubKey']['hex'].startswith('0020')])['scriptPubKey']['hex']
        into_block(bitcoind, funding['hex'], fund_spk, '0020' + 'ee' * 32,
                   'the funding, redirected')
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        assert any(i['txid'] == hop2 for i in funding['vin'])
        new = [c for c in l1.rpc.listpeerchannels(l2.info['id'])['channels']
               if c['funding_txid'] == res['txid']]
        wait_for(lambda: only_one([c for c in l1.rpc.listpeerchannels(l2.info['id'])['channels']
                                   if c['funding_txid'] == res['txid']])['state'] == 'CHANNELD_NORMAL')
        assert new and new[0]['opener'] == 'local'
        print('the node funded {} from that coin ({} of it): signed by its device'
              .format(res['txid'], amount))
        wait_for(lambda: ks.usable(l1, l2) and ks.usable(l2, l1))

        # It pays both ways, over that channel (an explicit route: on Bitcoin its
        # announcement waits for six blocks).
        scid = only_one([c for c in l1.rpc.listpeerchannels(l2.info['id'])['channels']
                         if c['funding_txid'] == res['txid']])['short_channel_id']

        def pay_over(payer, payee, msat, label):
            inv = payee.rpc.invoice(msat, label, label)
            final = payer.rpc.decode(inv['bolt11'])['min_final_cltv_expiry']
            if payer is l1:
                payer.rpc.call('preapproveinvoice', {'bolt11': inv['bolt11']})
            route = [{'id': payee.info['id'], 'channel': scid, 'amount_msat': msat, 'delay': final + 6}]
            payer.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
            assert payer.rpc.waitsendpay(inv['payment_hash'])['status'] == 'complete'
            wait_for(lambda: ks.chan(l1, scid)['htlcs'] == [] and ks.chan(l2, scid)['htlcs'] == [])
        validated = device.requests(35)
        pay_over(l1, l2, amount * 1000 // 4, 'out')
        pay_over(l2, l1, amount * 1000 // 8, 'in')
        assert device.requests(35) > validated
        print('the new channel {} paid both ways; {} commitments validated; refusals on it: {}'
              .format(scid, device.requests(35) - validated,
                      [ln for ln in device.output().splitlines() if 'POLICY REJECT' in ln and scid in ln]))
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()
