"""A keyless node pays only payments its device approved, within its limit.

The device signer approves a payment when `pay` or `keysend` asks it to
(`PREAPPROVE_INVOICE`, `PREAPPROVE_KEYSEND`), if the amount fits in what its
limit (by default a value in the reference unit, held in each asset at the
rate the wallet gives the device) leaves; it signs a commitment that adds
an HTLC we offer only for an approved payment hash, and charges the amount to
the asset.  Run with TEST_NETWORK=sequentia-regtest; the signer binary is
SEQLN_SIGNER, by default contrib/seqln-signer/target/release/seqln-signer.
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, wait_for

import os
import pytest

import test_keyless_close as kc

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')


@pytest.mark.skipif(not os.path.exists(kc.SIGNER), reason='needs the seqln-signer binary')
@pytest.mark.parametrize('opener', ['hub', 'keyless'])
def test_keyless_node_pays_only_approved_payments(node_factory, bitcoind, directory, opener):
    """With a limit of 20,000,000 atoms a day: a payment of 5,000,000 is
    approved and paid; one of 30,000,000 is declined before any HTLC is
    offered; an HTLC sent with `sendpay`, which asks for no approval, is
    refused by the device and never reaches the payee.  When the keyless
    node opened the channel, the fee of its funding counts against the same
    limit."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: kc.PAR, asset: kc.PAR})
    device, l1 = kc.keyless_node(node_factory, directory, pay_limit='20000000',
                                 broken_log='.*', may_reconnect=True)
    try:
        l2 = node_factory.get_node(may_reconnect=True)
        funder, fundee = (l2, l1) if opener == 'hub' else (l1, l2)
        addr = funder.rpc.newaddr('bech32')['bech32']
        txid = bitcoind.send_and_mine_block(addr, 2 * 10**8, asset)
        wait_for(lambda: any(o['txid'] == txid for o in funder.rpc.listfunds()['outputs']))
        funder.rpc.connect(fundee.info['id'], 'localhost', fundee.port)
        res = funder.rpc.call('fundchannel', {'id': fundee.info['id'], 'amount': 10**8,
                                              'asset': asset, 'announce': True})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        for a, b in ((l1, l2), (l2, l1)):
            wait_for(lambda: kc.channel(a, b)['state'] == 'CHANNELD_NORMAL')

        def settled():
            return kc.channel(l1, l2)['htlcs'] == [] and kc.channel(l2, l1)['htlcs'] == []
        if opener == 'hub':
            # Receiving needs no approval and is not charged.
            inv = l1.rpc.invoice(5 * 10**7 * 1000, 'in', 'in')['bolt11']
            l2.rpc.pay(inv)
            wait_for(settled)

        inv = l2.rpc.invoice(5 * 10**6 * 1000, 'ok', 'ok')['bolt11']
        assert l1.rpc.pay(inv)['status'] == 'complete'
        wait_for(settled)
        assert 'POLICY REJECT' not in device.output()

        inv = l2.rpc.invoice(3 * 10**7 * 1000, 'big', 'big')['bolt11']
        with pytest.raises(RpcError, match='declined'):
            l1.rpc.pay(inv)
        assert 'PREAPPROVE declined: a payment of 30000000000 msat' in device.output()
        fee = 0
        if opener == 'keyless':
            funding = bitcoind.rpc.getrawtransaction(res['txid'], True)
            fee = sum(round(v['value'] * 10**8) for v in funding['vout']
                      if v['scriptPubKey'].get('type') == 'fee')
            assert fee > 0
        left = 15000000000 - fee * 1000
        assert 'does not fit in the {} msat left this period'.format(left) in device.output()
        assert only_one(l2.rpc.listinvoices('big')['invoices'])['status'] == 'unpaid'

        inv = l2.rpc.invoice(10**6 * 1000, 'bypass', 'bypass')['bolt11']
        dec = l1.rpc.decode(inv)
        route = l1.rpc.getroute(l2.info['id'], 10**6 * 1000, 1)['route']
        l1.rpc.sendpay(route, dec['payment_hash'], payment_secret=dec['payment_secret'])
        wait_for(lambda: 'for a payment that was not approved' in device.output())
        print([x for x in device.output().splitlines() if 'POLICY REJECT' in x][:1])
        assert 'payment hash {}'.format(dec['payment_hash']) in device.output()
        assert only_one(l2.rpc.listinvoices('bypass')['invoices'])['status'] == 'unpaid'
        # The refused HTLC was never committed, so lightningd fails it back.
        # channeld died on the refusal and the channel has no owner until the
        # peer reconnects (lightningd does not disconnect on its own); after a
        # reconnect it is back and an approved payment goes through.
        assert 'owner' not in kc.channel(l1, l2)
        l1.rpc.disconnect(l2.info['id'], force=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        wait_for(lambda: kc.channel(l1, l2)['peer_connected']
                 and 'owner' in kc.channel(l1, l2) and settled())
        inv = l2.rpc.invoice(10**6 * 1000, 'after', 'after')['bolt11']
        assert l1.rpc.pay(inv)['status'] == 'complete'
        assert only_one(l2.rpc.listinvoices('bypass')['invoices'])['status'] == 'unpaid'
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()


@pytest.mark.skipif(not os.path.exists(kc.SIGNER), reason='needs the seqln-signer binary')
@pytest.mark.parametrize('rated', [True, False])
def test_keyless_default_limit_is_a_reference_value(node_factory, bitcoind, directory, rated):
    """With the device's default limit, 1,000 reference units a day, and the
    wallet's rate for the channel's asset (one reference unit per 10^8
    atoms, a dollar-priced asset), the keyless node opens a channel of 10
    units and pays 5 of them.  Without a rate the device cannot value the
    asset and holds it to 10,000,000 atoms, so the same payment is declined
    before any HTLC is offered."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: kc.PAR, asset: kc.PAR})
    rates = '{}={}'.format(asset, kc.PAR) if rated else None
    device, l1 = kc.keyless_node(node_factory, directory, pay_limit=None, rates=rates,
                                 broken_log='.*')
    try:
        l2 = node_factory.get_node()
        addr = l1.rpc.newaddr('bech32')['bech32']
        txid = bitcoind.send_and_mine_block(addr, 20 * 10**8, asset)
        wait_for(lambda: any(o['txid'] == txid for o in l1.rpc.listfunds()['outputs']))
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': 10 * 10**8,
                                          'asset': asset, 'announce': True})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        for a, b in ((l1, l2), (l2, l1)):
            wait_for(lambda: kc.channel(a, b)['state'] == 'CHANNELD_NORMAL')

        inv = l2.rpc.invoice(5 * 10**8 * 1000, 'five', 'five units')['bolt11']
        if rated:
            assert l1.rpc.pay(inv)['status'] == 'complete'
            assert only_one(l2.rpc.listinvoices('five')['invoices'])['status'] == 'paid'
            assert 'declined' not in device.output()
            assert 'POLICY REJECT' not in device.output()
        else:
            with pytest.raises(RpcError, match='declined'):
                l1.rpc.pay(inv)
            # The native device logs why; the browser build answers the same
            # decline without a log line.
            if kc.DEVICE == 'native':
                out = [x for x in device.output().splitlines() if 'PREAPPROVE declined' in x]
                print(out[:1])
                assert 'a payment of 500000000000 msat' in out[0]
            assert only_one(l2.rpc.listinvoices('five')['invoices'])['status'] == 'unpaid'
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()
