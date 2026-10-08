"""A keyless node's device approves an invoice against the asset it names.

An invoice on a Sequentia network names its asset (its `a` field). The device
approving `pay`'s request (`PREAPPROVE_INVOICE`) checks the amount against
what that asset's payment limit leaves for the period, not against the
smallest allowance among the assets of its channels. Run with
TEST_NETWORK=sequentia-regtest; SEQLN_DEVICE=wasm runs it on the browser build.
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
def test_keyless_invoice_charges_its_asset(node_factory, bitcoind, directory):
    """Channels in GOLD and SILV; limits of 20,000,000 GOLD and 2,000,000
    SILV atoms a day. A GOLD invoice of 5,000,000 is approved and paid
    although SILV has less left; a SILV invoice of 3,000,000 is declined,
    naming SILV; one of 1,000,000 is paid and charged to SILV."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: kc.PAR, gold: kc.PAR, silv: kc.PAR})
    device, l1 = kc.keyless_node(node_factory, directory, broken_log='.*', may_reconnect=True,
                                 pay_limits='{}=20000000,{}=2000000'.format(gold, silv))
    try:
        l2 = node_factory.get_node(may_reconnect=True)
        addr = l2.rpc.newaddr('bech32')['bech32']
        txids = [bitcoind.send(addr, 2 * 10**8, a) for a in (gold, silv)]
        bitcoind.generate_block(1, wait_for_mempool=txids)
        wait_for(lambda: len([o for o in l2.rpc.listfunds()['outputs']
                              if o['status'] == 'confirmed']) >= 2)
        l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
        for a in (gold, silv):
            res = l2.rpc.call('fundchannel', {'id': l1.info['id'], 'amount': 10**8,
                                              'asset': a, 'announce': False})
            bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        wait_for(lambda: all(c['state'] == 'CHANNELD_NORMAL'
                             for c in l1.rpc.listpeerchannels()['channels'])
                 and len(l1.rpc.listpeerchannels()['channels']) == 2)

        def settled():
            return all(c['htlcs'] == [] for c in l1.rpc.listpeerchannels()['channels'])

        # The keyless node receives 50,000,000 of each (receiving needs no
        # approval and is not charged).
        for a in (gold, silv):
            inv = l1.rpc.call('invoice', {'amount_msat': 5 * 10**7 * 1000, 'label': 'in-' + a[:8],
                                          'description': 'in', 'asset': a})['bolt11']
            assert l1.rpc.decode(inv)['asset'] == a
            l2.rpc.pay(inv)
            wait_for(settled)

        def hub_invoice(atoms, label, asset):
            inv = l2.rpc.call('invoice', {'amount_msat': atoms * 1000, 'label': label,
                                          'description': label, 'asset': asset})['bolt11']
            assert l1.rpc.decode(inv)['asset'] == asset
            return inv

        # GOLD, 5,000,000: within GOLD's 20,000,000; SILV has 2,000,000 left.
        inv = hub_invoice(5 * 10**6, 'gold5', gold)
        try:
            res = l1.rpc.pay(inv)
        except RpcError as e:
            print('GOLD invoice of 5000000 atoms:', e.error)
            print([x for x in device.output().splitlines() if 'PREAPPROVE' in x])
            raise
        assert res['status'] == 'complete'
        wait_for(settled)
        print('GOLD invoice of 5000000 atoms, SILV limit 2000000: paid')

        # SILV, 3,000,000: over SILV's 2,000,000, declined before any HTLC.
        inv = hub_invoice(3 * 10**6, 'silv3', silv)
        with pytest.raises(RpcError, match='declined'):
            l1.rpc.pay(inv)
        print('SILV invoice of 3000000 atoms: declined')
        if kc.DEVICE == 'native':
            # The WASM build has nowhere to write a decline's reason.
            line = [x for x in device.output().splitlines() if 'PREAPPROVE declined' in x][-1]
            print(line)
            assert ('a payment of 3000000000 msat of asset {}'.format(silv) in line
                    and 'does not fit in the 2000000000 msat left this period for that asset' in line)
        assert only_one(l2.rpc.listinvoices('silv3')['invoices'])['status'] == 'unpaid'
        assert settled()

        # SILV, 1,000,000: paid; the next 1,000,000 no longer fits (the
        # commitment charged SILV, with its fee allowance checked at approval).
        assert l1.rpc.pay(hub_invoice(10**6, 'silv1', silv))['status'] == 'complete'
        wait_for(settled)
        with pytest.raises(RpcError, match='declined'):
            l1.rpc.pay(hub_invoice(10**6, 'silv1b', silv))
        print('a second SILV invoice of 1000000 atoms: declined')
        if kc.DEVICE == 'native':
            line = [x for x in device.output().splitlines() if 'PREAPPROVE declined' in x][-1]
            print(line)
            assert 'msat of asset {}'.format(silv) in line and 'the 1000000000 msat left' in line
        # GOLD still has 15,000,000 left.
        assert l1.rpc.pay(hub_invoice(10 * 10**6, 'gold10', gold))['status'] == 'complete'
        print('GOLD invoice of 10000000 atoms after SILV ran out: paid')
        assert 'POLICY REJECT' not in device.output()
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()
