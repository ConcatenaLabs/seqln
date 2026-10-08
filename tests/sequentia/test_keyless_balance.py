"""A keyless node's device holds every commitment to the balance it tracks.

The device signer (`contrib/seqln-signer`) follows the value this side holds
in a channel from one commitment to the next: it may fall only by HTLCs this
side offered, approved, and settled.  channeld lists every HTLC a commitment
carries, those trimmed as dust too, so honest payments of any size pass; a
host that misstates the balance split, here by an edit of its own database,
has the next commitment refused, and the channel closes on the balance the
device tracked.  Run with TEST_NETWORK=sequentia-regtest; the signer binary is
SEQLN_SIGNER, by default contrib/seqln-signer/target/release/seqln-signer.
"""
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK, only_one, wait_for

import os
import pytest
import sqlite3

import test_keyless_close as kc

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

# One atom of the channel asset is worth a tenth of a reference atom: its
# dust limit is 5,460 atoms, so payments of a few thousand are trimmed.
CHEAP = 10**7


def channel_pair(node_factory, bitcoind, directory, rate, opener):
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: kc.PAR, asset: rate})
    dust = {'max-dust-htlc-exposure-msat': 10**12}
    device, l1 = kc.keyless_node(node_factory, directory, broken_log='.*',
                                 may_reconnect=True, **dust)
    l2 = node_factory.get_node(may_reconnect=True, options=dust)
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
    # Half the channel to the side that did not open it, so both can pay.
    payer, payee = (l2, l1) if opener == 'hub' else (l1, l2)
    inv = payee.rpc.invoice(5 * 10**7 * 1000, 'half', 'half')['bolt11']
    payer.rpc.pay(inv)
    wait_for(lambda: settled(l1, l2))
    return device, l1, l2, asset


def settled(l1, l2):
    return kc.channel(l1, l2)['htlcs'] == [] and kc.channel(l2, l1)['htlcs'] == []


@pytest.mark.skipif(not os.path.exists(kc.SIGNER), reason='needs the seqln-signer binary')
@pytest.mark.parametrize('opener', ['hub', 'keyless'])
def test_keyless_trimmed_payments_keep_the_balance(node_factory, bitcoind, directory, opener):
    """Payments under the dust limit, which have no output on any
    commitment, both ways, and larger ones: each completes, the device
    refuses nothing, and its balance matches the channel's."""
    device, l1, l2, asset = channel_pair(node_factory, bitcoind, directory, CHEAP, opener)
    try:
        for i, (payer, payee, atoms) in enumerate([(l1, l2, 4_000), (l2, l1, 3_000),
                                                    (l1, l2, 50_000), (l1, l2, 1_000),
                                                    (l2, l1, 20_000), (l2, l1, 2_500)]):
            inv = payee.rpc.invoice(atoms * 1000, 'p{}'.format(i), 'p')['bolt11']
            assert payer.rpc.pay(inv)['status'] == 'complete'
            wait_for(lambda: settled(l1, l2))
        out = device.output()
        assert 'POLICY REJECT' not in out, out
        print("six payments, four of them trimmed (dust limit {}): none refused"
              .format(kc.channel(l1, l2).get('dust_limit_msat')))
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()


def misstate_balance(node, atoms):
    """Move `atoms` of the keyless node's channel balance to its peer in its
    own database, as a host lying to its device would."""
    path = os.path.join(node.daemon.lightning_dir, TEST_NETWORK, 'lightningd.sqlite3')
    db = sqlite3.connect(path)
    try:
        (before,) = db.execute("SELECT msatoshi_local FROM channels").fetchone()
        db.execute("UPDATE channels SET msatoshi_local = msatoshi_local - ?", (atoms * 1000,))
        db.commit()
    finally:
        db.close()
    return before


@pytest.mark.skipif(not os.path.exists(kc.SIGNER), reason='needs the seqln-signer binary')
@pytest.mark.parametrize('opener', ['hub', 'keyless'])
def test_keyless_misstated_balance_refused(node_factory, bitcoind, executor, directory, opener):
    """The host takes 10,000 atoms off the keyless node's balance in its
    database.  The next commitment it asks the device to sign for the peer,
    for an approved payment, is refused: it leaves this wallet less than the
    device tracks.  The channel then closes unilaterally on the last
    commitment the device validated, which pays the balance it tracks."""
    device, l1, l2, asset = channel_pair(node_factory, bitcoind, directory, kc.PAR, opener)
    try:
        honest = int(kc.channel(l1, l2)['to_us_msat']) // 1000
        l1.stop()
        before = misstate_balance(l1, 10_000)
        print("host database: our balance {} msat, now {} msat".format(before, before - 10**7))
        l1.start()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        wait_for(lambda: kc.channel(l1, l2)['state'] == 'CHANNELD_NORMAL'
                 and kc.channel(l1, l2)['peer_connected'])

        # pay waits for the HTLC's outcome, which a refused commitment leaves
        # pending until a reconnect: watch the device and the peer instead.
        inv = l2.rpc.invoice(10**6 * 1000, 'after', 'after')['bolt11']
        executor.submit(l1.rpc.pay, inv)
        wait_for(lambda: 'POLICY REJECT' in device.output()
                 or l1.daemon.is_in_log('Bad commit_sig signature'))
        signed = l1.daemon.is_in_log('Bad commit_sig signature')
        assert not signed, ("the device signed the misstated commitment, which the peer "
                            "refused: {}".format(signed))
        refusal = only_one([line for line in device.output().splitlines()
                            if 'POLICY REJECT' in line][:1])
        print("device:", refusal)
        assert 'it leaves this wallet' in refusal and 'atoms of the channel, 99' in refusal
        assert l2.rpc.listinvoices('after')['invoices'][0]['status'] == 'unpaid'

        # The close: on the last commitment the device validated.
        res = l1.rpc.close(l2.info['id'], unilateraltimeout=10)
        print("close:", res['type'])
        assert res['type'] == 'unilateral'
        tx = bitcoind.rpc.decoderawtransaction(res['txs'][-1] if 'txs' in res else res['tx'])
        # Our own commitment: our balance is its to_local, the P2WSH output
        # (no HTLC is on it), less the commitment fee when we opened.
        ours = round(float(only_one([o for o in tx['vout'] if o['scriptPubKey']['type']
                                     == 'witness_v0_scripthash'])['value']) * 10**8)
        fee = round(float(only_one([o for o in tx['vout'] if o['scriptPubKey']['type']
                                    == 'fee'])['value']) * 10**8)
        due = honest - (fee if opener == 'keyless' else 0)
        print("unilateral close pays us {} atoms; the tracked balance {}{}, the misstated "
              "one {} less".format(ours, due, " (net of the {} fee)".format(fee)
                                   if opener == 'keyless' else "", 10_000))
        assert abs(ours - due) <= 2
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()
