"""The provider-signed credit (`option_seq_credit`, common/credit_scripts.h).

On a credit channel the opener, the provider, can credit the holder while the
holder cannot sign an update: it signs a note, "the holder is owed c atoms in
all", conditional on the preimage of the payment it was paid for.  The
provider's balance output, on both commitments, carries a CLAIM leaf that pays
the holder what its latest note still owes, with no signature from the holder;
the rest stays under the same script, the provider's after its delay.  The
provider issues notes from paid invoices (contrib/credit-seq) and sends them to
the holder's node, which keeps them and claims them once a commitment is on
chain.
Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from pyln.testing.utils import TIMEOUT
from utils import TEST_NETWORK, only_one, wait_for

import json
import os
import pytest
import sqlite3
import struct
import test_taproot_covenant as tc

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
CREDIT = {**tc.TCOV, **tc.SHORT, 'credit-channels': None}
CREDIT_PLUGIN = os.path.join(os.path.dirname(__file__), '..', '..', 'contrib',
                             'credit-seq', 'credit.py')
CREDIT_BIT = 176


def chan(a, b):
    return only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])


def open_chan(bitcoind, a, b, asset, atoms):
    a.rpc.connect(b.info['id'], 'localhost', b.port)
    res = a.rpc.call('fundchannel', {'id': b.info['id'], 'amount': atoms,
                                     'asset': asset, 'announce': True})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for x, y in ((a, b), (b, a)):
        wait_for(lambda: chan(x, y)['state'] == 'CHANNELD_NORMAL')
    return chan(a, b)


def sats(v):
    return int(Decimal(str(v)) * PAR)


def credit_setup(node_factory, bitcoind, holder_opts=None, provider_opts=None):
    """l1 pays; l2 provides credit to l3 on a GOLD channel l2 opened."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: 2 * PAR})
    l1, l2, l3 = node_factory.get_nodes(3, opts=[
        {**tc.TCOV, **tc.SHORT, 'may_reconnect': True},
        {**CREDIT, 'plugin': CREDIT_PLUGIN, 'may_reconnect': True, **(provider_opts or {})},
        {**CREDIT, 'may_reconnect': True, **(holder_opts or {})}])
    tc.fund_node(bitcoind, l1, gold, 10 * PAR)
    tc.fund_node(bitcoind, l2, gold, 10 * PAR)
    c12 = open_chan(bitcoind, l1, l2, gold, 4 * PAR)
    c23 = open_chan(bitcoind, l2, l3, gold, 2 * PAR)
    assert CREDIT_BIT in c23['channel_type']['bits']
    assert 'seq_credit/even' in c23['channel_type']['names']
    assert c23['opener'] == 'local'
    return l1, l2, l3, gold, silv, c12, c23


def credit_payment(l1, l2, l3, gold, msat, label):
    inv = l2.rpc.call('creditinvoice', {'id': l3.info['id'], 'amount_msat': msat,
                                        'label': label})
    route = [{'id': l2.info['id'], 'channel': chan(l1, l2)['short_channel_id'],
              'amount_msat': msat, 'delay': 30}]
    dec = l1.rpc.decode(inv['bolt11'])
    l1.rpc.sendpay(route, dec['payment_hash'], payment_secret=dec['payment_secret'],
                   bolt11=inv['bolt11'])
    res = l1.rpc.waitsendpay(dec['payment_hash'], TIMEOUT)
    assert res['status'] == 'complete'
    return dec['payment_hash'], res['payment_preimage']


def taproot_output(bitcoind, txid):
    """The one taproot output of a commitment that pays only the provider
    (the holder's balance is nothing, and no HTLC is in flight)."""
    dec = bitcoind.rpc.getrawtransaction(txid, 1)
    print("commitment outputs:", [(o['n'], o['scriptPubKey']['type'], o['value'])
                                  for o in dec['vout']])
    out = only_one([o for o in dec['vout'] if o['scriptPubKey']['type'] == 'witness_v1_taproot'])
    return out['n'], sats(out['value']), out['scriptPubKey']['hex']


def check_claim(bitcoind, holder, commitment, credit, preimage, gold):
    """The holder's onchaind claims `credit` from the provider's output of
    `commitment` by its CLAIM leaf: the note's credit and preimage in the
    witness, the credit to the holder, the rest under the same script."""
    n, v0, spk = taproot_output(bitcoind, commitment)
    claim, i = tc.confirmed_spender(bitcoind, commitment, n)
    print("credit claim:", json.dumps({k: claim[k] for k in ('txid', 'vsize', 'weight')}))
    wit = claim['vin'][i]['txinwitness']
    # What a script proof on another chain needs to spend an output of this
    # very script with these very notes (the evidence's l41_live.py).
    notes = holder.rpc.call('listcreditnotes')['notes']
    print("LIVE CREDIT OUTPUT", json.dumps({
        'spk': spk, 'value': v0, 'leaf': wit[3], 'control_block': wit[4],
        'notes': [{k: nt.get(k) for k in ('credit', 'payment_hash', 'signature', 'preimage')}
                  for nt in notes]}))
    # sig, credit, preimage, the CLAIM leaf, its control block.
    assert len(wit) == 5
    assert struct.unpack('<Q', bytes.fromhex(wit[1]))[0] == credit
    assert wit[2] == preimage
    print("claim leaf: {} bytes, control block {} bytes".format(
        len(wit[3]) // 2, len(wit[4]) // 2))
    assert sats(claim['vout'][0]['value']) == v0 - credit
    assert claim['vout'][0]['scriptPubKey']['hex'] == spk
    assert sats(claim['vout'][1]['value']) == credit
    assert claim['vout'][1]['asset'] == gold
    wait_for(lambda: any(o['txid'] == claim['txid'] and o['output'] == 1
                         and o['status'] == 'confirmed'
                         for o in holder.rpc.listfunds()['outputs']))
    return claim


def credit_twice(l1, l2, l3, gold):
    """l1 pays two invoices of l2 that credit l3: l2 issues a note for
    each, the second cumulative, and l3 holds both."""
    h1, x1 = credit_payment(l1, l2, l3, gold, 20_000_000_000, 'one')
    h2, x2 = credit_payment(l1, l2, l3, gold, 25_000_000_000, 'two')
    issued = l2.rpc.call('listcreditnotes', {'id': l3.info['id']})['notes']
    print("issued:", json.dumps(issued, indent=1))
    assert [n['credit'] for n in issued] == [20_000_000, 45_000_000]
    assert [n['payment_hash'] for n in issued] == [h1, h2]
    wait_for(lambda: len(l3.rpc.call('listcreditnotes', {'id': l2.info['id']})['notes']) == 2)
    held = l3.rpc.call('listcreditnotes', {'id': l2.info['id']})['notes']
    assert all(n['role'] == 'holder' for n in held)
    assert [n.get('preimage') for n in held] == [x1, x2]
    return held


def pay_direct(src, dst, c, msat, asset, wait=True):
    """`src` pays an invoice of `dst` in one HTLC over channel `c`."""
    inv = dst.rpc.call('invoice', {'amount_msat': msat, 'label': 'big',
                                   'description': 'big', 'asset': asset})
    dec = src.rpc.decode(inv['bolt11'])
    route = [{'id': dst.info['id'], 'channel': c['short_channel_id'],
              'amount_msat': msat, 'delay': 30}]
    src.rpc.sendpay(route, dec['payment_hash'], payment_secret=dec['payment_secret'],
                    bolt11=inv['bolt11'])
    if wait:
        src.rpc.waitsendpay(dec['payment_hash'], TIMEOUT)


def forget_notes(l2):
    """l2 forgets every note it issued: a provider that signs notes and
    then acts as if it had not."""
    l2.stop()
    db = sqlite3.connect(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK,
                                      'lightningd.sqlite3'))
    db.execute("DELETE FROM credit_notes")
    db.commit()
    db.close()
    l2.start()


def test_credit_notes_and_claim(node_factory, bitcoind, executor):
    """l1 pays two invoices of l2 that credit l3: l2 issues a note for each,
    the second cumulative, and l3 holds both, each checked against l2's
    credit key.  l2's node will not pay l3 out of what it owes it.  l3 then
    drops its commitment: it pays l2's balance to a credit output, from
    which l3's onchaind claims the second note, the rest staying under the
    same script until l2 sweeps it after its delay."""
    l1, l2, l3, gold, silv, c12, c23 = credit_setup(node_factory, bitcoind)
    # l3 holds no GOLD on chain: its claim pays its fee in SILV.
    tc.fund_node(bitcoind, l3, silv, 2 * PAR)
    held = credit_twice(l1, l2, l3, gold)

    # A forged note: refused.
    with pytest.raises(RpcError, match='not the provider'):
        l3.rpc.call('addcreditnote', {'id': l2.info['id'], 'credit': 99_000_000,
                                      'payment_hash': held[1]['payment_hash'],
                                      'signature': held[1]['signature']})

    # l2 has about 2 GOLD in the channel and owes 0.45 of it: its node
    # will not pay l3 1.6 GOLD.
    with pytest.raises(RpcError, match='WIRE_TEMPORARY_CHANNEL_FAILURE'):
        pay_direct(l2, l3, c23, 160_000_000_000, gold)
    l2.daemon.wait_for_log('must keep paying the 45000000 atoms it owes as credit')

    # l3 drops its commitment: it pays l2's balance to the credit output.
    l3.rpc.dev_fail(l2.info['id'])
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == 1)
    commitment = only_one(bitcoind.rpc.getrawmempool())
    bitcoind.generate_block(1, wait_for_mempool=commitment)
    claim = check_claim(bitcoind, l3, commitment, 45_000_000, held[1]['preimage'], gold)

    # l2 sweeps what remains after its delay (12 blocks).
    sweep, j = tc.wait_spender_after(bitcoind, claim['txid'], 0, 14)
    print("provider sweep:", sweep['txid'], sweep['vsize'])
    tc.mine_if_pending(bitcoind, sweep['txid'])


def test_credit_mutual_close_pays_holder(node_factory, bitcoind):
    """A mutual close pays the holder what its latest note owes it, out of
    the provider's side, as the CLAIM leaf would on chain."""
    l1, l2, l3, gold, silv, c12, c23 = credit_setup(node_factory, bitcoind)
    credit_twice(l1, l2, l3, gold)
    res = l2.rpc.close(l3.info['id'])
    assert res['type'] == 'mutual'
    close = only_one(res['txids'])
    bitcoind.generate_block(1, wait_for_mempool=close)
    l2.daemon.wait_for_log('Closing pays the holder 45000000sat of credit')
    l3.daemon.wait_for_log('Closing pays the holder 45000000sat of credit')
    dec = bitcoind.rpc.getrawtransaction(close, 1)
    print("close outputs:", [(o['n'], o['scriptPubKey']['type'], o['value'])
                             for o in dec['vout']])
    wait_for(lambda: any(o['txid'] == close and o['status'] == 'confirmed'
                         for o in l3.rpc.listfunds()['outputs']))
    mine = only_one([o for o in l3.rpc.listfunds()['outputs'] if o['txid'] == close])
    assert mine['amount_msat'] == 45_000_000_000
    assert mine['asset'] == gold


def test_credit_close_without_it_refused(node_factory, bitcoind):
    """A provider that forgets the notes it signed proposes a mutual close
    that pays the holder nothing: the holder will not sign it.  The
    provider can only drop its own commitment, whose balance output
    carries the CLAIM leaf too, and the holder claims its latest note from
    it."""
    l1, l2, l3, gold, silv, c12, c23 = credit_setup(
        node_factory, bitcoind,
        holder_opts={'allow_warning': True}, provider_opts={'allow_warning': True})
    tc.fund_node(bitcoind, l3, silv, 2 * PAR)
    held = credit_twice(l1, l2, l3, gold)
    forget_notes(l2)
    wait_for(lambda: chan(l2, l3)['peer_connected'])
    assert l2.rpc.call('listcreditnotes', {'id': l3.info['id']})['notes'] == []

    res = l2.rpc.close(l3.info['id'], unilateraltimeout=20)
    l3.daemon.wait_for_log('Bad closing_signed signature')
    assert res['type'] == 'unilateral'
    commitment = only_one(res['txids'])
    bitcoind.generate_block(1, wait_for_mempool=commitment)
    claim = check_claim(bitcoind, l3, commitment, 45_000_000, held[1]['preimage'], gold)
    # On the provider's own commitment the rest stays under its to_local:
    # it sweeps it after its delay.
    sweep, j = tc.wait_spender_after(bitcoind, claim['txid'], 0, 14)
    print("provider sweep:", sweep['txid'], sweep['vsize'])
    tc.mine_if_pending(bitcoind, sweep['txid'])


def test_credit_floor_refuses_provider_htlc(node_factory, bitcoind):
    """A provider that forgets its notes tries to move its balance below
    what it owes: an HTLC to the holder that would leave its balance
    output unable to pay the note's CLAIM if the provider dropped that
    commitment.  The holder's channeld refuses it.  The provider drops
    its last commitment instead and the holder claims from it."""
    l1, l2, l3, gold, silv, c12, c23 = credit_setup(
        node_factory, bitcoind,
        holder_opts={'allow_warning': True}, provider_opts={'allow_warning': True})
    tc.fund_node(bitcoind, l3, silv, 2 * PAR)
    held = credit_twice(l1, l2, l3, gold)
    forget_notes(l2)
    wait_for(lambda: chan(l2, l3)['peer_connected'])

    pay_direct(l2, l3, c23, 160_000_000_000, gold, wait=False)
    l3.daemon.wait_for_log('Bad peer_add_htlc: CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED')
    assert l3.rpc.listinvoices('big')['invoices'][0]['status'] == 'unpaid'

    l2.rpc.dev_fail(l3.info['id'])
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == 1)
    commitment = only_one(bitcoind.rpc.getrawmempool())
    bitcoind.generate_block(1, wait_for_mempool=commitment)
    check_claim(bitcoind, l3, commitment, 45_000_000, held[1]['preimage'], gold)


def test_credit_keyless_holder_away_then_claims(node_factory, bitcoind, directory):
    """l3 keeps its keys on a device signer (contrib/seqln-signer) in
    enforce mode, as a hosted user does: its node runs at the host, its
    device at the user's.  The device validates the credit channel's
    commitments against the credit trees.  It goes away, and l3 is paid
    twice through l2's credit invoices: l2 signs a cumulative note for each,
    and l3's node keeps both without the device.  The device returns,
    learns the latest note (with its preimage), and l3 drops its commitment
    and claims the note, the device signing the claim's fee coin, in SILV,
    and refusing nothing along the way."""
    import test_keyless_close as kc
    import test_keyless_start as ks
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: 2 * PAR})
    l1, l2 = node_factory.get_nodes(2, opts=[
        {**tc.TCOV, **tc.SHORT, 'may_reconnect': True},
        {**CREDIT, 'plugin': CREDIT_PLUGIN, 'may_reconnect': True}])
    device, l3 = kc.keyless_node(node_factory, directory, trace=True,
                                 options={**CREDIT}, may_reconnect=True)
    try:
        tc.fund_node(bitcoind, l1, gold, 10 * PAR)
        tc.fund_node(bitcoind, l2, gold, 10 * PAR)
        tc.fund_node(bitcoind, l3, silv, 2 * PAR)
        open_chan(bitcoind, l1, l2, gold, 4 * PAR)
        c23 = open_chan(bitcoind, l2, l3, gold, 2 * PAR)
        assert 'seq_credit/even' in c23['channel_type']['names']
        assert 'seq_credit/even' in chan(l3, l2)['channel_type']['names']

        # The device goes away; l3's node keeps running.
        device.stop()
        h1, x1 = credit_payment(l1, l2, l3, gold, 20_000_000_000, 'one')
        h2, x2 = credit_payment(l1, l2, l3, gold, 25_000_000_000, 'two')
        wait_for(lambda: len(l3.rpc.call('listcreditnotes', {'id': l2.info['id']})['notes']) == 2)
        held = l3.rpc.call('listcreditnotes', {'id': l2.info['id']})['notes']
        assert [(n['credit'], n['preimage']) for n in held] == [(20_000_000, x1), (45_000_000, x2)]
        print("held while the device was away:", json.dumps(held, indent=1))
        assert device.requests(67) == 0

        # The device returns and learns the latest note.
        ks.restart_device(device)
        wait_for(lambda: device.requests(67) >= 1)
        l3.daemon.wait_for_log('Signer told of credit note 45000000')

        # l3 drops its commitment and claims the note.
        l3.rpc.dev_fail(l2.info['id'])
        wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == 1)
        commitment = only_one(bitcoind.rpc.getrawmempool())
        bitcoind.generate_block(1, wait_for_mempool=commitment)
        claim = check_claim(bitcoind, l3, commitment, 45_000_000, x2, gold)
        assert only_one([o for o in claim['vout']
                         if o['scriptPubKey']['type'] == 'fee'])['asset'] == silv
        rejects = [ln for ln in device.output().splitlines() if 'POLICY REJECT' in ln]
        assert rejects == [], rejects
    finally:
        # The node first: a node whose device has gone is left waiting for
        # it to reconnect.
        if kc.answers(l3, timeout=2):
            l3.stop()
        device.stop()
