"""Quoted cross-asset forwarding (contrib/crossasset-seq).

A payer holding only GOLD pays an invoice in SILV through a quoting node that
holds a channel in each: the quoting node signs a quote (amounts in and out,
expiry, CLTV terms) for the payment hash, takes the incoming GOLD HTLC and
forwards an outgoing SILV HTLC under the same hash, and settles or fails the
two together.  Run with TEST_NETWORK=sequentia-regtest (README.md,
"Testing").
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, wait_for

import os
import pytest
import threading
import time

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
ATOM = 1000  # msat per atom
CROSS = os.path.join(os.path.dirname(__file__), '..', '..', 'contrib',
                     'crossasset-seq', 'crossasset.py')
HOLD = os.path.join(os.path.dirname(__file__), '..', '..', 'contrib',
                    'holdinvoice-seq', 'holdinvoice.py')

# The quoting node's own rate: 98.5 SILV atoms per GOLD atom, while the
# chain's fee rates value one GOLD atom at 100 SILV atoms.  Fees: 2,000 ppm
# plus one atom, in GOLD.
RATE, FEE_PPM, FEE_BASE = '98.5', 2000, 1 * ATOM
AMOUNT_OUT = 1970000 * ATOM                       # 1,970,000 SILV atoms
AMOUNT_IN = 20000000 + 20000000 * FEE_PPM // 10**6 + FEE_BASE   # 20,041 GOLD atoms


def invoice(node, label, asset):
    return node.rpc.call('invoice', {'amount_msat': AMOUNT_OUT, 'label': label,
                                     'description': label, 'asset': asset})['bolt11']


def chan(node, peer, asset):
    return only_one([c for c in node.rpc.listfunds()['channels']
                     if c['peer_id'] == peer.info['id'] and c['asset'] == asset])


def balance(node, peer, asset):
    """This node's side of its channel to peer in asset, in msat."""
    scid = chan(node, peer, asset)['short_channel_id']
    c = only_one([c for c in node.rpc.listpeerchannels(peer.info['id'])['channels']
                  if c.get('short_channel_id') == scid])
    return c['to_us_msat']


def books(l1, l2, l3, gold, silv):
    return {'payer GOLD': balance(l1, l2, gold), 'quoter GOLD': balance(l2, l1, gold),
            'quoter SILV': balance(l2, l3, silv), 'payee SILV': balance(l3, l2, silv)}


def no_htlcs(*nodes):
    return all(c['htlcs'] == [] for n in nodes for c in n.rpc.listpeerchannels()['channels'])


def network(node_factory, bitcoind, quoter_opts=None, payee_opts=None, pay_in=None,
            payer_opts=None):
    """l1 (payer) holds a public GOLD channel to l2 (the quoting node), which
    holds an unannounced SILV channel to l3 (the payee): the payee's invoice
    carries the hint for it.  pay_in replaces GOLD as the payer's asset."""
    gold = pay_in or bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates(dict({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: PAR // 100}))
    opts = [dict({'plugin': CROSS}, **(payer_opts or {})),
            dict({'plugin': CROSS}, **(quoter_opts or {})),
            payee_opts or {}]
    l1, l2, l3 = node_factory.get_nodes(3, opts=opts)
    txids = [bitcoind.send(l1.rpc.newaddr('bech32')['bech32'], 10 * PAR, gold),
             bitcoind.send(l2.rpc.newaddr('bech32')['bech32'], 10 * PAR, silv)]
    bitcoind.generate_block(1, wait_for_mempool=txids)
    for n in (l1, l2):
        wait_for(lambda: any(o['status'] == 'confirmed' for o in n.rpc.listfunds()['outputs']))
    for a, b, asset, public in ((l1, l2, gold, True), (l2, l3, silv, False)):
        a.rpc.connect(b.info['id'], 'localhost', b.port)
        res = a.rpc.call('fundchannel', {'id': b.info['id'], 'amount': PAR,
                                         'asset': asset, 'announce': public})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1), (l2, l3), (l3, l2)):
        wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state']
                 == 'CHANNELD_NORMAL')
    bitcoind.generate_block(6)
    wait_for(lambda: len(l3.rpc.listchannels()['channels']) == 2)
    # The payee knows the quoting node's channel update, so its invoices
    # carry the hint for it.
    wait_for(lambda: l3.rpc.listincoming()['incoming'] != [])
    l2.rpc.call('crossassetsetrate', {'asset_in': gold, 'asset_out': silv, 'rate': RATE,
                                      'fee_base_msat': FEE_BASE, 'fee_ppm': FEE_PPM})
    return l1, l2, l3, gold, silv


def hint(inv, node):
    """The invoice's route hint for the quoting node's unannounced channel
    to the payee: the name a payer knows it by."""
    return only_one([r[0]['short_channel_id'] for r in inv['routes']
                     if r[0]['pubkey'] == node.info['id']])


def send_quoted(l1, l2, l3, gold, silv, q, inv, d_in=0, d_out=0, out_channel=None):
    """Send the payment as crossassetpay would, by hand: the first hop gives
    the quoting node d_in msat more than the quote takes, and the onion asks
    it to forward d_out msat more than the quote pays."""
    final = inv['min_final_cltv_expiry']
    route = [{'id': l2.info['id'], 'channel': chan(l1, l2, gold)['short_channel_id'],
              'amount_msat': q['amount_in_msat'] + d_in, 'delay': final + q['cltv_delta']},
             {'id': l3.info['id'], 'channel': out_channel or hint(inv, l2),
              'amount_msat': q['amount_out_msat'] + d_out, 'delay': final}]
    l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'],
                   amount_msat=q['amount_out_msat'] + d_out)
    with pytest.raises(RpcError) as err:
        l1.rpc.waitsendpay(inv['payment_hash'])
    return err.value.error


def assert_refused(err, l2, why, ph):
    """The quoting node refused the HTLC itself, for the reason given, and
    sent nothing on."""
    print("payer sees:", err['message'], "| quoting node logged:", why)
    assert err['data']['erring_node'] == l2.info['id']
    assert err['data']['failcode'] == 0x400f
    assert l2.daemon.is_in_log(r'crossasset: refused the htlc for {}: {}'.format(ph, why))
    assert l2.rpc.listsendpays(payment_hash=ph)['payments'] == []


def test_payment_converts_through_quoting_node(node_factory, bitcoind):
    """A GOLD-only payer pays a SILV invoice through one quote: both HTLCs
    settle on one preimage and the three nodes' books equal the quote."""
    l1, l2, l3, gold, silv = network(node_factory, bitcoind)
    print("published:", l2.rpc.call('crossassetrates'))
    bolt11 = invoice(l3, 'conv', silv)

    # The payer's wallet holds GOLD only; plain pay refuses the SILV invoice.
    with pytest.raises(RpcError, match='cannot send asset'):
        l1.rpc.pay(bolt11)

    # The payer names the most it will give; a quote above it sends nothing.
    with pytest.raises(RpcError, match='the quote asks {}msat of {}, above maxamount_in_msat {}'
                       .format(AMOUNT_IN, gold, AMOUNT_IN - ATOM)):
        l1.rpc.call('crossassetpay', {'bolt11': bolt11, 'node_id': l2.info['id'],
                                      'maxamount_in_msat': AMOUNT_IN - ATOM})
    assert l1.rpc.listsendpays(bolt11)['payments'] == []

    before = books(l1, l2, l3, gold, silv)
    res = l1.rpc.call('crossassetpay', {'bolt11': bolt11, 'node_id': l2.info['id'],
                                        'maxamount_in_msat': AMOUNT_IN})
    q = res['quote']
    print("quote:", {k: q[k] for k in ('quote_id', 'asset_in', 'amount_in_msat', 'asset_out',
                                       'amount_out_msat', 'rate', 'fee_base_msat', 'fee_ppm',
                                       'expiry', 'cltv_delta', 'max_out_cltv')})
    assert (q['amount_in_msat'], q['amount_out_msat']) == (AMOUNT_IN, AMOUNT_OUT)
    assert (q['asset_in'], q['asset_out']) == (gold, silv)

    # One preimage: the payee's invoice, the quoting node's outgoing payment
    # and the payer's payment all name the same one.
    pre = res['payment_preimage']
    inv = only_one(l3.rpc.listinvoices('conv')['invoices'])
    out = only_one(l2.rpc.listsendpays(payment_hash=inv['payment_hash'])['payments'])
    assert inv['status'] == 'paid' and inv['payment_preimage'] == pre
    assert out['status'] == 'complete' and out['payment_preimage'] == pre
    print("preimage at payer, quoting node, payee:", pre, out['payment_preimage'],
          inv['payment_preimage'])
    fwd = only_one(l2.rpc.call('crossassetforwards')['forwards'])
    assert fwd['state'] == 'settled' and fwd['quote_id'] == q['quote_id']
    # The payer's own record: sent in GOLD, delivered in SILV.
    sent = only_one(l1.rpc.listsendpays(bolt11)['payments'])
    pays = only_one(l1.rpc.listpays(bolt11)['pays'])
    print("payer's listsendpays:", sent['status'], sent['amount_sent_msat'], sent['amount_msat'],
          "| listpays:", pays['status'], pays['amount_sent_msat'])
    assert (sent['amount_sent_msat'], sent['amount_msat']) == (AMOUNT_IN, AMOUNT_OUT)
    assert pays['status'] == 'complete'

    wait_for(lambda: no_htlcs(l1, l2, l3))
    after = books(l1, l2, l3, gold, silv)
    delta = {k: after[k] - before[k] for k in before}
    print("books, msat:", delta)
    assert delta == {'payer GOLD': -AMOUNT_IN, 'quoter GOLD': AMOUNT_IN,
                     'quoter SILV': -AMOUNT_OUT, 'payee SILV': AMOUNT_OUT}

    # The signed quote verifies against the quoting node's key; the payer's
    # check refuses it with any term changed, or from any other node.
    msg = l1.rpc.call('crossassetquotemessage', {'quote': q})['message']
    assert msg.startswith('seqln-crossasset-quote-v1:{')
    assert l1.rpc.checkmessage(msg, q['signature'], l2.info['id'])['verified']
    asked = {'node_id': l2.info['id'], 'payment_hash': q['payment_hash'], 'asset_in': gold,
             'asset_out': silv, 'amount_out_msat': AMOUNT_OUT + ATOM}
    tampered = dict(q, amount_out_msat=AMOUNT_OUT + ATOM, expiry=int(time.time()) + 30)
    with pytest.raises(RpcError, match="the quote's signature is not the quoting node's"):
        l1.rpc.call('crossassetcheckquote', dict(asked, quote=tampered))
    with pytest.raises(RpcError, match="the quote's node_id is"):
        other = dict(tampered, node_id=l3.info['id'])
        l1.rpc.call('crossassetcheckquote', dict(asked, quote=other, amount_out_msat=AMOUNT_OUT))


def test_amount_off_by_one_atom_refused(node_factory, bitcoind):
    """An HTLC one atom under or over the quote, or an onion asking the
    quoting node to forward one atom more, is refused before anything goes
    out; the quote stays usable, and the exact amounts then pay."""
    l1, l2, l3, gold, silv = network(node_factory, bitcoind)
    inv = l1.rpc.decode(invoice(l3, 'off', silv))
    q = l1.rpc.call('crossassetrequestquote', {
        'node_id': l2.info['id'], 'payment_hash': inv['payment_hash'], 'asset_in': gold,
        'asset_out': silv, 'amount_out_msat': AMOUNT_OUT})
    ph = inv['payment_hash']
    before = books(l1, l2, l3, gold, silv)

    err = send_quoted(l1, l2, l3, gold, silv, q, inv, d_in=-ATOM)
    assert_refused(err, l2, 'arrived with {}msat, the quote takes {}msat'.format(
        AMOUNT_IN - ATOM, AMOUNT_IN), ph)
    err = send_quoted(l1, l2, l3, gold, silv, q, inv, d_in=+ATOM)
    assert_refused(err, l2, 'arrived with {}msat, the quote takes {}msat'.format(
        AMOUNT_IN + ATOM, AMOUNT_IN), ph)
    err = send_quoted(l1, l2, l3, gold, silv, q, inv, d_out=+ATOM)
    assert_refused(err, l2, 'the onion forwards {}msat, the quote pays {}msat'.format(
        AMOUNT_OUT + ATOM, AMOUNT_OUT), ph)
    wait_for(lambda: no_htlcs(l1, l2, l3))
    assert books(l1, l2, l3, gold, silv) == before
    assert only_one(l3.rpc.listinvoices('off')['invoices'])['status'] == 'unpaid'

    # The refusals did not spend the quote: the exact amounts pay.
    route_ok = send_quoted_ok(l1, l2, l3, gold, silv, q, inv)
    print("then exact amounts:", route_ok['status'])
    assert only_one(l3.rpc.listinvoices('off')['invoices'])['status'] == 'paid'


def send_quoted_ok(l1, l2, l3, gold, silv, q, inv):
    final = inv['min_final_cltv_expiry']
    route = [{'id': l2.info['id'], 'channel': chan(l1, l2, gold)['short_channel_id'],
              'amount_msat': q['amount_in_msat'], 'delay': final + q['cltv_delta']},
             {'id': l3.info['id'], 'channel': hint(inv, l2),
              'amount_msat': q['amount_out_msat'], 'delay': final}]
    l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'],
                   amount_msat=q['amount_out_msat'])
    return l1.rpc.waitsendpay(inv['payment_hash'])


def test_expired_quote_refused(node_factory, bitcoind):
    """An HTLC that arrives after its quote's expiry is refused."""
    l1, l2, l3, gold, silv = network(node_factory, bitcoind)
    inv = l1.rpc.decode(invoice(l3, 'late', silv))
    q = l1.rpc.call('crossassetrequestquote', {
        'node_id': l2.info['id'], 'payment_hash': inv['payment_hash'], 'asset_in': gold,
        'asset_out': silv, 'amount_out_msat': AMOUNT_OUT, 'seconds': 2})
    assert q['expiry'] - time.time() <= 2
    time.sleep(q['expiry'] - time.time() + 1.5)
    before = books(l1, l2, l3, gold, silv)
    err = send_quoted(l1, l2, l3, gold, silv, q, inv)
    assert_refused(err, l2, 'quote {} expired at {}'.format(q['quote_id'], q['expiry']),
                   inv['payment_hash'])
    wait_for(lambda: no_htlcs(l1, l2, l3))
    assert books(l1, l2, l3, gold, silv) == before
    # The payer's own check refuses an expired quote too.
    with pytest.raises(RpcError, match='the quote expired'):
        l1.rpc.call('crossassetcheckquote', {'quote': q, 'node_id': l2.info['id'],
                                             'payment_hash': inv['payment_hash'],
                                             'asset_in': gold, 'asset_out': silv,
                                             'amount_out_msat': AMOUNT_OUT})


def test_payee_fails_and_quote_used_twice(node_factory, bitcoind):
    """The payee holds the SILV HTLC, then fails it: both HTLCs fail back and
    nobody's books move.  While it is held, the quoting node's cap of one
    open forward in SILV refuses a second quoted payment.  Sent again, the
    spent quote is refused."""
    l1, l2, l3, gold, silv = network(node_factory, bitcoind,
                                     quoter_opts={'crossasset-max-open': 1},
                                     payee_opts={'plugin': HOLD})
    bolt11 = invoice(l3, 'held', silv)
    inv = l1.rpc.decode(bolt11)
    ph = inv['payment_hash']
    l3.rpc.call('holdinvoice', {'payment_hash': ph, 'amount_msat': AMOUNT_OUT, 'asset': silv})
    # A second payment, quoted before the first opens.
    inv2 = l1.rpc.decode(invoice(l3, 'second', silv))
    q2 = l1.rpc.call('crossassetrequestquote', {
        'node_id': l2.info['id'], 'payment_hash': inv2['payment_hash'], 'asset_in': gold,
        'asset_out': silv, 'amount_out_msat': AMOUNT_OUT})
    before = books(l1, l2, l3, gold, silv)

    result = {}

    def pay():
        try:
            result['ok'] = l1.rpc.call('crossassetpay', {'bolt11': bolt11, 'node_id': l2.info['id'],
                                                         'maxamount_in_msat': AMOUNT_IN})
        except RpcError as e:
            result['err'] = e.error
    t = threading.Thread(target=pay)
    t.start()
    wait_for(lambda: l3.rpc.call('holdinvoicelookup', {'payment_hash': ph})['state'] == 'accepted')
    # Both legs are in flight at the quoting node, in their own assets.
    fwd = only_one(l2.rpc.call('crossassetforwards')['forwards'])
    assert fwd['state'] == 'forwarding'
    in_htlc = only_one(only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['htlcs'])
    out_htlc = only_one(only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['htlcs'])
    print("held: in", in_htlc['direction'], in_htlc['amount_msat'], "| out",
          out_htlc['direction'], out_htlc['amount_msat'])
    assert (in_htlc['amount_msat'], out_htlc['amount_msat']) == (AMOUNT_IN, AMOUNT_OUT)
    assert in_htlc['payment_hash'] == out_htlc['payment_hash'] == ph

    # The cap: one forward open in SILV, so the second quoted HTLC is refused.
    with pytest.raises(RpcError, match='forwards open in asset'):
        l1.rpc.call('crossassetrequestquote', {
            'node_id': l2.info['id'], 'payment_hash': '00' * 32, 'asset_in': gold,
            'asset_out': silv, 'amount_out_msat': AMOUNT_OUT})
    err = send_quoted(l1, l2, l3, gold, silv, q2, inv2)
    print("second payment while one is open:", err['message'])
    assert err['data']['erring_node'] == l2.info['id']
    assert l2.daemon.is_in_log(r'refused the htlc for {}: 1 forwards are open in asset {}, the cap'
                               .format(inv2['payment_hash'], silv))
    assert l2.rpc.listsendpays(payment_hash=inv2['payment_hash'])['payments'] == []

    # The payee fails the payment: both HTLCs fail back.
    l3.rpc.call('holdinvoicecancel', {'payment_hash': ph})
    t.join(60)
    print("payer's crossassetpay:", result.get('err', {}).get('message'))
    assert 'err' in result and 'the payment failed' in result['err']['message']
    wait_for(lambda: no_htlcs(l1, l2, l3))
    assert only_one(l2.rpc.call('crossassetforwards')['forwards'])['state'] == 'failed'
    assert only_one(l2.rpc.listsendpays(payment_hash=ph)['payments'])['status'] == 'failed'
    after = books(l1, l2, l3, gold, silv)
    print("books after the payee failed it:", {k: after[k] - before[k] for k in before})
    assert after == before

    # Used twice: the quote the failed payment spent is refused, with
    # nothing sent on.
    q = only_one(l2.rpc.call('crossassetforwards')['forwards'])
    err = send_quoted(l1, l2, l3, gold, silv, dict(q, cltv_delta=fwd_cltv_delta(l2)), inv)
    assert err['data']['erring_node'] == l2.info['id']
    assert l2.daemon.is_in_log(r'refused the htlc for {}: quote {} has already been used'
                               .format(ph, q['quote_id']))
    assert len(l2.rpc.listsendpays(payment_hash=ph)['payments']) == 1
    wait_for(lambda: no_htlcs(l1, l2, l3))
    assert books(l1, l2, l3, gold, silv) == before

    # With the forward closed, the second quote pays.
    send_quoted_ok(l1, l2, l3, gold, silv, q2, inv2)
    assert only_one(l3.rpc.listinvoices('second')['invoices'])['status'] == 'paid'

    # A fresh quote for the failed payment is a new grant, and is forwarded
    # (the payee, which cancelled its hold, fails it again).
    q3 = l1.rpc.call('crossassetrequestquote', {
        'node_id': l2.info['id'], 'payment_hash': ph, 'asset_in': gold,
        'asset_out': silv, 'amount_out_msat': AMOUNT_OUT})
    assert q3['quote_id'] != q['quote_id']
    wait_for(lambda: no_htlcs(l1, l2, l3))
    before = books(l1, l2, l3, gold, silv)
    err = send_quoted(l1, l2, l3, gold, silv, q3, inv)
    print("fresh quote after the failure, payer sees:", err['message'])
    assert len(l2.rpc.listsendpays(payment_hash=ph)['payments']) == 2
    assert only_one([f for f in l2.rpc.call('crossassetforwards')['forwards']
                     if f['payment_hash'] == ph])['quote_id'] == q3['quote_id']
    wait_for(lambda: no_htlcs(l1, l2, l3))
    assert books(l1, l2, l3, gold, silv) == before


def fwd_cltv_delta(node):
    return node.rpc.call('crossassetrates')['cltv_delta']


def test_sequence_token_is_one_leg_among_equals(node_factory, bitcoind):
    """The quoting node converts the Sequence token like any other asset: a
    payer holding only the token pays a SILV invoice."""
    seq = bitcoind.POLICY_ASSET
    l1, l2, l3, _, silv = network(node_factory, bitcoind, pay_in=seq)
    bolt11 = invoice(l3, 'from-seq', silv)
    before = books(l1, l2, l3, seq, silv)
    res = l1.rpc.call('crossassetpay', {'bolt11': bolt11, 'node_id': l2.info['id'],
                                        'maxamount_in_msat': AMOUNT_IN})
    assert (res['quote']['asset_in'], res['quote']['amount_in_msat']) == (seq, AMOUNT_IN)
    wait_for(lambda: no_htlcs(l1, l2, l3))
    after = books(l1, l2, l3, seq, silv)
    delta = {k: after[k] - before[k] for k in before}
    print("books, Sequence token in, SILV out, msat:", delta)
    assert delta == {'payer GOLD': -AMOUNT_IN, 'quoter GOLD': AMOUNT_IN,
                     'quoter SILV': -AMOUNT_OUT, 'payee SILV': AMOUNT_OUT}


def test_quoting_node_restarts_mid_forward(node_factory, bitcoind):
    """The quoting node stops while the payee holds the outgoing HTLC.  On
    restart lightningd replays the incoming HTLC; the plugin finds the spent
    quote on disk, sends nothing again, and settles the incoming HTLC with
    the preimage the outgoing one returns."""
    l1, l2, l3, gold, silv = network(node_factory, bitcoind,
                                     payer_opts={'may_reconnect': True},
                                     quoter_opts={'may_reconnect': True},
                                     payee_opts={'plugin': HOLD, 'may_reconnect': True})
    preimage = os.urandom(32).hex()
    bolt11 = l3.rpc.call('invoice', {'amount_msat': AMOUNT_OUT, 'label': 'restart',
                                     'description': 'restart', 'asset': silv,
                                     'preimage': preimage})['bolt11']
    inv = l1.rpc.decode(bolt11)
    ph = inv['payment_hash']
    l3.rpc.call('holdinvoice', {'payment_hash': ph, 'amount_msat': AMOUNT_OUT, 'asset': silv})
    before = books(l1, l2, l3, gold, silv)
    result = {}

    def pay():
        try:
            result['ok'] = l1.rpc.call('crossassetpay', {'bolt11': bolt11, 'node_id': l2.info['id'],
                                                         'maxamount_in_msat': AMOUNT_IN,
                                                         'retry_for': 600})
        except RpcError as e:
            result['err'] = e.error
    t = threading.Thread(target=pay)
    t.start()
    wait_for(lambda: l3.rpc.call('holdinvoicelookup', {'payment_hash': ph})['state'] == 'accepted')

    l2.restart()
    assert l2.daemon.is_in_log(r'crossasset: 1 published pair\(s\), 1 open forward\(s\) restored')
    for a, b in ((l1, l2), (l3, l2)):
        a.rpc.connect(b.info['id'], 'localhost', b.port)
    l2.daemon.wait_for_log(r'crossasset: resuming forward {} after a restart'.format(ph))
    l3.rpc.call('holdinvoicesettle', {'payment_hash': ph, 'preimage': preimage})
    t.join(120)
    print("payer after the quoting node restarted:", result.get('ok', result.get('err')))
    assert result['ok']['payment_preimage'] == preimage
    assert len(l2.rpc.listsendpays(payment_hash=ph)['payments']) == 1
    assert only_one(l2.rpc.call('crossassetforwards')['forwards'])['state'] == 'settled'
    wait_for(lambda: no_htlcs(l1, l2, l3))
    after = books(l1, l2, l3, gold, silv)
    delta = {k: after[k] - before[k] for k in before}
    print("books across the restart, msat:", delta)
    assert delta == {'payer GOLD': -AMOUNT_IN, 'quoter GOLD': AMOUNT_IN,
                     'quoter SILV': -AMOUNT_OUT, 'payee SILV': AMOUNT_OUT}


def test_lightningd_alone_never_converts(node_factory, bitcoind):
    """A forward in one asset that shares a quoted hash is left to
    lightningd and pays as usual; and with the plugin stopped, lightningd's
    own backstop refuses the cross-asset route the quote was for.  The
    plugin cannot be stopped while lightningd runs."""
    l1, l2, l3, gold, silv = network(node_factory, bitcoind, payer_opts={'may_reconnect': True},
                                     quoter_opts={'may_reconnect': True},
                                     payee_opts={'may_reconnect': True})
    # A GOLD channel from the quoting node to the payee, beside the SILV one.
    txid = bitcoind.send(l2.rpc.newaddr('bech32')['bech32'], 10 * PAR, gold)
    bitcoind.generate_block(1, wait_for_mempool=txid)
    wait_for(lambda: any(o['asset'] == gold and o['status'] == 'confirmed'
                         for o in l2.rpc.listfunds()['outputs']))
    res = l2.rpc.call('fundchannel', {'id': l3.info['id'], 'amount': PAR, 'asset': gold,
                                      'announce': True})
    bitcoind.generate_block(6, wait_for_mempool=res['txid'])
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 4)

    gold_inv = l1.rpc.decode(l3.rpc.call('invoice', {'amount_msat': 5000 * ATOM, 'label': 'g',
                                                     'description': 'g', 'asset': gold})['bolt11'])
    # Someone quotes that invoice's hash for a conversion it will never be.
    l2.rpc.call('crossassetquote', {'payment_hash': gold_inv['payment_hash'], 'asset_in': gold,
                                    'asset_out': silv, 'amount_out_msat': AMOUNT_OUT})
    l1.rpc.pay(l3.rpc.listinvoices('g')['invoices'][0]['bolt11'])
    assert only_one(l3.rpc.listinvoices('g')['invoices'])['status'] == 'paid'
    assert l2.rpc.call('crossassetforwards')['forwards'] == []
    assert not l2.daemon.is_in_log('crossasset: refused')
    print("GOLD payment sharing a quoted hash: paid, forwarded by lightningd")

    # Without the plugin, the cross-asset route is refused by lightningd.
    inv = l1.rpc.decode(invoice(l3, 'nofx', silv))
    q = l2.rpc.call('crossassetquote', {'payment_hash': inv['payment_hash'], 'asset_in': gold,
                                        'asset_out': silv, 'amount_out_msat': AMOUNT_OUT})
    # Named by its real scid, the unannounced SILV channel is unknown to the
    # plugin as to lightningd: nothing is forwarded and the quote is unspent.
    err = send_quoted(l1, l2, l3, gold, silv, q, inv,
                      out_channel=chan(l2, l3, silv)['short_channel_id'])
    print("real scid of the private channel, payer sees:", err['message'])
    assert err['data']['failcode'] == 0x400a
    assert l2.daemon.is_in_log('No peer channel with scid={}'.format(
        chan(l2, l3, silv)['short_channel_id']))
    assert l2.rpc.call('crossassetforwards')['forwards'] == []

    # The plugin cannot be stopped at runtime: an open forward depends on it.
    with pytest.raises(RpcError, match='cannot be managed when lightningd is up'):
        l2.rpc.plugin_stop('crossasset.py')
    del l2.daemon.opts['plugin']
    l2.restart()
    for a, b in ((l1, l2), (l2, l3)):
        a.rpc.connect(b.info['id'], 'localhost', b.port)
    for a, b in ((l1, l2), (l2, l3)):
        wait_for(lambda: all(c['peer_connected'] and c['state'] == 'CHANNELD_NORMAL'
                             for c in a.rpc.listpeerchannels(b.info['id'])['channels']))
    before = books(l1, l2, l3, gold, silv)
    err = send_quoted(l1, l2, l3, gold, silv, q, inv)
    print("plugin stopped, payer sees:", err['message'])
    assert err['data']['erring_node'] == l2.info['id']
    assert l2.daemon.is_in_log('Refusing to forward HTLC across an asset boundary')
    wait_for(lambda: no_htlcs(l1, l2, l3))
    assert books(l1, l2, l3, gold, silv) == before
