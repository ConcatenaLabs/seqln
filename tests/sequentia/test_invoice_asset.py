"""The asset in a BOLT11 invoice on a Sequentia network.

An invoice names the asset it is paid in, in the tagged field `a` (type 29,
52 characters: the 32-byte asset id in the order its hex is displayed).  The
field is under the invoice's signature like every other, and an invoice on a
Sequentia network without it is invalid: no asset, the Sequence token
included, is implied by its absence.  Run with TEST_NETWORK=sequentia-regtest
(README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from pyln.proto.bech32 import CHARSET, bech32_decode, bech32_encode
from utils import TEST_NETWORK, only_one, wait_for

import coincurve
import hashlib
import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
SIG_U5 = 104  # 65-byte recoverable signature, in 5-bit words


def fund(bitcoind, node, asset, atoms):
    addr = node.rpc.newaddr('bech32')['bech32']
    return bitcoind.send(addr, atoms, asset)


def open_channel(bitcoind, src, dst, asset, atoms=PAR):
    """src funds a channel to dst in asset and waits for it to be usable."""
    bitcoind.generate_block(1, wait_for_mempool=fund(bitcoind, src, asset, 10 * atoms))
    wait_for(lambda: any(o['status'] == 'confirmed' and o.get('asset') == asset
                         for o in src.rpc.listfunds()['outputs']))
    src.rpc.connect(dst.info['id'], 'localhost', dst.port)
    res = src.rpc.call('fundchannel', {'id': dst.info['id'], 'amount': atoms,
                                       'asset': asset})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for n, peer in ((src, dst), (dst, src)):
        wait_for(lambda: any(c['state'] == 'CHANNELD_NORMAL'
                             and c.get('channel_asset') == asset
                             for c in n.rpc.listpeerchannels(peer.info['id'])['channels']))


def words(inv):
    """An invoice's 5-bit data words, split into timestamp, fields and
    signature."""
    hrp, data = bech32_decode(inv)
    data = list(data)
    body, sig = data[:-SIG_U5], data[-SIG_U5:]
    ts, rest, fields = body[:7], body[7:], []
    while rest:
        tag, ln = CHARSET[rest[0]], rest[1] * 32 + rest[2]
        fields.append((tag, rest[3:3 + ln]))
        rest = rest[3 + ln:]
    return hrp, ts, fields, sig


def to_bytes(u5s):
    bits = ''.join(format(w, '05b') for w in u5s)
    bits += '0' * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def to_u5(data, nbits):
    bits = ''.join(format(b, '08b') for b in data)[:nbits]
    bits += '0' * (-len(bits) % 5)
    return [int(bits[i:i + 5], 2) for i in range(0, len(bits), 5)]


def assemble(hrp, ts, fields, sig=None, key=None):
    """Re-encode an invoice from its parts.  With a key, sign it afresh (as
    BOLT #11 does: sha256 of the hrp and the data words); otherwise keep
    the old signature words."""
    body = list(ts)
    for tag, data in fields:
        body += [CHARSET.find(tag), len(data) // 32, len(data) % 32] + list(data)
    if key is not None:
        msg = hrp.encode() + to_bytes(body)
        rsig = key.sign_recoverable(msg, hasher=lambda m: hashlib.sha256(m).digest())
        sig = to_u5(rsig, 520)
    return bech32_encode(hrp, bytes(body + list(sig)))


def test_invoice_carries_asset(node_factory, bitcoind):
    """`invoice asset=` puts the asset in the BOLT11 string, `decode` reads
    it back, and every other field is what it was."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2 = node_factory.get_nodes(2)
    open_channel(bitcoind, l1, l2, gold)

    res = l2.rpc.call('invoice', {'amount_msat': 123_456_000, 'label': 'g',
                                  'description': 'one gold thing', 'asset': gold,
                                  'expiry': 777, 'cltv': 33})
    inv = res['bolt11']
    dec = l1.rpc.decode(inv)
    assert dec['valid'] is True
    assert dec['asset'] == gold
    assert dec['payee'] == l2.info['id']
    assert dec['amount_msat'] == 123_456_000
    assert dec['description'] == 'one gold thing'
    assert dec['expiry'] == 777
    assert dec['min_final_cltv_expiry'] == 33
    assert dec['payment_hash'] == res['payment_hash']
    assert dec['payment_secret'] == res['payment_secret']
    assert 'extra' not in dec
    assert only_one(l2.rpc.listinvoices('g')['invoices'])['asset'] == gold

    # The field: `a`, 52 words, the asset id in display order.
    hrp, ts, fields, sig = words(inv)
    a = only_one([d for t, d in fields if t == 'a'])
    assert len(a) == 52
    assert to_bytes(a)[:32].hex() == gold

    # The asset is under the signature: the same signature over another
    # asset recovers another key, so the invoice no longer comes from l2.
    silv = bitcoind.issue_asset(1000)
    forged = assemble(hrp, ts, [(t, to_u5(bytes.fromhex(silv), 256) if t == 'a' else d)
                                for t, d in fields], sig)
    fdec = l1.rpc.decode(forged)
    assert fdec['asset'] == silv
    assert fdec['payee'] != l2.info['id']

    # Without asset= on a node whose channels hold one asset, that one.
    inv2 = l2.rpc.invoice(1000, 'plain', 'plain')['bolt11']
    assert l1.rpc.decode(inv2)['asset'] == gold


def test_invoice_without_asset_is_invalid(node_factory, bitcoind):
    """A Sequentia invoice that names no asset is invalid: `decode` refuses
    it and `pay` will not pay it, even signed correctly."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2 = node_factory.get_nodes(2)
    open_channel(bitcoind, l1, l2, gold)

    inv = l2.rpc.call('invoice', {'amount_msat': 1_000_000, 'label': 'x',
                                  'description': 'x', 'asset': gold})['bolt11']
    hrp, ts, fields, sig = words(inv)
    assert [t for t, _ in fields].count('a') == 1
    key = coincurve.PrivateKey(b'\x42' * 32)
    stripped = assemble(hrp, ts, [(t, d) for t, d in fields if t != 'a'], key=key)

    with pytest.raises(RpcError, match=r'a: missing: an invoice on sequentia-regtest'
                                       r' must name the asset it is paid in'):
        l1.rpc.decode(stripped)
    with pytest.raises(RpcError, match=r'a: missing'):
        l1.rpc.call('pay', {'bolt11': stripped, 'asset': gold})
    assert l1.rpc.listsendpays()['payments'] == []

    # The same invoice with its `a` field, signed by the same key, is valid.
    resigned = assemble(hrp, ts, fields, key=key)
    assert l1.rpc.decode(resigned)['asset'] == gold

    # A field of the wrong length is not skipped.
    short = assemble(hrp, ts, [(t, d[:51] if t == 'a' else d) for t, d in fields], key=key)
    with pytest.raises(RpcError, match=r'a: expected 52 characters, got 51'):
        l1.rpc.decode(short)


def test_invoice_refuses_unfunded_asset(node_factory, bitcoind):
    """An invoice in an asset the node holds no channel in is refused,
    unless the caller says allow_unfunded; with no asset named, a node
    whose channels hold several assets, or none, asks which."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: PAR})
    l1, l2, l3 = node_factory.get_nodes(3)

    # No channel at all.
    with pytest.raises(RpcError, match=r'no channel that can receive: name the asset'):
        l2.rpc.invoice(1000, 'none', 'none')
    with pytest.raises(RpcError, match=r'holds no channel in asset {}'.format(gold)):
        l2.rpc.call('invoice', {'amount_msat': 1000, 'label': 'g0',
                                'description': 'g0', 'asset': gold})

    open_channel(bitcoind, l1, l2, gold)
    scid = only_one(l2.rpc.listpeerchannels()['channels'])['short_channel_id']
    with pytest.raises(RpcError, match=r'holds no channel in asset {} \(it holds {} in {}\)'
                       .format(silv, scid, gold)):
        l2.rpc.call('invoice', {'amount_msat': 1000, 'label': 's',
                                'description': 's', 'asset': silv})
    assert l2.rpc.listinvoices()['invoices'] == []

    inv = l2.rpc.call('invoice', {'amount_msat': 1000, 'label': 's',
                                  'description': 's', 'asset': silv,
                                  'allow_unfunded': True})['bolt11']
    assert l1.rpc.decode(inv)['asset'] == silv
    assert only_one(l2.rpc.listinvoices('s')['invoices'])['asset'] == silv

    # Channels in two assets: the caller names one.
    open_channel(bitcoind, l3, l2, silv)
    with pytest.raises(RpcError, match=r'several assets: name the asset'):
        l2.rpc.invoice(1000, 'two', 'two')
    inv = l2.rpc.call('invoice', {'amount_msat': 1000, 'label': 'two',
                                  'description': 'two', 'asset': silv})['bolt11']
    assert l1.rpc.decode(inv)['asset'] == silv


def test_routehints_in_invoice_asset(node_factory, bitcoind):
    """The route hints of an invoice name only channels in its asset: a
    private channel in another asset is never offered to the payer, even
    when the channels in the asset cannot take the whole amount."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: PAR})
    l1, l2, l3 = node_factory.get_nodes(3)
    # Unannounced channels into l3, one per asset.
    open_channel(bitcoind, l1, l3, gold)
    open_channel(bitcoind, l2, l3, silv)
    chans = {c['channel_asset']: c for c in l3.rpc.listpeerchannels()['channels']}
    scids = [c['short_channel_id'] for c in chans.values()]
    # A hint names a channel by its short_channel_id or its alias.
    names = {a: {chans[a]['short_channel_id'], chans[a]['alias']['remote']}
             for a in (gold, silv)}

    def hint_scids(asset):
        # Both channels offered as hints, and 1.5 channels' worth asked
        # for: each channel alone is short of it.
        inv = l3.rpc.call('invoice', {'amount_msat': 150_000_000_000, 'label': 'h' + asset,
                                      'description': 'h', 'asset': asset,
                                      'exposeprivatechannels': scids})['bolt11']
        return [h['short_channel_id'] for r in l1.rpc.decode(inv).get('routes', [])
                for h in r]

    hints = hint_scids(gold)
    assert len(hints) == 1 and hints[0] in names[gold]
    hints = hint_scids(silv)
    assert len(hints) == 1 and hints[0] in names[silv]
