"""`decode` of an invoice for another network.

A Sequentia node and a Bitcoin node read the same BOLT11 format, and an
invoice says which network it is for in its prefix (`lnbcrt` for Bitcoin
regtest, `lnsqrt` for sequentia-regtest).  When either network is a
Sequentia one and the two differ, `decode` shows the invoice's fields but
answers `valid: false`, with `warning_network` naming both networks; `pay`
refuses it.  Between two Bitcoin networks `decode` reads the invoice as
upstream does: a Bitcoin mainnet invoice on a Bitcoin regtest node is
valid.  Run with TEST_NETWORK=sequentia-regtest, and with
TEST_NETWORK=regtest for the Bitcoin side (README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from pyln.proto.bech32 import CHARSET, bech32_decode, bech32_encode
from utils import TEST_NETWORK

import coincurve
import hashlib
import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK not in ('sequentia-regtest', 'regtest'),
                                reason='needs TEST_NETWORK=sequentia-regtest or regtest')

SEQ = TEST_NETWORK == 'sequentia-regtest'
SIG_U5 = 104
KEY = coincurve.PrivateKey(b'\x24' * 32)
ASSET = '11' * 32


def to_bytes(u5s):
    bits = ''.join(format(w, '05b') for w in u5s)
    bits += '0' * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def to_u5(data, nbits):
    bits = ''.join(format(b, '08b') for b in data)[:nbits]
    bits += '0' * (-len(bits) % 5)
    return [int(bits[i:i + 5], 2) for i in range(0, len(bits), 5)]


def for_network(inv, prefix, asset):
    """The invoice re-made for another network: its prefix swapped, the
    asset field `a` set (or dropped, for None), and signed by KEY."""
    hrp, data = bech32_decode(inv)
    body = list(data)[:-SIG_U5]
    ts, rest, fields = body[:7], body[7:], []
    while rest:
        tag, ln = CHARSET[rest[0]], rest[1] * 32 + rest[2]
        fields.append((tag, rest[3:3 + ln]))
        rest = rest[3 + ln:]
    fields = [(t, d) for t, d in fields if t != 'a']
    if asset:
        fields.append(('a', to_u5(bytes.fromhex(asset), 256)))
    old = 'lnsqrt' if hrp.startswith('lnsqrt') else 'lnbcrt'
    hrp = prefix + hrp[len(old):]
    out = list(ts)
    for tag, d in fields:
        out += [CHARSET.find(tag), len(d) // 32, len(d) % 32] + list(d)
    msg = hrp.encode() + to_bytes(out)
    sig = to_u5(KEY.sign_recoverable(msg, hasher=lambda m: hashlib.sha256(m).digest()), 520)
    return bech32_encode(hrp, bytes(out + sig))


def test_decode_refuses_another_networks_invoice(node_factory, bitcoind):
    l1 = node_factory.get_node()
    req = {'amount_msat': 1_000_000, 'label': 'own', 'description': 'own'}
    if SEQ:
        req.update({'asset': bitcoind.POLICY_ASSET, 'allow_unfunded': True})
    own = l1.rpc.call('invoice', req)['bolt11']
    mine = 'sequentia-regtest' if SEQ else 'regtest'
    dec = l1.rpc.decode(own)
    assert dec['valid'] is True and 'warning_network' not in dec

    if SEQ:
        assert own.startswith('lnsqrt')
        other, other_name, other_prefix = for_network(own, 'lnbcrt', None), 'regtest', 'bcrt'
    else:
        assert own.startswith('lnbcrt')
        other, other_name, other_prefix = for_network(own, 'lnsqrt', ASSET), 'sequentia-regtest', 'sqrt'

    dec = l1.rpc.decode(other)
    print("decode, on {}, of an ln{} invoice:".format(mine, other_prefix),
          {k: dec.get(k) for k in ('type', 'currency', 'valid', 'warning_network')})
    assert dec['type'] == 'bolt11 invoice'
    assert dec['currency'] == other_prefix
    assert dec['payee'] == KEY.public_key.format().hex()
    assert dec['valid'] is False
    assert dec['warning_network'] == (
        'the invoice is for {} (ln{}), and this node runs {} (ln{})'
        .format(other_name, other_prefix, mine, 'sqrt' if SEQ else 'bcrt'))

    with pytest.raises(RpcError) as err:
        l1.rpc.call('pay', {'bolt11': other})
    print("pay of it:", err.value.error['message'])
    assert l1.rpc.listsendpays()['payments'] == []

    # Between two Bitcoin networks decode reads the invoice as upstream
    # does: BOLT #11's first test vector, a mainnet invoice, on regtest.
    if not SEQ:
        vec = l1.rpc.decode(
            'lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3z'
            'ygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pk'
            'x2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrs'
            'gq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjs'
            'rvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql')
        print("decode, on regtest, of an lnbc invoice:", vec['currency'], vec['valid'])
        assert vec['currency'] == 'bc' and vec['valid'] is True
        assert 'warning_network' not in vec
