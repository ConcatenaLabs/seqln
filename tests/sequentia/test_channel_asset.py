"""The asset of every channel, the Sequence token's included.

On a Sequentia network `listpeerchannels` names each channel's asset in
`channel_asset`, as `listfunds` does in `asset`: the policy asset is named
like any other, so a client never reads a missing value as "any asset".
Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK, only_one, wait_for

import hashlib
import json
import os
import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
HOLD = os.path.join(os.path.dirname(__file__), '..', '..', 'contrib',
                    'holdinvoice-seq', 'holdinvoice.py')


def test_policy_asset_channel_names_its_asset(node_factory, bitcoind):
    l1, l2 = node_factory.get_nodes(2, opts=[{}, {'plugin': HOLD}])
    txid = bitcoind.send_and_mine_block(l1.rpc.newaddr('bech32')['bech32'], 2 * PAR)
    wait_for(lambda: any(o['txid'] == txid and o['status'] == 'confirmed'
                         for o in l1.rpc.listfunds()['outputs']))
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.fundchannel(l2.info['id'], PAR)
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state']
                 == 'CHANNELD_NORMAL')
    for a, b in ((l1, l2), (l2, l1)):
        c = only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])
        print("listpeerchannels on a Sequence token channel:",
              {k: c.get(k) for k in ('short_channel_id', 'state', 'channel_asset')})
        assert c['channel_asset'] == bitcoind.POLICY_ASSET
        f = only_one(a.rpc.listfunds()['channels'])
        assert f['asset'] == bitcoind.POLICY_ASSET

    # A hold that names no asset is in the node's one asset, named.
    p = os.urandom(32)
    h = hashlib.sha256(p).hexdigest()
    reg = l2.rpc.call('holdinvoice', {'payment_hash': h, 'amount_msat': 10**9})
    assert reg['asset'] == bitcoind.POLICY_ASSET
    scid = only_one(l1.rpc.listpeerchannels()['channels'])['short_channel_id']
    route = [{'id': l2.info['id'], 'channel': scid, 'amount_msat': 10**9, 'delay': 200}]
    l1.rpc.sendpay(route, h)
    wait_for(lambda: l2.rpc.call('holdinvoicelookup', {'payment_hash': h})['state'] == 'accepted')
    assert l2.rpc.call('holdinvoicelookup', {'payment_hash': h})['asset'] == bitcoind.POLICY_ASSET
    l2.rpc.call('holdinvoicesettle', {'payment_hash': h, 'preimage': p.hex()})
    assert l1.rpc.waitsendpay(h)['status'] == 'complete'

    # A hold an older plugin recorded as "policy" (no id) is read back as
    # the network's policy asset, and holds an HTLC in it.
    p2 = os.urandom(32)
    h2 = hashlib.sha256(p2).hexdigest()
    l2.rpc.plugin_stop(HOLD)
    l2.rpc.datastore(key=['holdinvoice-seq', h2], string=json.dumps(
        {'state': 'waiting', 'preimage': None, 'amount_msat': 10**9, 'asset': 'policy',
         'label': '', 'description': '', 'cltv': 0}))
    l2.rpc.plugin_start(HOLD)
    assert l2.rpc.call('holdinvoicelookup', {'payment_hash': h2})['asset'] == bitcoind.POLICY_ASSET
    l1.rpc.sendpay(route, h2)
    wait_for(lambda: l2.rpc.call('holdinvoicelookup', {'payment_hash': h2})['state'] == 'accepted')
    l2.rpc.call('holdinvoicesettle', {'payment_hash': h2, 'preimage': p2.hex()})
    assert l1.rpc.waitsendpay(h2)['status'] == 'complete'
