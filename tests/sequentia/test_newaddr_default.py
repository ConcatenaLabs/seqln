"""`newaddr` on Sequentia gives an address the node can spend.

hsmd cannot sign a taproot wallet input on an elements chain, and an
explicit `p2tr` is refused there.  So the default, and `all`, give the
bech32 (P2WPKH) address alone: an operator who funds the node with plain
`newaddr` can then withdraw the coin, or open a channel from it.

Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import TEST_NETWORK, only_one, wait_for

import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')


def test_newaddr_default_is_spendable(node_factory, bitcoind):
    l1 = node_factory.get_node()

    plain = l1.rpc.newaddr()
    assert list(plain) == ['bech32'], plain
    every = l1.rpc.newaddr('all')
    assert list(every) == ['bech32'], every
    with pytest.raises(RpcError, match="should be 'p2tr', 'bech32', or 'all'"):
        l1.rpc.newaddr('p2tr')

    txid = bitcoind.send_and_mine_block(plain['bech32'], 10**7)
    wait_for(lambda: any(o['txid'] == txid and o['status'] == 'confirmed'
                         for o in l1.rpc.listfunds()['outputs']))

    # Spending the coin is what crashed hsmd when the default was p2tr.
    out = l1.rpc.withdraw(bitcoind.getnewaddress(), 'all')
    bitcoind.generate_block(1, wait_for_mempool=out['txid'])
    assert bitcoind.rpc.getrawtransaction(out['txid'], True)['confirmations'] >= 1
    wait_for(lambda: not any(o['txid'] == txid for o in l1.rpc.listfunds()['outputs']))
    assert l1.rpc.getinfo()['id']
