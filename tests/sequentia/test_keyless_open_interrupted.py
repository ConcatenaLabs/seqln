"""A keyless node's channel open interrupted by its device going away.

A wallet moves coins to Lightning by having its keyless node fund a channel:
the node signs the funding with the device and broadcasts it.  If the app is
then closed or reinstalled, the device is gone.  The channel still locks in
(channeld fetched the per-commitment point while the device was there), but a
hosted node restarted in the meantime cannot start: its hsmd waits for the
device, so the node answers no RPC, and a service that reads its channels for
the wallet lists none.  The coins have left the node's on-chain wallet and no
channel shows: the move looks lost.  They are in the channel's funding output,
unspent, and once the device is back (the wallet's phrase derives the same
one) the node starts, the channel is there, and the coins can be paid out of
it.  Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK, only_one, wait_for

import os
import pytest
import subprocess
import time

import test_keyless_close as kc

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')


@pytest.mark.skipif(not os.path.exists(kc.SIGNER), reason='needs the seqln-signer binary')
def test_keyless_open_survives_its_device_going_away(node_factory, bitcoind, directory):
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: kc.PAR, asset: kc.PAR})
    port = kc.free_port()
    host_priv, host_pub = kc.genkey()
    dev_priv, dev_pub = kc.genkey()

    def device():
        d = kc.Device(directory, port, dev_priv, host_pub)
        d.start()
        return d

    dev = device()
    l1 = node_factory.get_node(start=False, may_fail=True, may_reconnect=True, broken_log='.*',
                               options={'subdaemon': 'hsmd:' + kc.PROXY})
    l1.daemon.env.update({'SEQLN_SIGNER_LISTEN': '127.0.0.1:{}'.format(port),
                          'SEQLN_HOST_PRIVKEY': host_priv,
                          'SEQLN_SIGNER_PEER_PUBKEY': dev_pub,
                          'SEQLN_SIGNER_OP_TIMEOUT_MS': '120000' if kc.DEVICE == 'wasm' else '5000'})
    l1.start()
    restarted = None
    try:
        l2 = node_factory.get_node(may_reconnect=True)
        addr = l1.rpc.newaddr('bech32')['bech32']
        txid = bitcoind.send_and_mine_block(addr, 20 * 10**8, asset)
        wait_for(lambda: any(o['txid'] == txid for o in l1.rpc.listfunds()['outputs']))
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': 10 * 10**8,
                                          'asset': asset, 'announce': True})
        funding_out = res['outnum']

        # The funding is broadcast; the app goes away with the device, and the
        # host restarts the node while the funding confirms.
        dev.stop()
        kc.kill_tree(l1.daemon.proc.pid)
        l1.daemon.proc.wait()
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        bitcoind.generate_block(5)
        restarted = subprocess.Popen(l1.daemon.cmd_line, env=l1.daemon.env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        checks = []
        for _ in range(10):
            time.sleep(2)
            checks.append(kc.answers(l1, timeout=3))
        out = bitcoind.rpc.gettxout(res['txid'], funding_out)
        print('device away, node restarted: answered {} of {} checks over 20 s; funding {}:{} '
              'unspent with {} confirmations, {} of the asset'.format(
                  sum(checks), len(checks), res['txid'], funding_out,
                  out['confirmations'], out['value']))
        assert not any(checks), checks
        assert out['confirmations'] >= 6 and out['asset'] == asset
        assert round(out['value'] * 10**8) == 10 * 10**8

        # The wallet comes back with the same device: the node starts, its
        # channel is there, and the coins are spendable from it.
        dev = device()
        wait_for(lambda: kc.answers(l1, timeout=3), timeout=120)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        wait_for(lambda: kc.channel(l1, l2)['state'] == 'CHANNELD_NORMAL' and kc.channel(l1, l2)['peer_connected'],
                 timeout=120)
        ours = kc.channel(l1, l2)['to_us_msat'] // 1000
        print('device back: node answers, channel {} {}, {} atoms ours'.format(
            kc.channel(l1, l2)['short_channel_id'], kc.channel(l1, l2)['state'], ours))
        assert ours > 9 * 10**8
        inv = l2.rpc.invoice(10**8 * 1000, 'after', 'after')['bolt11']
        assert l1.rpc.pay(inv)['status'] == 'complete'
        assert only_one(l2.rpc.listinvoices('after')['invoices'])['status'] == 'paid'
        print('paid 1 unit out of the recovered channel')
    finally:
        if restarted is not None:
            kc.kill_tree(restarted.pid)
            restarted.wait()
        elif kc.answers(l1, timeout=2):
            l1.stop()
        dev.stop()
