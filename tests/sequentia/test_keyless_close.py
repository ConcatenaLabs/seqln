"""A keyless node closing a channel.

A keyless node runs `lightning_hsmd_proxy` as its hsmd and keeps its keys on a
device signer (`contrib/seqln-signer`) in enforce mode, connecting in the way a
browser device does.  When a mutual close completes, and again whenever it
starts with a channel closing, lightningd signs the closing transaction with
the message it uses for its own commitment.  The node must get that signature
and keep running.  Run with TEST_NETWORK=sequentia-regtest (README.md,
"Testing"); the signer binary is SEQLN_SIGNER, by default
contrib/seqln-signer/target/release/seqln-signer.
"""
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK, only_one, wait_for

import os
import pytest
import signal
import socket
import subprocess
import threading
import time

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

REPO = os.path.join(os.path.dirname(__file__), '..', '..')
PROXY = os.path.abspath(os.path.join(REPO, 'lightningd', 'lightning_hsmd_proxy'))
CLI = os.path.abspath(os.path.join(REPO, 'cli', 'lightning-cli'))
SIGNER = os.environ.get('SEQLN_SIGNER', os.path.abspath(os.path.join(
    REPO, 'contrib', 'seqln-signer', 'target', 'release', 'seqln-signer')))
MNEMONIC = ' '.join(['abandon'] * 11 + ['about'])
PAR = 10**8


def genkey():
    out = subprocess.check_output([SIGNER, '--genkey']).decode().split()
    return out[1], out[3]


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Device(object):
    """The device signer, reconnecting whenever its session ends, as a
    browser does."""
    def __init__(self, directory, port, priv, host_pub):
        self.dir = os.path.join(directory, 'device')
        os.makedirs(self.dir, exist_ok=True)
        with open(os.path.join(self.dir, 'hsm_secret'), 'wb') as f:
            f.write(bytes(32) + MNEMONIC.encode())
        self.log = os.path.join(self.dir, 'device.log')
        self.env = dict(os.environ, SEQLN_SIGNER_PRIVKEY=priv,
                        SEQLN_HOST_PEER_PUBKEY=host_pub,
                        SEQLN_SIGNER_POLICY='enforce')
        self.cmd = [SIGNER, '--connect', '127.0.0.1:{}'.format(port)]
        self.stopping = False
        self.proc = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        with open(self.log, 'a') as logf:
            while not self.stopping:
                self.proc = subprocess.Popen(self.cmd, cwd=self.dir, env=self.env,
                                             stdout=logf, stderr=logf)
                self.proc.wait()
                time.sleep(0.3)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopping = True
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
        self.thread.join(timeout=10)

    def output(self):
        with open(self.log) as f:
            return f.read()


def keyless_node(node_factory, directory):
    """A node whose hsmd is the proxy, served by a device in enforce mode."""
    port = free_port()
    host_priv, host_pub = genkey()
    dev_priv, dev_pub = genkey()
    device = Device(directory, port, dev_priv, host_pub)
    device.start()
    node = node_factory.get_node(start=False, may_fail=True,
                                 options={'subdaemon': 'hsmd:' + PROXY})
    node.daemon.env.update({'SEQLN_SIGNER_LISTEN': '127.0.0.1:{}'.format(port),
                            'SEQLN_HOST_PRIVKEY': host_priv,
                            'SEQLN_SIGNER_PEER_PUBKEY': dev_pub,
                            'SEQLN_SIGNER_OP_TIMEOUT_MS': '5000'})
    node.start()
    return device, node


def answers(node, timeout=5):
    """Whether the node answers getinfo within `timeout` seconds."""
    try:
        return subprocess.run([CLI, '--lightning-dir=' + node.daemon.lightning_dir,
                               '--network=' + TEST_NETWORK, 'getinfo'],
                              capture_output=True, timeout=timeout).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def kill_tree(pid):
    """SIGKILL a process and every process below it (a killed lightningd
    leaves its subdaemons running, the proxy holding the signer's port)."""
    below = subprocess.run(['pgrep', '-P', str(pid)], capture_output=True,
                           text=True).stdout.split()
    for p in [pid] + [int(c) for c in below]:
        try:
            os.kill(p, signal.SIGSTOP)
        except ProcessLookupError:
            pass
    for c in below:
        kill_tree(int(c))
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def channel(node, peer):
    return only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])


@pytest.mark.skipif(not os.path.exists(SIGNER), reason='needs the seqln-signer binary')
def test_keyless_node_closes_and_restarts(node_factory, bitcoind, directory):
    """A hub closes a channel in an asset with a keyless node.  The keyless
    node completes the close and keeps answering; restarted while the close
    is still unconfirmed, it comes back with the channel still closing and
    hands the closing transaction to the network again."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, asset: PAR})
    device, l1 = keyless_node(node_factory, directory)
    try:
        l2 = node_factory.get_node()
        addr = l2.rpc.newaddr('bech32')['bech32']
        txid = bitcoind.send_and_mine_block(addr, 2 * 10**8, asset)
        wait_for(lambda: any(o['txid'] == txid for o in l2.rpc.listfunds()['outputs']))
        l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
        res = l2.rpc.call('fundchannel', {'id': l1.info['id'], 'amount': 10**8,
                                          'asset': asset, 'announce': True})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        for a, b in ((l1, l2), (l2, l1)):
            wait_for(lambda: channel(a, b)['state'] == 'CHANNELD_NORMAL')
        inv = l1.rpc.invoice(10**7 * 1000, 'to-l1', 'to l1')['bolt11']
        l2.rpc.pay(inv)
        wait_for(lambda: channel(l1, l2)['htlcs'] == [])

        # The hub closes; no block is produced, so the close stays pending.
        l2.rpc.close(l1.info['id'])
        deadline = time.time() + 60
        while time.time() < deadline:
            if not answers(l1):
                break
            if channel(l1, l2)['state'] == 'CLOSINGD_COMPLETE':
                break
            time.sleep(0.5)
        if not answers(l1):
            # The node is wedged: restarting it is what an operator would do.
            kill_tree(l1.daemon.proc.pid)
            l1.daemon.proc.wait()
            before = device.output().count('POLICY REJECT')
            restarted = subprocess.Popen(l1.daemon.cmd_line, env=l1.daemon.env,
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
            # Watch it for a minute: up, its peer reconnects, and then?
            seen = []
            for i in range(30):
                time.sleep(2)
                seen.append(answers(l1))
                if i == 2:
                    try:
                        l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
                    except Exception:
                        pass
            kill_tree(restarted.pid)
            restarted.wait()
            after = device.output().count('POLICY REJECT') - before
            pytest.fail("the keyless node stopped answering when the close "
                        "completed ({} refusals by the device); restarted, it "
                        "answered in {} of {} checks over a minute, the last "
                        "{}, and the device refused {} more times"
                        .format(before, sum(seen), len(seen),
                                "answered" if seen[-1] else "did not", after))
        assert channel(l1, l2)['state'] == 'CLOSINGD_COMPLETE'
        close_txid = only_one(bitcoind.rpc.getrawmempool())

        # Restart with the close unconfirmed; the peer reconnects.
        l1.restart()
        assert answers(l1)
        assert channel(l1, l2)['state'] == 'CLOSINGD_COMPLETE'
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
        time.sleep(5)
        assert answers(l1)
        assert channel(l1, l2)['state'] == 'CLOSINGD_COMPLETE'
        assert 'POLICY REJECT' not in device.output()
        assert not l1.daemon.is_in_log('device REJECTED')

        bitcoind.generate_block(1, wait_for_mempool=close_txid)
        wait_for(lambda: channel(l1, l2)['state'] == 'ONCHAIN')
        closing = bitcoind.rpc.getrawtransaction(close_txid, True)
        assert {o['asset'] for o in closing['vout']} == {asset}
    finally:
        if answers(l1, timeout=2):
            l1.stop()
        device.stop()
