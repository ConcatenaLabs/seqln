"""A keyless node closing a channel.

A keyless node runs `lightning_hsmd_proxy` as its hsmd and keeps its keys on a
device signer (`contrib/seqln-signer`) in enforce mode, connecting in the way a
browser device does.  When a mutual close completes, and again whenever it
starts with a channel closing, lightningd signs the closing transaction with
the message it uses for its own commitment.  The node must get that signature
and keep running, whichever side opened the channel (the opener pays the close
fee out of its balance, which the device holds the close to).  Run with TEST_NETWORK=sequentia-regtest (README.md,
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
# SEQLN_DEVICE=wasm serves the keyless node from the browser build instead
# (the `wasm-pack --target nodejs` package in contrib/seqln-signer/wasm/pkg,
# run under Node by wasm/test/device_serve.mjs, which reads the same files and
# environment as the native binary).
WASM_DEVICE = os.path.abspath(os.path.join(
    REPO, 'contrib', 'seqln-signer', 'wasm', 'test', 'device_serve.mjs'))
DEVICE = os.environ.get('SEQLN_DEVICE', 'native')
MNEMONIC = ' '.join(['abandon'] * 11 + ['about'])
PAR = 10**8
# The device's payment limit (atoms of each asset a day) in these tests: their
# payments are larger than the default of 10,000,000.
TEST_PAY_LIMIT = '1000000000'


def genkey():
    """A Noise static keypair (the native binary makes it, whichever device
    serves the node)."""
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
    def __init__(self, directory, port, priv, host_pub, trace=False, pay_limit=TEST_PAY_LIMIT,
                 pay_limits=None, close_to=None):
        self.dir = os.path.join(directory, 'device')
        os.makedirs(self.dir, exist_ok=True)
        with open(os.path.join(self.dir, 'hsm_secret'), 'wb') as f:
            f.write(bytes(32) + MNEMONIC.encode())
        self.log = os.path.join(self.dir, 'device.log')
        self.env = dict(os.environ, SEQLN_SIGNER_PRIVKEY=priv,
                        SEQLN_HOST_PEER_PUBKEY=host_pub,
                        SEQLN_SIGNER_POLICY='enforce',
                        SEQLN_SIGNER_PAY_LIMIT=pay_limit)
        if pay_limits:
            self.env['SEQLN_SIGNER_PAY_LIMITS'] = pay_limits
        if close_to:
            self.env['SEQLN_SIGNER_CLOSE_TO'] = ','.join(close_to)
        if trace:
            self.env['SEQLN_SIGNER_TRACE'] = '1'
        if DEVICE == 'wasm':
            self.cmd = ['node', WASM_DEVICE, '--connect', '127.0.0.1:{}'.format(port)]
        else:
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

    def requests(self, msgtype):
        """How many requests of `msgtype` the device served (trace only)."""
        with open(os.path.join(self.dir, 'seqln-signer.log')) as f:
            return f.read().count('TRACE req type=Some({}) '.format(msgtype))


def keyless_node(node_factory, directory, trace=False, pay_limit=TEST_PAY_LIMIT, pay_limits=None,
                 close_to=None, dev_fail=True, **node_opts):
    """A node whose hsmd is the proxy, served by a device in enforce mode.
    `pay_limits` is SEQLN_SIGNER_PAY_LIMITS (`<asset>=<atoms>,...`);
    `close_to` the scripts (hex) its wallet names for a close to pay.
    `dev_fail=False` runs lightningd without the harness's
    dev-fail-on-subdaemon-fail, which exits it on any subdaemon failure, so a
    refusal by the device plays out as it does in production."""
    port = free_port()
    host_priv, host_pub = genkey()
    dev_priv, dev_pub = genkey()
    device = Device(directory, port, dev_priv, host_pub, trace, pay_limit, pay_limits, close_to)
    device.start()
    node = node_factory.get_node(start=False, may_fail=True,
                                 options={'subdaemon': 'hsmd:' + PROXY}, **node_opts)
    if not dev_fail:
        node.daemon.opts.pop('dev-fail-on-subdaemon-fail', None)
    node.daemon.env.update({'SEQLN_SIGNER_LISTEN': '127.0.0.1:{}'.format(port),
                            'SEQLN_HOST_PRIVKEY': host_priv,
                            'SEQLN_SIGNER_PEER_PUBKEY': dev_pub,
                            # The WASM device takes seconds over its first
                            # sweep (it derives its wallet scripts once):
                            # the proxy's default timeout, not a short one.
                            'SEQLN_SIGNER_OP_TIMEOUT_MS': '120000' if DEVICE == 'wasm' else '5000'})
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
@pytest.mark.parametrize('opener', ['hub', 'keyless'])
def test_keyless_node_closes_and_restarts(node_factory, bitcoind, directory, opener):
    """A hub closes a channel in an asset with a keyless node.  The keyless
    node completes the close and keeps answering; restarted while the close
    is still unconfirmed, it comes back with the channel still closing and
    hands the closing transaction to the network again."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, asset: PAR})
    device, l1 = keyless_node(node_factory, directory)
    try:
        l2 = node_factory.get_node()
        funder, fundee = (l2, l1) if opener == 'hub' else (l1, l2)
        addr = funder.rpc.newaddr('bech32')['bech32']
        txid = bitcoind.send_and_mine_block(addr, 2 * 10**8, asset)
        wait_for(lambda: any(o['txid'] == txid for o in funder.rpc.listfunds()['outputs']))
        funder.rpc.connect(fundee.info['id'], 'localhost', fundee.port)
        res = funder.rpc.call('fundchannel', {'id': fundee.info['id'], 'amount': 10**8,
                                              'asset': asset, 'announce': True})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        for a, b in ((l1, l2), (l2, l1)):
            wait_for(lambda: channel(a, b)['state'] == 'CHANNELD_NORMAL')
        inv = fundee.rpc.invoice(10**7 * 1000, 'to-fundee', 'to the fundee')['bolt11']
        funder.rpc.pay(inv)
        wait_for(lambda: channel(l1, l2)['htlcs'] == [])
        # The device keeps its channel store (counters, balance) on disk.
        assert os.path.exists(os.path.join(device.dir, 'seqln-signer-channels'))

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


@pytest.mark.skipif(not os.path.exists(SIGNER), reason='needs the seqln-signer binary')
@pytest.mark.parametrize('opener', ['hub', 'keyless'])
def test_keyless_node_broadcasts_its_validated_commitment(node_factory, bitcoind, directory,
                                                          opener):
    """The device signs a commitment of ours for broadcast only when it is a
    transaction the device validated and has not revoked.  lightningd asks
    for nothing else: the preempt slot at every commitment step, a payment
    each way, `dev-sign-last-tx`, a unilateral close with the hub gone, and
    the closing node's restart (which signs the commitment again) are all
    signed, and the commitment confirms."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, asset: PAR})
    device, l1 = keyless_node(node_factory, directory, trace=True)
    try:
        l2 = node_factory.get_node(may_reconnect=True)
        funder, fundee = (l2, l1) if opener == 'hub' else (l1, l2)
        addr = funder.rpc.newaddr('bech32')['bech32']
        txid = bitcoind.send_and_mine_block(addr, 2 * 10**8, asset)
        wait_for(lambda: any(o['txid'] == txid for o in funder.rpc.listfunds()['outputs']))
        funder.rpc.connect(fundee.info['id'], 'localhost', fundee.port)
        res = funder.rpc.call('fundchannel', {'id': fundee.info['id'], 'amount': 10**8,
                                              'asset': asset, 'announce': True})
        bitcoind.generate_block(1, wait_for_mempool=res['txid'])
        for a, b in ((l1, l2), (l2, l1)):
            wait_for(lambda: channel(a, b)['state'] == 'CHANNELD_NORMAL')

        def settled():
            return channel(l1, l2)['htlcs'] == [] and channel(l2, l1)['htlcs'] == []
        inv = fundee.rpc.invoice(3 * 10**7 * 1000, 'out', 'out')['bolt11']
        funder.rpc.pay(inv)
        wait_for(settled)
        inv = funder.rpc.invoice(10**7 * 1000, 'back', 'back')['bolt11']
        fundee.rpc.pay(inv)
        wait_for(settled)
        l1.rpc.dev_sign_last_tx(l2.info['id'])
        assert 'POLICY REJECT' not in device.output()
        # VALIDATE_COMMITMENT_TX (35) for commitment 0 and each step after;
        # SIGN_COMMITMENT_TX (5) for the preempt slot at each step after 0,
        # and once for dev-sign-last-tx.
        validated, signed = device.requests(35), device.requests(5)
        print("validated {}, signed for broadcast {}".format(validated, signed))
        assert validated >= 5 and signed >= validated

        # The hub goes away; the keyless node closes on its own.
        l2.stop()
        res = l1.rpc.close(l2.info['id'], unilateraltimeout=1)
        assert res['type'] == 'unilateral'
        commitment = only_one(res['txids'])
        wait_for(lambda: commitment in bitcoind.rpc.getrawmempool())
        assert channel(l1, l2)['state'] == 'AWAITING_UNILATERAL'

        # Restarted while the commitment is unconfirmed, lightningd signs it
        # again: the device, restarted too, still knows it validated it.
        l1.stop()
        if device.proc and device.proc.poll() is None:
            device.proc.kill()
        l1.start()
        assert answers(l1)
        l1.daemon.wait_for_log('sendrawtx exit 0')
        assert 'POLICY REJECT' not in device.output()
        assert not l1.daemon.is_in_log('device REJECTED')
        print("signed for broadcast after the close and the restart: {}"
              .format(device.requests(5) - signed))
        assert device.requests(5) >= signed + 2

        bitcoind.generate_block(1, wait_for_mempool=commitment)
        wait_for(lambda: channel(l1, l2)['state'] in ('FUNDING_SPEND_SEEN', 'ONCHAIN'))
        spent = bitcoind.rpc.getrawtransaction(commitment, True)
        assert {o['asset'] for o in spent['vout']} == {asset}
    finally:
        if answers(l1, timeout=2):
            l1.stop()
        device.stop()


def test_keyless_node_closes_to_its_wallets_address(node_factory, bitcoind, directory):
    """A keyless node closes its channel cooperatively, paying its balance to
    an address of the wallet that holds its device's seed, outside the node:
    the device signs that close because the wallet named the address to it
    (SEQLN_SIGNER_CLOSE_TO here, approveCloseDestination in a browser). A
    close to an address not named is refused (the signer's unit test
    close_to_an_approved_destination_is_signed)."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, asset: PAR})
    wallet_addr = bitcoind.rpc.getnewaddress()
    script = bitcoind.rpc.getaddressinfo(wallet_addr)['scriptPubKey']
    device, l1 = keyless_node(node_factory, directory, close_to=[script])
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
        inv = l1.rpc.call('invoice', {'amount_msat': 10**7 * 1000, 'label': 'in',
                                      'description': 'to the keyless node', 'asset': asset})
        l2.rpc.call('pay', {'bolt11': inv['bolt11'], 'asset': asset})
        wait_for(lambda: channel(l1, l2)['htlcs'] == [] and channel(l1, l2)['to_us_msat'] == 10**10)

        closed = l1.rpc.close(l2.info['id'], 30, wallet_addr)
        print('close to the wallet:', {k: closed.get(k) for k in ('type', 'txids')})
        assert closed['type'] == 'mutual'
        close_txid = only_one(closed['txids'])
        bitcoind.generate_block(1, wait_for_mempool=close_txid)
        tx = bitcoind.rpc.getrawtransaction(close_txid, True)
        to_wallet = [o for o in tx['vout'] if o['scriptPubKey'].get('hex') == script]
        assert len(to_wallet) == 1
        assert to_wallet[0]['asset'] == asset
        # The balance less the close fee, which the keyless node (the fundee) does not pay.
        assert float(to_wallet[0]['value']) == 10**7 / PAR
        assert 'POLICY REJECT' not in device.output()
    finally:
        if answers(l1, timeout=2):
            l1.stop()
        device.stop()


@pytest.mark.xfail(strict=True, reason=(
    "lightningd takes the peer's signed closing transaction as the channel's last_tx while "
    "negotiating, so once the device refuses to sign it nothing broadcastable is left: close "
    "answers 'The signing device refused to sign the closing transaction' and the channel "
    "stays in AWAITING_UNILATERAL instead of falling back to its commitment"))
def test_keyless_node_refused_close_falls_back_to_unilateral(node_factory, bitcoind, directory):
    """A cooperative close to an address the device was not given is refused:
    closingd fails, lightningd keeps running, and `close` should fall back to a
    unilateral close after its timeout, which pays this node. Run without the
    harness's dev-fail-on-subdaemon-fail, which would exit lightningd on the
    refusal and is not how a node runs."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, asset: PAR})
    elsewhere = bitcoind.rpc.getnewaddress()
    device, l1 = keyless_node(node_factory, directory, dev_fail=False,
                              broken_log='rejected request WIRE_HSMD_SIGN_MUTUAL_CLOSE_TX'
                                         '|STATUS_FAIL_HSM_IO: Bad hsm_sign_mutual_close_tx reply'
                                         '|device REJECTED|device REFUSED|refused to sign our')
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
        inv = l1.rpc.call('invoice', {'amount_msat': 10**7 * 1000, 'label': 'in',
                                      'description': 'to the keyless node', 'asset': asset})
        l2.rpc.call('pay', {'bolt11': inv['bolt11'], 'asset': asset})
        wait_for(lambda: channel(l1, l2)['htlcs'] == [] and channel(l1, l2)['to_us_msat'] == 10**10)

        closed = l1.rpc.close(l2.info['id'], 10, elsewhere)
        print('close to an address the device was not given:', {k: closed.get(k) for k in ('type', 'txids')})
        assert closed['type'] == 'unilateral'
        assert 'SIGN_MUTUAL_CLOSE_TX refused' in device.output()
        assert answers(l1)
        # The unilateral close pays nothing to the address the device refused.
        close_txid = only_one(closed['txids'])
        tx = bitcoind.rpc.getrawtransaction(close_txid, True)
        want = bitcoind.rpc.getaddressinfo(elsewhere)['scriptPubKey']
        assert all(o['scriptPubKey'].get('hex') != want for o in tx['vout'])
    finally:
        if answers(l1, timeout=2):
            l1.stop()
        device.stop()
