"""A keyless node starts while a channel is closing, and its device refuses.

A keyless node runs `lightning_hsmd_proxy` as its hsmd; its keys are on a
device signer (`contrib/seqln-signer`) in enforce mode.  At every start
lightningd signs again the transaction that closes each channel in
CLOSINGD_COMPLETE or AWAITING_UNILATERAL, with the message it uses for its own
commitment, and sends it.  A device whose store does not record that
transaction refuses it, and is right to: the request carries no HTLC list, so a
commitment the device did not validate itself could pay anything.  A store an
older device wrote holds no validated commitments and no balance: the device
that imports it marks each of its channels as predating validation, refuses
every such closing transaction and every other commitment step for them, and
its peer closes them.

The node survives the refusal: it logs it with the channel, sends nothing, and
goes on starting.  The channel stays in its state; once its funding is spent
onchaind resolves it from the chain.  What a mutual close or an HTLC timeout
pays the node goes to its wallet, and the device signs its spend like any
other wallet output; what the peer's commitment pays it is held in the wallet
in the channel's asset (the device signs no spend of that output: it signs
only the wallet's own keys).  A node with its own keys signs and sends the
transaction again, as before.

Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing"), and with
TEST_NETWORK=regtest for the same path on Bitcoin; the signer binary is
SEQLN_SIGNER, by default contrib/seqln-signer/target/release/seqln-signer.
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from pyln.testing.utils import JSONRPCError
from utils import TEST_NETWORK, only_one, sync_blockheight, wait_for

import hashlib
import hmac
import os
import pytest
import re
import sqlite3
import struct
import threading

import test_keyless_close as kc

pytestmark = pytest.mark.skipif(TEST_NETWORK not in ('sequentia-regtest', 'regtest'),
                                reason='needs TEST_NETWORK=sequentia-regtest or regtest')
needs_signer = pytest.mark.skipif(not os.path.exists(kc.SIGNER),
                                  reason='needs the seqln-signer binary')

SEQ = TEST_NETWORK == 'sequentia-regtest'
HOLD = os.path.join(os.path.dirname(__file__), '..', '..', 'contrib',
                    'holdinvoice-seq', 'holdinvoice.py')
CAP = 10**7      # each channel, in atoms of its asset (satoshis on Bitcoin)
PAY = 3 * 10**6  # what the hub pays the keyless node on each channel
# The store version the upgraded device imports (see store_as_version).
STORE = int(os.environ.get('SEQLN_TEST_OLD_STORE', '2'))
# lightningd's line when the device refuses its closing transaction.
SKIPPED = (r'The signing device refused to sign our {} transaction {} '
           r'.*in state {}: not broadcasting it')
# The hub's connectd, when the keyless node's daemons go away mid-session.
HUB_BROKEN = 'Subd did not close, forcing close'
# The device's refusal of a step on a channel from the old store.
PREDATES = r'POLICY REJECT: SIGN_{} refused: channel \d+ of peer [0-9a-f]+ predates validation'
PREDATES_REVOKE = r'POLICY REJECT: REVOKE_COMMITMENT_TX refused: channel \d+ of peer [0-9a-f]+ predates validation'


def coin(bitcoind):
    """The channels' asset: a newly issued one on Sequentia, the coin on Bitcoin."""
    if not SEQ:
        return None
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: kc.PAR, asset: kc.PAR})
    return asset


def fund(bitcoind, node, atoms, asset):
    addr = node.rpc.newaddr('bech32')['bech32']
    if SEQ:
        txid = bitcoind.send_and_mine_block(addr, atoms, asset)
    else:
        txid = bitcoind.rpc.sendtoaddress(addr, atoms / 10**8)
        bitcoind.generate_block(1, wait_for_mempool=txid)
    wait_for(lambda: any(o['txid'] == txid for o in node.rpc.listfunds()['outputs']))


def chan(node, scid):
    return only_one([c for c in node.rpc.listpeerchannels()['channels']
                     if c.get('short_channel_id') == scid])


def open_paid_channel(bitcoind, hub, keyless, asset):
    """The hub opens a channel to the keyless node and pays it PAY over that
    channel, so the keyless node holds a balance in it.  Returns its scid."""
    hub.rpc.connect(keyless.info['id'], 'localhost', keyless.port)
    args = {'id': keyless.info['id'], 'amount': CAP, 'announce': True}
    if asset:
        args['asset'] = asset
    res = hub.rpc.call('fundchannel', args)
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    wait_for(lambda: any(c['funding_txid'] == res['txid'] and c['state'] == 'CHANNELD_NORMAL'
                         and 'short_channel_id' in c
                         for c in keyless.rpc.listpeerchannels()['channels']))
    scid = only_one([c for c in keyless.rpc.listpeerchannels()['channels']
                     if c['funding_txid'] == res['txid']])['short_channel_id']
    wait_for(lambda: chan(hub, scid)['state'] == 'CHANNELD_NORMAL')
    inv = keyless.rpc.invoice(PAY * 1000, 'in-' + scid, 'in')
    final = hub.rpc.decode(inv['bolt11'])['min_final_cltv_expiry']
    route = [{'id': keyless.info['id'], 'channel': scid, 'amount_msat': PAY * 1000,
              'delay': final + 6}]
    hub.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
    assert hub.rpc.waitsendpay(inv['payment_hash'])['status'] == 'complete'
    wait_for(lambda: chan(keyless, scid)['htlcs'] == [] and chan(hub, scid)['htlcs'] == [])
    return scid


def refuse_broadcasts(node):
    """The node's backend refuses every transaction the node sends, as the
    testnet's refused a commitment over its fee cap: the node's own closing
    transaction never reaches the network."""
    def refuse(r):
        return {'id': r['id'], 'result': None,
                'error': {'code': -26, 'message': 'max-fee-exceeded'}}
    node.daemon.rpcproxy.mock_rpc('sendrawtransaction', refuse)


def restart_device(device):
    device.stop()
    device.stopping = False
    device.proc = None
    device.thread = threading.Thread(target=device.run, daemon=True)
    device.start()


# The device's channel store (contrib/seqln-signer/src/policy.rs): magic,
# version, count, then each entry's fixed part and the fields later versions
# add, then (from version 5) the payment ledger and (from version 7) the
# closes the device signed; a MAC keyed from the seed closes it.  A device
# that imports a store older than version 6 marks every channel in it as
# predating validation and signs no commitment step for it.
ENTRY = 33 + 8 + 8 + 32 + 2 + 2 + 2 + 33 * 5 + 1 + 1


def store_mac(payload):
    seed = hashlib.pbkdf2_hmac('sha512', kc.MNEMONIC.encode(), b'mnemonic', 2048, 64)
    prk = hmac.new(b'seqln-signer chstore mac v1', seed, hashlib.sha256).digest()
    key = hmac.new(prk, b'\x01', hashlib.sha256).digest()
    return hmac.new(key, payload, hashlib.sha256).digest()


def store_as_version(device, version):
    """Rewrite the device's channel store as an older signer wrote it:
    version 1 holds each channel's parameters only; version 2 adds the
    opener, the revocation counters and the upfront shutdown scripts.  Neither
    records a balance, a validated commitment or a payment.  That is the
    store an older device hands the signer that replaces it."""
    assert version in (1, 2)
    path = os.path.join(device.dir, 'seqln-signer-channels')
    blob = open(path, 'rb').read()
    payload, mac = blob[:-32], blob[-32:]
    assert hmac.compare_digest(store_mac(payload), mac)
    assert payload[:4] == b'SQCH' and payload[4] in (6, 7, 8), payload[:5]
    v = payload[4]
    count = struct.unpack('<I', payload[5:9])[0]
    o, entries = 9, []

    def u8():
        nonlocal o
        o += 1
        return payload[o - 1]

    def skip(n):
        nonlocal o
        o += n

    def u16():
        nonlocal o
        o += 2
        return struct.unpack('<H', payload[o - 2:o])[0]

    def side():
        if u8():
            skip(24)
            skip(u16() * (8 + 32 + 4))
    for _ in range(count):
        entry = payload[o:o + ENTRY]
        skip(ENTRY)
        v2 = o
        skip(1)                        # opener
        for _ in range(2):             # revocation counters
            if u8():
                skip(8)
        for _ in range(2):             # upfront shutdown scripts
            skip(u16())
        if version >= 2:
            entry += payload[v2:o]
        for _ in range(2):             # commitment splits (version 3)
            if u8():
                skip(32)
        skip(u8() * 40)                # validated commitments (version 4)
        if u8():                       # payment tracking (version 5)
            skip(33)
        side()
        side()
        skip(8)
        if u8():                       # shutdown script's wallet index (6)
            skip(4)
        if v >= 8:                     # predates validation (8)
            skip(1)
        entries.append(entry)
    old = b'SQCH' + bytes([version]) + struct.pack('<I', count) + b''.join(entries)
    with open(path + '.tmp', 'wb') as f:
        f.write(old + store_mac(old))
    os.rename(path + '.tmp', path)
    return count


def refusals(device):
    return device.output().count('POLICY REJECT: SIGN_COMMITMENT_TX refused')


def usable(a, b):
    return any(c['state'] == 'CHANNELD_NORMAL' and c.get('peer_connected')
               and 'channeld' in (c.get('owner') or '')
               for c in a.rpc.listpeerchannels(b.info['id'])['channels'])


def pays_both_ways(bitcoind, hub, keyless, asset):
    """The channels that came through the old store predate validation and
    move no more: the hub closes those still open, as the cutover does (each
    reconnection otherwise ends in the device refusing their reestablish).
    A channel the hub opens then is validated from its first commitment and
    pays each way."""
    try:
        keyless.rpc.connect(hub.info['id'], 'localhost', hub.port)
    except RpcError:
        pass
    closes, closed_fundings = [], []
    for c in hub.rpc.listpeerchannels(keyless.info['id'])['channels']:
        if c['state'] == 'CHANNELD_NORMAL':
            closes += hub.rpc.close(c['short_channel_id'], unilateraltimeout=1)['txids']
            closed_fundings.append(c['funding_txid'])
    if closes:
        bitcoind.generate_block(1, wait_for_mempool=closes)
        # Both sides follow the closes before the new channel opens (the hub
        # drops the connection once it sees each funding spent).
        for a, b in ((hub, keyless), (keyless, hub)):
            wait_for(lambda: all(c['state'] in ('ONCHAIN', 'FUNDING_SPEND_SEEN', 'CLOSED')
                                 for c in a.rpc.listpeerchannels(b.info['id'])['channels']
                                 if c.get('funding_txid') in closed_fundings))
        try:
            keyless.rpc.connect(hub.info['id'], 'localhost', hub.port)
        except RpcError:
            pass
    scid = open_paid_channel(bitcoind, hub, keyless, asset)
    wait_for(lambda: usable(hub, keyless) and usable(keyless, hub))
    inv = hub.rpc.invoice(PAY * 1000 // 4, 'after-out', 'after')['bolt11']
    assert keyless.rpc.pay(inv)['status'] == 'complete'
    return scid


def spend_all(bitcoind, node, addr, asset):
    """Spend every wallet output of `asset` to `addr`.  On Sequentia the
    transaction is built with the asset named (`fundpsbt`, `addpsbtoutput`),
    so its change and fee are in that asset; `withdraw` names none."""
    if not SEQ:
        return node.rpc.withdraw(addr, 'all')['txid']
    res = node.rpc.call('fundpsbt', {'satoshi': 'all', 'feerate': 'normal',
                                     'startweight': 1000, 'asset': asset})
    amount = res['excess_msat'] // 1000
    psbt = node.rpc.call('addpsbtoutput', {'satoshi': amount, 'initialpsbt': res['psbt'],
                                           'destination': addr, 'asset': asset})['psbt']
    signed = node.rpc.signpsbt(psbt)['signed_psbt']
    return node.rpc.sendpsbt(signed)['txid']


def sweep_to_address(bitcoind, node, txid, asset):
    """The node's wallet spends what `txid` paid it, with its device's
    signature, to a new address of its own (the device moves the node's
    coins to nothing else but a channel the node opens); returns the spending
    txid and the output, once the spend confirms."""
    wait_for(lambda: any(o['txid'] == txid and o['status'] == 'confirmed'
                         for o in node.rpc.listfunds()['outputs']))
    out = only_one([o for o in node.rpc.listfunds()['outputs'] if o['txid'] == txid])
    addr = node.rpc.newaddr('bech32')['bech32']
    for _ in range(5):
        try:
            spent = spend_all(bitcoind, node, addr, asset)
            break
        except RpcError as e:
            # The peer's commitment pays us after one block (CSV 1).
            if 'csv locked' not in str(e) and 'could not afford' not in str(e).lower():
                raise
            bitcoind.generate_block(1)
            sync_blockheight(bitcoind, [node])
    bitcoind.generate_block(1, wait_for_mempool=spent)
    tx = bitcoind.rpc.getrawtransaction(spent, True)
    assert any(i['txid'] == txid and i['vout'] == out['output'] for i in tx['vin'])
    paid = [v for v in tx['vout'] if v['scriptPubKey'].get('address') == addr]
    assert len(paid) == 1
    if SEQ:
        assert paid[0]['asset'] == asset
    return spent, out


def holds(bitcoind, node, txid, asset):
    """The node's wallet lists the output `txid` pays it, confirmed and in
    the channel's asset; returns it."""
    wait_for(lambda: any(o['txid'] == txid and o['status'] == 'confirmed'
                         for o in node.rpc.listfunds()['outputs']))
    out = only_one([o for o in node.rpc.listfunds()['outputs'] if o['txid'] == txid])
    if SEQ:
        assert out['asset'] == asset
    return out


def set_aside(node, txid):
    """Reserve the wallet output `txid` pays the node, so a spend of the
    node's other outputs leaves it out."""
    out = only_one([o for o in node.rpc.listfunds()['outputs'] if o['txid'] == txid])
    psbt = node.rpc.call('utxopsbt', {'satoshi': 'all', 'feerate': 'normal', 'startweight': 0,
                                      'utxos': ['{}:{}'.format(txid, out['output'])],
                                      'reserve': 1000})['psbt']
    assert psbt


def check_device_signed_none(device, requests_before, refusals_before):
    """Every SIGN_COMMITMENT_TX the device was asked since was refused."""
    asked = device.requests(5) - requests_before
    refused = refusals(device) - refusals_before
    print('SIGN_COMMITMENT_TX since the restart: asked {}, refused {}'.format(asked, refused))
    assert asked == refused > 0


@needs_signer
def test_keyless_start_awaiting_unilateral(node_factory, bitcoind, directory):
    """The keyless node closes a channel while the hub is away, and its
    commitment never reaches the network.  The hub closes too and its
    commitment confirms.  The device is upgraded (its store loses the
    validated commitments) and the node restarts: the device refuses the
    commitment lightningd signs again, the node logs that, starts, follows
    the hub's commitment on chain, and its wallet holds what that paid it,
    in the channel's asset.
    A channel opened afterwards pays both ways (the second one, from the old
    store, predates validation and moves no more).  The hub, with its own keys,
    restarted with its commitment unconfirmed, sends it again as before."""
    asset = coin(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True,
                                 broken_log='.*', may_reconnect=True)
    try:
        l2 = node_factory.get_node(may_reconnect=True, broken_log=HUB_BROKEN)
        fund(bitcoind, l2, 4 * CAP, asset)
        closing = open_paid_channel(bitcoind, l2, l1, asset)
        open_paid_channel(bitcoind, l2, l1, asset)

        refuse_broadcasts(l1)
        l2.stop()
        ours = only_one(l1.rpc.close(closing, unilateraltimeout=1)['txids'])
        wait_for(lambda: chan(l1, closing)['state'] == 'AWAITING_UNILATERAL')
        l1.daemon.wait_for_log('sendrawtx exit 26')
        l1.stop()
        device.stop()
        assert store_as_version(device, STORE) == 2
        l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', None)

        l2.start()
        theirs = only_one(l2.rpc.close(closing, unilateraltimeout=1)['txids'])
        wait_for(lambda: theirs in bitcoind.rpc.getrawmempool())
        # A node with its own keys signs its commitment again at start and
        # sends it.
        l2.restart()
        l2.daemon.wait_for_log('sendrawtx exit 0')
        assert not l2.daemon.is_in_log('signing device refused')
        bitcoind.generate_block(1, wait_for_mempool=theirs)

        restart_device(device)
        asked, refused = device.requests(5), refusals(device)
        l1.start()
        l1.daemon.wait_for_log(SKIPPED.format('commitment', ours, 'AWAITING_UNILATERAL'))
        assert kc.answers(l1)
        assert re.search(PREDATES.format('COMMITMENT_TX'), device.output())

        # The hub's commitment spent the funding: the node follows it, and
        # its wallet holds what the commitment paid it, in the channel's
        # asset.
        wait_for(lambda: chan(l1, closing)['state'] == 'ONCHAIN')
        out = holds(bitcoind, l1, theirs, asset)
        print('the hub commitment {} paid {} to the keyless node'.format(theirs, out['amount_msat']))
        assert out['amount_msat'] == PAY * 1000

        check_device_signed_none(device, asked, refused)
        with pytest.raises(JSONRPCError):
            bitcoind.rpc.getrawtransaction(ours)
        pays_both_ways(bitcoind, l2, l1, asset)
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()


def hide_blocks_from(node, bitcoind, height):
    """The node's backend shows it no block at or above `height`: a node
    that was down starts behind the chain, and its peers reconnect before it
    has caught up."""
    def getblockhash(r):
        if r['params'][0] >= height:
            return {'id': r['id'], 'result': None,
                    'error': {'code': -8, 'message': 'Block height out of range'}}
        return {'id': r['id'], 'result': bitcoind.rpc.getblockhash(r['params'][0]),
                'error': None}
    node.daemon.rpcproxy.mock_rpc('getblockhash', getblockhash)


@needs_signer
def test_keyless_start_closing_sigexchange(node_factory, bitcoind, directory):
    """The hub closes a channel mutually.  The keyless node signs the close
    but stops before it records the close complete: its database keeps
    CLOSINGD_SIGEXCHANGE, as it does when lightningd stops on a device
    refusing the close it signs again.  Its own broadcast never reaches the
    network; the hub's confirms.  The device is upgraded and the node starts
    behind the chain: the hub reconnects, and the device refuses the
    channel's reestablish (it predates validation), so the node never gets to
    sign its closing transaction again.  The node keeps running; once it
    sees the close it follows it, and its wallet spends what the close paid
    it.  A channel opened afterwards pays both ways."""
    asset = coin(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True,
                                 broken_log='.*', may_reconnect=True)
    try:
        l2 = node_factory.get_node(may_reconnect=True, broken_log=HUB_BROKEN)
        fund(bitcoind, l2, 4 * CAP, asset)
        closing = open_paid_channel(bitcoind, l2, l1, asset)
        open_paid_channel(bitcoind, l2, l1, asset)

        refuse_broadcasts(l1)
        close = only_one(l2.rpc.close(closing)['txids'])
        wait_for(lambda: chan(l1, closing)['state'] == 'CLOSINGD_COMPLETE')
        wait_for(lambda: close in bitcoind.rpc.getrawmempool())
        l1.stop()
        device.stop()
        db = sqlite3.connect(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK,
                                          'lightningd.sqlite3'))
        n = db.execute("UPDATE channels SET state=5 WHERE state=6").rowcount
        db.commit()
        db.close()
        assert n == 1
        assert store_as_version(device, STORE) == 2
        l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', None)
        hide_blocks_from(l1, bitcoind, bitcoind.rpc.getblockcount() + 1)
        bitcoind.generate_block(1, wait_for_mempool=close)
        wait_for(lambda: chan(l2, closing)['state'] == 'ONCHAIN')

        restart_device(device)
        asked, refused = device.requests(5), refusals(device)
        l1.start(wait_for_bitcoind_sync=False)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        # The channel predates validation: the device refuses the revocation
        # channeld sends again at reestablish, so channeld stops before the
        # hub's report that the funding is spent reaches the node, and the
        # node never asks for its closing transaction.  It keeps running.
        wait_for(lambda: re.search(PREDATES_REVOKE, device.output()))
        assert kc.answers(l1)
        assert device.requests(5) - asked == refusals(device) - refused

        l1.daemon.rpcproxy.mock_rpc('getblockhash', None)
        wait_for(lambda: chan(l1, closing)['state'] == 'ONCHAIN')
        bitcoind.generate_block(1)
        swept, out = sweep_to_address(bitcoind, l1, close, asset)
        print('the close {} paid {} to the keyless node, which moved it to its own address in {}'
              .format(close, out['amount_msat'], swept))
        assert out['amount_msat'] >= PAY * 1000 * 9 // 10
        pays_both_ways(bitcoind, l2, l1, asset)
        # A second start finds the channel closed on chain: nothing to sign.
        asked = device.requests(5)
        l1.restart()
        assert kc.answers(l1)
        assert chan(l1, closing)['state'] == 'ONCHAIN'
        assert device.requests(5) == asked
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()


@needs_signer
def test_keyless_start_closing_complete(node_factory, bitcoind, directory):
    """As above, but the database records the close complete: at start
    lightningd signs the close again, the upgraded device refuses it, and the
    node logs that and starts.  The hub's close confirms; the node follows it
    and spends what it paid it."""
    asset = coin(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True,
                                 broken_log='.*', may_reconnect=True)
    try:
        l2 = node_factory.get_node(may_reconnect=True, broken_log=HUB_BROKEN)
        fund(bitcoind, l2, 4 * CAP, asset)
        closing = open_paid_channel(bitcoind, l2, l1, asset)
        open_paid_channel(bitcoind, l2, l1, asset)

        refuse_broadcasts(l1)
        close = only_one(l2.rpc.close(closing)['txids'])
        wait_for(lambda: chan(l1, closing)['state'] == 'CLOSINGD_COMPLETE')
        wait_for(lambda: close in bitcoind.rpc.getrawmempool())
        l1.stop()
        device.stop()
        assert store_as_version(device, STORE) == 2
        l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', None)

        restart_device(device)
        asked, refused = device.requests(5), refusals(device)
        l1.start()
        l1.daemon.wait_for_log(SKIPPED.format('mutual close', close, 'CLOSINGD_COMPLETE'))
        assert kc.answers(l1)
        assert re.search(PREDATES.format('COMMITMENT_TX'), device.output())
        assert chan(l1, closing)['state'] == 'CLOSINGD_COMPLETE'

        bitcoind.generate_block(1, wait_for_mempool=close)
        wait_for(lambda: chan(l1, closing)['state'] == 'ONCHAIN')
        bitcoind.generate_block(1)
        swept, out = sweep_to_address(bitcoind, l1, close, asset)
        print('the close {} paid {} to the keyless node, which moved it to its own address in {}'
              .format(close, out['amount_msat'], swept))
        check_device_signed_none(device, asked, refused)
        pays_both_ways(bitcoind, l2, l1, asset)
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()


@needs_signer
def test_keyless_start_onchain_htlc(node_factory, bitcoind, directory):
    """The keyless node pays the hub, which holds the HTLC and closes while
    the keyless node is away; its commitment, carrying the HTLC, confirms and
    the node, back, follows it (ONCHAIN).  It stops; the device is upgraded;
    the HTLC expires; the node restarts.  It starts, times the HTLC out on
    chain with its device's signature, the payment fails, and its wallet
    spends what the timeout returned, with its device's signature.  A
    channel opened afterwards pays both ways."""
    asset = coin(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True,
                                 broken_log='.*', may_reconnect=True)
    try:
        l2 = node_factory.get_node(may_reconnect=True, options={'plugin': HOLD},
                                   broken_log=HUB_BROKEN)
        fund(bitcoind, l2, 4 * CAP, asset)
        closing = open_paid_channel(bitcoind, l2, l1, asset)
        open_paid_channel(bitcoind, l2, l1, asset)

        preimage = os.urandom(32)
        h = hashlib.sha256(preimage).hexdigest()
        amount = PAY * 1000 // 2
        hold = {'payment_hash': h, 'amount_msat': amount}
        if asset:
            hold['asset'] = asset
        l2.rpc.call('holdinvoice', hold)
        l1.rpc.preapprovekeysend(l2.info['id'], h, amount)
        route = [{'id': l2.info['id'], 'channel': closing, 'amount_msat': amount, 'delay': 30}]
        l1.rpc.sendpay(route, h)
        wait_for(lambda: l2.rpc.call('holdinvoicelookup', {'payment_hash': h})['state'] == 'accepted')
        expiry = only_one(chan(l1, closing)['htlcs'])['expiry']

        l1.stop()
        device.stop()
        theirs = only_one(l2.rpc.close(closing, unilateraltimeout=1)['txids'])
        bitcoind.generate_block(1, wait_for_mempool=theirs)
        restart_device(device)
        l1.start()
        wait_for(lambda: chan(l1, closing)['state'] == 'ONCHAIN')
        wait_for(lambda: any(o['txid'] == theirs for o in l1.rpc.listfunds()['outputs']))
        before = {o['txid'] for o in l1.rpc.listfunds()['outputs']}
        l1.stop()
        device.stop()
        assert store_as_version(device, STORE) == 2

        height = bitcoind.rpc.getblockcount()
        bitcoind.generate_block(max(expiry - height, 0) + 1)
        restart_device(device)
        asked = device.requests(5)
        l1.start()
        assert kc.answers(l1)

        # onchaind times the HTLC out of the hub's commitment, with the
        # device's signature, and the payment fails.
        def payment_failed():
            bitcoind.generate_block(1)
            return only_one(l1.rpc.listsendpays(payment_hash=h)['payments'])['status'] == 'failed'
        wait_for(payment_failed)
        assert l1.daemon.is_in_log('Broadcast for onchaind tx')
        wait_for(lambda: [o for o in l1.rpc.listfunds()['outputs']
                          if o['txid'] not in before and o['txid'] != theirs])
        new = [o for o in l1.rpc.listfunds()['outputs']
               if o['txid'] not in before and o['txid'] != theirs]
        timeout_tx = only_one(new)['txid']
        holds(bitcoind, l1, theirs, asset)
        set_aside(l1, theirs)
        swept, out = sweep_to_address(bitcoind, l1, timeout_tx, asset)
        print('the HTLC timeout {} returned {} to the keyless node, which moved it to its own address in {}'
              .format(timeout_tx, out['amount_msat'], swept))
        assert device.requests(5) == asked
        pays_both_ways(bitcoind, l2, l1, asset)
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()


@needs_signer
def test_keyless_close_command_refused(node_factory, bitcoind, directory):
    """A refusal after start is the same: the upgraded device has validated
    no commitment of a channel yet, the hub is away, and `close` times out
    into a unilateral close.  The device refuses the commitment, the node
    logs that and keeps running, and `close` fails with the refusal instead
    of naming a transaction it never sent.  The hub's close later confirms
    and the node follows it."""
    asset = coin(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True,
                                 broken_log='.*', may_reconnect=True)
    try:
        l2 = node_factory.get_node(may_reconnect=True, broken_log=HUB_BROKEN)
        fund(bitcoind, l2, 4 * CAP, asset)
        closing = open_paid_channel(bitcoind, l2, l1, asset)
        l1.stop()
        device.stop()
        assert store_as_version(device, STORE) == 1
        l2.stop()
        restart_device(device)
        asked, refused = device.requests(5), refusals(device)
        l1.start()
        ours = chan(l1, closing)
        with pytest.raises(RpcError, match='The signing device refused to sign the closing transaction'):
            l1.rpc.close(closing, unilateraltimeout=1)
        l1.daemon.wait_for_log(SKIPPED.format('commitment', '[0-9a-f]{64}', 'AWAITING_UNILATERAL'))
        assert kc.answers(l1)
        assert chan(l1, closing)['state'] == 'AWAITING_UNILATERAL'
        check_device_signed_none(device, asked, refused)
        assert ours['state'] == 'CHANNELD_NORMAL'

        # Back, the hub hears the channel failed and sends its commitment.
        l2.start()
        wait_for(lambda: chan(l2, closing)['state'] == 'AWAITING_UNILATERAL')
        bitcoind.generate_block(1, wait_for_mempool=1)
        wait_for(lambda: chan(l1, closing)['state'] == 'ONCHAIN')
        assert kc.answers(l1)
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()
