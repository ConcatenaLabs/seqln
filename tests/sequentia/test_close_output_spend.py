"""What a channel close pays a keyless node goes only to the node's own scripts.

A keyless node's device signs the spend of what a close paid it only when
every output of the spending transaction, the fee aside, pays one of the
device's own wallet scripts, and the fee is within the device's payment limit
for its asset.  Three kinds of close output, each spent here with the device's
signature to the node's own address and confirmed:

  * what the peer's commitment pays the node, which its wallet holds with the
    channel noted (the device signs it with the channel's payment key);
  * what the node's own commitment pays it once its delay has passed, which
    lightningd sweeps to the node's wallet;
  * what a mutual close pays it (the device remembers the closes it signed).

A spend paying any other script is refused, and so is one whose fee is over
the device's payment limit for the asset: the node cannot finalize the
transaction and sends nothing, and the device logs why.  On Bitcoin regtest
the honest transaction with an output redirected is forced into a block
(`generateblock`) and refused: the device's signature commits to every output.
What a sweep's SIGHASH_SINGLE|ANYONECANPAY signature lets a host take is
shown in a block too: the fee it left, never more.

Run with TEST_NETWORK=sequentia-regtest and with TEST_NETWORK=regtest;
SEQLN_DEVICE=wasm serves the node from the browser build (see
test_keyless_close.py).
"""
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from pyln.testing.utils import JSONRPCError
from utils import TEST_NETWORK, only_one, sync_blockheight, wait_for

import os
import pytest
import re

import test_keyless_close as kc
import test_keyless_start as ks

pytestmark = pytest.mark.skipif(TEST_NETWORK not in ('sequentia-regtest', 'regtest'),
                                reason='needs TEST_NETWORK=sequentia-regtest or regtest')
needs_device = pytest.mark.skipif(
    not os.path.exists(kc.SIGNER) or (kc.DEVICE == 'wasm' and not os.path.exists(
        os.path.join(os.path.dirname(kc.WASM_DEVICE), '..', 'pkg', 'seqln_signer_wasm.js'))),
    reason='needs the seqln-signer binary (and the wasm package for SEQLN_DEVICE=wasm)')

SEQ = TEST_NETWORK == 'sequentia-regtest'
# The device's payment limit here, in atoms of each asset: above what a spend
# at the lowest feerate pays, and above the fee of the penalty the watchtower
# has the device pre-sign at every commitment step (about 7,200 atoms at this
# chain's feerate), below what a spend at 200,000 perkw pays.
LIMIT = 20000
CHEAP, DEAR = '253perkw', '200000perkw'
# The delay the hub asks of the keyless node's own commitment, in blocks.
DELAY = 6
REFUSED = 'POLICY REJECT: SIGN_WITHDRAWAL refused: '
FOREIGN = "which is not one of this device's own scripts"


def spend(node, addr, asset, feerate):
    """Spend all of the node's wallet in `asset` to `addr` at `feerate`
    (`fundpsbt`, `addpsbtoutput`, `signpsbt`, `sendpsbt`: the fee is paid in
    the asset spent).  Returns the txid; on a refusal the inputs are released
    and the error raised."""
    args = {'satoshi': 'all', 'feerate': feerate, 'startweight': 1000}
    if asset:
        args['asset'] = asset
    res = node.rpc.call('fundpsbt', args)
    out = {'satoshi': res['excess_msat'] // 1000, 'initialpsbt': res['psbt'],
           'destination': addr}
    if asset:
        out['asset'] = asset
    psbt = node.rpc.call('addpsbtoutput', out)['psbt']
    signed = node.rpc.signpsbt(psbt)['signed_psbt']
    try:
        return node.rpc.sendpsbt(signed)['txid']
    except RpcError:
        node.rpc.unreserveinputs(psbt)
        raise


def spender_of(bitcoind, txid):
    """The mempool transaction spending an output of `txid`, once there."""
    def find():
        for t in bitcoind.rpc.getrawmempool():
            if any(i.get('txid') == txid for i in bitcoind.rpc.getrawtransaction(t, True)['vin']):
                return t
        return None
    wait_for(lambda: find() is not None)
    return find()


def own_address(node):
    return node.rpc.newaddr('bech32')['bech32']


def refused_spend(bitcoind, node, device, asset, addr, feerate, reason):
    """The device refuses to sign the spend: nothing is sent and it says why."""
    before = device.output().count(REFUSED)
    with pytest.raises(RpcError, match='not finalizeable'):
        spend(node, addr, asset, feerate)
    wait_for(lambda: device.output().count(REFUSED) > before)
    line = [ln for ln in device.output().splitlines() if REFUSED in ln][-1]
    print('refused:', line.split('seqln-signer: ', 1)[-1])
    assert reason in line, line
    return line


def redirected_into_block(bitcoind, raw, own_spk, txid):
    """Bitcoin regtest: the honest transaction `raw`, its output to the
    node's own script redirected to another, forced into a block, is refused
    by the chain: the device's signature commits to the outputs.  The
    Sequentia test chain's blocks are made by its staking committee from the
    mempool (`generateblock` cannot make one there: bad-posvrf-missing), and
    its mempool, holding the honest spend, refuses the redirected one as a
    replacement paying too little before it reaches the scripts."""
    if SEQ:
        return None
    other = '0014' + 'ee' * 20
    assert own_spk.startswith('0014') and len(own_spk) == len(other)
    assert raw.count(own_spk) == 1
    bad = raw.replace(own_spk, other)
    with pytest.raises(JSONRPCError) as e:
        bitcoind.rpc.generateblock(bitcoind.rpc.getnewaddress(), [bad])
    print('redirected {} forced into a block: {}'.format(txid, e.value.error['message']))
    assert 'mandatory-script-verify-flag-failed' in e.value.error['message'], e.value.error
    return e.value.error['message']


def checks_scripts_one_by_one(bitcoind):
    """Restart the chain's node with -par=1, so a block it refuses names the
    script failure (in parallel it says only block-validation-failed).
    Bitcoin regtest only: there the tests force transactions into blocks."""
    if SEQ:
        return
    bitcoind.stop()
    bitcoind.cmd_line.append('-par=1')
    bitcoind.start()


def spend_to_own(bitcoind, node, txid, asset):
    """Spend what `txid` paid the node to the node's own address, cheaply:
    the device signs, the spend confirms.  Returns the spending txid."""
    addr = own_address(node)
    for _ in range(5):
        try:
            spent = spend(node, addr, asset, CHEAP)
            break
        except RpcError as e:
            # The peer's commitment pays us after one block (CSV 1).
            if 'csv locked' not in str(e) and 'could not afford' not in str(e).lower():
                raise
            bitcoind.generate_block(1)
            sync_blockheight(bitcoind, [node])
    raw = bitcoind.rpc.getrawtransaction(spent)
    tx = bitcoind.rpc.decoderawtransaction(raw)
    out = only_one([v for v in tx['vout'] if v['scriptPubKey'].get('address') == addr])
    redirected_into_block(bitcoind, raw, out['scriptPubKey']['hex'], spent)
    bitcoind.generate_block(1, wait_for_mempool=spent)
    tx = bitcoind.rpc.getrawtransaction(spent, True)
    assert any(i['txid'] == txid for i in tx['vin'])
    if SEQ:
        assert out['asset'] == asset
    wait_for(lambda: any(o['txid'] == spent and o['status'] == 'confirmed'
                         for o in node.rpc.listfunds()['outputs']))
    print('{} paid the node {}; the node spent it to its own address in {}'
          .format(txid, out.get('value'), spent))
    return spent


def check_refusals(bitcoind, node, device, txid, asset):
    """What `txid` paid the node: to another script, refused; over the
    limit, refused; still unspent."""
    refused_spend(bitcoind, node, device, asset, bitcoind.getnewaddress(), CHEAP, FOREIGN)
    line = refused_spend(bitcoind, node, device, asset, own_address(node), DEAR,
                         "payment limit for that asset has left this period")
    assert re.search(r'\(\d+ of {} atoms\)'.format(LIMIT), line), line
    assert any(o['txid'] == txid for o in node.rpc.listfunds()['outputs'])


@needs_device
def test_peers_commitment_output(node_factory, bitcoind, directory):
    """The hub closes unilaterally; its commitment pays the keyless node,
    whose wallet holds the output with the channel noted.  The device signs
    its spend with the channel's payment key, only to the node's own
    address and within its limit."""
    asset = ks.coin(bitcoind)
    checks_scripts_one_by_one(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True, pay_limit=str(LIMIT),
                                 may_reconnect=True, broken_log='.*')
    try:
        l2 = node_factory.get_node(may_reconnect=True, broken_log=ks.HUB_BROKEN)
        ks.fund(bitcoind, l2, 2 * ks.CAP, asset)
        scid = ks.open_paid_channel(bitcoind, l2, l1, asset)
        funding = ks.chan(l2, scid)['funding_txid']
        l2.rpc.dev_fail(l1.info['id'])
        theirs = spender_of(bitcoind, funding)
        bitcoind.generate_block(1, wait_for_mempool=theirs)
        wait_for(lambda: ks.chan(l1, scid)['state'] == 'ONCHAIN')
        out = ks.holds(bitcoind, l1, theirs, asset)
        assert out['amount_msat'] == ks.PAY * 1000
        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l1])

        check_refusals(bitcoind, l1, device, theirs, asset)
        spend_to_own(bitcoind, l1, theirs, asset)
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()


@needs_device
def test_mutual_close_output(node_factory, bitcoind, directory):
    """The hub closes mutually; the device signs the close and remembers it,
    across a restart, so what it pays the node is held to the same rule."""
    asset = ks.coin(bitcoind)
    checks_scripts_one_by_one(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True, pay_limit=str(LIMIT),
                                 may_reconnect=True, broken_log='.*')
    try:
        l2 = node_factory.get_node(may_reconnect=True, broken_log=ks.HUB_BROKEN)
        ks.fund(bitcoind, l2, 2 * ks.CAP, asset)
        scid = ks.open_paid_channel(bitcoind, l2, l1, asset)
        close = only_one(l2.rpc.close(scid)['txids'])
        bitcoind.generate_block(1, wait_for_mempool=close)
        wait_for(lambda: ks.chan(l1, scid)['state'] == 'ONCHAIN')
        out = ks.holds(bitcoind, l1, close, asset)
        print('the close {} paid the keyless node {}'.format(close, out['amount_msat']))

        # The device forgets nothing over a restart.
        ks.restart_device(device)
        check_refusals(bitcoind, l1, device, close, asset)
        spend_to_own(bitcoind, l1, close, asset)
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()


def sweep_of(bitcoind, node, commitment):
    """The transaction in the mempool spending `commitment`'s to_local."""
    for txid in bitcoind.rpc.getrawmempool():
        tx = bitcoind.rpc.getrawtransaction(txid, True)
        if any(i['txid'] == commitment for i in tx['vin']):
            return txid, tx
    return None


def sweep_taken_in_block(bitcoind, sweep_txid):
    """Bitcoin regtest: the device signs the sweep SIGHASH_SINGLE|ANYONECANPAY,
    committing to its input and output 0 only.  A host may add an output:
    taking the fee the sweep left, the block takes it; taking an atom more,
    the block is refused.  The limit bounds that fee."""
    if SEQ:
        return None
    raw = bitcoind.rpc.getrawtransaction(sweep_txid)
    tx = bitcoind.rpc.decoderawtransaction(raw)
    prev = bitcoind.rpc.getrawtransaction(tx['vin'][0]['txid'], True)
    v_in = round(prev['vout'][tx['vin'][0]['vout']]['value'] * 10**8)
    v_out = round(sum(o['value'] for o in tx['vout']) * 10**8)
    fee = v_in - v_out
    print('the sweep {} pays {} of {}: fee {}'.format(sweep_txid, v_out, v_in, fee))
    other = '0014' + 'ee' * 20

    def with_output(value):
        # Splice an output into the serialization: version(4) marker+flag(2)
        # vin..., then the output count and outputs, then witnesses.
        b = bytes.fromhex(raw)
        assert b[4:6] == b'\x00\x01'
        p = 6
        nin = b[p]
        p += 1
        for _ in range(nin):
            p += 36
            p += 1 + b[p]
            p += 4
        nout = b[p]
        q = p + 1
        for _ in range(nout):
            q += 8
            q += 1 + b[q]
        extra = value.to_bytes(8, 'little') + bytes([22]) + bytes.fromhex(other)
        return (b[:p] + bytes([nout + 1]) + b[p + 1:q] + extra + b[q:]).hex()

    with pytest.raises(JSONRPCError) as e:
        bitcoind.rpc.generateblock(bitcoind.rpc.getnewaddress(), [with_output(fee + 1)])
    print('an added output taking {} (one more than the fee): {}'
          .format(fee + 1, e.value.error['message']))
    assert 'bad-txns-in-belowout' in e.value.error['message']
    stolen = with_output(fee)
    taken = bitcoind.rpc.generateblock(bitcoind.rpc.getnewaddress(), [stolen])
    print('an added output taking the fee {}: block {}'.format(fee, taken['hash']))
    return bitcoind.rpc.decoderawtransaction(stolen)['txid']


@needs_device
def test_own_commitment_after_delay(node_factory, bitcoind, directory):
    """The keyless node closes unilaterally with the hub away; once its
    delay has passed lightningd sweeps what its commitment pays it.  The
    device signs the sweep only within the payment limit of the channel's
    asset: with the limit below the sweep's fee it refuses (and the node,
    whose sweep is a request it cannot do without, stops); with the limit
    raised, the node starts, the sweep is signed and confirms."""
    asset = ks.coin(bitcoind)
    checks_scripts_one_by_one(bitcoind)
    device, l1 = kc.keyless_node(node_factory, directory, trace=True,
                                 may_reconnect=True, broken_log='.*')
    try:
        # The hub asks a short delay of the keyless node's to_local.
        l2 = node_factory.get_node(may_reconnect=True, broken_log=ks.HUB_BROKEN,
                                   options={'watchtime-blocks': DELAY})
        ks.fund(bitcoind, l2, 2 * ks.CAP, asset)
        scid = ks.open_paid_channel(bitcoind, l2, l1, asset)
        l2.stop()
        # The device's limit drops below the sweep's fee.
        l1.stop()
        device.env['SEQLN_SIGNER_PAY_LIMIT'] = '1'
        ks.restart_device(device)
        l1.start()
        commitment = only_one(l1.rpc.close(scid, unilateraltimeout=1)['txids'])
        bitcoind.generate_block(1, wait_for_mempool=commitment)

        # Once the commitment confirms, lightningd has the sweep of its
        # to_local signed ahead (it broadcasts it when the delay is over).
        refusal = 'POLICY REJECT: SIGN_ANY_DELAYED_PAYMENT_TO_US refused: what it lets leave this device'
        wait_for(lambda: refusal in device.output())
        line = [ln for ln in device.output().splitlines() if refusal in ln][-1]
        print('refused:', line.split('seqln-signer: ', 1)[-1])
        wait_for(lambda: not kc.answers(l1, timeout=2))
        l1.daemon.proc.wait()
        assert l1.daemon.is_in_log('EOF reading from HSM after WIRE_HSMD_SIGN_ANY_DELAYED_PAYMENT_TO_US')
        assert sweep_of(bitcoind, l1, commitment) is None

        device.env['SEQLN_SIGNER_PAY_LIMIT'] = str(10**7)
        ks.restart_device(device)
        l1.start()
        wait_for(lambda: ks.chan(l1, scid)['state'] == 'ONCHAIN')

        bitcoind.generate_block(DELAY - 1)
        sync_blockheight(bitcoind, [l1])
        wait_for(lambda: sweep_of(bitcoind, l1, commitment) is not None)
        sweep, tx = sweep_of(bitcoind, l1, commitment)
        print('the node swept its commitment {} in {}'.format(commitment, sweep))
        # One output to a script (the wallet lists it below), in the
        # channel's asset.
        assert len([o for o in tx['vout'] if o['scriptPubKey'].get('address')]) == 1
        if SEQ:
            assert {o['asset'] for o in tx['vout']} == {asset}
        taken = sweep_taken_in_block(bitcoind, sweep)
        if taken is None:
            bitcoind.generate_block(1, wait_for_mempool=sweep)
        # Either way the node's wallet holds output 0 of what confirmed.
        landed = taken or sweep
        wait_for(lambda: any(o['txid'] == landed and o['status'] == 'confirmed'
                             for o in l1.rpc.listfunds()['outputs']))
    finally:
        if kc.answers(l1, timeout=2):
            l1.stop()
        device.stop()
