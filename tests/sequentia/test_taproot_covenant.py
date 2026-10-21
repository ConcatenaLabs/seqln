"""The taproot-covenant channel type (`option_seq_taproot_covenant`).

Its commitment transactions spend the usual 2-of-2 funding output and pay
taproot outputs: to_local and the HTLCs are script trees whose internal key is
the revocation key, to_remote is the P2WPKH of the static payment basepoint.
An HTLC output's own leaves send the holder's claim to its delayed output by
covenant, so `commitment_signed` carries no HTLC signatures and every claim
attaches its fee from another input, in any asset the node accepts.
The scripts are in common/tcov_scripts.h.
Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from pyln.testing.utils import TIMEOUT
from utils import TEST_NETWORK, only_one, sync_blockheight, wait_for

import json
import os
import pytest
import time

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
TCOV = {'taproot-covenant-channels': None}
TCOV_BIT = 172


def fund_node(bitcoind, node, asset, atoms):
    addr = node.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send(addr, atoms, asset)
    bitcoind.generate_block(1, wait_for_mempool=txid)
    wait_for(lambda: any(o['txid'] == txid and o['status'] == 'confirmed'
                         for o in node.rpc.listfunds()['outputs']))


def open_channel(bitcoind, l1, l2, asset, atoms, **kwargs):
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.call('fundchannel', dict({'id': l2.info['id'], 'amount': atoms,
                                           'asset': asset}, **kwargs))
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['state']
                 == 'CHANNELD_NORMAL')
    return only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])


def pay(src, dst, msat, asset):
    inv = dst.rpc.call('invoice', {'amount_msat': msat, 'label': 'l%d' % pay.n,
                                   'description': 'tcov', 'asset': asset})
    pay.n += 1
    return src.rpc.pay(inv['bolt11'])


pay.n = 0


def commitment_outputs(bitcoind, node, peer):
    tx = node.rpc.dev_sign_last_tx(peer.info['id'])['tx']
    return bitcoind.rpc.decoderawtransaction(tx)


def test_tcov_negotiated_and_pays_both_ways(node_factory, bitcoind):
    """Both peers offer the type: it is the channel's type, both commitments
    pay taproot outputs (to_remote P2WPKH), HTLCs in flight are taproot
    outputs too, and payments complete both ways."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2 = node_factory.get_nodes(2, opts=[TCOV, TCOV])
    fund_node(bitcoind, l1, gold, 10 * PAR)
    chan = open_channel(bitcoind, l1, l2, gold, PAR)
    print("channel_type:", chan['channel_type'])
    assert TCOV_BIT in chan['channel_type']['bits']
    assert 'seq_taproot_covenant/even' in chan['channel_type']['names']

    # l2 needs more than its reserve (1% of the channel) to pay back.
    pay(l1, l2, 4_000_000_000, gold)
    pay(l2, l1, 1_000_000_000, gold)

    for a, b in ((l1, l2), (l2, l1)):
        dec = commitment_outputs(bitcoind, a, b)
        kinds = sorted(o['scriptPubKey']['type'] for o in dec['vout'])
        print("commitment of", a.info['id'][:8], kinds)
        # to_local is taproot, to_remote P2WPKH, plus the fee output.
        assert 'witness_v1_taproot' in kinds
        assert 'witness_v0_keyhash' in kinds
        assert 'witness_v0_scripthash' not in kinds


def test_tcov_not_negotiated_without_both(node_factory, bitcoind):
    """A peer that does not offer the type gets an ordinary channel."""
    gold = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR})
    l1, l2 = node_factory.get_nodes(2, opts=[TCOV, {}])
    fund_node(bitcoind, l1, gold, 10 * PAR)
    chan = open_channel(bitcoind, l1, l2, gold, PAR)
    assert TCOV_BIT not in chan['channel_type']['bits']
    # Asked for explicitly, the peer refuses it.
    l3 = node_factory.get_node(options=TCOV)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    with pytest.raises(RpcError):
        l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': PAR,
                                    'asset': gold, 'channel_type': [12, TCOV_BIT]})


# Short locks, so a test mines tens of blocks, not thousands.
SHORT = {'watchtime-blocks': 12, 'cltv-final': 20, 'cltv-delta': 20,
         'max-dust-htlc-exposure-msat': 10**12}
HOLD = os.path.join(os.path.dirname(__file__), '..', 'plugins', 'hold_invoice.py')


def tcov_pair(node_factory, bitcoind, opts=({}, {})):
    """A GOLD channel of the new type, l1 -> l2.  SILV is another asset the
    nodes accept for fees, worth two reference atoms an atom."""
    gold = bitcoind.issue_asset(1000)
    silv = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, gold: PAR, silv: 2 * PAR})
    l1, l2 = node_factory.get_nodes(2, opts=[{**TCOV, **SHORT, **opts[0]},
                                             {**TCOV, **SHORT, **opts[1]}])
    fund_node(bitcoind, l1, gold, 10 * PAR)
    chan = open_channel(bitcoind, l1, l2, gold, PAR)
    assert TCOV_BIT in chan['channel_type']['bits']
    return l1, l2, gold, silv, chan['short_channel_id']


def held_htlc(l1, l2, executor, msat, gold):
    """l1 pays l2; l2's hold plugin keeps the HTLC unresolved."""
    inv = l2.rpc.call('invoice', {'amount_msat': msat, 'label': 'held%d' % msat,
                                  'description': 'held', 'asset': gold})
    fut = executor.submit(l1.rpc.pay, inv['bolt11'])
    wait_for(lambda: [h['state'] for h in only_one(
        l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs']]
        == ['SENT_ADD_ACK_REVOCATION'])
    l2.daemon.wait_for_log('Calling invoice_payment hook')
    htlc = only_one(only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'])
    return fut, htlc


def asset_of(bitcoind, vout):
    return vout.get('asset')


def spender_of(bitcoind, txid, n, txids):
    for t in txids:
        d = bitcoind.rpc.getrawtransaction(t, 1)
        for i, vin in enumerate(d['vin']):
            if vin.get('txid') == txid and vin.get('vout') == n:
                return d, i
    return None, None


def recent_txids(bitcoind, blocks=30):
    """The mempool, then the last `blocks` blocks' transactions."""
    txids = list(bitcoind.rpc.getrawmempool())
    h = bitcoind.rpc.getblockcount()
    for height in range(max(0, h - blocks), h + 1):
        txids += bitcoind.rpc.getblock(bitcoind.rpc.getblockhash(height))['tx'][1:]
    return txids


def wait_spender(bitcoind, txid, n):
    """The transaction spending txid:n, in the mempool or a recent block."""
    found = []

    def f():
        d, i = spender_of(bitcoind, txid, n, recent_txids(bitcoind))
        if d:
            found.append((d, i))
        return bool(d)
    wait_for(f)
    return found[-1]


def mine_if_pending(bitcoind, txid):
    """Mine `txid` if it is still in the mempool (it may be mined already)."""
    if txid in bitcoind.rpc.getrawmempool():
        bitcoind.generate_block(1, wait_for_mempool=txid)


def confirmed_spender(bitcoind, txid, n):
    """The transaction spending txid:n that a block holds, mining until one
    does: lightningd may have replaced the one first seen in the mempool."""
    for _ in range(10):
        h = bitcoind.rpc.getblockcount()
        txids = []
        for height in range(max(0, h - 30), h + 1):
            txids += bitcoind.rpc.getblock(bitcoind.rpc.getblockhash(height))['tx'][1:]
        d, i = spender_of(bitcoind, txid, n, txids)
        if d:
            return d, i
        bitcoind.generate_block(1)
        time.sleep(0.5)
    raise ValueError('no block spends {}:{}'.format(txid, n))


def mine_to(bitcoind, height):
    while bitcoind.rpc.getblockcount() < height:
        bitcoind.generate_block(min(10, height - bitcoind.rpc.getblockcount()))


def builds_of(node, txid, n):
    """How many times lightningd has built a spend of txid:n."""
    node.daemon.logs_catchup()
    pat = 'tcov spend of {}:{} '.format(txid, n)
    return len([ln for ln in node.daemon.logs if pat in ln])


def assert_claim_settled(bitcoind, node, txid, n):
    """Once the spend of txid:n is mined, three more blocks build it no more
    (each build asks the signer again and reserves fee coins)."""
    before = builds_of(node, txid, n)
    bitcoind.generate_block(3)
    sync_blockheight(bitcoind, [node])
    assert builds_of(node, txid, n) == before


def test_tcov_timeout_claim_fee_in_other_asset(node_factory, bitcoind, executor):
    """l1 force-closes with an HTLC it offered in flight.  Past the HTLC's
    CLTV its timeout leaf sends the HTLC's whole value, in GOLD, to l1's
    delayed output D by covenant, with the fee from a SILV coin: l1 holds
    no GOLD outside the channel.  After the delay l1 sweeps D."""
    l1, l2, gold, silv, scid = tcov_pair(node_factory, bitcoind,
                                         opts=({}, {'plugin': HOLD, 'may_fail': True}))
    # No GOLD left in l1's wallet: the fee must come from another asset.
    addr = bitcoind.rpc.getnewaddress()
    l1.rpc.call('withdraw', {'destination': addr, 'satoshi': 'all', 'asset': gold})
    bitcoind.generate_block(1, wait_for_mempool=1)
    fund_node(bitcoind, l1, silv, 5 * PAR)
    wait_for(lambda: all(o['asset'] != gold for o in l1.rpc.listfunds()['outputs']
                         if o['status'] == 'confirmed'))

    msat = 3_000_000_000
    fut, htlc = held_htlc(l1, l2, executor, msat, gold)
    l2.stop()
    commitment = only_one(l1.rpc.close(scid, unilateraltimeout=1)['txids'])
    bitcoind.generate_block(1, wait_for_mempool=commitment)
    dec = bitcoind.rpc.getrawtransaction(commitment, 1)
    htlc_out = only_one([o['n'] for o in dec['vout']
                         if o['scriptPubKey']['type'] == 'witness_v1_taproot'
                         and int(Decimal(o['value']) * PAR) == msat // 1000])

    mine_to(bitcoind, htlc['expiry'] + 1)
    wait_spender(bitcoind, commitment, htlc_out)
    claim, i = confirmed_spender(bitcoind, commitment, htlc_out)
    print("timeout claim:", json.dumps({k: claim[k] for k in ('txid', 'vsize', 'weight')}))
    assert i == 0
    out0 = claim['vout'][0]
    assert out0['scriptPubKey']['type'] == 'witness_v1_taproot'
    assert out0['asset'] == gold
    assert int(Decimal(out0['value']) * PAR) == msat // 1000
    fee_outs = [o for o in claim['vout'] if o['scriptPubKey']['type'] == 'fee']
    assert only_one(fee_outs)['asset'] == silv
    assert len(claim['vin']) >= 2
    # Witness: <sig> <leaf> <control block>, the leaf the timeout's.
    wit = claim['vin'][0]['txinwitness']
    assert len(wit) == 3 and len(wit[0]) == 128

    # D, after l1's delay, back to its wallet.
    sweep, j = wait_spender_after(bitcoind, claim['txid'], 0, 13)
    assert sweep['vout'][0]['asset'] == gold
    mine_if_pending(bitcoind, sweep['txid'])
    wait_for(lambda: any(o['txid'] == sweep['txid'] and o['asset'] == gold
                         for o in l1.rpc.listfunds()['outputs']))
    assert_claim_settled(bitcoind, l1, commitment, htlc_out)


def wait_spender_after(bitcoind, txid, n, blocks):
    """The spend of txid:n, in the mempool or a block, mining up to `blocks`
    more blocks (plus a margin) for it to appear."""
    for _ in range(blocks + 5):
        d, i = spender_of(bitcoind, txid, n, recent_txids(bitcoind, blocks + 40))
        if d:
            return d, i
        bitcoind.generate_block(1)
        time.sleep(0.5)
    return wait_spender(bitcoind, txid, n)


def test_tcov_success_claim_with_preimage(node_factory, bitcoind, executor):
    """l2 force-closes holding an HTLC it received; once it learns the
    preimage its success leaf sends the HTLC's value to its own delayed
    output by covenant, the fee from another input; then l2 sweeps it."""
    l1, l2, gold, silv, scid = tcov_pair(node_factory, bitcoind,
                                         opts=({'may_fail': True}, {'plugin': HOLD}))
    fund_node(bitcoind, l2, gold, 5 * PAR)
    msat = 3_000_000_000
    fut, htlc = held_htlc(l1, l2, executor, msat, gold)
    l1.stop()
    commitment = only_one(l2.rpc.close(scid, unilateraltimeout=1)['txids'])
    bitcoind.generate_block(1, wait_for_mempool=commitment)
    dec = bitcoind.rpc.getrawtransaction(commitment, 1)
    htlc_out = only_one([o['n'] for o in dec['vout']
                         if o['scriptPubKey']['type'] == 'witness_v1_taproot'
                         and int(Decimal(o['value']) * PAR) == msat // 1000])
    # Release the hold: l2 learns it may take the payment.
    open(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'unhold'), 'w').close()
    wait_spender(bitcoind, commitment, htlc_out)
    claim, i = confirmed_spender(bitcoind, commitment, htlc_out)
    print("success claim:", json.dumps({k: claim[k] for k in ('txid', 'vsize', 'weight')}))
    assert i == 0
    out0 = claim['vout'][0]
    assert out0['scriptPubKey']['type'] == 'witness_v1_taproot'
    assert out0['asset'] == gold
    assert int(Decimal(out0['value']) * PAR) == msat // 1000
    wit = claim['vin'][0]['txinwitness']
    assert len(wit) == 4 and len(wit[1]) == 64   # <sig> <preimage> <leaf> <cb>
    sweep, j = wait_spender_after(bitcoind, claim['txid'], 0, 13)
    mine_if_pending(bitcoind, sweep['txid'])


def test_tcov_revoked_commitment_punished(node_factory, bitcoind, executor):
    """l1 broadcasts a commitment it revoked, with an HTLC on it; l2's
    onchaind takes every output of it by the key path."""
    l1, l2, gold, silv, scid = tcov_pair(
        node_factory, bitcoind,
        opts=({'may_fail': True},
              {'plugin': HOLD}))
    msat = 3_000_000_000
    fut, htlc = held_htlc(l1, l2, executor, msat, gold)
    snapshot = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']
    revoked = bitcoind.rpc.decoderawtransaction(snapshot)
    open(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'unhold'), 'w').close()
    fut.result(TIMEOUT)
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: only_one(a.rpc.listpeerchannels(b.info['id'])['channels'])['htlcs'] == [])
    l1.stop()
    bitcoind.rpc.sendrawtransaction(snapshot)
    bitcoind.generate_block(1, wait_for_mempool=revoked['txid'])
    targets = [o['n'] for o in revoked['vout']
               if o['scriptPubKey']['type'] == 'witness_v1_taproot']
    assert len(targets) == 2, revoked['vout']   # l1's to_local and the HTLC
    for n in targets:
        pen, i = wait_spender(bitcoind, revoked['txid'], n)
        assert len(pen['vin'][i]['txinwitness']) == 1   # the key path
    bitcoind.generate_block(1)
    victim_addrs = set(a.get('bech32') for a in l2.rpc.call('listaddresses')['addresses'])
    for n in targets:
        pen, i = spender_of(bitcoind, revoked['txid'], n,
                            bitcoind.rpc.getblock(bitcoind.rpc.getbestblockhash())['tx'])
        assert pen is not None
        assert pen['vout'][0]['scriptPubKey']['address'] in victim_addrs


def test_tcov_tower_punishes_revoked_commitment(node_factory, bitcoind, executor,
                                                directory):
    """The cheater broadcasts a commitment it revoked, carrying an HTLC it
    received and holds the preimage of, and wins the race for the HTLC
    output: its success leaf sends the HTLC by covenant to its delayed
    output D.  The victim is offline.  speculad, with no key and no
    signature from the victim's device, takes the cheater's to_local and D
    by their REVOKE leaf, whose witness is the revoked per-commitment secret,
    into the victim's static payment script, paying the fee from a SILV
    coin.  Back online, the victim's wallet holds both."""
    from test_watchtower import (Speculad, fee_wallet, sqlite_backup,
                                 sqlite_restore, channel)
    victim = {'watchtower-store': 'on', 'may_reconnect': True}
    cheater = {'may_fail': True, 'may_reconnect': True, 'broken_log': '.*',
               'disconnect': ['-WIRE_UPDATE_FULFILL_HTLC']}
    l1, l2, gold, silv, scid = tcov_pair(node_factory, bitcoind,
                                         opts=(cheater, victim))
    # l2 pays l1; l1 learns the preimage and stops before telling l2.
    pay(l1, l2, 4_000_000_000, gold)
    msat = 2_000_000_000
    inv = l1.rpc.call('invoice', {'amount_msat': msat, 'label': 'held',
                                  'description': 'held', 'asset': gold})['bolt11']
    paying = executor.submit(l2.rpc.pay, inv)
    l1.daemon.wait_for_log('dev_disconnect: -WIRE_UPDATE_FULFILL_HTLC')
    assert [h['direction'] for h in channel(l1, l2)['htlcs']] == ['in']

    backup = os.path.join(directory, 'cheater.sqlite3')
    sqlite_backup(l1, backup)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    paying.result(TIMEOUT)
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: channel(a, b)['htlcs'] == [])
    pay(l1, l2, 1_000_000_000, gold)
    store = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'watchtower')

    l2.stop()
    l1.stop()
    sqlite_restore(l1, backup)
    l1.start()
    l1.rpc.close(l2.info['id'], 1)
    l1.daemon.wait_for_log('sendrawtx exit 0')
    revoked_txid = only_one(bitcoind.rpc.getrawmempool())
    revoked = bitcoind.rpc.getrawtransaction(revoked_txid, True)
    assert any(os.path.exists(os.path.join(store, d, 'justice', revoked_txid))
               for d in os.listdir(store)), "the victim's store has no justice for it"
    bitcoind.generate_block(1, wait_for_mempool=revoked_txid)

    # The cheater's covenant claim of the HTLC into its D.
    rawtx, claim_txid, blocks = l1.wait_for_onchaind_tx(
        'OUR_HTLC_SUCCESS_TX', 'OUR_UNILATERAL/THEIR_HTLC')
    l1.stop()
    if blocks > 0:
        bitcoind.generate_block(blocks)
    if claim_txid not in bitcoind.rpc.getrawmempool():
        bitcoind.rpc.sendrawtransaction(rawtx)
    bitcoind.generate_block(1, wait_for_mempool=claim_txid)
    claim = bitcoind.rpc.getrawtransaction(claim_txid, True)
    assert claim['vin'][0]['txid'] == revoked_txid

    outs = {o['n']: o for o in revoked['vout']}
    to_local_spk = claim['vout'][0]['scriptPubKey']['hex']   # D has to_local's script
    to_local = [n for n, o in outs.items() if o['scriptPubKey']['hex'] == to_local_spk]
    victim_spk = only_one([o for o in outs.values()
                           if o['scriptPubKey']['type'] == 'witness_v0_keyhash'])['scriptPubKey']['hex']
    targets = [(revoked_txid, n) for n in to_local] + [(claim_txid, 0)]
    values = {(revoked_txid, n): outs[n]['value'] for n in to_local}
    values[(claim_txid, 0)] = claim['vout'][0]['value']
    print("revoked {}: to_local {}, D {}:0".format(revoked_txid, to_local, claim_txid))

    # The tower holds SILV only.
    wallet = fee_wallet(bitcoind, silv)
    tower = Speculad(l2, bitcoind, wallet, directory)

    def punished(txids):
        found = {}
        for t in txids:
            try:
                dec = bitcoind.rpc.getrawtransaction(t, True)
            except Exception:
                continue
            for i, vin in enumerate(dec.get('vin', [])):
                key = (vin.get('txid'), vin.get('vout'))
                if key in targets:
                    found[key] = (dec, i)
        return found

    tower.start()
    try:
        deadline = time.time() + TIMEOUT
        while True:
            pending = punished(bitcoind.rpc.getrawmempool())
            if set(targets) <= set(pending) or time.time() > deadline:
                break
            time.sleep(1)
        print(tower.output())
        assert sorted(set(targets) - set(pending)) == [], "unpunished"
        block = bitcoind.generate_block(1)[0]
    finally:
        tower.stop()

    mined = punished(bitcoind.rpc.getblock(block)['tx'])
    assert set(mined) == set(targets), (mined.keys(), targets)
    for key, (j, i) in mined.items():
        sweep = j['vout'][i]
        assert sweep['asset'] == gold
        assert sweep['scriptPubKey']['hex'] == victim_spk
        assert Decimal(sweep['value']) == Decimal(values[key])
        # The REVOKE leaf: <secret> <leaf> <control block>, no signature.
        wit = j['vin'][i]['txinwitness']
        assert len(wit) == 3 and len(wit[0]) == 64
        fee = only_one([o for o in j['vout'] if o['scriptPubKey']['type'] == 'fee'])
        assert fee['asset'] == silv
    for j in {j['txid']: j for j, _ in mined.values()}.values():
        print("justice {}: {} vB, {} inputs".format(j['txid'], j['vsize'], len(j['vin'])))

    # Back online, the victim's wallet has what the tower took.
    l2.start()
    sweeps = set(j['txid'] for j, _ in mined.values())
    wait_for(lambda: sweeps <= set(o['txid'] for o in l2.rpc.listfunds()['outputs']
                                   if o['asset'] == gold))


@pytest.mark.parametrize('leaf', ['timeout', 'success'])
def test_tcov_claim_on_their_commitment(node_factory, bitcoind, executor, leaf):
    """The other side's commitment is on chain with an HTLC l1 offered.
    'timeout': l2 closed and never learned the preimage; past the CLTV l1
    takes the HTLC by the TIMEOUT leaf of l2's commitment, straight to its
    wallet.  'success': l1 closed; l2 learns the preimage and takes the HTLC
    by the SUCCESS leaf of l1's commitment, straight to its wallet."""
    l1, l2, gold, silv, scid = tcov_pair(
        node_factory, bitcoind,
        opts=({'may_fail': True}, {'plugin': HOLD, 'may_fail': True}))
    fund_node(bitcoind, l2, gold, 5 * PAR)
    msat = 3_000_000_000
    fut, htlc = held_htlc(l1, l2, executor, msat, gold)
    if leaf == 'timeout':
        closer, claimer = l2, l1
        l1.stop()
    else:
        closer, claimer = l1, l2
    commitment = only_one(closer.rpc.close(scid, unilateraltimeout=1)['txids'])
    bitcoind.generate_block(1, wait_for_mempool=commitment)
    dec = bitcoind.rpc.getrawtransaction(commitment, 1)
    htlc_out = only_one([o['n'] for o in dec['vout']
                         if o['scriptPubKey']['type'] == 'witness_v1_taproot'
                         and int(Decimal(o['value']) * PAR) == msat // 1000])
    if leaf == 'timeout':
        l2.stop()
        l1.start()
        mine_to(bitcoind, htlc['expiry'] + 1)
    else:
        open(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'unhold'), 'w').close()
    wait_spender(bitcoind, commitment, htlc_out)
    claim, i = confirmed_spender(bitcoind, commitment, htlc_out)
    print("{} claim on their commitment: {}".format(
        leaf, json.dumps({k: claim[k] for k in ('txid', 'vsize', 'weight')})))
    wit = claim['vin'][i]['txinwitness']
    assert len(wit) == (3 if leaf == 'timeout' else 4)
    out0 = claim['vout'][0]
    assert out0['asset'] == gold
    # To the claimer's own wallet, not to a covenant destination.
    assert out0['scriptPubKey']['type'] == 'witness_v0_keyhash'
    wait_for(lambda: any(o['txid'] == claim['txid']
                         for o in claimer.rpc.listfunds()['outputs']))

