"""The keyless watchtower (speculad) on channels in an issued asset.

A node that keeps the watchtower store (`--watchtower-store=on`) has its signer
pre-sign a justice set for every commitment its peer revokes.  speculad, which
holds no key, reads that store and answers a breach while the node is down.
These tests break a channel in an asset priced away from par while the victim
is offline and check that speculad sweeps every output of the revoked
commitment to the victim, in the channel asset, with a fee the network relays:
in the channel asset, or, once the node has delisted it, in another asset the
tower holds.
Run with TEST_NETWORK=sequentia-regtest (README.md, "Testing").
"""
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from pyln.testing.utils import TIMEOUT
from utils import TEST_NETWORK, only_one, wait_for

import json
import os
import sqlite3
import pytest
import subprocess
import time

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'sequentia-regtest',
                                reason='needs TEST_NETWORK=sequentia-regtest')

PAR = 10**8
# One atom of CHEAP is worth a tenth of a reference atom; one atom of DEAR is
# worth a hundred.  (An asset worth a thousandth of a reference atom cannot
# carry an HTLC output here: at the harness feerate, some 11 million of its
# atoms per kw, an HTLC transaction's fee alone exceeds the largest HTLC,
# 2^32-1 msat, so every HTLC is trimmed.)
CHEAP = 10**7
DEAR = 10**10
# The node's minimum relay fee, reference atoms per kvB.
MIN_RELAY_PER_KVB = 100

SPECULAD = os.path.join(os.path.dirname(__file__), '..', '..',
                        'speculad', 'speculad')
HOLD_PLUGIN = os.path.join(os.path.dirname(__file__), '..', 'plugins',
                           'hold_invoice.py')


class Speculad(object):
    """speculad watching `node`'s store, paying fees from the `wallet` of the
    Sequentia node.  Every CLI call it makes is logged, one method per line,
    so a test can count them."""
    def __init__(self, node, bitcoind, wallet, directory):
        self.netdir = os.path.join(node.daemon.lightning_dir, TEST_NETWORK)
        self.log = os.path.join(directory, 'speculad.log')
        self.calls = os.path.join(directory, 'speculad-cli-calls')
        wrapper = os.path.join(directory, 'speculad-cli')
        with open(wrapper, 'w') as f:
            f.write('#!/bin/sh\n'
                    'for a in "$@"; do case "$a" in -*) ;; *) '
                    'echo "$a" >> {calls}; break;; esac; done\n'
                    'exec sequentia-cli "$@"\n'.format(calls=self.calls))
        os.chmod(wrapper, 0o755)
        self.cmd = [SPECULAD,
                    '--netdir=' + self.netdir,
                    '--network=' + TEST_NETWORK,
                    '--poll-interval=1',
                    '--fee-wallet=' + wallet,
                    '--cli=' + wrapper,
                    '--cli=-datadir=' + bitcoind.bitcoin_dir,
                    '--cli=-conf=' + bitcoind.conf_file]
        self.proc = None

    def start(self):
        self.logf = open(self.log, 'w')
        self.proc = subprocess.Popen(self.cmd, stderr=self.logf,
                                     stdout=self.logf)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=TIMEOUT)
        if self.proc:
            self.logf.close()

    def calls_made(self):
        if not os.path.exists(self.calls):
            return []
        with open(self.calls) as f:
            return [line.strip() for line in f]

    def output(self):
        with open(self.log) as f:
            return f.read()


def cli(bitcoind, *args):
    return subprocess.check_output(
        ['sequentia-cli', '-datadir=' + bitcoind.bitcoin_dir,
         '-conf=' + bitcoind.conf_file] + list(args)).decode().strip()


def fee_wallet(bitcoind, asset, holdings=None):
    """A wallet of its own for the tower, holding `asset` in exactly one
    P2WPKH output (or one output per (asset, amount) of `holdings`):
    everything the tower broadcasts for one breach must share it.  Wallet
    RPCs through the fixture stop working once a second wallet is loaded, so
    this is the last thing a test funds through the fixture."""
    name = 'speculad-fee'
    bitcoind.rpc.createwallet(name)
    holdings = holdings or [(asset, 1)]
    txids = [fund_fee_wallet(bitcoind, name, a, amount) for a, amount in holdings]
    bitcoind.generate_block(1, wait_for_mempool=txids)
    utxos = json.loads(cli(bitcoind, '-rpcwallet=' + name, 'listunspent'))
    assert sorted(u['asset'] for u in utxos) == sorted(a for a, _ in holdings), utxos
    return name


def fund_fee_wallet(bitcoind, name, asset, amount):
    """Send `amount` units of `asset` to the fee wallet `name`, paying the fee
    in the asset itself; returns the txid (unconfirmed)."""
    addr = cli(bitcoind, '-rpcwallet=' + name, 'getnewaddress', '', 'bech32')
    return cli(bitcoind, '-rpcwallet=lightningd-tests', '-named', 'sendtoaddress',
               'address=' + addr, 'amount={}'.format(amount), 'assetlabel=' + asset,
               'fee_asset_label=' + bitcoind.POLICY_ASSET)


def db_query(node, query):
    """Read the live database.  It runs in WAL mode, so a copy of the main
    file alone (what the harness's db_query reads) misses recent writes."""
    path = os.path.join(node.daemon.lightning_dir, TEST_NETWORK, 'lightningd.sqlite3')
    db = sqlite3.connect('file:{}?mode=ro'.format(path), uri=True)
    try:
        return db.execute(query).fetchall()
    finally:
        db.close()


def fund_asset(bitcoind, node, asset, atoms):
    addr = node.rpc.newaddr('bech32')['bech32']
    txid = bitcoind.send_and_mine_block(addr, atoms, asset)
    wait_for(lambda: any(o['txid'] == txid for o in node.rpc.listfunds()['outputs']))


def asset_channel(node_factory, bitcoind, rate, atoms, opts):
    """l1 opens an announced channel of `atoms` of a fresh asset priced at
    `rate` to l2.  `opts` are the two nodes' options."""
    asset = bitcoind.issue_asset(1000)
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, asset: rate})
    l1, l2 = node_factory.get_nodes(2, opts=opts)
    fund_asset(bitcoind, l1, asset, 2 * atoms)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    res = l1.rpc.call('fundchannel', {'id': l2.info['id'], 'amount': atoms,
                                      'asset': asset, 'announce': True})
    bitcoind.generate_block(1, wait_for_mempool=res['txid'])
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: channel(a, b)['state'] == 'CHANNELD_NORMAL')
    return l1, l2, asset


def channel(node, peer):
    return only_one(node.rpc.listpeerchannels(peer.info['id'])['channels'])


def unhold(node):
    open(os.path.join(node.daemon.lightning_dir, TEST_NETWORK, 'unhold'), 'w').close()


def fee_atoms(dec, asset):
    fee = only_one([o for o in dec['vout'] if o['scriptPubKey']['type'] == 'fee'])
    assert fee['asset'] == asset
    return int(Decimal(fee['value']) * PAR)


def spenders(bitcoind, txids, txid):
    """{vout: (spending tx decoded, input index)} for the outputs of `txid`
    spent by the transactions `txids`."""
    found = {}
    for t in txids:
        dec = bitcoind.rpc.getrawtransaction(t, True)
        for i, vin in enumerate(dec['vin']):
            if vin.get('txid') == txid:
                found[vin['vout']] = (dec, i)
    return found


def breach(node_factory, bitcoind, executor, directory, rate, victim_offers,
           tower_phase=None):
    """l1 cheats l2 on a channel in an asset priced at `rate`: it broadcasts
    a commitment, revoked since, that carries a pending HTLC (offered by l2
    when `victim_offers`, by l1 otherwise) while l2 is down.  speculad, for
    l2, must sweep every output of it but l2's own to l2.  `tower_phase`,
    when given, is called as tower_phase(bitcoind, asset) once the revoked
    commitment is mined, and returns the tower's fee wallet and a function
    run once the tower has started (or None).  Returns the nodes, the
    asset, the revoked commitment, the justice transactions decoded, and
    the tower's log."""
    hold = {'plugin': HOLD_PLUGIN}
    # The dust-exposure limit is a number of atoms of the channel asset, and
    # its default leaves no room for an HTLC on a channel whose feerate in
    # atoms is high (the cheap asset).
    dust = {'max-dust-htlc-exposure-msat': 10**12}
    victim = {'watchtower-store': 'on', **dust}
    cheater = {**dust, 'may_fail': True,
               'broken_log': r'onchaind-chan#[0-9]*: Could not find resolution for output .*: did \*we\* cheat\?'}
    if victim_offers:
        opts = [{**cheater, **hold}, victim]
    else:
        opts = [cheater, {**victim, **hold}]
    l1, l2, asset = asset_channel(node_factory, bitcoind, rate, 10**8, opts)

    amount_msat = 2 * 10**6 * 1000
    if victim_offers:
        # l2 needs a balance to offer from: a payment l1 -> l2 settles in full.
        inv = l2.rpc.invoice(2 * amount_msat, 'fund-l2', 'fund l2')['bolt11']
        l1.rpc.pay(inv)
        payer, payee = l2, l1
    else:
        payer, payee = l1, l2

    inv = payee.rpc.invoice(amount_msat, 'held', 'held')['bolt11']
    paying = executor.submit(payer.rpc.pay, inv)
    # The HTLC is irrevocably committed on both sides once the payee's hook
    # holds it: l1's current commitment carries it.
    want = 'RCVD_ADD_ACK_REVOCATION' if victim_offers else 'SENT_ADD_ACK_REVOCATION'
    wait_for(lambda: [h['state'] for h in channel(l1, l2)['htlcs']] == [want])
    payee.daemon.wait_for_log('Calling invoice_payment hook')

    snapshot = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']
    revoked = bitcoind.rpc.decoderawtransaction(snapshot)
    revoked_txid = revoked['txid']
    htlc_outs = [o['n'] for o in revoked['vout']
                 if o['scriptPubKey']['type'] == 'witness_v0_scripthash'
                 and Decimal(o['value']) * PAR == amount_msat // 1000]
    assert len(htlc_outs) == 1, revoked['vout']

    # Settle it: both sides move on and l1 revokes the snapshot.
    unhold(payee)
    paying.result(TIMEOUT)
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: channel(a, b)['htlcs'] == [])

    store = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'watchtower')
    wait_for(lambda: any(os.path.exists(os.path.join(store, d, 'justice', revoked_txid))
                         for d in os.listdir(store)))
    victim_addrs = set(a.get('bech32') for a in l2.rpc.call('listaddresses')['addresses'])

    # The victim goes down; the cheater broadcasts and goes down too.
    l2.stop()
    l1.stop()
    bitcoind.rpc.sendrawtransaction(snapshot)
    bitcoind.generate_block(1, wait_for_mempool=revoked_txid)

    if tower_phase:
        wallet, started = tower_phase(bitcoind, asset)
    else:
        wallet, started = fee_wallet(bitcoind, asset), None
    tower = Speculad(l2, bitcoind, wallet, directory)
    tower.start()
    try:
        if started:
            started(tower)
        outs = {o['n']: o for o in revoked['vout']}
        # Every output l1 could claim is revocable: P2WSH, to_local and HTLCs.
        targets = [n for n, o in outs.items()
                   if o['scriptPubKey']['type'] == 'witness_v0_scripthash']
        assert set(htlc_outs) <= set(targets)
        # Every target is spent by a transaction in one view of the mempool:
        # transactions that replace one another do not count twice.
        deadline = time.time() + TIMEOUT
        while True:
            pending = spenders(bitcoind, bitcoind.rpc.getrawmempool(), revoked_txid)
            if set(targets) <= set(pending) or time.time() > deadline:
                break
            time.sleep(1)
        print(tower.output())
        unpunished = sorted(set(targets) - set(pending))
        assert unpunished == [], ("outputs {} of the revoked commitment went "
                                  "unpunished (HTLC outputs: {})"
                                  .format(unpunished, htlc_outs))
        block = bitcoind.generate_block(1)[0]
    finally:
        tower.stop()

    mined = spenders(bitcoind, bitcoind.rpc.getblock(block)['tx'], revoked_txid)
    assert set(mined) == set(targets), (mined.keys(), targets)
    for n, (j, i) in mined.items():
        sweep = j['vout'][i]
        assert sweep['asset'] == asset
        assert sweep['scriptPubKey']['address'] in victim_addrs
        assert int(Decimal(sweep['value']) * PAR) == int(Decimal(outs[n]['value']) * PAR)
    justice = {j['txid']: j for j, _ in mined.values()}
    # The victim's own output was always the victim's.
    others = [n for n, o in outs.items()
              if n not in targets and o['scriptPubKey']['type'] != 'fee']
    for n in others:
        assert outs[n]['scriptPubKey']['type'] == 'witness_v0_keyhash'
    return l1, l2, asset, revoked, list(justice.values()), tower.output()


@pytest.mark.parametrize('rate', [PAR, CHEAP, DEAR], ids=['par', 'cheap', 'dear'])
@pytest.mark.parametrize('victim_offers', [False, True], ids=['cheater-offered', 'victim-offered'])
def test_watchtower_sweeps_asset_breach(node_factory, bitcoind, executor,
                                        directory, rate, victim_offers):
    """A breach with a pending HTLC on an asset channel, the victim offline:
    the tower sweeps the cheater's balance and the HTLC to the victim, in the
    asset, paying a fee that is worth at least the relay minimum."""
    l1, l2, asset, revoked, justice, _ = breach(node_factory, bitcoind, executor,
                                                directory, rate, victim_offers)
    for j in justice:
        atoms = fee_atoms(j, asset)
        value = atoms * rate / PAR
        floor = MIN_RELAY_PER_KVB * j['vsize'] / 1000
        print("justice {}: {} vB, fee {} atoms = {} reference atoms, relay floor {}"
              .format(j['txid'], j['vsize'], atoms, value, floor))
        assert value >= floor


@pytest.mark.parametrize('victim_offers', [False, True], ids=['cheater-offered', 'victim-offered'])
def test_watchtower_fee_in_another_asset(node_factory, bitcoind, executor,
                                         directory, victim_offers):
    """The channel's asset is delisted between the breach and the tower's
    answer.  The tower holds that asset, a small coin of the policy asset and
    a large coin of another accepted asset: it pays the justice fee from the
    accepted asset whose largest coin covers the most fees, the other asset
    here, never preferring the policy asset, and says so; every output is
    still swept to the victim in the channel asset."""
    other = bitcoind.issue_asset(1000)
    # One atom of OTHER is worth ten reference atoms.
    other_rate = 10**9

    def tower_phase(bitcoind, asset):
        bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, other: other_rate})
        return fee_wallet(bitcoind, asset, [(asset, 1),
                                            (bitcoind.POLICY_ASSET, Decimal('0.01')),
                                            (other, 1)]), None

    l1, l2, asset, revoked, justice, log = breach(node_factory, bitcoind, executor,
                                                  directory, DEAR, victim_offers,
                                                  tower_phase)
    assert asset not in json.dumps(bitcoind.rpc.getfeeexchangerates())
    for j in justice:
        fee = only_one([o for o in j['vout'] if o['scriptPubKey']['type'] == 'fee'])
        atoms = int(Decimal(fee['value']) * PAR)
        value = atoms * other_rate / PAR
        floor = MIN_RELAY_PER_KVB * j['vsize'] / 1000
        print("justice {}: {} vB, fee {} atoms of {} = {} reference atoms, relay floor {}"
              .format(j['txid'], j['vsize'], atoms, fee['asset'], value, floor))
        assert fee['asset'] == other
        assert value >= floor
    assert 'fee {} atoms of asset {}, the channel asset is not accepted for fees by this node'.format(
        atoms, other) in log


def test_watchtower_fee_coin_missing_then_funded(node_factory, bitcoind, executor,
                                                 directory):
    """A tower holding no coin of an asset the node accepts says so, and
    funds the justice once it holds one."""
    other = bitcoind.issue_asset(1000)

    def tower_phase(bitcoind, asset):
        bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, other: PAR})
        name = fee_wallet(bitcoind, asset)

        def started(tower):
            wait_for(lambda: 'the fee wallet holds no coin in an asset this node '
                     'accepts for fees, nor is the channel asset accepted (it holds: '
                     '100000000 atoms of {}); trying again every round'.format(asset)
                     in tower.output())
            # No justice goes out meanwhile.
            assert bitcoind.rpc.getrawmempool() == []
            txid = fund_fee_wallet(bitcoind, name, other, 1)
            bitcoind.generate_block(1, wait_for_mempool=txid)
        return name, started

    l1, l2, asset, revoked, justice, log = breach(node_factory, bitcoind, executor,
                                                  directory, CHEAP, False,
                                                  tower_phase)
    for j in justice:
        fee = only_one([o for o in j['vout'] if o['scriptPubKey']['type'] == 'fee'])
        assert fee['asset'] == other
    assert log.count('trying again every round') == 1


def test_watchtower_store_bounded(node_factory, bitcoind, directory):
    """Many payments over an asset channel.  The store keeps one justice file
    of fixed size per revoked commitment, the tower's work per round does not
    grow with them while the channel is open, the node keeps no penalty base
    it has used, and the channel's store is gone once the node forgets the
    closed channel."""
    dust = {'max-dust-htlc-exposure-msat': 10**12}
    opts = {'watchtower-store': 'on', **dust}
    l1, l2, asset = asset_channel(node_factory, bitcoind, DEAR, 10**8, [opts, opts])
    dbid = only_one(db_query(l2, "SELECT id FROM channels"))[0]
    store = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'watchtower', str(dbid))
    justice = os.path.join(store, 'justice')

    payments = 40
    for i in range(payments):
        inv = l2.rpc.invoice(10**6 * 1000, 'p{}'.format(i), 'p')['bolt11']
        l1.rpc.pay(inv)
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: channel(a, b)['htlcs'] == [])

    files = os.listdir(justice)
    sizes = sorted(os.path.getsize(os.path.join(justice, f)) for f in files)
    print("{} payments: {} justice files, sizes {}..{} bytes, {} bytes in all"
          .format(payments, len(files), sizes[0], sizes[-1], sum(sizes)))
    # One file per commitment l1 revoked, two per payment.  Its size is fixed
    # by what that commitment held: one blob for l1's balance and two per
    # HTLC (its output, and the output of l1's second-stage transaction for
    # it; none or one HTLC here), never by how many states came before it.
    assert len(files) == 2 * payments
    assert sizes[-1] < 4 * sizes[0]

    # Used penalty bases are dropped: what is left is the commitments the
    # peer has not revoked yet.
    for n in (l1, l2):
        rows = db_query(n, "SELECT COUNT(*) FROM penalty_bases")[0][0]
        print("{}: {} penalty bases".format(n.daemon.prefix, rows))
        assert rows <= 2

    # The tower's work per round while the channel is open: one look at the
    # funding output, never one per revoked commitment.
    tower = Speculad(l2, bitcoind, 'none', directory)
    tower.cmd = [c for c in tower.cmd if not c.startswith('--fee-wallet')]
    tower.start()
    try:
        wait_for(lambda: tower.calls_made().count('getbestblockhash') >= 5)
    finally:
        tower.stop()
    calls = tower.calls_made()
    rounds = calls.count('getbestblockhash')
    print("tower: {} calls in {} rounds: {}".format(
        len(calls), rounds, {m: calls.count(m) for m in set(calls)}))
    assert calls.count('getrawtransaction') == 0
    assert len(calls) <= 8 * rounds

    # Close; once the node forgets the channel, its store is gone.
    l1.rpc.close(l2.info['id'])
    bitcoind.generate_block(1, wait_for_mempool=1)
    for n in (l1, l2):
        wait_for(lambda: channel(n, l2 if n == l1 else l1)['state'] == 'ONCHAIN')
    assert os.path.isdir(store)
    bitcoind.generate_block(100)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'] == [])
    assert not os.path.exists(store)


def sqlite_backup(node, dest):
    """A consistent copy of `node`'s live database (it runs in WAL mode)."""
    path = os.path.join(node.daemon.lightning_dir, TEST_NETWORK, 'lightningd.sqlite3')
    src = sqlite3.connect('file:{}?mode=ro'.format(path), uri=True)
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()


def sqlite_restore(node, backup):
    netdir = os.path.join(node.daemon.lightning_dir, TEST_NETWORK)
    for suffix in ('-wal', '-shm'):
        if os.path.exists(os.path.join(netdir, 'lightningd.sqlite3' + suffix)):
            os.unlink(os.path.join(netdir, 'lightningd.sqlite3' + suffix))
    with open(backup, 'rb') as f, open(os.path.join(netdir, 'lightningd.sqlite3'), 'wb') as t:
        t.write(f.read())


@pytest.mark.parametrize('second_stage', ['htlc-success', 'htlc-timeout'])
def test_watchtower_punishes_second_stage_in_delisted_asset(node_factory, bitcoind,
                                                            executor, directory,
                                                            second_stage):
    """The cheater broadcasts a revoked commitment carrying an HTLC and wins
    the race for the HTLC output with its own second-stage transaction
    (HTLC-success for an HTLC it received, HTLC-timeout for one it offered),
    which the victim signed for that commitment.  Then the node delists the
    channel's asset.  The tower, the victim offline, sweeps the cheater's
    balance and the output of that second-stage transaction to the victim,
    in the channel asset, paying the fee in another asset it holds."""
    other = bitcoind.issue_asset(1000)
    other_rate = 10**9
    success = second_stage == 'htlc-success'
    hold = {'plugin': HOLD_PLUGIN}
    dust = {'max-dust-htlc-exposure-msat': 10**12}
    victim = {'watchtower-store': 'on', **dust, 'may_reconnect': True}
    cheater = {**dust, 'may_fail': True, 'may_reconnect': True,
               'broken_log': '.*'}
    if success:
        # The cheater learns the preimage of the HTLC it receives, and stops
        # before telling the victim: its commitment still carries the HTLC.
        cheater['disconnect'] = ['-WIRE_UPDATE_FULFILL_HTLC']
        opts = [cheater, victim]
    else:
        opts = [cheater, {**victim, **hold}]
    l1, l2, asset = asset_channel(node_factory, bitcoind, DEAR, 10**8, opts)

    amount_msat = 2 * 10**6 * 1000
    if success:
        inv = l2.rpc.invoice(2 * amount_msat, 'fund-l2', 'fund l2')['bolt11']
        l1.rpc.pay(inv)
        inv = l1.rpc.invoice(amount_msat, 'held', 'held')['bolt11']
        paying = executor.submit(l2.rpc.pay, inv)
        l1.daemon.wait_for_log('dev_disconnect: -WIRE_UPDATE_FULFILL_HTLC')
        assert [h['direction'] for h in channel(l1, l2)['htlcs']] == ['in']
    else:
        inv = l2.rpc.invoice(amount_msat, 'held', 'held')['bolt11']
        paying = executor.submit(l1.rpc.pay, inv)
        wait_for(lambda: [h['state'] for h in channel(l1, l2)['htlcs']]
                 == ['SENT_ADD_ACK_REVOCATION'])
        l2.daemon.wait_for_log('Calling invoice_payment hook')

    # The cheater keeps a copy of this state.
    backup = os.path.join(directory, 'cheater.sqlite3')
    sqlite_backup(l1, backup)

    # Both sides move on, and the cheater revokes the state it kept.
    if success:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    else:
        unhold(l2)
    paying.result(TIMEOUT)
    for a, b in ((l1, l2), (l2, l1)):
        wait_for(lambda: channel(a, b)['htlcs'] == [])
    inv = l2.rpc.invoice(10**6, 'move-on', 'move on')['bolt11']
    l1.rpc.pay(inv)
    victim_addrs = set(a.get('bech32') for a in l2.rpc.call('listaddresses')['addresses'])
    store = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'watchtower')

    # The victim goes down.  The cheater comes back on the state it kept and
    # closes the channel with it.
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

    # Its second-stage transaction for the HTLC output.
    if success:
        rawtx, stage2_txid, blocks = l1.wait_for_onchaind_tx(
            'OUR_HTLC_SUCCESS_TX', 'OUR_UNILATERAL/THEIR_HTLC')
    else:
        rawtx, stage2_txid, blocks = l1.wait_for_onchaind_tx(
            'OUR_HTLC_TIMEOUT_TX', 'OUR_UNILATERAL/OUR_HTLC')
    l1.stop()
    if blocks > 0:
        bitcoind.generate_block(blocks)
    bitcoind.rpc.sendrawtransaction(rawtx)
    bitcoind.generate_block(1, wait_for_mempool=stage2_txid)
    stage2 = bitcoind.rpc.getrawtransaction(stage2_txid, True)
    htlc_out = only_one(stage2['vin'])['vout']
    assert only_one(stage2['vin'])['txid'] == revoked_txid
    print("{}: {} spends HTLC output {} of the revoked commitment {}"
          .format(second_stage, stage2_txid, htlc_out, revoked_txid))

    # The node no longer accepts the channel's asset for fees.
    bitcoind.set_fee_rates({bitcoind.POLICY_ASSET: PAR, other: other_rate})
    wallet = fee_wallet(bitcoind, asset, [(asset, 1), (other, 1)])

    outs = {o['n']: o for o in revoked['vout']}
    targets = [(revoked_txid, n) for n, o in outs.items()
               if o['scriptPubKey']['type'] == 'witness_v0_scripthash' and n != htlc_out]
    targets.append((stage2_txid, 0))
    values = {(revoked_txid, n): outs[n]['value'] for n in outs}
    values[(stage2_txid, 0)] = stage2['vout'][0]['value']

    def punished(txids):
        found = {}
        for t in txids:
            try:
                dec = bitcoind.rpc.getrawtransaction(t, True)
            except Exception:
                continue        # replaced since the mempool was listed
            for i, vin in enumerate(dec.get('vin', [])):
                key = (vin.get('txid'), vin.get('vout'))
                if key in targets:
                    found[key] = (dec, i)
        return found

    tower = Speculad(l2, bitcoind, wallet, directory)
    tower.start()
    try:
        deadline = time.time() + TIMEOUT
        while True:
            pending = punished(bitcoind.rpc.getrawmempool())
            if set(targets) <= set(pending) or time.time() > deadline:
                break
            time.sleep(1)
        print(tower.output())
        unpunished = sorted(set(targets) - set(pending))
        assert unpunished == [], "unpunished: {}".format(unpunished)
        block = bitcoind.generate_block(1)[0]
    finally:
        tower.stop()

    mined = punished(bitcoind.rpc.getblock(block)['tx'])
    assert set(mined) == set(targets), (mined.keys(), targets)
    for key, (j, i) in mined.items():
        sweep = j['vout'][i]
        assert sweep['asset'] == asset
        assert sweep['scriptPubKey']['address'] in victim_addrs
        assert Decimal(sweep['value']) == Decimal(values[key])
        fee = only_one([o for o in j['vout'] if o['scriptPubKey']['type'] == 'fee'])
        assert fee['asset'] == other
    for j in {j['txid']: j for j, _ in mined.values()}.values():
        fee = only_one([o for o in j['vout'] if o['scriptPubKey']['type'] == 'fee'])
        atoms = int(Decimal(fee['value']) * PAR)
        print("justice {}: {} vB, spends {}, fee {} atoms of {} = {} reference atoms"
              .format(j['txid'], j['vsize'],
                      [(v['txid'][:8], v['vout']) for v in j['vin']],
                      atoms, fee['asset'], atoms * other_rate / PAR))
        assert atoms * other_rate / PAR >= MIN_RELAY_PER_KVB * j['vsize'] / 1000
