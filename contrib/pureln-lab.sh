#!/bin/bash
# A local pure-LN swap lab: a Sequentia node on liquid-regtest and two SeqLN
# nodes sharing a GOLD channel and a SILV channel (SILV stands in for the BTC
# leg, as seqdex's xchain live tests do).  ln2 runs the holdinvoice-seq plugin,
# so it can be the maker.  Built to measure what a swap costs end to end with
# nothing else on the wire; the seqdex tests it feeds are
# `go test ./pkg/xchain -run TestPureLN -v` with the env from `env`.
#
#   pureln-lab.sh up      start the chain and both nodes
#   pureln-lab.sh fund    issue GOLD/SILV, fund both nodes, open both channels
#   pureln-lab.sh env     print the env the seqdex xchain live tests want
#   pureln-lab.sh mine N  mine N blocks
#   pureln-lab.sh l1|l2|cli ...   run lightning-cli / sequentia-cli against a node
#   pureln-lab.sh down    stop everything
#   pureln-lab.sh wipe    down and delete the state
#
# Paths, all overridable:
#   LNLAB_DIR      state directory            (default /tmp/seqln-pureln-lab)
#   SEQUENTIA_DIR  a built Sequentia checkout  (default ~/Sequentia)
#   SEQLN_DIR      a built seqln checkout      (default: the one this script is in)
set -euo pipefail
T=${LNLAB_DIR:-/tmp/seqln-pureln-lab}
SEQUENTIA_DIR=${SEQUENTIA_DIR:-$HOME/Sequentia}
SEQLN_DIR=${SEQLN_DIR:-$(cd "$(dirname "$0")/.." && pwd)}
SEQD=$SEQUENTIA_DIR/src/sequentiad
SCLI="$SEQUENTIA_DIR/src/sequentia-cli -chain=liquid-regtest -datadir=$T/seq -rpcport=17300 -rpcuser=seq -rpcpassword=seq"
LND=$SEQLN_DIR/lightningd/lightningd
LCLI=$SEQLN_DIR/cli/lightning-cli
HOLD=$SEQLN_DIR/contrib/holdinvoice-seq/holdinvoice.py
NET=liquid-regtest

l1() { $LCLI --lightning-dir=$T/ln1 --network=$NET "$@"; }
l2() { $LCLI --lightning-dir=$T/ln2 --network=$NET "$@"; }
cli() { $SCLI "$@"; }

node_conf() { # $1=dir $2=port $3=extra
	mkdir -p "$1"
	cat > "$1/config" <<EOF
network=$NET
bitcoin-cli=$SEQUENTIA_DIR/src/sequentia-cli
bitcoin-datadir=$T/seq
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcport=17300
bitcoin-rpcuser=seq
bitcoin-rpcpassword=seq
addr=127.0.0.1:$2
log-level=debug
log-file=$1/log
allow-deprecated-apis=false
developer
dev-fast-gossip
dev-bitcoind-poll=1
funding-confirms=1
force-feerates=5000
min-emergency-msat=1000sat
$3
EOF
}

up() {
	mkdir -p $T/seq
	if ! cli ping >/dev/null 2>&1; then
		$SEQD -chain=$NET -datadir=$T/seq -rpcport=17300 -rpcuser=seq -rpcpassword=seq \
			-validatepegin=0 -con_blocksubsidy=5000000000 -blindedaddresses=0 \
			-con_default_blinded_addresses=0 -txindex=1 -listen=0 -fallbackfee=0.00001 \
			-daemon
		while ! cli ping >/dev/null 2>&1; do sleep 0.3; done
	fi
	cli -named createwallet wallet_name=lab descriptors=false >/dev/null 2>&1 || cli loadwallet lab >/dev/null 2>&1 || true
	if [ "$(cli getblockcount)" -lt 101 ]; then
		cli generatetoaddress 101 "$(cli getnewaddress)" >/dev/null
	fi
	node_conf $T/ln1 27171 ""
	node_conf $T/ln2 27172 "plugin=$HOLD"
	for i in 1 2; do
		if ! $LCLI --lightning-dir=$T/ln$i --network=$NET getinfo >/dev/null 2>&1; then
			setsid -f nohup "$LND" --lightning-dir=$T/ln$i < /dev/null > $T/ln$i/stdout 2>&1
		fi
	done
	for i in 1 2; do
		while ! $LCLI --lightning-dir=$T/ln$i --network=$NET getinfo >/dev/null 2>&1; do sleep 0.3; done
	done
	echo "ln1 $(l1 getinfo | jq -r .id)  ln2 $(l2 getinfo | jq -r .id)"
}

mine() { cli generatetoaddress "${1:-1}" "$(cli getnewaddress)" >/dev/null; }

fund() {
	local policy
	policy=$(cli dumpassetlabels | jq -r .bitcoin)
	if [ ! -f $T/assets ]; then
		local gold silv
		gold=$(cli -named issueasset assetamount=1000 tokenamount=1 blind=false fee_asset=$policy | jq -r .asset)
		silv=$(cli -named issueasset assetamount=1000 tokenamount=1 blind=false fee_asset=$policy | jq -r .asset)
		mine 1
		echo "GOLD=$gold" > $T/assets
		echo "SILV=$silv" >> $T/assets
		echo "POLICY=$policy" >> $T/assets
	fi
	. $T/assets
	# The open fee market values no asset by default; a channel funded in an
	# asset needs that asset accepted for fees.
	cli setfeeexchangerates "{\"$POLICY\":100000000,\"$GOLD\":100000000,\"$SILV\":100000000}" >/dev/null
	for i in 1 2; do
		local a
		a=$($LCLI --lightning-dir=$T/ln$i --network=$NET newaddr bech32 | jq -r .bech32)
		cli -named sendtoaddress address=$a amount=10 assetlabel=bitcoin fee_asset_label=bitcoin >/dev/null
		cli -named sendtoaddress address=$a amount=100 assetlabel=$GOLD fee_asset_label=bitcoin >/dev/null
		cli -named sendtoaddress address=$a amount=100 assetlabel=$SILV fee_asset_label=bitcoin >/dev/null
	done
	mine 2
	sleep 3
	l1 connect "$(l2 getinfo | jq -r .id)" 127.0.0.1 27172 >/dev/null
	local id2 id1
	id2=$(l2 getinfo | jq -r .id); id1=$(l1 getinfo | jq -r .id)
	# GOLD: the maker (ln2) pays the asset in a BUY, so it funds, pushing half.
	l2 -k fundchannel id=$id1 amount=5000000000 asset=$GOLD push_msat=2500000000000 announce=true >/dev/null
	mine 1; sleep 2
	# SILV ("BTC"): the taker (ln1) pays the hold in a BUY, so it funds.
	l1 -k fundchannel id=$id2 amount=5000000000 asset=$SILV push_msat=2500000000000 announce=true >/dev/null
	mine 6; sleep 2
	l1 listpeerchannels | jq -r '.channels[] | [.state, .short_channel_id, .channel_asset // "?", .to_us_msat] | @tsv'
}

env_() {
	. $T/assets
	echo "export SEQLN_TAKER_SOCK=$T/ln1/$NET/lightning-rpc"
	echo "export SEQLN_MAKER_SOCK=$T/ln2/$NET/lightning-rpc"
	echo "export SEQLN_ASSET_ID=$GOLD"
	echo "export SEQLN_BTC_ASSET_ID=$SILV"
}

down() {
	l1 stop >/dev/null 2>&1 || true
	l2 stop >/dev/null 2>&1 || true
	cli stop >/dev/null 2>&1 || true
	sleep 1
}

case "${1:-}" in
up) up ;;
fund) fund ;;
env) env_ ;;
mine) mine "${2:-1}" ;;
down) down ;;
wipe) down; rm -rf $T ;;
l1) shift; l1 "$@" ;;
l2) shift; l2 "$@" ;;
cli) shift; cli "$@" ;;
*) echo "usage: $0 up|fund|env|mine [n]|down|wipe|l1 ...|l2 ...|cli ..."; exit 1 ;;
esac
