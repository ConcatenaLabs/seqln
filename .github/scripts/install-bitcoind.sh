#!/bin/sh
# If an argument is specified, that dir is checked before downloading,
# and updated after successful install.

set -e

export BITCOIN_VERSION=27.1
export ELEMENTS_VERSION=23.2.1
# Sequentia Core, from the testnet's download page, which keeps every release.
export SEQUENTIA_VERSION=25.2.6
SEQUENTIA_SHA256=dc37f5e89c6ed5e54beb486e4518aa90c6608151d66aaa1d65d5d0ea7efff8b3

DIRNAME="bitcoin-${BITCOIN_VERSION}"
EDIRNAME="elements-${ELEMENTS_VERSION}"
FILENAME="${DIRNAME}-x86_64-linux-gnu.tar.gz"
EFILENAME="${EDIRNAME}-x86_64-linux-gnu.tar.gz"

cd /tmp/

# Since we inadvertently broke `elementsd` support in the past we only
# want to download and enable the daemon that is actually going to be
# used when running in CI. Otherwise we could end up accidentally
# testing against `bitcoind` but still believe that we ran against
# `elementsd`.
if [ "$TEST_NETWORK" = "sequentia-regtest" ]; then
    SDIRNAME="sequentia-core-${SEQUENTIA_VERSION}"
    SFILENAME="${SDIRNAME}-linux-x86_64.tar.gz"
    if [ -f "$1/${SFILENAME}" ]; then
	cp "$1/${SFILENAME}" .
    else
	wget "https://sequentiatestnet.com/download/${SFILENAME}"
    fi
    echo "${SEQUENTIA_SHA256}  ${SFILENAME}" | sha256sum -c -
    tar -xf "${SFILENAME}"
    [ "$1" = "" ] || cp "${SFILENAME}" "$1"/
    sudo mv "${SDIRNAME}"/bin/sequentiad "${SDIRNAME}"/bin/sequentia-cli "/usr/local/bin"
    rm -rf "${SFILENAME}" "${SDIRNAME}"
fi

# A Sequentia chain anchors to a Bitcoin Core regtest parent, so it needs
# bitcoind as well.
if [ "$TEST_NETWORK" = "liquid-regtest" ]; then
    if [ -f "$1/${EFILENAME}" ]; then
	cp "$1/${EFILENAME}" .
    else
	wget "https://github.com/ElementsProject/elements/releases/download/elements-${ELEMENTS_VERSION}/${EFILENAME}"
    fi
    tar -xf "${EFILENAME}"
    [ "$1" = "" ] || cp "${EFILENAME}" "$1"/
    sudo mv "${EDIRNAME}"/bin/* "/usr/local/bin"
    rm -rf "${EFILENAME}" "${EDIRNAME}"
else
    if [ -f "$1/${FILENAME}" ]; then
	cp "$1/${FILENAME}" .
    else
	wget "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/${FILENAME}"
    fi
    tar -xf "${FILENAME}"
    [ "$1" = "" ] || cp "${FILENAME}" "$1"/
    sudo mv "${DIRNAME}"/bin/* "/usr/local/bin"
    rm -rf "${FILENAME}" "${DIRNAME}"
fi

