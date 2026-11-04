"""Shared set-up for the Sequentia tests.

These tests check how SeqLN behaves on a Sequentia network as it is really
run, so their nodes keep the network's own timelock defaults (final CLTV,
per-hop delta, to_self_delay) instead of the short test values the rest of
the suite uses on every chain.
"""
import pytest
import pyln.testing.utils


@pytest.fixture(autouse=True)
def sequentia_network_defaults(monkeypatch):
    monkeypatch.setattr(pyln.testing.utils, 'SEQUENTIA_NETWORK_DEFAULTS', True)
