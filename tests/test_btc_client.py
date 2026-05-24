"""Bitcoin client tests — all HTTP mocked."""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

import pytest

from vrt1_verifier.btc_client import BtcFetchError, fetch_tx


class _FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


def test_fetch_tx_validates_network():
    with pytest.raises(ValueError, match="unsupported"):
        fetch_tx("ab" * 32, network="liquid")


def test_fetch_tx_validates_txid_length():
    with pytest.raises(ValueError, match="64 hex"):
        fetch_tx("short", network="signet")


def test_fetch_tx_rejects_non_hex_txid_alphabet():
    """Round-2 fix: a 64-char string that passes the length check but
    contains URL meta-characters ('?', '#', '/') could alter the
    request URL when interpolated."""
    bad = "a" * 60 + "?x=/"   # 64 chars, but not hex
    with pytest.raises(ValueError, match="hex characters"):
        fetch_tx(bad, network="signet")
    # Newline injection variant (also exactly 64 chars).
    bad2 = "a" * 62 + "\nx"
    assert len(bad2) == 64
    with pytest.raises(ValueError, match="hex characters"):
        fetch_tx(bad2, network="signet")


def test_fetch_tx_success_with_confirmation():
    raw_hex = "02000000" + "00" * 100
    meta = {
        "txid": "ab" * 32,
        "status": {"confirmed": True, "block_height": 200001},
    }

    def fake_urlopen(url, timeout=None):
        url_str = url if isinstance(url, str) else url.full_url
        if url_str.endswith("/hex"):
            return _FakeResp(raw_hex.encode())
        return _FakeResp(json.dumps(meta).encode())

    with patch("vrt1_verifier.btc_client.urllib.request.urlopen",
               side_effect=fake_urlopen):
        r = fetch_tx("ab" * 32, network="signet")

    assert r.raw_hex == raw_hex
    assert r.confirmed is True
    assert r.block_height == 200001
    assert r.network == "signet"
    assert "signet" in r.explorer_url
    assert r.txid in r.explorer_url


def test_fetch_tx_404_raises_btcfetcherror():
    err = urllib.error.HTTPError(
        url="https://mempool.space/signet/api/tx/ab/hex",
        code=404, msg="Not Found", hdrs={}, fp=io.BytesIO(b""),
    )
    with patch("vrt1_verifier.btc_client.urllib.request.urlopen", side_effect=err):
        with pytest.raises(BtcFetchError, match="not found"):
            fetch_tx("ab" * 32, network="signet")


def test_fetch_tx_network_error_raises_btcfetcherror():
    with patch("vrt1_verifier.btc_client.urllib.request.urlopen",
               side_effect=urllib.error.URLError("connection refused")):
        with pytest.raises(BtcFetchError, match="network error"):
            fetch_tx("ab" * 32, network="signet")


def test_fetch_tx_non_hex_body_rejected():
    def fake_urlopen(url, timeout=None):
        return _FakeResp(b"<html>404 page</html>")
    with patch("vrt1_verifier.btc_client.urllib.request.urlopen",
               side_effect=fake_urlopen):
        with pytest.raises(BtcFetchError, match="non-hex"):
            fetch_tx("ab" * 32, network="signet")


def test_fetch_tx_meta_failure_is_nonfatal():
    raw_hex = "02000000" + "00" * 100
    call_count = {"n": 0}

    def fake_urlopen(url, timeout=None):
        call_count["n"] += 1
        url_str = url if isinstance(url, str) else url.full_url
        if url_str.endswith("/hex"):
            return _FakeResp(raw_hex.encode())
        raise urllib.error.URLError("meta endpoint flaky")

    with patch("vrt1_verifier.btc_client.urllib.request.urlopen",
               side_effect=fake_urlopen):
        r = fetch_tx("ab" * 32, network="signet")

    # Meta call failed but the raw hex came through; confirmation is None.
    assert r.raw_hex == raw_hex
    assert r.confirmed is None
    assert r.block_height is None
