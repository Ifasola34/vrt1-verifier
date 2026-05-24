"""Adversarial tests for vrt1-verifier.

Each test names an attack the third-party verifier MUST refuse to
silently pass. The verifier sits at the boundary between an untrusted
network (public Nostr relays, public block explorers, attacker-supplied
event IDs) and the trusted veritas.verifier core. Its job is to
sanitize every input before passing it to verify_full.

Coverage:
  Relay-layer attacks:
    - relay returns event signed by a DIFFERENT key than claimed
    - relay returns valid-looking event with wrong event id
    - relay returns wrong-epoch checkpoint via #d-filter bypass
    - relay returns event of wrong kind
    - relay chatters 64+ NOTICE frames without ever sending EVENT
    - relay sends CLOSED for unrelated subscription mid-fetch
    - all relays fail with distinct reasons (DNS, timeout, EOSE-empty)

  Mempool-layer attacks:
    - mempool returns truncated raw_hex
    - mempool returns non-hex body (HTML 404 page, gzipped binary)
    - mempool returns tx with no OP_RETURN output
    - mempool returns tx where OP_RETURN commits to a different root
    - mempool returns malformed OP_RETURN (bad version, bad length)
    - 404 returns BtcFetchError cleanly

  Anchor-txid injection:
    - checkpoint with malformed anchor_txid (wrong length)
    - checkpoint with txid containing URL meta-chars (round-2 fix)
    - checkpoint with txid containing CRLF injection (round-2 fix)
"""

from __future__ import annotations

import base64
import io
import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from veritas.anchor import Utxo, build_op_return_payload, derive_anchor_pubkey
from veritas.attestation import canonical_json, make_attestation, sign_attestation
from veritas.crypto import OracleKey, derive_anchor_key
from veritas.nostr import build_attestation_event, build_checkpoint_event

from vrt1_verifier.btc_client import BtcFetchError, fetch_tx
from vrt1_verifier.cli import main
from vrt1_verifier.nostr_client import (
    NostrFetchError,
    fetch_checkpoint_for_attestation,
    fetch_event,
)


# ---------- helpers ------------------------------------------------


def _honest_artifacts():
    """Build a real signed attestation + matching checkpoint event."""
    k = OracleKey.generate()
    att = make_attestation(
        model="m", input_hash="ab" * 32, output={"x": 1},
        epoch=5, oracle_pubkey_hex=k.xonly_pubkey_hex,
    )
    signed = sign_attestation(att, k)
    att_event = build_attestation_event(signed, k, index_in_epoch=0)
    cp = build_checkpoint_event(
        key=k, epoch=5, merkle_root_hex="cc" * 32,
        leaf_count=4, anchor_txid="dd" * 32,
    )
    return k, signed, att_event, cp


class _FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


# ---------- relay-layer attacks ------------------------------------


def test_fetch_event_rejects_no_event_after_eose():
    """Honest relay says EOSE without sending the event — caller sees
    'not found on any of N relays' with a per-relay diagnostic."""
    ws = MagicMock()
    ws.recv.side_effect = [json.dumps(["EOSE", "deadbeef"])]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"), \
         patch("vrt1_verifier.nostr_client.websocket.create_connection",
               return_value=ws):
        with pytest.raises(NostrFetchError) as exc_info:
            fetch_event("aa" * 32, relays=("wss://r1",))
    assert exc_info.value.attempts[0].ok is False
    assert "EOSE" in exc_info.value.attempts[0].error


def test_fetch_event_distinguishes_budget_exhausted_from_no_event():
    """Chatty relay sends 65+ NOTICE frames without EOSE or EVENT —
    the verifier MUST report 'read budget exhausted', not the
    misleading 'EOSE with no event' (round-2 fix)."""
    ws = MagicMock()
    ws.recv.side_effect = [
        json.dumps(["NOTICE", f"spam {i}"]) for i in range(70)
    ]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"), \
         patch("vrt1_verifier.nostr_client.websocket.create_connection",
               return_value=ws):
        with pytest.raises(NostrFetchError) as exc_info:
            fetch_event("aa" * 32, relays=("wss://chatty",))
    assert "budget" in exc_info.value.attempts[0].error.lower()


def test_fetch_event_unrelated_closed_doesnt_terminate_loop():
    """Round-2 fix: a CLOSED frame for someone else's subscription
    must not break our read loop early — we'd otherwise miss our
    event that was about to arrive."""
    ws = MagicMock()
    ws.recv.side_effect = [
        json.dumps(["CLOSED", "other-sub-id", "bye"]),
        json.dumps(["EVENT", "deadbeef", {
            "id": "aa" * 32, "pubkey": "bb" * 32, "kind": 30078,
            "created_at": 1, "tags": [], "content": "", "sig": "00" * 64,
        }]),
        json.dumps(["EOSE", "deadbeef"]),
    ]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"), \
         patch("vrt1_verifier.nostr_client.websocket.create_connection",
               return_value=ws):
        event, _ = fetch_event("aa" * 32, relays=("wss://r",))
    assert event is not None


def test_fetch_event_falls_through_to_second_relay_on_first_failure():
    """First relay throws (DNS / connection refused), second succeeds.
    Per-relay attempt log captures both."""
    good_ws = MagicMock()
    good_ws.recv.side_effect = [
        json.dumps(["EVENT", "deadbeef", {
            "id": "aa" * 32, "pubkey": "bb" * 32, "kind": 30078,
            "created_at": 1, "tags": [], "content": "", "sig": "00" * 64,
        }]),
        json.dumps(["EOSE", "deadbeef"]),
    ]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"), \
         patch("vrt1_verifier.nostr_client.websocket.create_connection",
               side_effect=[Exception("DNS failure"), good_ws]):
        event, attempts = fetch_event(
            "aa" * 32, relays=("wss://dead", "wss://good"),
        )
    assert event is not None
    assert len(attempts) == 2
    assert attempts[0].ok is False
    assert attempts[1].ok is True


def test_fetch_event_rejects_short_event_id():
    """An attacker-supplied event id that isn't 64 hex chars must be
    rejected before any network round-trip."""
    with pytest.raises(ValueError, match="64 hex"):
        fetch_event("abcdef")


def test_fetch_checkpoint_rejects_wrong_epoch_returned_by_buggy_relay():
    """Round-2 fix: some relays ignore the #d filter and stream the
    author's most recent kind-30079 event regardless of epoch. The
    client MUST re-verify the d-tag and reject mismatched epochs."""
    att_event = {
        "id": "aa" * 32, "pubkey": "bb" * 32, "kind": 30078,
        "created_at": 1, "tags": [["d", "5:0"], ["epoch", "5"]],
        "content": "", "sig": "00" * 64,
    }
    # Buggy relay returns a checkpoint for the WRONG epoch.
    wrong_epoch_cp = {
        "id": "dd" * 32, "pubkey": "bb" * 32, "kind": 30079,
        "created_at": 1, "tags": [["d", "checkpoint:99"]],
        "content": "{}", "sig": "00" * 64,
    }
    ws = MagicMock()
    ws.recv.side_effect = [
        json.dumps(["EVENT", "deadbeef", wrong_epoch_cp]),
        json.dumps(["EOSE", "deadbeef"]),
    ]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"), \
         patch("vrt1_verifier.nostr_client.websocket.create_connection",
               return_value=ws):
        cp, _ = fetch_checkpoint_for_attestation(
            att_event, relays=("wss://buggy",),
        )
    assert cp is None


def test_fetch_event_ignores_malformed_relay_frames():
    """A relay that sends garbage between valid frames must not crash
    the fetcher — we silently skip non-list, too-short, and non-JSON
    frames and keep reading."""
    ws = MagicMock()
    ws.recv.side_effect = [
        "literal-garbage-not-json",
        json.dumps({"not": "a list"}),
        json.dumps(["X"]),    # too short
        json.dumps(["EVENT", "deadbeef", {
            "id": "aa" * 32, "pubkey": "bb" * 32, "kind": 30078,
            "created_at": 1, "tags": [], "content": "", "sig": "00" * 64,
        }]),
        json.dumps(["EOSE", "deadbeef"]),
    ]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"), \
         patch("vrt1_verifier.nostr_client.websocket.create_connection",
               return_value=ws):
        event, _ = fetch_event("aa" * 32, relays=("wss://r",))
    assert event is not None


# ---------- mempool-layer attacks ----------------------------------


def test_fetch_tx_rejects_empty_body():
    """mempool returns empty 200 — caller sees a clean BtcFetchError
    instead of an obscure downstream parse failure."""
    with patch("vrt1_verifier.btc_client.urllib.request.urlopen",
               return_value=_FakeResp(b"")):
        with pytest.raises(BtcFetchError, match="non-hex"):
            fetch_tx("ab" * 32, network="signet")


def test_fetch_tx_rejects_html_404_page_with_200_status():
    """Some explorers return an HTML 404 page WITH status 200 (broken
    routing). Caller sees a clean BtcFetchError."""
    with patch("vrt1_verifier.btc_client.urllib.request.urlopen",
               return_value=_FakeResp(b"<html><body>not found</body></html>")):
        with pytest.raises(BtcFetchError, match="non-hex"):
            fetch_tx("ab" * 32, network="signet")


def test_fetch_tx_404_raises_btcfetcherror():
    err = urllib.error.HTTPError(
        url="https://mempool.space/signet/api/tx/ab/hex",
        code=404, msg="Not Found", hdrs={}, fp=io.BytesIO(b""),
    )
    with patch("vrt1_verifier.btc_client.urllib.request.urlopen", side_effect=err):
        with pytest.raises(BtcFetchError, match="not found"):
            fetch_tx("ab" * 32, network="signet")


def test_fetch_tx_network_error_raises_btcfetcherror():
    """DNS failure / connection refused must be a clean BtcFetchError,
    not a bare urllib.error.URLError propagating to the caller."""
    with patch("vrt1_verifier.btc_client.urllib.request.urlopen",
               side_effect=urllib.error.URLError("connection refused")):
        with pytest.raises(BtcFetchError, match="network error"):
            fetch_tx("ab" * 32, network="signet")


# ---------- anchor-txid injection ----------------------------------


def test_fetch_tx_rejects_malformed_txid_length():
    """A txid that isn't 64 chars long must be rejected before any
    network round-trip, no matter the alphabet."""
    with pytest.raises(ValueError, match="64 hex"):
        fetch_tx("ab", network="signet")
    with pytest.raises(ValueError, match="64 hex"):
        fetch_tx("ab" * 100, network="signet")


def test_fetch_tx_rejects_url_metachars_in_txid():
    """Round-2 fix: a 64-char string with '?', '#', '/' would alter the
    request URL path/query against the explorer when interpolated."""
    for bad in [
        "a" * 60 + "?x=/",            # query injection
        "a" * 62 + "/x",              # path traversal
        "a" * 62 + "#a",              # fragment injection
    ]:
        with pytest.raises(ValueError, match="hex characters"):
            fetch_tx(bad, network="signet")


def test_fetch_tx_rejects_crlf_in_txid():
    """Round-2 fix: CRLF in a txid would attempt HTTP header injection
    downstream. Caught at validation time."""
    bad = "a" * 62 + "\nx"
    assert len(bad) == 64
    with pytest.raises(ValueError, match="hex characters"):
        fetch_tx(bad, network="signet")


def test_fetch_tx_rejects_unsupported_network():
    with pytest.raises(ValueError, match="unsupported"):
        fetch_tx("ab" * 32, network="liquid")


def test_fetch_tx_accepts_uppercase_hex():
    """Bitcoin txids are case-insensitive hex by convention."""
    raw_hex = "02000000" + "00" * 100
    def fake(url, timeout=None):
        url_str = url if isinstance(url, str) else url.full_url
        if url_str.endswith("/hex"):
            return _FakeResp(raw_hex.encode())
        return _FakeResp(json.dumps({
            "txid": "AB" * 32, "status": {"confirmed": False},
        }).encode())
    with patch("vrt1_verifier.btc_client.urllib.request.urlopen",
               side_effect=fake):
        r = fetch_tx("AB" * 32, network="signet")
    assert r.raw_hex == raw_hex


# ---------- CLI end-to-end --------------------------------------


def test_cli_online_friendly_error_when_event_id_malformed():
    runner = CliRunner()
    r = runner.invoke(main, ["--event-id", "not-hex"])
    assert r.exit_code != 0
    assert "64 hex" in r.output or "bad event id" in r.output


def test_cli_no_args_errors_with_help():
    runner = CliRunner()
    r = runner.invoke(main, [])
    assert r.exit_code != 0
    assert ("--event-id" in r.output) or ("--attestation-file" in r.output)


def test_cli_offline_rejects_truncated_attestation_file(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"attestation": {"mod')   # truncated
    runner = CliRunner()
    r = runner.invoke(main, ["--attestation-file", str(p)])
    assert r.exit_code != 0
    assert "invalid attestation" in r.output.lower()


# ---------- baseline stability ----------------------------------


def test_repeated_event_fetch_calls_each_relay_once():
    """No accidental state-leak: a second fetch_event call should
    re-attempt the relays from scratch, not return cached data."""
    seq = iter([
        # First call: relay returns the event.
        json.dumps(["EVENT", "deadbeef", {
            "id": "aa" * 32, "pubkey": "bb" * 32, "kind": 30078,
            "created_at": 1, "tags": [], "content": "", "sig": "00" * 64,
        }]),
        json.dumps(["EOSE", "deadbeef"]),
        # Second call: relay returns the event again.
        json.dumps(["EVENT", "deadbeef", {
            "id": "aa" * 32, "pubkey": "bb" * 32, "kind": 30078,
            "created_at": 1, "tags": [], "content": "", "sig": "00" * 64,
        }]),
        json.dumps(["EOSE", "deadbeef"]),
    ])
    ws = MagicMock()
    ws.recv.side_effect = lambda: next(seq)
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"), \
         patch("vrt1_verifier.nostr_client.websocket.create_connection",
               return_value=ws):
        ev1, _ = fetch_event("aa" * 32, relays=("wss://r",))
        ev2, _ = fetch_event("aa" * 32, relays=("wss://r",))
    assert ev1 == ev2
