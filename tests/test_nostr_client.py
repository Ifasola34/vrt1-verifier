"""Nostr client tests — all WebSocket calls mocked."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from vrt1_verifier.nostr_client import (
    NostrFetchError,
    fetch_checkpoint_for_attestation,
    fetch_event,
)


def _fake_event(event_id: str = "aa" * 32) -> dict:
    return {
        "id": event_id, "pubkey": "bb" * 32, "kind": 30078,
        "created_at": 1700000000, "tags": [["d", "5:0"], ["epoch", "5"]],
        "content": "", "sig": "cc" * 64,
    }


def _ws_returning(messages: list) -> MagicMock:
    """Build a mock WebSocket connection whose .recv() drains the given list."""
    ws = MagicMock()
    ws.recv.side_effect = [json.dumps(m) for m in messages]
    return ws


def test_fetch_event_validates_id_length():
    with pytest.raises(ValueError, match="64 hex"):
        fetch_event("abc")


def test_fetch_event_returns_on_first_success():
    sent = []
    ws = _ws_returning([
        ["EVENT", "IGNORE", _fake_event()],  # wrong sub_id, skipped
        ["EVENT", None, _fake_event()],      # sub_id placeholder, patched below
        ["EOSE", None],
    ])
    # Patch sub_id placeholders to whatever the client generates.
    with patch("vrt1_verifier.nostr_client.websocket.create_connection",
               return_value=ws) as create:
        with patch("vrt1_verifier.nostr_client.secrets.token_hex",
                   return_value="deadbeef"):
            ws.recv.side_effect = [
                json.dumps(["EVENT", "deadbeef", _fake_event()]),
                json.dumps(["EOSE", "deadbeef"]),
            ]
            event, attempts = fetch_event(
                "aa" * 32, relays=("wss://relay.test",),
            )
    assert event["id"] == "aa" * 32
    assert len(attempts) == 1 and attempts[0].ok
    create.assert_called_once_with("wss://relay.test", timeout=6.0)


def test_fetch_event_falls_through_to_second_relay():
    bad_ws = MagicMock()
    bad_ws.recv.side_effect = Exception("connection reset")
    good_ws = MagicMock()
    good_ws.recv.side_effect = [
        json.dumps(["EVENT", "deadbeef", _fake_event()]),
        json.dumps(["EOSE", "deadbeef"]),
    ]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"):
        with patch("vrt1_verifier.nostr_client.websocket.create_connection",
                   side_effect=[Exception("DNS failure"), good_ws]):
            event, attempts = fetch_event(
                "aa" * 32, relays=("wss://dead.relay", "wss://good.relay"),
            )
    assert event is not None
    assert len(attempts) == 2
    assert attempts[0].ok is False and "DNS failure" in attempts[0].error
    assert attempts[1].ok is True


def test_fetch_event_raises_when_all_relays_fail():
    ws = MagicMock()
    ws.recv.side_effect = [json.dumps(["EOSE", "deadbeef"])]  # no EVENT before EOSE
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"):
        with patch("vrt1_verifier.nostr_client.websocket.create_connection",
                   return_value=ws):
            with pytest.raises(NostrFetchError, match="not found on any"):
                fetch_event("aa" * 32, relays=("wss://r1",))


def test_fetch_event_ignores_malformed_relay_frames():
    ws = MagicMock()
    ws.recv.side_effect = [
        "not-json",
        json.dumps({"not": "a list"}),
        json.dumps(["X"]),  # too short
        json.dumps(["EVENT", "deadbeef", _fake_event()]),
        json.dumps(["EOSE", "deadbeef"]),
    ]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"):
        with patch("vrt1_verifier.nostr_client.websocket.create_connection",
                   return_value=ws):
            event, _ = fetch_event("aa" * 32, relays=("wss://r",))
    assert event["id"] == "aa" * 32


def test_fetch_checkpoint_uses_epoch_tag_filter():
    att_event = _fake_event()  # tags include ["epoch","5"]
    ws = MagicMock()
    checkpoint = {
        "id": "dd" * 32, "pubkey": "bb" * 32, "kind": 30079,
        "created_at": 1700000600,
        "tags": [["d", "checkpoint:5"], ["root", "ee" * 32]],
        "content": json.dumps({"epoch": 5, "root": "ee" * 32, "count": 4,
                               "anchor_txid": "ff" * 32}),
        "sig": "11" * 64,
    }
    ws.recv.side_effect = [
        json.dumps(["EVENT", "deadbeef", checkpoint]),
        json.dumps(["EOSE", "deadbeef"]),
    ]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"):
        with patch("vrt1_verifier.nostr_client.websocket.create_connection",
                   return_value=ws):
            cp, attempts = fetch_checkpoint_for_attestation(
                att_event, relays=("wss://r",),
            )
    assert cp is not None and cp["kind"] == 30079
    # The first sent message should be the REQ with #d filter.
    first_send = ws.send.call_args_list[0][0][0]
    req = json.loads(first_send)
    assert req[0] == "REQ"
    assert req[2]["#d"] == ["checkpoint:5"]
    assert req[2]["kinds"] == [30079]
    assert req[2]["authors"] == ["bb" * 32]


def test_fetch_checkpoint_returns_none_when_no_match():
    att_event = _fake_event()
    ws = MagicMock()
    ws.recv.side_effect = [json.dumps(["EOSE", "deadbeef"])]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"):
        with patch("vrt1_verifier.nostr_client.websocket.create_connection",
                   return_value=ws):
            cp, attempts = fetch_checkpoint_for_attestation(
                att_event, relays=("wss://r",),
            )
    assert cp is None
    assert len(attempts) == 1 and not attempts[0].ok
