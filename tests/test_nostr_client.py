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
            with pytest.raises(NostrFetchError, match="not found on any") as exc_info:
                fetch_event("aa" * 32, relays=("wss://r1",))
    # Round-2 fix: NostrFetchError carries per-relay diagnostics.
    assert exc_info.value.attempts
    assert exc_info.value.attempts[0].relay == "wss://r1"
    assert "EOSE" in exc_info.value.attempts[0].error


def test_fetch_event_distinguishes_budget_exhausted_from_no_event():
    """Round-2 fix: when a relay sends 64+ NOTICE/AUTH frames without
    EOSE, we shouldn't report 'EOSE with no event' (it's a lie)."""
    ws = MagicMock()
    # 64 NOTICE frames + 1 more for the loop bound — no EVENT, no EOSE.
    ws.recv.side_effect = [json.dumps(["NOTICE", "chatty"]) for _ in range(70)]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"):
        with patch("vrt1_verifier.nostr_client.websocket.create_connection",
                   return_value=ws):
            with pytest.raises(NostrFetchError) as exc_info:
                fetch_event("aa" * 32, relays=("wss://chatty",))
    assert exc_info.value.attempts[0].error
    assert "budget" in exc_info.value.attempts[0].error.lower()


def test_fetch_event_ignores_unrelated_closed_frame():
    """Round-2 fix: a CLOSED frame for someone else's sub_id must not
    terminate our loop. We only break on CLOSED for OUR sub_id."""
    ws = MagicMock()
    ws.recv.side_effect = [
        json.dumps(["CLOSED", "different-subscription", "bye"]),
        json.dumps(["EVENT", "deadbeef", _fake_event()]),
        json.dumps(["EOSE", "deadbeef"]),
    ]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"):
        with patch("vrt1_verifier.nostr_client.websocket.create_connection",
                   return_value=ws):
            event, _ = fetch_event("aa" * 32, relays=("wss://r",))
    assert event is not None  # would have been None if CLOSED short-circuited


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


def test_fetch_checkpoint_rejects_wrong_epoch_returned_by_relay():
    """Round-2 fix: a relay that ignores the #d filter might stream
    the author's most recent kind-30079 event regardless of epoch.
    The client must re-check the d-tag and reject mismatched epochs
    rather than accepting them silently."""
    att_event = _fake_event()  # epoch tag = "5"
    wrong_epoch_checkpoint = {
        "id": "dd" * 32, "pubkey": "bb" * 32, "kind": 30079,
        "created_at": 1700000600,
        "tags": [["d", "checkpoint:99"]],   # wrong epoch
        "content": "{}", "sig": "ff" * 64,
    }
    ws = MagicMock()
    ws.recv.side_effect = [
        json.dumps(["EVENT", "deadbeef", wrong_epoch_checkpoint]),
        json.dumps(["EOSE", "deadbeef"]),
    ]
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"):
        with patch("vrt1_verifier.nostr_client.websocket.create_connection",
                   return_value=ws):
            cp, attempts = fetch_checkpoint_for_attestation(
                att_event, relays=("wss://buggy-relay",),
            )
    # The wrong-epoch event must be rejected client-side.
    assert cp is None
