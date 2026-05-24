"""Minimal Nostr relay client for fetching events by ID.

Nostr is a WebSocket protocol. To fetch a known event:
  C -> R: ["REQ", "<sub_id>", {"ids": ["<event_id_hex>"]}]
  R -> C: ["EVENT", "<sub_id>", {event}]
  R -> C: ["EOSE", "<sub_id>"]
  C -> R: ["CLOSE", "<sub_id>"]

We try a small set of public relays in order so a single dead relay
doesn't break verification. The first successful fetch wins.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Iterable

import websocket  # websocket-client (sync)


DEFAULT_RELAYS = (
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
    "wss://relay.primal.net",
)


class NostrFetchError(Exception):
    """Raised when no relay returned the requested event."""


@dataclass
class NostrRelayAttempt:
    relay: str
    ok: bool
    error: str | None


def _fetch_from_one_relay(
    relay_url: str,
    event_id_hex: str,
    timeout_seconds: float,
) -> dict | None:
    """Connect to a single relay, request an event by id, return the event dict
    or None if the relay had nothing.

    Raises (anything WebSocketException can throw) on connection failure.
    """
    sub_id = secrets.token_hex(8)
    ws = websocket.create_connection(relay_url, timeout=timeout_seconds)
    try:
        req = json.dumps(["REQ", sub_id, {"ids": [event_id_hex]}])
        ws.send(req)
        event: dict | None = None
        # Read until EOSE or until we get our event. Bounded by message count
        # so a chatty relay can't hang us forever.
        for _ in range(64):
            raw = ws.recv()
            try:
                msg = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if not isinstance(msg, list) or len(msg) < 2:
                continue
            if msg[0] == "EVENT" and len(msg) >= 3 and msg[1] == sub_id:
                event = msg[2]
            elif msg[0] == "EOSE" and msg[1] == sub_id:
                break
            elif msg[0] == "CLOSED":
                break
        try:
            ws.send(json.dumps(["CLOSE", sub_id]))
        except Exception:
            pass
        return event
    finally:
        try:
            ws.close()
        except Exception:
            pass


def fetch_event(
    event_id_hex: str,
    *,
    relays: Iterable[str] = DEFAULT_RELAYS,
    timeout_seconds: float = 6.0,
) -> tuple[dict, list[NostrRelayAttempt]]:
    """Fetch a Nostr event by id, trying each relay in order.

    Returns (event_dict, attempts) — the event dict on first success, plus
    a per-relay attempt log for transparency in the CLI output.
    Raises NostrFetchError if every relay failed or had no event.
    """
    if not event_id_hex or len(event_id_hex) != 64:
        raise ValueError("event_id_hex must be 64 hex chars")
    attempts: list[NostrRelayAttempt] = []
    for relay in relays:
        try:
            event = _fetch_from_one_relay(relay, event_id_hex, timeout_seconds)
        except Exception as e:
            attempts.append(NostrRelayAttempt(relay=relay, ok=False, error=str(e)))
            continue
        if event is not None:
            attempts.append(NostrRelayAttempt(relay=relay, ok=True, error=None))
            return event, attempts
        attempts.append(NostrRelayAttempt(
            relay=relay, ok=False, error="relay returned EOSE with no matching event",
        ))
    raise NostrFetchError(
        f"event {event_id_hex} not found on any of {len(attempts)} relays"
    )


def fetch_checkpoint_for_attestation(
    attestation_event: dict,
    *,
    relays: Iterable[str] = DEFAULT_RELAYS,
    timeout_seconds: float = 6.0,
) -> tuple[dict | None, list[NostrRelayAttempt]]:
    """Find the checkpoint event for the epoch of an attestation event.

    VERITAS checkpoints are kind 30079 with a `d` tag of `checkpoint:<epoch>`.
    We REQ a filter by author + kind + d-tag and take the first match.
    """
    pubkey = attestation_event.get("pubkey")
    epoch_tag = None
    for t in attestation_event.get("tags", []):
        if len(t) >= 2 and t[0] == "epoch":
            epoch_tag = t[1]
            break
    if pubkey is None or epoch_tag is None:
        return None, []

    sub_id = secrets.token_hex(8)
    flt = {
        "authors": [pubkey],
        "kinds": [30079],
        "#d": [f"checkpoint:{epoch_tag}"],
        "limit": 1,
    }
    attempts: list[NostrRelayAttempt] = []
    for relay in relays:
        try:
            ws = websocket.create_connection(relay, timeout=timeout_seconds)
        except Exception as e:
            attempts.append(NostrRelayAttempt(relay=relay, ok=False, error=str(e)))
            continue
        try:
            ws.send(json.dumps(["REQ", sub_id, flt]))
            event: dict | None = None
            for _ in range(32):
                try:
                    raw = ws.recv()
                except Exception:
                    break
                try:
                    msg = json.loads(raw)
                except (ValueError, TypeError):
                    continue
                if not isinstance(msg, list) or len(msg) < 2:
                    continue
                if msg[0] == "EVENT" and len(msg) >= 3 and msg[1] == sub_id:
                    event = msg[2]
                    break
                if msg[0] == "EOSE" and msg[1] == sub_id:
                    break
            try:
                ws.send(json.dumps(["CLOSE", sub_id]))
            except Exception:
                pass
        finally:
            try:
                ws.close()
            except Exception:
                pass
        if event is not None:
            attempts.append(NostrRelayAttempt(relay=relay, ok=True, error=None))
            return event, attempts
        attempts.append(NostrRelayAttempt(
            relay=relay, ok=False, error="no checkpoint for that epoch on this relay",
        ))
    return None, attempts
