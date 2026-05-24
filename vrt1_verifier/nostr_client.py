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
    """Raised when no relay returned the requested event.

    Carries the per-relay `attempts` list so the CLI/caller can show
    the user WHY each relay failed (DNS, timeout, EOSE-with-no-event,
    response-bound exhausted, etc.) instead of a bare "not found".
    """

    def __init__(self, message: str, attempts: list["NostrRelayAttempt"] | None = None) -> None:
        super().__init__(message)
        self.attempts = attempts or []


@dataclass
class NostrRelayAttempt:
    relay: str
    ok: bool
    error: str | None


def _fetch_from_one_relay(
    relay_url: str,
    event_id_hex: str,
    timeout_seconds: float,
) -> tuple[dict | None, str | None]:
    """Connect to a single relay, request an event by id, return
    (event_dict_or_None, reason_or_None).

    `reason` is None on clean success (event found OR EOSE with no
    matching event). Otherwise it describes why we gave up — so the
    caller can distinguish "relay said nothing" from "we hit our
    read-budget on a chatty relay" from "an unrelated subscription
    was closed". Raises on connection failure.
    """
    sub_id = secrets.token_hex(8)
    ws = websocket.create_connection(relay_url, timeout=timeout_seconds)
    try:
        req = json.dumps(["REQ", sub_id, {"ids": [event_id_hex]}])
        ws.send(req)
        event: dict | None = None
        reason: str | None = None
        # Read until EOSE or until we get our event. Bounded by message count
        # so a chatty relay can't hang us forever.
        for _ in range(64):
            try:
                raw = ws.recv()
            except Exception:
                # WebSocket dropped mid-stream — match the defensive
                # pattern used by fetch_checkpoint_for_attestation
                # below. If we already collected `event` earlier we
                # return it; otherwise fall through to the empty-event
                # path. This avoids losing a valid event already in
                # hand to a flaky relay.
                break
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
            elif msg[0] == "CLOSED" and len(msg) >= 2 and msg[1] == sub_id:
                # Only break on a CLOSED for OUR sub_id, not an unrelated one.
                break
        else:
            # Loop hit its bound without ever seeing our EOSE — tell the
            # caller so they can distinguish this from a clean "no event".
            if event is None:
                reason = "read budget (64 frames) exhausted before EOSE"
        try:
            ws.send(json.dumps(["CLOSE", sub_id]))
        except Exception:
            pass
        return event, reason
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
            event, reason = _fetch_from_one_relay(
                relay, event_id_hex, timeout_seconds,
            )
        except Exception as e:
            attempts.append(NostrRelayAttempt(relay=relay, ok=False, error=str(e)))
            continue
        if event is not None:
            attempts.append(NostrRelayAttempt(relay=relay, ok=True, error=None))
            return event, attempts
        attempts.append(NostrRelayAttempt(
            relay=relay, ok=False,
            error=reason or "relay returned EOSE with no matching event",
        ))
    # Attach per-relay failures to the exception so the CLI can render them.
    raise NostrFetchError(
        f"event {event_id_hex} not found on any of {len(attempts)} relays",
        attempts=attempts,
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
    expected_d_tag = f"checkpoint:{epoch_tag}"
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
                    candidate = msg[2]
                    # Defensive: a malicious relay could send candidate
                    # as a non-dict ("not a dict") or {"tags": null}.
                    # Skip such garbage rather than crashing the fetcher.
                    try:
                        tags = candidate.get("tags", [])
                        if not isinstance(tags, list):
                            continue
                        if any(
                            len(t) >= 2 and t[0] == "d" and t[1] == expected_d_tag
                            for t in tags
                        ):
                            event = candidate
                            break
                    except (AttributeError, TypeError):
                        continue
                    # Otherwise keep reading — the relay might send our
                    # match in a later frame.
                elif msg[0] == "EOSE" and msg[1] == sub_id:
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
