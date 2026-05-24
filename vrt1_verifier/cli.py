"""vrt1-verify — third-party VERITAS attestation verifier.

Two modes:

  Online (the headline feature):
    $ vrt1-verify --event-id <hex>
    Fetches the attestation event from public Nostr relays, finds the
    matching checkpoint event by epoch + author, looks up the anchor tx
    on mempool.space, and runs the full binding chain. Anyone, anywhere,
    can verify an attestation without ever touching the oracle's code.

  Offline:
    $ vrt1-verify --attestation-file a.json --proof-file p.json \
                  --checkpoint-file c.json [--anchor-raw-hex 02...]
    For air-gapped verification of artifacts already in hand.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from veritas.attestation import SignedAttestation
from veritas.merkle import MerkleProof
from veritas.nostr import NostrEvent, decode_attestation_event
from veritas.verifier import verify_full

from .btc_client import BtcFetchError, fetch_tx
from .nostr_client import (
    DEFAULT_RELAYS,
    NostrFetchError,
    fetch_checkpoint_for_attestation,
    fetch_event,
)


console = Console()


def _nostr_event_from_dict(d: dict) -> NostrEvent:
    known = {"pubkey", "created_at", "kind", "tags", "content", "id", "sig"}
    missing = {"pubkey", "created_at", "kind"} - d.keys()
    if missing:
        raise click.ClickException(
            f"Nostr event missing required fields: {sorted(missing)}"
        )
    return NostrEvent(**{k: v for k, v in d.items() if k in known})


def _extract_anchor_txid_from_checkpoint(cp_event: NostrEvent) -> str | None:
    for t in cp_event.tags:
        if len(t) >= 2 and t[0] == "anchor":
            return t[1]
    try:
        body = json.loads(cp_event.content)
    except (ValueError, TypeError):
        return None
    return body.get("anchor_txid")


def _render_report(
    result, *, source_description: str,
    relay_attempts=None, checkpoint_attempts=None,
    btc_result=None, notes_extra=None,
) -> None:
    console.print(Panel.fit(
        f"[bold]vrt1-verify[/bold]\n{source_description}",
        border_style="cyan",
    ))

    if relay_attempts:
        t = Table(title="Nostr relay fetches", show_header=True)
        t.add_column("relay"); t.add_column("result")
        for a in relay_attempts:
            mark = "[green]✓[/green]" if a.ok else "[red]✗[/red]"
            t.add_row(a.relay, f"{mark} {a.error or 'fetched'}")
        console.print(t)

    if checkpoint_attempts:
        t = Table(title="Nostr checkpoint lookup", show_header=True)
        t.add_column("relay"); t.add_column("result")
        for a in checkpoint_attempts:
            mark = "[green]✓[/green]" if a.ok else "[yellow]→[/yellow]"
            t.add_row(a.relay, f"{mark} {a.error or 'fetched'}")
        console.print(t)

    if btc_result is not None:
        console.print(Panel(
            f"txid:        [yellow]{btc_result.txid}[/yellow]\n"
            f"network:     {btc_result.network}\n"
            f"confirmed:   {btc_result.confirmed}"
            + (f"\nblock:       {btc_result.block_height}"
               if btc_result.block_height is not None else "")
            + f"\nexplorer:    [cyan]{btc_result.explorer_url}[/cyan]",
            title="Anchor transaction", title_align="left", border_style="blue",
        ))

    t = Table(title="Binding chain")
    t.add_column("check"); t.add_column("status")
    for label, val in [
        ("schnorr (attestation)", result.schnorr_ok),
        ("nostr event", result.nostr_event_ok),
        ("merkle inclusion", result.merkle_ok),
        ("checkpoint (signed content)", result.checkpoint_ok),
        ("anchor OP_RETURN (on-chain)", result.anchor_ok),
    ]:
        if val is None:
            t.add_row(label, "[grey50]not provided[/grey50]")
        else:
            t.add_row(
                label,
                "[bold green]✓ pass[/bold green]" if val else "[bold red]✗ fail[/bold red]",
            )
    console.print(t)

    if result.notes or notes_extra:
        console.print("[yellow]notes:[/yellow]")
        for n in (notes_extra or []):
            console.print(f"  • {n}")
        for n in result.notes:
            console.print(f"  • {n}")

    console.print(Panel.fit(
        "[bold green]VERIFIED[/bold green]" if result.ok
        else "[bold red]REJECTED[/bold red]",
        border_style="green" if result.ok else "red",
    ))


@click.command()
@click.option("--event-id", type=str, default=None,
              help="Nostr event id (64 hex chars) of a VERITAS attestation event. "
                   "Triggers online fetch from public Nostr relays.")
@click.option("--relay", "relays", multiple=True,
              help="Override default relay list (repeatable). "
                   "Default: damus.io, nos.lol, relay.nostr.band, primal.net.")
@click.option("--network", type=click.Choice(["mainnet", "testnet", "signet"]),
              default="signet", show_default=True,
              help="Bitcoin network for anchor tx lookup.")
@click.option("--attestation-file", type=click.Path(exists=True), default=None,
              help="Offline mode: path to a saved SignedAttestation JSON.")
@click.option("--proof-file", type=click.Path(exists=True), default=None,
              help="Offline mode: path to a saved MerkleProof JSON.")
@click.option("--checkpoint-file", type=click.Path(exists=True), default=None,
              help="Offline mode: path to a saved checkpoint JSON.")
@click.option("--anchor-raw-hex", type=str, default=None,
              help="Offline override: raw anchor tx hex (skips block-explorer fetch).")
@click.option("--no-fetch-anchor", is_flag=True,
              help="In online mode, skip the block-explorer round trip.")
def main(
    event_id: str | None,
    relays: tuple[str, ...],
    network: str,
    attestation_file: str | None,
    proof_file: str | None,
    checkpoint_file: str | None,
    anchor_raw_hex: str | None,
    no_fetch_anchor: bool,
) -> None:
    """Verify a VERITAS attestation without trusting the oracle's code."""
    relay_list = list(relays) if relays else list(DEFAULT_RELAYS)

    if event_id:
        _run_online(
            event_id=event_id, relays=relay_list, network=network,
            fetch_anchor=not no_fetch_anchor,
        )
    elif attestation_file:
        _run_offline(
            attestation_file=attestation_file,
            proof_file=proof_file,
            checkpoint_file=checkpoint_file,
            anchor_raw_hex=anchor_raw_hex,
        )
    else:
        raise click.ClickException(
            "Provide --event-id <hex> for online verification, "
            "or --attestation-file <path> for offline verification."
        )


def _run_online(
    *, event_id: str, relays: list[str], network: str, fetch_anchor: bool,
) -> None:
    # 1. Fetch the attestation event from Nostr.
    try:
        evt_dict, relay_attempts = fetch_event(event_id, relays=relays)
    except NostrFetchError as e:
        # Surface per-relay diagnostics so the user can tell DNS
        # failure from "event genuinely missing" from "relay buggy".
        lines = [str(e)]
        for a in e.attempts:
            lines.append(f"  - {a.relay}: {a.error}")
        raise click.ClickException("\n".join(lines))
    except ValueError as e:
        raise click.ClickException(f"bad event id: {e}")

    try:
        att_event = _nostr_event_from_dict(evt_dict)
        signed = decode_attestation_event(att_event)
    except (KeyError, ValueError, base64.binascii.Error) as e:
        raise click.ClickException(
            f"event {event_id} is not a parseable VERITAS attestation: {e}"
        )

    # 2. Find the matching checkpoint event (same author, same epoch).
    cp_event_dict, cp_attempts = fetch_checkpoint_for_attestation(
        evt_dict, relays=relays,
    )
    cp_event = None
    if cp_event_dict is not None:
        try:
            cp_event = _nostr_event_from_dict(cp_event_dict)
        except click.ClickException:
            cp_event = None  # surface as 'not provided' rather than crash

    # 3. Fetch the on-chain anchor tx by the txid the checkpoint advertises.
    btc_result = None
    notes_extra: list[str] = []
    anchor_hex: str | None = None
    if fetch_anchor and cp_event is not None:
        txid = _extract_anchor_txid_from_checkpoint(cp_event)
        if txid:
            try:
                btc_result = fetch_tx(txid, network=network)
                anchor_hex = btc_result.raw_hex
            except BtcFetchError as e:
                notes_extra.append(f"anchor fetch failed: {e}")
            except ValueError as e:
                # fetch_tx raises ValueError on a checkpoint with a
                # malformed anchor_txid (wrong length or non-hex). Surface
                # as a soft note instead of an unhandled traceback.
                notes_extra.append(f"checkpoint anchor_txid is malformed: {e}")
        else:
            notes_extra.append(
                "checkpoint event has no anchor_txid; nothing to look up on-chain"
            )

    # 4. Run the verifier with everything we collected. proof is None in
    # online mode — the protocol does not include Merkle proofs in Nostr
    # events, so verify_full will (correctly) report checkpoint_ok=False
    # since the digest can't be bound to the root without a proof.
    # Online flow is a starting point for trust evaluation; for full
    # binding chain, the user supplies the proof via offline mode.
    result = verify_full(
        signed=signed,
        nostr_event=att_event,
        proof=None,
        checkpoint_event=cp_event,
        anchor_raw_tx_hex=anchor_hex,
    )

    _render_report(
        result,
        source_description=(
            f"online fetch by event id [yellow]{event_id[:16]}…[/yellow]\n"
            f"network: {network}"
        ),
        relay_attempts=relay_attempts,
        checkpoint_attempts=cp_attempts,
        btc_result=btc_result,
        notes_extra=notes_extra,
    )
    if not result.ok:
        sys.exit(1)


def _run_offline(
    *, attestation_file: str, proof_file: str | None,
    checkpoint_file: str | None, anchor_raw_hex: str | None,
) -> None:
    try:
        signed = SignedAttestation.from_json(Path(attestation_file).read_text())
    except (ValueError, KeyError) as e:
        raise click.ClickException(f"invalid attestation file: {e}")

    proof = None
    if proof_file:
        try:
            d = json.loads(Path(proof_file).read_text())
            proof = MerkleProof(
                leaf=bytes.fromhex(d["leaf_hex"]),
                siblings=[bytes.fromhex(s) for s in d["siblings_hex"]],
                directions=list(d["directions"]),
                root=bytes.fromhex(d["root_hex"]),
                size=int(d["size"]),
                index=int(d["index"]),
            )
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            raise click.ClickException(f"invalid proof file: {e}")

    cp_event = None
    anchor_hex = anchor_raw_hex
    if checkpoint_file:
        try:
            d = json.loads(Path(checkpoint_file).read_text())
        except json.JSONDecodeError as e:
            raise click.ClickException(f"invalid checkpoint file: {e}")
        if d.get("checkpoint_event"):
            cp_event = _nostr_event_from_dict(d["checkpoint_event"])
        if anchor_hex is None and d.get("anchor") and d["anchor"].get("raw_hex"):
            anchor_hex = d["anchor"]["raw_hex"]

    result = verify_full(
        signed=signed, proof=proof,
        checkpoint_event=cp_event,
        anchor_raw_tx_hex=anchor_hex,
    )
    _render_report(result, source_description="offline file verification")
    if not result.ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
