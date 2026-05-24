"""CLI tests.

Offline test: build real artifacts via the veritas oracle, write them to
JSON files, run `vrt1-verify` on them, assert it prints VERIFIED + exits 0.

Online test: mock the Nostr relay + mempool.space layers; assert the CLI
runs the binding chain against fetched artifacts.
"""

from __future__ import annotations

import base64
import io
import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from veritas.anchor import Utxo, derive_anchor_pubkey
from veritas.attestation import canonical_json
from veritas.crypto import OracleKey, derive_anchor_key
from veritas.oracle import Oracle, OracleConfig
from vrt1_verifier.cli import main


def _funded_utxo(okey: OracleKey) -> Utxo:
    priv = derive_anchor_key(okey)
    return Utxo(
        txid="ab" * 32, vout=0, value_sats=100_000,
        pubkey_compressed=derive_anchor_pubkey(priv),
    )


@pytest.fixture
def honest_artifacts(tmp_path: Path):
    okey = OracleKey.generate()
    oracle = Oracle(okey, OracleConfig(
        data_dir=tmp_path / "data",
        anchor_utxo=_funded_utxo(okey),
        fee_sats=400,
    ))
    signed, evt = oracle.attest("veritas.sentiment.keyword.v1", "bullish rally up")
    epoch = oracle.close_epoch()
    proof = oracle.inclusion_proof(epoch.number, 0)

    att_path = tmp_path / "att.json"
    proof_path = tmp_path / "proof.json"
    cp_path = tmp_path / "cp.json"

    att_path.write_text(signed.to_json())
    proof_path.write_text(json.dumps({
        "leaf_hex": proof.leaf.hex(),
        "siblings_hex": [s.hex() for s in proof.siblings],
        "directions": proof.directions,
        "root_hex": proof.root.hex(),
        "size": proof.size,
        "index": proof.index,
    }))
    cp_path.write_text(json.dumps({
        "checkpoint_event": epoch.checkpoint_event.to_dict(),
        "anchor": {"raw_hex": epoch.anchor_tx.raw_hex},
    }))

    return {
        "okey": okey, "oracle": oracle, "epoch": epoch,
        "signed": signed, "evt": evt, "proof": proof,
        "att_path": att_path, "proof_path": proof_path, "cp_path": cp_path,
    }


# ---------- offline mode ------------------------------------------


def test_offline_full_chain_verifies(honest_artifacts):
    runner = CliRunner()
    a = honest_artifacts
    result = runner.invoke(main, [
        "--attestation-file", str(a["att_path"]),
        "--proof-file", str(a["proof_path"]),
        "--checkpoint-file", str(a["cp_path"]),
    ])
    assert result.exit_code == 0, result.output
    assert "VERIFIED" in result.output
    assert "✓ pass" in result.output


def test_offline_rejects_tampered_attestation(honest_artifacts, tmp_path: Path):
    """Mutate the saved attestation output post-sign; signature must fail."""
    a = honest_artifacts
    d = json.loads(a["att_path"].read_text())
    d["attestation"]["output"] = {"label": "tampered"}
    bad_path = tmp_path / "bad.json"
    bad_path.write_text(json.dumps(d, sort_keys=True))

    runner = CliRunner()
    result = runner.invoke(main, [
        "--attestation-file", str(bad_path),
        "--proof-file", str(a["proof_path"]),
        "--checkpoint-file", str(a["cp_path"]),
    ])
    assert result.exit_code == 1
    assert "REJECTED" in result.output


def test_no_args_errors():
    runner = CliRunner()
    result = runner.invoke(main, [])
    assert result.exit_code != 0
    assert "--event-id" in result.output or "--attestation-file" in result.output


# ---------- online mode -------------------------------------------


class _FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


def test_online_fetches_event_checkpoint_and_anchor(honest_artifacts):
    a = honest_artifacts
    # Encode the SignedAttestation as a Nostr event content blob (matches
    # what build_attestation_event does).
    att_blob = base64.b64encode(canonical_json(
        {"attestation": a["signed"].attestation.to_payload(),
         "sig": a["signed"].sig}
    )).decode("ascii")
    att_event_dict = {
        "id": a["evt"].id,
        "pubkey": a["evt"].pubkey,
        "kind": 30078,
        "created_at": a["evt"].created_at,
        "tags": a["evt"].tags,
        "content": att_blob,
        "sig": a["evt"].sig,
    }
    cp_event_dict = a["epoch"].checkpoint_event.to_dict()
    anchor_hex = a["epoch"].anchor_tx.raw_hex
    anchor_txid = a["epoch"].anchor_tx.txid

    # Fake Nostr WebSocket: first call returns the attestation event, second
    # call returns the checkpoint event.
    ws1, ws2 = MagicMock(), MagicMock()
    ws1.recv.side_effect = [
        json.dumps(["EVENT", "deadbeef", att_event_dict]),
        json.dumps(["EOSE", "deadbeef"]),
    ]
    ws2.recv.side_effect = [
        json.dumps(["EVENT", "deadbeef", cp_event_dict]),
        json.dumps(["EOSE", "deadbeef"]),
    ]

    def fake_btc_open(url, timeout=None):
        url_str = url if isinstance(url, str) else url.full_url
        if url_str.endswith("/hex"):
            return _FakeResp(anchor_hex.encode())
        return _FakeResp(json.dumps({
            "txid": anchor_txid,
            "status": {"confirmed": True, "block_height": 200_000},
        }).encode())

    runner = CliRunner()
    with patch("vrt1_verifier.nostr_client.secrets.token_hex",
               return_value="deadbeef"), \
         patch("vrt1_verifier.nostr_client.websocket.create_connection",
               side_effect=[ws1, ws2]), \
         patch("vrt1_verifier.btc_client.urllib.request.urlopen",
               side_effect=fake_btc_open):
        result = runner.invoke(main, [
            "--event-id", a["evt"].id, "--network", "signet",
            "--relay", "wss://test.relay",
        ])

    # Online mode never has a proof (Nostr doesn't carry one), so the
    # checkpoint check should NOT pass — verifier fails closed per design.
    # The CLI should exit nonzero in that case but still print the report
    # showing anchor + nostr passing.
    assert "schnorr" in result.output.lower()
    assert "anchor" in result.output.lower()
    # Nostr event + attestation Schnorr should both verify.
    assert "✓ pass" in result.output


def test_online_bad_event_id_errors():
    runner = CliRunner()
    result = runner.invoke(main, ["--event-id", "not-hex"])
    assert result.exit_code != 0
    assert "64 hex" in result.output or "bad event id" in result.output
