# vrt1-verifier

[![CI](https://github.com/Ifasola34/vrt1-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/Ifasola34/vrt1-verifier/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**Third-party verifier for [VERITAS](https://github.com/Ifasola34/veritas) (VRT1) Bitcoin-anchored AI attestations.**

Anyone can verify a VERITAS attestation without ever touching the oracle's code, without trusting any company, and without an account anywhere. This tool pulls the artifacts off the public Nostr network and Bitcoin block explorers, then runs the full binding chain and tells you what passed and what didn't.

That last sentence is the entire point. The whole VERITAS pitch — *"trust math and Bitcoin instead of trusting the publisher"* — only matters if an independent party can actually do the trusting-of-math step. This is that party's tool.

---

## How it works

```
                    ┌──────────────────┐
   --event-id <hex> │ Nostr relays     │  fetch attestation event
        ────────────▶  (Damus, etc.)   │  fetch matching checkpoint
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │ mempool.space    │  fetch raw anchor tx hex
                    │ (or other)       │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │ veritas.verifier │  Schnorr ✓  Nostr ✓
                    │ verify_full()    │  Merkle ✓  Checkpoint ✓
                    │                  │  OP_RETURN ✓
                    └──────────────────┘
                              │
                              ▼
                    [bold green]VERIFIED[/]  or  [bold red]REJECTED[/]
```

The verifier binds every link:

- Attestation Schnorr signature → Nostr event signature → event pubkey matches attestation oracle
- Merkle proof leaf → attestation digest, proof root → checkpoint signed content
- Checkpoint signed content → on-chain `OP_RETURN` epoch + leaf_count + root

Any mismatch anywhere fails the chain. The 20-case adversarial test suite in the [veritas repo](https://github.com/Ifasola34/veritas/blob/main/tests/test_verifier_adversarial.py) names the specific attacks the underlying `verify_full` refuses.

---

## Install

Requires Python 3.10+ (avoid 3.14 until `coincurve` ships wheels for it).

```bash
git clone https://github.com/Ifasola34/vrt1-verifier.git
cd vrt1-verifier
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

---

## Usage

### Online — fetch from Nostr + Bitcoin, no local files

```bash
vrt1-verify --event-id 7c4f8a2b…  --network signet
```

What it does:
1. Connects to public Nostr relays (Damus, nos.lol, relay.nostr.band, primal.net) and fetches the event with that ID.
2. Decodes the attestation from the event's base64 content.
3. Looks up the matching checkpoint event for the same author + epoch.
4. Reads the `anchor_txid` from the checkpoint, fetches the raw tx hex from mempool.space.
5. Runs `verify_full`, prints a per-check report and a final pass/fail.

Note: Nostr does not carry Merkle inclusion proofs in the standard event format, so an online-only verification cannot complete the full binding chain — it confirms signatures and the on-chain commitment exist, but cannot bind the specific attestation digest to the root without a proof. The oracle exposes proofs via `GET /epoch/{n}/proof/{i}`; once you have one, run offline mode to complete the chain.

### Offline — verify saved artifacts

```bash
vrt1-verify \
    --attestation-file att.json \
    --proof-file proof.json \
    --checkpoint-file checkpoint.json
```

This runs the complete binding chain. If `checkpoint.json` ships an `anchor.raw_hex` field (the VERITAS oracle writes it that way), the on-chain check runs automatically; otherwise pass `--anchor-raw-hex 02000000…` to provide it.

### Options

| Flag | Default | Effect |
|---|---|---|
| `--event-id <hex>` | — | 64-char Nostr event id; triggers online mode |
| `--relay <url>` | 4 public relays | Override (repeatable) |
| `--network <name>` | `signet` | `mainnet` \| `testnet` \| `signet` for the anchor lookup |
| `--attestation-file <path>` | — | Offline mode entry point |
| `--proof-file <path>` | — | Offline mode: Merkle proof JSON |
| `--checkpoint-file <path>` | — | Offline mode: checkpoint JSON (may carry `anchor.raw_hex`) |
| `--anchor-raw-hex <hex>` | — | Override the anchor tx hex (skips block-explorer fetch) |
| `--no-fetch-anchor` | off | In online mode, skip the block-explorer round trip |

Exit code: `0` on `VERIFIED`, `1` on `REJECTED`.

---

## Tests

```bash
$ pytest -v
19 passed in 0.08s
```

All network calls (WebSocket to relays, HTTP to mempool.space) are mocked, so the suite runs fully offline. Coverage:

- Nostr client: id validation, single-relay success, multi-relay fallback, all-fail rejection, malformed-frame tolerance, checkpoint filter shape.
- Bitcoin client: network/txid validation, success with confirmation metadata, 404 → `BtcFetchError`, network-error → `BtcFetchError`, non-hex body rejection, non-fatal meta-endpoint failure.
- CLI: offline VERIFIED on honest artifacts, REJECTED on a tampered attestation, no-args error, online end-to-end with mocked Nostr + mempool, bad-event-id rejection.

---

## Why this is a separate repo

Three reasons:

1. **It proves the protocol is consumable.** A grant reviewer or a wary user can install this without installing the oracle code. The fact that VERITAS verification works through a different package, by a different entry point, with no shared state, is the strongest signal that VRT1 is a real interoperable protocol rather than a single-binary product.
2. **It minimizes the trusted code path.** Verifiers should depend on as little as possible. This repo's only first-party dependency is `veritas` itself (specifically `veritas.verifier`, `veritas.attestation`, `veritas.merkle`, `veritas.nostr`); the oracle, the L402 paywall, the broadcaster, and the server are all absent.
3. **It's where third-party features live.** Public-relay fetching, block-explorer integration, and (eventually) browser-extension wiring belong here rather than weighing down the oracle.

---

## License

MIT — see [`LICENSE`](LICENSE).
