"""Bitcoin block-explorer client for fetching raw tx hex.

Uses mempool.space's public REST API. Supports mainnet, testnet, and
signet via the standard URL prefixes. No auth required for read.

  GET /api/tx/{txid}/hex   -> raw tx hex (plain text)
  GET /api/tx/{txid}       -> tx metadata (JSON) — used for confirmation status
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


_NETWORK_BASES = {
    "mainnet": "https://mempool.space/api",
    "testnet": "https://mempool.space/testnet/api",
    "signet": "https://mempool.space/signet/api",
}


class BtcFetchError(Exception):
    """Raised when the block explorer can't return a tx."""


@dataclass
class TxFetchResult:
    txid: str
    raw_hex: str
    confirmed: bool | None
    block_height: int | None
    network: str
    explorer_url: str


def fetch_tx(
    txid: str,
    *,
    network: str = "signet",
    timeout_seconds: float = 10.0,
) -> TxFetchResult:
    """Fetch the raw hex + confirmation status of a tx.

    Raises BtcFetchError on transport failure, 404, or malformed response.
    """
    if network not in _NETWORK_BASES:
        raise ValueError(
            f"unsupported network {network!r}; one of {sorted(_NETWORK_BASES)}"
        )
    if not txid or len(txid) != 64:
        raise ValueError("txid must be 64 hex chars")
    base = _NETWORK_BASES[network]

    # 1. Raw hex
    hex_url = f"{base}/tx/{txid}/hex"
    try:
        with urllib.request.urlopen(hex_url, timeout=timeout_seconds) as resp:
            raw_hex = resp.read().decode("utf-8", errors="replace").strip()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise BtcFetchError(f"tx {txid} not found on {network}")
        raise BtcFetchError(f"HTTP {e.code} fetching tx hex: {e.reason}")
    except (urllib.error.URLError, TimeoutError) as e:
        raise BtcFetchError(f"network error fetching tx hex: {e}")

    if not raw_hex or not all(c in "0123456789abcdefABCDEF" for c in raw_hex):
        raise BtcFetchError("block explorer returned non-hex body")

    # 2. Confirmation metadata (best-effort; non-fatal on failure)
    confirmed: bool | None = None
    block_height: int | None = None
    meta_url = f"{base}/tx/{txid}"
    try:
        with urllib.request.urlopen(meta_url, timeout=timeout_seconds) as resp:
            meta = json.loads(resp.read().decode("utf-8", errors="replace"))
        status = meta.get("status", {})
        confirmed = bool(status.get("confirmed"))
        block_height = status.get("block_height")
    except Exception:
        pass

    explorer_url_base = base.replace("/api", "")
    return TxFetchResult(
        txid=txid,
        raw_hex=raw_hex,
        confirmed=confirmed,
        block_height=block_height,
        network=network,
        explorer_url=f"{explorer_url_base}/tx/{txid}",
    )
