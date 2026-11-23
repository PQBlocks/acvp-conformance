"""Test fixture loader for ACVP and Wycheproof test vectors."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

_CACHE = Path(os.path.expanduser(os.environ.get("PQC_VECTORS_DIR", "~/.cache/pqc-vectors")))


def load(name: str) -> List[Dict[str, Any]]:
    """Load testGroups from cached Wycheproof or ACVP JSON vector file."""
    # 1. Wycheproof
    wp = _CACHE / "wycheproof" / "testvectors_v1" / f"{name}.json"
    if wp.is_file():
        data = json.loads(wp.read_text(encoding="utf-8"))
        return data.get("testGroups", [])

    # 2. ACVP
    acvp = _CACHE / "ACVP-Server" / "gen-val" / "json-files" / name / "internalProjection.json"
    if acvp.is_file():
        data = json.loads(acvp.read_text(encoding="utf-8"))
        return data.get("testGroups", [])

    # 3. Direct file under ACVP
    direct = _CACHE / "ACVP-Server" / "gen-val" / "json-files" / f"{name}.json"
    if direct.is_file():
        data = json.loads(direct.read_text(encoding="utf-8"))
        return data.get("testGroups", [])

    raise FileNotFoundError(f"Fixture not found: {name}")


def _official_hashes() -> Dict[str, str]:
    from pqblocks_acvp.vectors import _STATIC_OFFICIAL_HASHES
    return {v: k for k, v in _STATIC_OFFICIAL_HASHES.items()}
