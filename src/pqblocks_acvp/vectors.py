#!/usr/bin/env python3
"""Vector fixture loader for pqblocks-acvp.

Loads official NIST ACVP test vectors from the cached ACVP-Server gen-val
corpus with pinned sha256 verification (E10), malformed-JSON detection (E8),
and missing-fixture detection (E9).

Supported vector sets (spec parameter names, e.g. "ML-KEM-768"):
  ML-KEM-512, ML-KEM-768, ML-KEM-1024,
  ML-DSA-44, ML-DSA-65, ML-DSA-87,
  SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f, SLH-DSA-SHA2-192s,
  SLH-DSA-SHA2-192f, SLH-DSA-SHA2-256s, SLH-DSA-SHA2-256f,
  SLH-DSA-SHAKE-128s, ... (all 12 SLH-DSA sets).
"""

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Errors for E8-E10 per edge-case ledger
# ---------------------------------------------------------------------------


class VectorFixtureError(Exception):
    """Base class for vector fixture errors."""


class MalformedVectorJSONError(VectorFixtureError, ValueError):
    """E8 - Malformed vector JSON (parse error location: line/col)."""

    def __init__(self, message: str, line: Optional[int] = None, column: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.line = line
        self.column = column


class MissingVectorFixtureError(VectorFixtureError, FileNotFoundError):
    """E9 - Missing vector fixture (fixture path)."""

    def __init__(self, path: str):
        super().__init__(f"vector fixture not found: {path}")
        self.path = path


class FixtureIntegrityError(VectorFixtureError, ValueError):
    """E10 - Fixture sha256 mismatch (expected, got)."""

    def __init__(self, path: str, expected: str, got: str):
        super().__init__(f"fixture integrity check failed: {path} (expected {expected}, got {got})")
        self.path = path
        self.expected = expected
        self.got = got


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VectorGroup:
    """A single ACVP test group: parameter set name + list of test cases."""
    parameter_set: str
    tests: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Cache layout
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_CACHE = Path(os.path.expanduser(os.environ.get("PQC_VECTORS_DIR", "~/.cache/pqc-vectors")))
_ACVP = _CACHE / "ACVP-Server" / "gen-val" / "json-files"

# ---------------------------------------------------------------------------
# Pinned sha256 index: "acvp:<set-dir>:<file>" -> sha256 hex
# ---------------------------------------------------------------------------

_STATIC_OFFICIAL_HASHES = {
    "acvp:ML-KEM-encapDecap-FIPS203": "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f",
    "acvp:ML-KEM-encapDecap-FIPS203-tr1": "5e88fbd351dc2915b2ab399f5dffd269e1cdbdd0186103ab0e90b374cf592187",
    "acvp:ML-KEM-keyGen-FIPS203": "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b",
    "acvp:ML-DSA-keyGen-FIPS204": "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf",
    "acvp:ML-DSA-sigGen-FIPS204": "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22",
    "acvp:ML-DSA-sigGen-FIPS204-tr1": "b61576c765b1eb0e6a667a67a68380df944592be8740f9c020c9ea5a89136f18",
    "acvp:ML-DSA-sigVer-FIPS204": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
    "acvp:SLH-DSA-keyGen-FIPS205": "f758b3b180c3035c8353be2aba9e41756f9bc98ed45eeefee1f3a52bf6176fe6",
    "acvp:SLH-DSA-sigGen-FIPS205": "62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba",
    "acvp:SLH-DSA-sigVer-FIPS205": "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792",
}

PINNED_SHA256: Dict[str, str] = {}


def _pin_vectors() -> None:
    """Populate PINNED_SHA256 from static hashes."""
    global PINNED_SHA256
    for label, sha in _STATIC_OFFICIAL_HASHES.items():
        PINNED_SHA256[label] = sha
        _, _, name = label.partition(":")
        path = str(_ACVP / name / "internalProjection.json")
        PINNED_SHA256[f"acvp:{name}:{path}"] = sha


_pin_vectors()

# ---------------------------------------------------------------------------
# Internal: resolve spec vector_set name -> list of ACVP corpus directories
# ---------------------------------------------------------------------------

# Known ACVP corpus directories (as present in the sparse-checkout cache)
_ACVP_DIRS = [
    "ML-KEM-encapDecap-FIPS203", "ML-KEM-encapDecap-FIPS203-tr1", "ML-KEM-keyGen-FIPS203",
    "ML-DSA-keyGen-FIPS204", "ML-DSA-sigGen-FIPS204", "ML-DSA-sigGen-FIPS204-tr1", "ML-DSA-sigVer-FIPS204",
    "SLH-DSA-keyGen-FIPS205", "SLH-DSA-sigGen-FIPS205", "SLH-DSA-sigVer-FIPS205",
]

# Map spec parameter names to families.
_FAMILY_PREFIXES = ("ML-KEM", "ML-DSA", "SLH-DSA")


def _resolve_vector_set(vector_set: str) -> List[str]:
    """Map a spec parameter name (e.g. 'ML-KEM-768') to corpus dirs that
    belong to the same algorithm family. Returns dir names under _ACVP
    (may be empty)."""
    fam = "-".join(vector_set.split("-")[:2]).upper()  # ML-KEM / ML-DSA / SLH-DSA
    if not _ACVP.is_dir():
        return []
    dirs = [d for d in os.listdir(_ACVP) if d.startswith(fam)]
    return sorted(dirs)


def _load_file_verified(path: Path, set_dir: str) -> dict:
    """Read + sha256-verify + parse a single internalProjection.json file."""
    key = f"acvp:{set_dir}:{path}"
    expected = PINNED_SHA256.get(key)
    if expected is None:
        expected = PINNED_SHA256.get(f"acvp:{set_dir}")
    with open(path, "rb") as f:
        raw = f.read()
    actual = hashlib.sha256(raw).hexdigest()
    if expected is None:
        raise FixtureIntegrityError(str(path), "<missing from pin>", actual)
    if actual != expected:
        raise FixtureIntegrityError(str(path), expected, actual)
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise MalformedVectorJSONError(
            f"malformed vector JSON: {e.msg} at line {e.lineno}, column {e.colno}",
            line=e.lineno, column=e.colno,
        ) from e


# ---------------------------------------------------------------------------
# Public API: load_vectors
# ---------------------------------------------------------------------------


def load_vectors(vector_set: str, revision: str = "gen-val") -> List[VectorGroup]:
    """Load all vector groups for the given vector set with integrity checks.

    Args:
        vector_set: Spec parameter name, e.g. "ML-KEM-768", "ML-DSA-65",
            "SLH-DSA-SHA2-128s". Matched against parameterSet fields inside
            every ACVP corpus file for the algorithm family.
        revision: Pinned revision (default "gen-val"). Only "gen-val" is
            supported because we load from the extracted sparse checkout.

    Returns:
        List[VectorGroup] filtered to groups whose parameterSet == vector_set.
        Empty list if no group matches (E14: empty vector set).

    Raises:
        FileNotFoundError (E9): no corpus directory for this family / no file.
        MalformedVectorJSONError (E8): JSON parse failure with line/col.
        FixtureIntegrityError (E10): sha256 mismatch (expected vs got).
        ValueError: unknown vector set family (E1).
    """
    if revision != "gen-val":
        raise ValueError(f"unsupported vector revision: {revision!r} (only 'gen-val' is pinned)")

    fam = "-".join(vector_set.split("-")[:2]).upper()  # ML-KEM / ML-DSA / SLH-DSA
    if fam not in ("ML-KEM", "ML-DSA", "SLH-DSA"):
        raise ValueError(f"unknown vector set: {vector_set}")

    dirs = _resolve_vector_set(vector_set)
    if not dirs:
        raise FileNotFoundError(f"vector fixture not found: {vector_set} (no corpus dir for family {fam})")

    groups: List[VectorGroup] = []
    any_file = False
    for d in dirs:
        path = _ACVP / d / "internalProjection.json"
        if not path.is_file():
            continue
        any_file = True
        doc = _load_file_verified(path, d)  # raises E8/E10
        for g in doc.get("testGroups", []):
            if g.get("parameterSet") == vector_set:
                groups.append(VectorGroup(parameter_set=vector_set, tests=g.get("tests", [])))

    if not any_file:
        raise FileNotFoundError(f"vector fixture not found: {vector_set} (no internalProjection.json under {_ACVP})")
    if not groups:
        raise FileNotFoundError(f"vector fixture not found: {vector_set} (no testGroups with parameterSet {vector_set!r} under {_ACVP})")
    return groups


# ---------------------------------------------------------------------------
# Convenience utilities
# ---------------------------------------------------------------------------


def list_vector_sets() -> List[str]:
    """Return spec parameter-set names (e.g. 'ML-KEM-768') found in cached fixtures."""
    if not _ACVP.is_dir():
        return []
    param_sets = set()
    for d in os.listdir(_ACVP):
        path = _ACVP / d / "internalProjection.json"
        if not path.is_file():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            for g in doc.get("testGroups", []):
                ps = g.get("parameterSet")
                if ps:
                    param_sets.add(ps)
        except (json.JSONDecodeError, AttributeError, OSError):
            continue  # skip unreadable/malformed fixture files
    return sorted(param_sets)


def check_integrity(vector_set: str, revision: str = "gen-val") -> bool:
    """Return True if load_vectors succeeds without E8/E9/E10."""
    try:
        load_vectors(vector_set, revision)
        return True
    except (FileNotFoundError, MalformedVectorJSONError, FixtureIntegrityError, ValueError):
        return False


__all__ = [
    "VectorFixtureError", "MalformedVectorJSONError", "MissingVectorFixtureError",
    "FixtureIntegrityError", "VectorGroup", "load_vectors", "list_vector_sets",
    "check_integrity",
]


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Vector fixture loader (S5)")
    p.add_argument("--list", action="store_true")
    p.add_argument("--check", metavar="SET")
    a = p.parse_args()
    if a.list:
        for v in list_vector_sets():
            print(v)
        sys.exit(0)
    if a.check:
        sys.exit(0 if check_integrity(a.check) else 1)
    p.print_help()
    sys.exit(2)
