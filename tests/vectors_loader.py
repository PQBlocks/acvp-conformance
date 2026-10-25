"""Loader for NIST ACVP test vectors in tests/vectors/."""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_DIR = os.path.join(HERE, "vectors")


def sets(filt=""):
    out = []
    if not os.path.isdir(VECTORS_DIR):
        return out
    for name in sorted(os.listdir(VECTORS_DIR)):
        path = os.path.join(VECTORS_DIR, name, "internalProjection.json")
        if os.path.isfile(path):
            if filt.lower() in name.lower():
                out.append(("acvp", name, path))
    return out


def load(name):
    found = sets(name)
    if not found:
        raise FileNotFoundError(f"No official vector set matches {name!r} under {VECTORS_DIR}")
    groups = []
    for kind, set_name, path in found:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for g in doc.get("testGroups", []):
            g = dict(g)
            g["_source"] = f"{kind}:{set_name}"
            groups.append(g)
    return groups
