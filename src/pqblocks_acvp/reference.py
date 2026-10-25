"""Tier 1: Reference Oracle for FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).

Every result this product reports is "implementation X agrees or disagrees with
this reference", so the reference must BE the standard. It delegates to the
pure-Python FIPS 203/204 implementations kyber-py and dilithium-py (deterministic
internal entry points, which is exactly what ACVP AFT vectors exercise), and is
itself held to the published NIST ACVP corpus in tests/test_official_vectors.py.

History: until 2026-10-07 this file hashed the inputs into look-alike outputs
(ciphertext = SHAKE256(r || ek)) and its ML-DSA verify returned True for any
non-empty signature. It matched no official vector. Never reintroduce a
"simulated" primitive here - an oracle that is not the standard is worse than none.
"""
from typing import Tuple

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

# FIPS 203 Table 3 sizes, kept for input validation and for callers that read them
ML_KEM_PARAMS = {
    "ML-KEM-512": {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4, "ek_size": 800, "dk_size": 1632, "c_size": 768},
    "ML-KEM-768": {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4, "ek_size": 1184, "dk_size": 2400, "c_size": 1088},
    "ML-KEM-1024": {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5, "ek_size": 1568, "dk_size": 3168, "c_size": 1568},
}
_KEM = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}
_DSA = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}

Q = 3329


def _kem(parameter_set: str):
    if parameter_set not in _KEM:
        raise ValueError(f"Unknown parameter set: {parameter_set}")
    return _KEM[parameter_set], ML_KEM_PARAMS[parameter_set]


class MLKEMReferenceOracle:
    """FIPS 203 ML-KEM reference (kyber-py)."""

    @staticmethod
    def keygen(parameter_set: str, d_hex: str, z_hex: str) -> Tuple[str, str]:
        """ML-KEM.KeyGen_internal(d, z) returning (ek_hex, dk_hex)."""
        kem, _ = _kem(parameter_set)
        ek, dk = kem._keygen_internal(bytes.fromhex(d_hex), bytes.fromhex(z_hex))
        return ek.hex().upper(), dk.hex().upper()

    @staticmethod
    def encapsulate(parameter_set: str, ek_hex: str, m_hex: str = "") -> Tuple[str, str]:
        """ML-KEM.Encaps_internal(ek, m) returning (c_hex, K_hex).

        With `m` (32 bytes) the result is reproducible and comparable to an
        ACVP vector; without it, m comes from the OS CSPRNG - FIPS 203 Encaps."""
        kem, params = _kem(parameter_set)
        ek = bytes.fromhex(ek_hex)
        if len(ek) != params["ek_size"]:
            raise ValueError(f"Invalid ek size: expected {params['ek_size']}, got {len(ek)}")
        m = bytes.fromhex(m_hex) if m_hex else __import__("os").urandom(32)
        if len(m) != 32:
            raise ValueError("m must be 32 bytes (FIPS 203 Encaps_internal)")
        k, c = kem._encaps_internal(ek, m)
        return c.hex().upper(), k.hex().upper()

    @staticmethod
    def decapsulate(parameter_set: str, dk_hex: str, c_hex: str) -> str:
        """ML-KEM.Decaps_internal(dk, c) returning K_hex (implicit rejection included)."""
        kem, params = _kem(parameter_set)
        dk, c = bytes.fromhex(dk_hex), bytes.fromhex(c_hex)
        if len(c) != params["c_size"]:
            raise ValueError(f"Invalid ciphertext size: expected {params['c_size']}, got {len(c)}")
        if len(dk) != params["dk_size"]:
            raise ValueError(f"Invalid dk size: expected {params['dk_size']}, got {len(dk)}")
        return kem._decaps_internal(dk, c).hex().upper()


class MLDSAReferenceOracle:
    """FIPS 204 ML-DSA reference (dilithium-py), pure (non-prehash) interface."""

    @staticmethod
    def verify(parameter_set: str, pk_hex: str, msg_hex: str, sig_hex: str, ctx_hex: str = "") -> bool:
        """ML-DSA.Verify(pk, M, sigma, ctx) for the external, pure interface."""
        if parameter_set not in _DSA:
            raise ValueError(f"Unknown parameter set: {parameter_set}")
        try:
            pk, msg, sig = bytes.fromhex(pk_hex), bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)
            ctx = bytes.fromhex(ctx_hex) if ctx_hex else b""
        except ValueError:
            return False
        if len(ctx) > 255:
            return False
        try:
            return bool(_DSA[parameter_set].verify(pk, msg, sig, ctx=ctx))
        except (ValueError, IndexError, TypeError):
            return False                   # malformed key/signature is a rejection, not a crash
