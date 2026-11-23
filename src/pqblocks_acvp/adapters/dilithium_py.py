"""Adapter wrapper for dilithium_py.ml_dsa_65.

This module implements AdapterProtocol and delegates to the dilithium_py.ml_dsa_65
singleton instance. It enforces FIPS 204 wire-size checks before reaching the
underlying library (reject-then-act per spec §3 E4-E6) and returns real bool
from verify().
"""
from typing import Tuple
from pqblocks_acvp.adapters import AdapterProtocol


class DilithiumPyAdapter(AdapterProtocol):
    """Wrapper for dilithium_py.ml_dsa_65 that implements AdapterProtocol."""

    # FIPS 204 §3 sizes for ML-DSA-65
    _PK_SIZE = 1952
    _SK_SIZE = 4032
    _SIG_SIZE = 3309

    def __init__(self):
        from dilithium_py.ml_dsa import ML_DSA_65
        self._sig = ML_DSA_65  # Already a singleton instance

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a public key (pk) and secret key (sk)."""
        pk, sk = self._sig.keygen()
        return (bytes(pk), bytes(sk))

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        """Sign a message with the secret key."""
        return bytes(self._sig.sign(bytes(sk), bytes(msg)))

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify a signature with the public key."""
        if len(pk) != self._PK_SIZE:
            raise ValueError(
                f"public key length {len(pk)} != {self._PK_SIZE} for ML-DSA-65"
            )
        if len(sig) != self._SIG_SIZE:
            raise ValueError(
                f"signature length {len(sig)} != {self._SIG_SIZE} for ML-DSA-65"
            )
        return bool(self._sig.verify(bytes(pk), bytes(msg), bytes(sig)))

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        err = "Signature adapter does not support encaps"
        raise NotImplementedError(err)

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        err = "Signature adapter does not support decapsulation"
        raise NotImplementedError(err)


def load_adapter(impl_adapter: str) -> AdapterProtocol:
    """Load and return a dilithium_py.ml_dsa_65 adapter by its import path."""
    if impl_adapter == "dilithium_py.ml_dsa_65":
        return DilithiumPyAdapter()
    raise ImportError(f"adapter module not found: {impl_adapter}")
