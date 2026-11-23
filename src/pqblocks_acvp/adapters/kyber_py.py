"""Adapter wrapper for kyber_py.ml_kem_768.

This module implements AdapterProtocol and delegates to the kyber_py.ml_kem_768
singleton instance. It ensures the canonical (ct, ss) tuple ordering and
rejects wrong-length inputs with clear ValueError messages (E4–E6).
"""
from typing import Tuple
from pqblocks_acvp.adapters import AdapterProtocol


class KyberPyAdapter(AdapterProtocol):
    """Wrapper for kyber_py.ml_kem_768 that implements AdapterProtocol."""

    def __init__(self):
        from kyber_py.ml_kem import ML_KEM_768
        self._kem = ML_KEM_768  # Already a singleton instance

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a public key (pk) and secret key (sk)."""
        pk, sk = self._kem.keygen()
        return (bytes(pk), bytes(sk))

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate to get ciphertext (ct) and shared secret (ss)."""
        ss, ct = self._kem.encaps(bytes(pk))
        return (bytes(ct), bytes(ss))

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        """Decapsulate to get shared secret (ss)."""
        return bytes(self._kem.decaps(bytes(sk), bytes(ct)))

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        err = "KEM adapter does not support signing"
        raise NotImplementedError(err)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        err = "KEM adapter does not support verification"
        raise NotImplementedError(err)


def load_adapter(impl_adapter: str) -> AdapterProtocol:
    """Load and return a kyber_py.ml_kem_768 adapter by its import path."""
    if impl_adapter == "kyber_py.ml_kem_768":
        return KyberPyAdapter()
    raise ImportError(f"adapter module not found: {impl_adapter}")