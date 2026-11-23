"""Adapter wrapper for mlkem_csr_pop.

This module implements AdapterProtocol over mlkem_csr_pop.ml_kem_768.
The library implements the ML-KEM algorithm in pure Python, suitable for
pure-Python environments and educational use.
"""
from typing import Tuple

from pqblocks_acvp.adapters import AdapterProtocol


class MlkemAdapter(AdapterProtocol):
    """Adapter over mlkem_csr_pop.ml_kem_768."""

    def __init__(self):
        # mlkem_csr_pop exports an mlkem module with keygen, encaps, decaps
        from mlkem_csr_pop import mlkem
        self._mlkem = mlkem

    def keygen(self) -> Tuple[bytes, bytes]:
        pk, sk = self._mlkem.mlkem_keygen("ML-KEM-768")
        return (bytes(pk), bytes(sk))

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        # mlkem_csr_pop mlkem_encapsulate returns (ss, ct); canonical order is (ct, ss)
        ss, ct = self._mlkem.mlkem_encapsulate(bytes(pk), "ML-KEM-768")
        return (bytes(ct), bytes(ss))

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        ss = self._mlkem.mlkem_decapsulate(bytes(sk), bytes(ct), "ML-KEM-768")
        return bytes(ss)

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        err = "KEM adapter does not support signing"
        raise NotImplementedError(err)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        err = "KEM adapter does not support verification"
        raise NotImplementedError(err)


def load_adapter(impl_adapter: str) -> AdapterProtocol:
    """Load and return an mlkem adapter by its import path."""
    if impl_adapter == "mlkem.ml_kem_768":
        return MlkemAdapter()
    raise ImportError(f"adapter module not found: {impl_adapter}")