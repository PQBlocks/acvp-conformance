"""Adapter wrapper for oqs (liboqs-python).

This module implements AdapterProtocol over oqs.KeyEncapsulation('ML-KEM-768')
and oqs.Signature('ML-DSA-65').  liboqs returns bytes from generate_keypair()
(public key only); the secret key is obtained via export_secret_key() and the
adapter keeps it for the protocol's (pk, sk) keygen contract.
"""
from typing import Tuple

import oqs

from pqblocks_acvp.adapters import AdapterProtocol


class OqsPythonAdapter(AdapterProtocol):
    """Adapter over oqs.KeyEncapsulation('ML-KEM-768') for ML-KEM-768."""

    _ALG = "ML-KEM-768"

    def __init__(self):
        self._kem = oqs.KeyEncapsulation(self._ALG)
        self._sk = None

    def keygen(self) -> Tuple[bytes, bytes]:
        pk = bytes(self._kem.generate_keypair())
        sk = bytes(self._kem.export_secret_key())
        self._sk = sk
        return (pk, sk)

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        if len(pk) != self._kem.length_public_key:
            raise ValueError(
                f"public key length {len(pk)} != {self._kem.length_public_key} for ML-KEM-768"
            )
        ct, ss = self._kem.encap_secret(bytes(pk))
        return (bytes(ct), bytes(ss))

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        if len(ct) != self._kem.length_ciphertext:
            raise ValueError(
                f"ciphertext length {len(ct)} != {self._kem.length_ciphertext} for ML-KEM-768"
            )
        return bytes(self._kem.decap_secret(bytes(ct)))

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        err = "KEM adapter does not support signing"
        raise NotImplementedError(err)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        err = "KEM adapter does not support verification"
        raise NotImplementedError(err)


class OqsPythonSignatureAdapter(AdapterProtocol):
    """Adapter over oqs.Signature('ML-DSA-65') for ML-DSA-65."""

    _ALG = "ML-DSA-65"

    def __init__(self):
        self._sig = oqs.Signature(self._ALG)

    def keygen(self) -> Tuple[bytes, bytes]:
        pk = bytes(self._sig.generate_keypair())
        sk = bytes(self._sig.export_secret_key())
        return (pk, sk)

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return bytes(self._sig.sign(bytes(msg)))

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        if len(pk) != self._sig.length_public_key:
            raise ValueError(
                f"public key length {len(pk)} != {self._sig.length_public_key} for ML-DSA-65"
            )
        if len(sig) != self._sig.length_signature:
            raise ValueError(
                f"signature length {len(sig)} != {self._sig.length_signature} for ML-DSA-65"
            )
        return bool(self._sig.verify(bytes(msg), bytes(sig), bytes(pk)))

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        err = "Signature adapter does not support encaps"
        raise NotImplementedError(err)

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        err = "Signature adapter does not support decapsulation"
        raise NotImplementedError(err)


class OqsPythonSlhDsaAdapter(AdapterProtocol):
    """Adapter over oqs.Signature('SLH_DSA_PURE_SHA2_128S') for SLH-DSA-SHA2-128s."""

    _ALG = "SLH_DSA_PURE_SHA2_128S"

    def __init__(self):
        self._sig = oqs.Signature(self._ALG)

    def keygen(self) -> Tuple[bytes, bytes]:
        pk = bytes(self._sig.generate_keypair())
        sk = bytes(self._sig.export_secret_key())
        return (pk, sk)

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return bytes(self._sig.sign(bytes(msg)))

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        if len(pk) != self._sig.length_public_key:
            raise ValueError(
                f"public key length {len(pk)} != {self._sig.length_public_key} for SLH-DSA-SHA2-128s"
            )
        if len(sig) != self._sig.length_signature:
            raise ValueError(
                f"signature length {len(sig)} != {self._sig.length_signature} for SLH-DSA-SHA2-128s"
            )
        return bool(self._sig.verify(bytes(msg), bytes(sig), bytes(pk)))

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        err = "Signature adapter does not support encaps"
        raise NotImplementedError(err)

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        err = "Signature adapter does not support decapsulation"
        raise NotImplementedError(err)


def load_adapter(impl_adapter: str) -> AdapterProtocol:
    """Load and return an oqs adapter by its import path.

    Supported paths: oqs.ml_kem_768, oqs.ml_dsa_65, oqs.SLH_DSA_PURE_SHA2_128S
    """
    if impl_adapter == "oqs.ml_kem_768":
        return OqsPythonAdapter()
    if impl_adapter == "oqs.ml_dsa_65":
        return OqsPythonSignatureAdapter()
    if impl_adapter == "oqs.SLH_DSA_PURE_SHA2_128S":
        return OqsPythonSlhDsaAdapter()
    raise ImportError(f"adapter module not found: {impl_adapter}")