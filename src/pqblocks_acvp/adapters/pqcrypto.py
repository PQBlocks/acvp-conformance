"""Adapter wrapper for pqcrypto.

This module implements AdapterProtocol over pqcrypto.kem.ml_kem_768 and
pqcrypto.sign.ml_dsa_65.  pqcrypto modules expose module-level functions
(keygen/encaps/decaps / keygen/sign/verify) rather than singleton instances.
"""
from typing import Tuple

import pqcrypto.kem.ml_kem_768 as _kem768
import pqcrypto.sign.ml_dsa_65 as _sig65

from pqblocks_acvp.adapters import AdapterProtocol


class PqcryptoAdapter(AdapterProtocol):
    """Adapter over pqcrypto for ML-KEM-768 and ML-DSA-65.

    Adapts pqcrypto's module-level API to AdapterProtocol.  Wrong-length
    inputs are rejected with ValueError naming the field, expected length and
    actual length (FIPS 203 / FIPS 204 sizes) before reaching pqcrypto.
    """

    # ML-KEM-768 sizes (FIPS 203 §3)
    MLKEM768_PK_SIZE = _kem768.PUBLIC_KEY_SIZE
    MLKEM768_SK_SIZE = _kem768.SECRET_KEY_SIZE
    MLKEM768_CT_SIZE = _kem768.CIPHERTEXT_SIZE
    MLKEM768_SS_SIZE = _kem768.SHARED_SECRET_SIZE

    # ML-DSA-65 sizes (FIPS 204 §3)
    MLDSA65_PK_SIZE = _sig65.PUBLIC_KEY_SIZE
    MLDSA65_SK_SIZE = _sig65.SECRET_KEY_SIZE
    MLDSA65_SIG_SIZE = _sig65.SIGNATURE_SIZE

    def __init__(self):
        self._kem = _kem768
        self._sig = _sig65

    # -- KEM operations --

    def keygen(self) -> Tuple[bytes, bytes]:
        pk, sk = self._kem.keygen()
        return (bytes(pk), bytes(sk))

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        if len(pk) != self.MLKEM768_PK_SIZE:
            raise ValueError(
                f"public key length {len(pk)} != {self.MLKEM768_PK_SIZE} for ML-KEM-768"
            )
        # pqcrypto returns (ct, ss); protocol canonicalises as (ct, ss) too.
        ct, ss = self._kem.encaps(bytes(pk))
        return (bytes(ct), bytes(ss))

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        if len(ct) != self.MLKEM768_CT_SIZE:
            raise ValueError(
                f"ciphertext length {len(ct)} != {self.MLKEM768_CT_SIZE} for ML-KEM-768"
            )
        return bytes(self._kem.decaps(bytes(sk), bytes(ct)))

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        err = "KEM adapter does not support signing"
        raise NotImplementedError(err)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        err = "KEM adapter does not support verification"
        raise NotImplementedError(err)


class PqcryptoSignatureAdapter(AdapterProtocol):
    """Adapter over pqcrypto.sign.ml_dsa_65 for ML-DSA-65."""

    MLDSA65_PK_SIZE = _sig65.PUBLIC_KEY_SIZE
    MLDSA65_SK_SIZE = _sig65.SECRET_KEY_SIZE
    MLDSA65_SIG_SIZE = _sig65.SIGNATURE_SIZE

    def __init__(self):
        self._sig = _sig65

    def keygen(self) -> Tuple[bytes, bytes]:
        pk, sk = self._sig.keygen()
        return (bytes(pk), bytes(sk))

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return bytes(self._sig.sign(bytes(sk), bytes(msg)))

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        if len(pk) != self.MLDSA65_PK_SIZE:
            raise ValueError(
                f"public key length {len(pk)} != {self.MLDSA65_PK_SIZE} for ML-DSA-65"
            )
        if len(sig) != self.MLDSA65_SIG_SIZE:
            raise ValueError(
                f"signature length {len(sig)} != {self.MLDSA65_SIG_SIZE} for ML-DSA-65"
            )
        try:
            self._sig.verify(bytes(pk), bytes(msg), bytes(sig))
            return True
        except Exception:
            return False

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        err = "Signature adapter does not support encaps"
        raise NotImplementedError(err)

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        err = "Signature adapter does not support decapsulation"
        raise NotImplementedError(err)


def load_adapter(impl_adapter: str) -> AdapterProtocol:
    """Load and return a pqcrypto adapter by its import path.

    Supported paths: pqcrypto.ml_kem_768, pqcrypto.ml_dsa_65
    """
    if impl_adapter == "pqcrypto.ml_kem_768":
        return PqcryptoAdapter()
    if impl_adapter == "pqcrypto.ml_dsa_65":
        return PqcryptoSignatureAdapter()
    raise ImportError(f"adapter module not found: {impl_adapter}")