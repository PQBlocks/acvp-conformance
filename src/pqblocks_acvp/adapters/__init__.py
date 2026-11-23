"""Adapter protocol (ABC) and registry for pqblocks-acvp.

This module defines the unified interface that Python PQC libraries must implement
to be compatible with the ACVP KAT runner. It also provides a registry and
loading function for known adapters.

Design notes
------------
* kyber_py.ml_kem_768 and dilithium_py.ml_dsa_65 are *instances* (singletons),
  not classes. The wrapper classes below delegate to them and translate their
  native tuple ordering into the protocol's canonical ``(ct, ss)`` order.
* Wrong-length inputs are rejected loudly with ``ValueError`` naming the field,
  the expected length and the actual length (defensive parsing, reject-then-act).
"""
from typing import Protocol, Type, Dict, runtime_checkable


@runtime_checkable
class AdapterProtocol(Protocol):
    """Unified adapter interface for Python PQC libraries (kyber_py, dilithium_py, pqcrypto, oqs, mlkem).

    The protocol requires the following methods:
    - keygen() -> tuple[bytes, bytes]: Generate public key (pk) and secret key (sk)
    - encaps(pk: bytes) -> tuple[bytes, bytes]: Encapsulate to get ciphertext (ct) and shared secret (ss)
    - decaps(sk: bytes, ct: bytes) -> bytes: Decapsulate to get shared secret (ss)
    - sign(sk: bytes, msg: bytes) -> bytes: Sign a message with the secret key
    - verify(pk: bytes, msg: bytes, sig: bytes) -> bool: Verify a signature with the public key

    All methods must return appropriate types and handle errors appropriately.
    """

    def keygen(self) -> tuple[bytes, bytes]:
        """Generate a public key (pk) and secret key (sk)."""
        ...

    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        """Encapsulate to get ciphertext (ct) and shared secret (ss)."""
        ...

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        """Decapsulate to get shared secret (ss)."""
        ...

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        """Sign a message with the secret key."""
        ...

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify a signature with the public key."""
        ...


# Registry of known adapters
_adapter_registry: Dict[str, Type[AdapterProtocol]] = {}

_REQUIRED_METHODS = ("keygen", "encaps", "decaps", "sign", "verify")


def _protocol_missing_methods(obj: object) -> tuple[str, ...]:
    """Return names of protocol methods missing or non-callable on *obj*."""
    missing = []
    for m in _REQUIRED_METHODS:
        attr = getattr(obj, m, None)
        if not callable(attr):
            missing.append(m)
    return tuple(missing)


def _check_protocol(obj: object, impl_adapter: str) -> None:
    """Raise TypeError listing missing protocol methods if *obj* doesn't conform."""
    missing = _protocol_missing_methods(obj)
    if missing:
        raise TypeError(
            f"adapter missing required method: {', '.join(missing)}"
        )


# --- Adapter Wrappers ---


class KyberAdapterWrapper:
    """Adapter wrapper for kyber_py.ml_kem providing AdapterProtocol conformance.

    kyber_py.ml_kem exposes pre-instantiated ML_KEM singleton objects (instances,
    not classes). ML-KEM has three parameter sets with distinct FIPS 203 wire
    sizes, so each concrete subclass below pins one variant (module attribute,
    human name). The base class carries the shared logic.

    NOTE on tuple ordering: kyber_py's ``encaps(ek)`` returns ``(K, c)`` =
    ``(shared_secret, ciphertext)``. ``AdapterProtocol`` canonicalises this as
    ``(ct, ss)`` = ``(ciphertext, shared_secret)``. We re-order here.
    """

    _VARIANT = "ML-KEM-768"
    _MODULE_ATTR = "ML_KEM_768"

    def __init__(self):
        import kyber_py.ml_kem as _ml_kem
        # Pre-instantiated singleton instance; do NOT call it.
        self._kem = getattr(_ml_kem, self._MODULE_ATTR)

    def keygen(self) -> tuple[bytes, bytes]:
        pk, sk = self._kem.keygen()
        return (bytes(pk), bytes(sk))

    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        # kyber_py returns (ss, ct); protocol wants (ct, ss).
        ss, ct = self._kem.encaps(bytes(pk))
        return (bytes(ct), bytes(ss))

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        return bytes(self._kem.decaps(bytes(sk), bytes(ct)))

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        err = "KEM adapter does not support signing"
        raise NotImplementedError(err)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        err = "KEM adapter does not support verification"
        raise NotImplementedError(err)


class KyberAdapterWrapper512(KyberAdapterWrapper):
    """ML-KEM-512 (FIPS 203 §5.1): pk=800, sk=1632, ct=768."""

    _VARIANT = "ML-KEM-512"
    _MODULE_ATTR = "ML_KEM_512"


class KyberAdapterWrapper768(KyberAdapterWrapper):
    """ML-KEM-768 (FIPS 203 §5.2): pk=1184, sk=2400, ct=1088."""

    _VARIANT = "ML-KEM-768"
    _MODULE_ATTR = "ML_KEM_768"


class KyberAdapterWrapper1024(KyberAdapterWrapper):
    """ML-KEM-1024 (FIPS 203 §5.3): pk=1568, sk=3168, ct=1568."""

    _VARIANT = "ML-KEM-1024"
    _MODULE_ATTR = "ML_KEM_1024"


class DilithiumAdapterWrapper:
    """Adapter wrapper for dilithium_py.ml_dsa providing AdapterProtocol conformance.

    dilithium_py.ml_dsa exposes pre-instantiated ML_DSA singleton objects (instances,
    not classes). ML-DSA has three parameter sets with distinct FIPS 204 §3 wire
    sizes, so each concrete subclass below pins one variant (module attribute,
    human name, pk/sk/sig lengths). The base class carries the shared logic.

    Wrong-length public keys and signatures are rejected with ``ValueError``
    naming the field, expected length and actual length (FIPS 204 sizes),
    before reaching the underlying library.
    """

    # FIPS 204 §3 defaults = ML-DSA-65; overridden per variant subclass.
    _VARIANT = "ML-DSA-65"
    _MODULE_ATTR = "ML_DSA_65"
    _PK_SIZE = 1952
    _SK_SIZE = 4032
    _SIG_SIZE = 3309

    def __init__(self):
        import dilithium_py.ml_dsa as _ml_dsa
        # Pre-instantiated singleton instance; do NOT call it.
        self._sig = getattr(_ml_dsa, self._MODULE_ATTR)

    def keygen(self) -> tuple[bytes, bytes]:
        pk, sk = self._sig.keygen()
        return (bytes(pk), bytes(sk))

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return bytes(self._sig.sign(bytes(sk), bytes(msg)))

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        if len(pk) != self._PK_SIZE:
            raise ValueError(
                f"public key length {len(pk)} != {self._PK_SIZE} for {self._VARIANT}"
            )
        if len(sig) != self._SIG_SIZE:
            raise ValueError(
                f"signature length {len(sig)} != {self._SIG_SIZE} for {self._VARIANT}"
            )
        return bool(self._sig.verify(bytes(pk), bytes(msg), bytes(sig)))

    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        err = "Signature adapter does not support encaps"
        raise NotImplementedError(err)

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        err = "Signature adapter does not support decapsulation"
        raise NotImplementedError(err)


class DilithiumAdapterWrapper44(DilithiumAdapterWrapper):
    """ML-DSA-44 (FIPS 204 §3.1): pk=1312, sk=2560, sig=2420."""

    _VARIANT = "ML-DSA-44"
    _MODULE_ATTR = "ML_DSA_44"
    _PK_SIZE = 1312
    _SK_SIZE = 2560
    _SIG_SIZE = 2420


class DilithiumAdapterWrapper65(DilithiumAdapterWrapper):
    """ML-DSA-65 (FIPS 204 §3.2): pk=1952, sk=4032, sig=3309."""

    _VARIANT = "ML-DSA-65"
    _MODULE_ATTR = "ML_DSA_65"
    _PK_SIZE = 1952
    _SK_SIZE = 4032
    _SIG_SIZE = 3309


class DilithiumAdapterWrapper87(DilithiumAdapterWrapper):
    """ML-DSA-87 (FIPS 204 §3.3): pk=2592, sk=4896, sig=4627."""

    _VARIANT = "ML-DSA-87"
    _MODULE_ATTR = "ML_DSA_87"
    _PK_SIZE = 2592
    _SK_SIZE = 4896
    _SIG_SIZE = 4627


def load_adapter(impl_adapter: str) -> AdapterProtocol:
    """Load and return an adapter instance by its import path.

    Args:
        impl_adapter: Import path string, e.g. "kyber_py.ml_kem_768" or
            "dilithium_py.ml_dsa_65", "pqcrypto.ml_kem_768", "oqs.ml_kem_768",
            "mlkem.ml_kem_768", or any registered name.

    Returns:
        An instance of a class that implements AdapterProtocol

    Raises:
        ImportError: If the module cannot be imported
        TypeError: If the loaded class/object does not implement AdapterProtocol
    """
    # Registry (built-in + user-registered) takes precedence.
    if impl_adapter in _adapter_registry:
        return _adapter_registry[impl_adapter]()

    # Built-in known adapters (also registered below).
    if impl_adapter == "kyber_py.ml_kem_768":
        return KyberAdapterWrapper768()
    if impl_adapter == "kyber_py.ml_kem_512":
        return KyberAdapterWrapper512()
    if impl_adapter == "kyber_py.ml_kem_1024":
        return KyberAdapterWrapper1024()
    if impl_adapter == "dilithium_py.ml_dsa_65":
        return DilithiumAdapterWrapper65()
    if impl_adapter == "dilithium_py.ml_dsa_44":
        return DilithiumAdapterWrapper44()
    if impl_adapter == "dilithium_py.ml_dsa_87":
        return DilithiumAdapterWrapper87()

    # --- S3 wrappers: dispatch to per-module load_adapter() so that pqcrypto/oqs/mLkem paths resolve.
    # Each wrapper module (pqcrypto.py, oqs_python.py, mlkem.py) exports its own load_adapter(path)
    # that knows how to instantiate the right adapter class for its library.
    if impl_adapter.startswith("pqcrypto."):
        from pqblocks_acvp.adapters.pqcrypto import load_adapter as _pqcrypto_load
        return _pqcrypto_load(impl_adapter)
    if impl_adapter.startswith("oqs."):
        from pqblocks_acvp.adapters.oqs_python import load_adapter as _oqs_load
        return _oqs_load(impl_adapter)
    if impl_adapter.startswith("mlkem."):
        from pqblocks_acvp.adapters.mlkem import load_adapter as _mlkem_load
        return _mlkem_load(impl_adapter)

    # Generic loading for other adapters: "module.Class"
    if "." not in impl_adapter:
        raise ImportError(f"adapter module not found: {impl_adapter}")

    module_name, class_name = impl_adapter.rsplit(".", 1)
    try:
        module = __import__(module_name, fromlist=[class_name])
        cls = getattr(module, class_name)
    except ImportError as e:
        raise ImportError(f"adapter module not found: {impl_adapter}") from e
    except AttributeError as e:
        raise ImportError(f"adapter class not found: {impl_adapter}") from e

    # Check conformance
    if isinstance(cls, type):
        # class -> instantiate then check
        instance = cls()
        _check_protocol(instance, impl_adapter)
        return instance
    # Pre-instantiated adapter object
    _check_protocol(cls, impl_adapter)
    return cls


def register_adapter(impl_adapter: str, cls: Type[AdapterProtocol]) -> None:
    """Register a custom adapter class.

    Args:
        impl_adapter: Import path string, e.g. "mycompany.myadapter"
        cls: The adapter class that implements AdapterProtocol
    """
    _adapter_registry[impl_adapter] = cls


def get_registered_adapters() -> Dict[str, Type[AdapterProtocol]]:
    """Get the current registry of known adapters (a defensive copy)."""
    return dict(_adapter_registry)


# --- Register built-in adapters (S2 core) so the registry is populated at import time.
register_adapter("kyber_py.ml_kem_768", KyberAdapterWrapper768)
register_adapter("kyber_py.ml_kem_512", KyberAdapterWrapper512)
register_adapter("kyber_py.ml_kem_1024", KyberAdapterWrapper1024)
register_adapter("dilithium_py.ml_dsa_65", DilithiumAdapterWrapper65)
register_adapter("dilithium_py.ml_dsa_44", DilithiumAdapterWrapper44)
register_adapter("dilithium_py.ml_dsa_87", DilithiumAdapterWrapper87)

# --- S3 wrappers: dispatch to per-module load_adapter() so that pqcrypto/oqs/mLkem paths resolve.
# Each wrapper module (pqcrypto.py, oqs_python.py, mlkem.py) exports its own load_adapter(path)
# that knows how to instantiate the right adapter class for its library.
# NOTE: The actual dispatch lives inside load_adapter() above; this comment block is for documentation only.


# Legacy adapters for backwards compatibility
from .base import BasePQCAdapter
from .reference import ReferencePQCAdapter
from .liboqs import LibOQSAdapter
from .pyca import PyCAAdapter
from .go_bridge import GoBridgeAdapter

__all__ = [
    "AdapterProtocol",
    "load_adapter",
    "BasePQCAdapter",
    "ReferencePQCAdapter",
    "LibOQSAdapter",
    "PyCAAdapter",
    "GoBridgeAdapter",
]
