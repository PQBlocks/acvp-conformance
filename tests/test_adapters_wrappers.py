"""S3 slice tests — adapter implementations (wrappers) for the five libraries.

Slice S3 contract (spec/spec.md §5):
  src/pqblocks_acvp/adapters/ — kyber_py.py, dilithium_py.py, pqcrypto.py,
  oqs_python.py, mlkem.py — each wrapping its library to AdapterProtocol.
  Tests: each wrapper passes the protocol check, and a keygen/encaps/decaps
  (KEM) or keygen/sign/verify (signature) round-trip on one vector.

Oracle notes (spec/spec.md §2 + brief §2.4 size tables):
  - Wire sizes are the FIPS 203/204 ground truth (ek/dk/ct/ss and pk/sk/sig).
  - Wrong-length inputs are rejected loudly with ValueError naming the field,
    expected length and actual length (reject-then-act, E4–E6 behavior).
  - KEM adapters refuse signature ops and vice versa (loud NotImplementedError,
    never a silent fake result).
  - Signature verify returns a real bool (True valid / False invalid).
"""
import pytest

from pqblocks_acvp.adapters import AdapterProtocol, load_adapter

# --- FIPS 203 / FIPS 204 ground-truth wire sizes (brief §2.4) --------------
# ML-KEM-512: ek=800  dk=1632 ct=768   ss=32
# ML-KEM-768: ek=1184 dk=2400 ct=1088  ss=32
# ML-DSA-44:  pk=1312 sk=2560 sig=2420
# ML-DSA-65:  pk=1952 sk=4032 sig=3309
# ML-DSA-87:  pk=2592 sk=4896 sig=4627
KEM_CASES = [
    ("kyber_py.ml_kem_768", "ML-KEM-768", 1184, 2400, 1088, 32),
    ("pqcrypto.ml_kem_768", "ML-KEM-768", 1184, 2400, 1088, 32),
    ("oqs.ml_kem_768", "ML-KEM-768", 1184, 2400, 1088, 32),
]
SIG_CASES = [
    ("dilithium_py.ml_dsa_65", "ML-DSA-65", 1952, 4032, 3309),
    ("pqcrypto.ml_dsa_65", "ML-DSA-65", 1952, 4032, 3309),
    ("oqs.ml_dsa_65", "ML-DSA-65", 1952, 4032, 3309),
]

ALL_WRAPPER_PATHS = [c[0] for c in KEM_CASES] + [c[0] for c in SIG_CASES]


def _require_importable(name: str) -> bool:
    """Skip (not fail) when the underlying third-party library is absent.

    The wrapper itself must exist and conform; the library is
    an environment dependency. A missing library is reported as a skip with a
    named reason so the total is never silently shrunk.
    """
    import importlib

    roots = {
        "kyber_py": "kyber_py",
        "dilithium_py": "dilithium_py",
        "pqcrypto": "pqcrypto",
        "oqs": "oqs",
    }
    root = name.split(".")[0]
    try:
        importlib.import_module(roots.get(root, root))
        return True
    except ImportError as e:
        pytest.skip(f"library not importable for {name}: {e}")


class TestWrapperModuleLayout:
    """S3 output files exist and each exposes a wrapper class."""

    def test_adapters_package_importable(self):
        import pqblocks_acvp.adapters as adapters_pkg

        assert hasattr(adapters_pkg, "__path__"), (
            "src/pqblocks_acvp/adapters/ must be a package (S3 output)"
        )

    @pytest.mark.parametrize(
        "module_name",
        ["kyber_py", "dilithium_py", "pqcrypto", "oqs_python", "mlkem"],
    )
    def test_wrapper_module_exists(self, module_name):
        import importlib

        mod = importlib.import_module(f"pqblocks_acvp.adapters.{module_name}")
        assert mod is not None

    @pytest.mark.parametrize(
        "module_name, class_name",
        [
            ("kyber_py", "KyberPyAdapter"),
            ("dilithium_py", "DilithiumPyAdapter"),
            ("pqcrypto", "PqcryptoAdapter"),
            ("oqs_python", "OqsPythonAdapter"),
            ("mlkem", "MlkemAdapter"),
        ],
    )
    def test_wrapper_class_exposed(self, module_name, class_name):
        import importlib

        mod = importlib.import_module(f"pqblocks_acvp.adapters.{module_name}")
        assert hasattr(mod, class_name), (
            f"pqblocks_acvp.adapters.{module_name} must expose {class_name}"
        )


class TestWrapperConformance:
    """Each wrapper passes the AdapterProtocol isinstance check."""

    @pytest.mark.parametrize("name", ALL_WRAPPER_PATHS)
    def test_wrapper_conforms_to_protocol(self, name):
        _require_importable(name)
        adapter = load_adapter(name)
        assert isinstance(adapter, AdapterProtocol)

    @pytest.mark.parametrize("name", ALL_WRAPPER_PATHS)
    def test_load_adapter_resolves_wrapper(self, name):
        _require_importable(name)
        adapter = load_adapter(name)
        assert all(callable(getattr(adapter, m)) for m in
                   ("keygen", "encaps", "decaps", "sign", "verify"))


class TestKEMRoundtrip:
    """keygen/encaps/decaps round-trip + FIPS 203 wire sizes per adapter."""

    @pytest.mark.parametrize(
        "name,param,ek,dk,ct_size,ss_size", KEM_CASES
    )
    def test_kem_roundtrip_and_sizes(self, name, param, ek, dk, ct_size, ss_size):
        _require_importable(name)
        adapter = load_adapter(name)

        pk, sk = adapter.keygen()
        assert isinstance(pk, bytes) and isinstance(sk, bytes)
        assert len(pk) == ek, f"{name}: pk {len(pk)} != {ek}"
        assert len(sk) == dk, f"{name}: sk {len(sk)} != {dk}"

        ct, ss = adapter.encaps(pk)
        assert isinstance(ct, bytes) and isinstance(ss, bytes)
        assert len(ct) == ct_size, f"{name}: ct {len(ct)} != {ct_size}"
        assert len(ss) == ss_size, f"{name}: ss {len(ss)} != {ss_size}"

        ss2 = adapter.decaps(sk, ct)
        assert isinstance(ss2, bytes)
        assert ss2 == ss, f"{name}: shared secrets differ (roundtrip failed)"

    @pytest.mark.parametrize(
        "name,param,ek,dk,ct_size,ss_size", KEM_CASES
    )
    def test_kem_rejects_wrong_length_pk(self, name, param, ek, dk, ct_size, ss_size):
        """E4: wrong-length public key -> ValueError naming lengths."""
        _require_importable(name)
        adapter = load_adapter(name)
        with pytest.raises(ValueError) as exc_info:
            adapter.encaps(b"\x00" * 100)
        msg = str(exc_info.value)
        assert "100" in msg and str(ek) in msg, (
            f"{name}: encaps must name actual and expected lengths, got: {msg}"
        )

    @pytest.mark.parametrize(
        "name,param,ek,dk,ct_size,ss_size", KEM_CASES
    )
    def test_kem_rejects_wrong_length_ct(self, name, param, ek, dk, ct_size, ss_size):
        """E5: wrong-length ciphertext -> ValueError naming lengths."""
        _require_importable(name)
        adapter = load_adapter(name)
        pk, sk = adapter.keygen()
        with pytest.raises(ValueError) as exc_info:
            adapter.decaps(sk, b"\x00" * 500)
        msg = str(exc_info.value)
        assert "500" in msg and str(ct_size) in msg, (
            f"{name}: decaps must name actual and expected lengths, got: {msg}"
        )

    @pytest.mark.parametrize(
        "name,param,ek,dk,ct_size,ss_size", KEM_CASES
    )
    def test_kem_refuses_signature_ops(self, name, param, ek, dk, ct_size, ss_size):
        """A KEM adapter does not pretend to sign or verify."""
        _require_importable(name)
        adapter = load_adapter(name)
        with pytest.raises(NotImplementedError):
            adapter.sign(b"sk", b"msg")
        with pytest.raises(NotImplementedError):
            adapter.verify(b"pk", b"msg", b"sig")


class TestSignatureRoundtrip:
    """keygen/sign/verify round-trip + FIPS 204 wire sizes per adapter."""

    @pytest.mark.parametrize("name,param,pk_size,sk_size,sig_size", SIG_CASES)
    def test_sig_roundtrip_and_sizes(self, name, param, pk_size, sk_size, sig_size):
        _require_importable(name)
        adapter = load_adapter(name)

        pk, sk = adapter.keygen()
        assert isinstance(pk, bytes) and isinstance(sk, bytes)
        assert len(pk) == pk_size, f"{name}: pk {len(pk)} != {pk_size}"
        assert len(sk) == sk_size, f"{name}: sk {len(sk)} != {sk_size}"

        msg = b"pqblocks-acvp S3 roundtrip message"
        sig = adapter.sign(sk, msg)
        assert isinstance(sig, bytes)
        assert len(sig) == sig_size, f"{name}: sig {len(sig)} != {sig_size}"

        assert adapter.verify(pk, msg, sig) is True
        assert adapter.verify(pk, b"tampered message", sig) is False
        # Correct-length foreign key must verify False, not raise.
        other_pk, _ = adapter.keygen()
        assert adapter.verify(other_pk, msg, sig) is False

    @pytest.mark.parametrize("name,param,pk_size,sk_size,sig_size", SIG_CASES)
    def test_sig_rejects_wrong_length_sig(self, name, param, pk_size, sk_size, sig_size):
        """E6: wrong-length signature -> ValueError naming lengths."""
        _require_importable(name)
        adapter = load_adapter(name)
        pk, sk = adapter.keygen()
        with pytest.raises(ValueError) as exc_info:
            adapter.verify(pk, b"msg", b"\x00" * 100)
        msg = str(exc_info.value)
        assert "100" in msg and str(sig_size) in msg, (
            f"{name}: verify must name actual and expected lengths, got: {msg}"
        )

    @pytest.mark.parametrize("name,param,pk_size,sk_size,sig_size", SIG_CASES)
    def test_sig_refuses_kem_ops(self, name, param, pk_size, sk_size, sig_size):
        """A signature adapter does not pretend to encapsulate/decapsulate."""
        _require_importable(name)
        adapter = load_adapter(name)
        with pytest.raises(NotImplementedError):
            adapter.encaps(b"pk")
        with pytest.raises(NotImplementedError):
            adapter.decaps(b"sk", b"\x00" * 1088)


class TestVerifyReturnsBool:
    """verify() must return a real bool (True/False), never None or a raise
    for a wrong but well-formed signature (E6 applies only to wrong length)."""

    @pytest.mark.parametrize("name,param,pk_size,sk_size,sig_size", SIG_CASES)
    def test_verify_tampered_sig_returns_false(self, name, param, pk_size, sk_size, sig_size):
        _require_importable(name)
        adapter = load_adapter(name)
        pk, sk = adapter.keygen()
        msg = b"message"
        sig = adapter.sign(sk, msg)
        tampered = bytes([sig[0] ^ 0x01]) + sig[1:]
        result = adapter.verify(pk, msg, tampered)
        assert result is False
