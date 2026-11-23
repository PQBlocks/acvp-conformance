"""Tests for adapter protocol conformance and registry (E2-E3 edge cases).

Slice S2 contract (spec/spec.md §5):
  src/pqblocks_acvp/adapters.py with AdapterProtocol (Protocol class),
  load_adapter(impl_adapter: str) -> AdapterProtocol, registry of known adapters.

Tests:
- protocol conformance for kyber_py.ml_kem_768 / dilithium_py.ml_dsa_65
- load_adapter for kyber_py.ml_kem_768 and dilithium_py.ml_dsa_65
- E2 (missing adapter module) -> ImportError naming the module
- E3 (adapter protocol mismatch) -> TypeError listing missing methods
- registry: known adapters registered, custom registration, defensive copy
- roundtrip + tuple ordering + wire sizes for both adapters

Oracle notes (spec/spec.md §3):
- E2 mandates `ImportError("adapter module not found: X")`.
- E3 mandates `TypeError("adapter missing required method: X")` listing the
  missing methods (this is the message product code must emit).
"""
import sys
import types

import pytest

from pqblocks_acvp.adapters import (
    AdapterProtocol,
    get_registered_adapters,
    load_adapter,
    register_adapter,
)

# --- FIPS 203 / FIPS 204 sizes for the two named adapters ------------------
# ML-KEM-768 (FIPS 203 §3): ek=384k+32=1184, dk=768k+96=2400,
# c=32(du*k+dv)=1088, K=32.  ML-DSA-65 (FIPS 204 §3): pk=1952, sk=4032,
# sig=3309.
MLKEM768_EK = 1184
MLKEM768_DK = 2400
MLKEM768_CT = 1088
MLKEM768_SS = 32
MLDSA65_PK = 1952
MLDSA65_SK = 4032
MLDSA65_SIG = 3309


def _make_module(name, **attrs):
    """Create a module object and inject it into sys.modules.

    Lets a test define an adapter class locally and still have the real
    importlib code path in load_adapter resolve it by import path.
    """
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


class TestAdapterProtocolConformance:
    """Test that known adapters implement AdapterProtocol correctly."""

    def test_adapter_protocol_conformance_kyber(self):
        """kyber_py.ml_kem_768 implements AdapterProtocol."""
        adapter = load_adapter("kyber_py.ml_kem_768")
        assert isinstance(adapter, AdapterProtocol)

    def test_adapter_protocol_conformance_dilithium(self):
        """dilithium_py.ml_dsa_65 implements AdapterProtocol."""
        adapter = load_adapter("dilithium_py.ml_dsa_65")
        assert isinstance(adapter, AdapterProtocol)

    def test_protocol_is_runtime_checkable(self):
        """AdapterProtocol can be used with isinstance() (runtime_checkable)."""
        assert isinstance(load_adapter("kyber_py.ml_kem_768"), AdapterProtocol)
        assert isinstance(load_adapter("dilithium_py.ml_dsa_65"), AdapterProtocol)

    def test_protocol_requires_all_five_methods(self):
        """A bare object with none of the methods is NOT conformant."""
        assert not isinstance(object(), AdapterProtocol)


class TestLoadAdapter:
    """Test load_adapter function."""

    def test_load_adapter_kyber(self):
        """load_adapter returns valid adapter for kyber_py.ml_kem_768."""
        adapter = load_adapter("kyber_py.ml_kem_768")
        assert hasattr(adapter, "keygen")
        assert hasattr(adapter, "encaps")
        assert hasattr(adapter, "decaps")

    def test_load_adapter_dilithium(self):
        """load_adapter returns valid adapter for dilithium_py.ml_dsa_65."""
        adapter = load_adapter("dilithium_py.ml_dsa_65")
        assert hasattr(adapter, "keygen")
        assert hasattr(adapter, "sign")
        assert hasattr(adapter, "verify")

    def test_load_adapter_returns_fresh_registry_entry(self):
        """A registered name resolves through the registry, not a hardcoded branch."""
        seen = load_adapter("kyber_py.ml_kem_768")
        known = get_registered_adapters()
        assert "kyber_py.ml_kem_768" in known
        assert isinstance(seen, known["kyber_py.ml_kem_768"])

    def test_load_adapter_rejects_empty_string(self):
        """An empty adapter path is a load error, not a crash."""
        with pytest.raises(ImportError):
            load_adapter("")


class TestRegistry:
    """The registry of known adapters (S2 output)."""

    def test_known_adapters_registered(self):
        """Built-in adapter names are present in the registry."""
        known = get_registered_adapters()
        assert "kyber_py.ml_kem_768" in known
        assert "dilithium_py.ml_dsa_65" in known

    def test_get_registered_adapters_is_defensive_copy(self):
        """Mutating the returned mapping cannot corrupt the registry."""
        known = get_registered_adapters()
        known["poisoned"] = dict
        assert "poisoned" not in get_registered_adapters()

    def test_register_adapter_then_load(self, monkeypatch):
        """register_adapter + load_adapter round-trip works, then is undone."""
        sentinel = "PQC_ACVP_TEST_SENTINEL"

        class FakeAdapter:
            def keygen(self):
                return (b"pk", b"sk")

            def encaps(self, pk):
                return (b"ct", b"ss")

            def decaps(self, sk, ct):
                return b"ss"

            def sign(self, sk, msg):
                return b"sig"

            def verify(self, pk, msg, sig):
                return sentinel

        monkeypatch.setitem(
            sys.modules,
            "fake_adapter_module",
            _make_module("fake_adapter_module", FakeAdapter=FakeAdapter),
        )

        register_adapter("fake_adapter_module.FakeAdapter", FakeAdapter)
        try:
            loaded = load_adapter("fake_adapter_module.FakeAdapter")
            assert isinstance(loaded, FakeAdapter)
            assert loaded.verify(b"pk", b"msg", b"sig") == sentinel
        finally:
            from pqblocks_acvp.adapters import _adapter_registry

            _adapter_registry.pop("fake_adapter_module.FakeAdapter", None)


class TestEdgeCaseE2:
    """E2: Missing adapter module - ImportError naming the path."""

    def test_E2_missing_adapter_module(self):
        """ImportError for nonexistent module (E2)."""
        with pytest.raises(ImportError) as exc_info:
            load_adapter("nonexistent.module")
        assert "adapter module not found" in str(exc_info.value)
        assert "nonexistent.module" in str(exc_info.value)

    def test_E2_wrong_import_path(self):
        """ImportError for invalid import path (E2)."""
        with pytest.raises(ImportError) as exc_info:
            load_adapter("nonexistent")
        assert "adapter module not found" in str(exc_info.value) or "adapter class not found" in str(exc_info.value)

    def test_E2_bare_name_reports_module_not_found(self):
        """A path with no module part is reported as a missing module."""
        with pytest.raises(ImportError) as exc_info:
            load_adapter("nonexistent")
        assert "adapter module not found" in str(exc_info.value)
        assert "nonexistent" in str(exc_info.value)

    def test_E2_missing_class_in_existing_module(self):
        """Existing module, missing attribute -> ImportError naming the class."""
        with pytest.raises(ImportError) as exc_info:
            load_adapter("kyber_py.ml_kem.NoSuchAdapter")
        assert "adapter class not found" in str(exc_info.value)
        assert "kyber_py.ml_kem.NoSuchAdapter" in str(exc_info.value)


class TestEdgeCaseE3:
    """E3: Adapter protocol mismatch - TypeError listing missing methods."""

    def test_E3_protocol_mismatch(self):
        """TypeError when the loaded class does not implement the protocol (E3)."""
        with pytest.raises(TypeError) as exc_info:
            load_adapter("builtins.dict")
        message = str(exc_info.value)
        assert "adapter missing required method" in message
        # E3: "listing missing methods"
        for method in ("keygen", "encaps", "decaps", "sign", "verify"):
            assert method in message

    def test_E3_missing_method(self):
        """TypeError when an adapter defines only some of the methods (E3).

        Oracle per spec §3 E3: `TypeError("adapter missing required method: X")`
        listing the missing methods. The local class is injected into
        sys.modules so load_adapter's real importlib path resolves it.
        """

        class IncompleteAdapter:
            def keygen(self):
                return (b"pk", b"sk")

        monkeypatch_mod = _make_module(
            "incomplete_adapter_module", IncompleteAdapter=IncompleteAdapter
        )
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "incomplete_adapter_module", monkeypatch_mod)
            with pytest.raises(TypeError) as exc_info:
                load_adapter("incomplete_adapter_module.IncompleteAdapter")

        message = str(exc_info.value)
        assert "adapter missing required method" in message
        for method in ("encaps", "decaps", "sign", "verify"):
            assert method in message
        assert "keygen" not in message.replace("keygen, ", "")


class TestAdapterRoundtrip:
    """Test actual cryptographic operations and their wire sizes."""

    def test_adapter_roundtrip_kyber(self):
        """keygen/encaps/decaps roundtrip works for kyber_py.ml_kem_768."""
        adapter = load_adapter("kyber_py.ml_kem_768")

        pk, sk = adapter.keygen()
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

        ct, ss1 = adapter.encaps(pk)
        assert isinstance(ct, bytes)
        assert isinstance(ss1, bytes)

        ss2 = adapter.decaps(sk, ct)
        assert isinstance(ss2, bytes)
        assert ss1 == ss2, "Encaps/Decaps roundtrip failed: shared secrets don't match"

    def test_kyber_wire_sizes_per_fips203(self):
        """Sizes match FIPS 203 for ML-KEM-768 (ek/dk/c/K)."""
        adapter = load_adapter("kyber_py.ml_kem_768")
        pk, sk = adapter.keygen()
        assert len(pk) == MLKEM768_EK
        assert len(sk) == MLKEM768_DK
        ct, ss = adapter.encaps(pk)
        assert len(ct) == MLKEM768_CT
        assert len(ss) == MLKEM768_SS

    def test_kyber_encaps_returns_ct_then_ss(self):
        """AdapterProtocol returns (ct, ss), not the library's (ss, ct)."""
        adapter = load_adapter("kyber_py.ml_kem_768")
        pk, sk = adapter.keygen()
        ct, ss = adapter.encaps(pk)
        # 32-byte shared secret must be the SECOND element per the protocol
        assert len(ss) == MLKEM768_SS
        assert len(ct) == MLKEM768_CT
        assert len(ct) > len(ss)
        assert adapter.decaps(sk, ct) == ss

    def test_kyber_decaps_rejects_wrong_length_ciphertext(self):
        """A wrong-length ciphertext is rejected loudly, not silently."""
        adapter = load_adapter("kyber_py.ml_kem_768")
        pk, sk = adapter.keygen()
        with pytest.raises(ValueError):
            adapter.decaps(sk, b"\x00" * 32)

    def test_adapter_roundtrip_dilithium(self):
        """sign/verify roundtrip works for dilithium_py.ml_dsa_65."""
        adapter = load_adapter("dilithium_py.ml_dsa_65")

        pk, sk = adapter.keygen()
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

        msg = b"test message for signing"
        sig = adapter.sign(sk, msg)
        assert isinstance(sig, bytes)

        assert adapter.verify(pk, msg, sig), "Signature verification failed"
        assert not adapter.verify(pk, b"wrong message", sig), "Should not verify wrong message"
        # Per spec §3 E4, a wrong-length public key is rejected with ValueError
        # before reaching the library (reject-then-act), not a bare False.
        with pytest.raises(ValueError):
            adapter.verify(b"wrong pk", msg, sig)

    def test_dilithium_wire_sizes_per_fips204(self):
        """Sizes match FIPS 204 for ML-DSA-65 (pk/sk/sig)."""
        adapter = load_adapter("dilithium_py.ml_dsa_65")
        pk, sk = adapter.keygen()
        assert len(pk) == MLDSA65_PK
        assert len(sk) == MLDSA65_SK
        sig = adapter.sign(sk, b"message")
        assert len(sig) == MLDSA65_SIG

    def test_dilithium_verify_rejects_wrong_length_pk(self):
        """A wrong-length public key raises an actionable ValueError."""
        adapter = load_adapter("dilithium_py.ml_dsa_65")
        pk, sk = adapter.keygen()
        msg = b"test message for signing"
        sig = adapter.sign(sk, msg)

        with pytest.raises(ValueError) as exc_info:
            adapter.verify(b"wrong pk", msg, sig)
        message = str(exc_info.value)
        assert "public key" in message
        assert str(MLDSA65_PK) in message
        assert str(len(b"wrong pk")) in message

    def test_dilithium_verify_rejects_correct_length_foreign_key(self):
        """A correct-length key that is NOT the signer's must return False.

        This is the meaningful negative case: the length is right, the key is
        wrong, and the adapter must report False rather than raise.
        """
        adapter = load_adapter("dilithium_py.ml_dsa_65")
        msg = b"test message for signing"
        pk_a, sk_a = adapter.keygen()
        pk_b, _ = adapter.keygen()
        sig_a = adapter.sign(sk_a, msg)

        assert adapter.verify(pk_a, msg, sig_a)
        assert not adapter.verify(pk_b, msg, sig_a), "foreign key verified"

    def test_dilithium_verify_rejects_wrong_length_signature(self):
        """A wrong-length signature raises an actionable ValueError."""
        adapter = load_adapter("dilithium_py.ml_dsa_65")
        pk, sk = adapter.keygen()
        msg = b"test message for signing"
        sig = adapter.sign(sk, msg)

        with pytest.raises(ValueError) as exc_info:
            adapter.verify(pk, msg, sig[:100])
        message = str(exc_info.value)
        assert "signature" in message
        assert str(MLDSA65_SIG) in message
        assert "100" in message

    def test_kem_adapter_refuses_signature_ops(self):
        """A KEM adapter does not pretend to sign (loud NotImplementedError)."""
        adapter = load_adapter("kyber_py.ml_kem_768")
        pk, _ = adapter.keygen()
        with pytest.raises(NotImplementedError):
            adapter.sign(pk, b"msg")
        with pytest.raises(NotImplementedError):
            adapter.verify(pk, b"msg", b"sig")

    def test_signature_adapter_refuses_kem_ops(self):
        """A signature adapter does not pretend to encapsulate."""
        adapter = load_adapter("dilithium_py.ml_dsa_65")
        pk, sk = adapter.keygen()
        with pytest.raises(NotImplementedError):
            adapter.encaps(pk)
        with pytest.raises(NotImplementedError):
            adapter.decaps(sk, b"\x00" * 1088)
