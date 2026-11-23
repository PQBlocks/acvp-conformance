"""Direct unit tests for individual adapter modules to achieve complete branch coverage.
"""
import pytest
from pqblocks_acvp.adapters.kyber_py import KyberPyAdapter, load_adapter as load_kyber
from pqblocks_acvp.adapters.dilithium_py import DilithiumPyAdapter, load_adapter as load_dilithium
from pqblocks_acvp.adapters.mlkem import MlkemAdapter, load_adapter as load_mlkem
import runpy
import sys
from unittest.mock import patch


def test_kyber_py_adapter_direct():
    adapter = load_kyber("kyber_py.ml_kem_768")
    assert isinstance(adapter, KyberPyAdapter)
    
    pk, sk = adapter.keygen()
    assert isinstance(pk, bytes) and isinstance(sk, bytes)
    
    ct, ss = adapter.encaps(pk)
    assert isinstance(ct, bytes) and isinstance(ss, bytes)
    
    ss_decap = adapter.decaps(sk, ct)
    assert ss_decap == ss
    
    with pytest.raises(NotImplementedError, match="KEM adapter does not support signing"):
        adapter.sign(sk, b"hello")
        
    with pytest.raises(NotImplementedError, match="KEM adapter does not support verification"):
        adapter.verify(pk, b"hello", b"sig")

    with pytest.raises(ImportError):
        load_kyber("unknown.adapter")


def test_dilithium_py_adapter_direct():
    adapter = load_dilithium("dilithium_py.ml_dsa_65")
    assert isinstance(adapter, DilithiumPyAdapter)
    
    pk, sk = adapter.keygen()
    assert len(pk) == DilithiumPyAdapter._PK_SIZE
    assert len(sk) == DilithiumPyAdapter._SK_SIZE
    
    sig = adapter.sign(sk, b"test message")
    assert len(sig) == DilithiumPyAdapter._SIG_SIZE
    
    valid = adapter.verify(pk, b"test message", sig)
    assert valid is True
    
    # Wrong PK length
    with pytest.raises(ValueError, match="public key length"):
        adapter.verify(pk[:-1], b"test message", sig)
        
    # Wrong Sig length
    with pytest.raises(ValueError, match="signature length"):
        adapter.verify(pk, b"test message", sig[:-1])
        
    with pytest.raises(NotImplementedError, match="Signature adapter does not support encaps"):
        adapter.encaps(pk)
        
    with pytest.raises(NotImplementedError, match="Signature adapter does not support decapsulation"):
        adapter.decaps(sk, b"ct")

    with pytest.raises(ImportError):
        load_dilithium("unknown.adapter")


def test_mlkem_adapter_direct():
    try:
        adapter = load_mlkem("mlkem.ml_kem_768")
        assert isinstance(adapter, MlkemAdapter)
        pk, sk = adapter.keygen()
        ct, ss = adapter.encaps(pk)
        ss_decap = adapter.decaps(sk, ct)
        assert ss_decap == ss
        with pytest.raises(NotImplementedError):
            adapter.sign(sk, b"msg")
        with pytest.raises(NotImplementedError):
            adapter.verify(pk, b"msg", b"sig")
    except (ImportError, ModuleNotFoundError):
        pass

    with pytest.raises(ImportError):
        load_mlkem("unknown.adapter")


def test_main_module():
    with patch.object(sys, "argv", ["pqblocks_acvp", "--help"]):
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("pqblocks_acvp.__main__", run_name="__main__")
        assert exc.value.code == 0
