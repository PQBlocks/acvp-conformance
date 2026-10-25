# pqblocks-acvp

Cross-implementation NIST ACVP and FIPS 203/204/205 post-quantum cryptography conformance harness.
Use it when evaluating and verifying post-quantum cryptography implementations against official NIST ACVP test corpora without denominator shrinkage.
Standards implemented: NIST ACVP, FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA).

```bash
pip install pqblocks-acvp
```

```python
from pqblocks_acvp.runner import build_golden_session
from pqblocks_acvp.harness import ConformanceHarness
from pqblocks_acvp.adapters.reference import ReferencePQCAdapter

session = build_golden_session()
harness = ConformanceHarness([ReferencePQCAdapter()])
reports = harness.run_session(session)
rep = reports["Reference-FIPS-Oracle"]
print(f"Executed {rep.total_attempted} cases: {rep.passed} passed (denominator verified: {rep.denominator_verified})")
```

---

## Why PQBlocks?

Most conformance testing scripts suffer from favorable-case attrition: when a target library lacks support for an algorithm or key format (such as Go `crypto/mlkem` lacking ML-KEM-512, or liboqs using internal randomness), tests are silently omitted or dropped from the denominator, inflating the reported pass rate.

`pqblocks-acvp` solves this with:
1. **Strict 4-Way Error Taxonomy**: Every test case is categorized into exactly one of: `PASS`, `DOCUMENTED_VALIDATION_REJECTION`, `UNSUPPORTED_OPERATION`, `ADAPTER_INVOCATION_ERROR`, or `MISMATCH`.
2. **Strict Denominator Preservation**: The total attempted cases must strictly equal the sum of all taxonomy buckets:
   $$\text{Attempted} = \text{Passed} + \text{DVR} + \text{Unsupported} + \text{Errors} + \text{Mismatches}$$
3. **Cross-Implementation Adapters**: Bridges different library interfaces, including expanded decapsulation keys (2,400–3,168 bytes) vs seed keys (64 bytes), pure Python reference oracles, `pyca/cryptography`, and `liboqs`.
4. **Independent Re-execution Framework**: Random sampling and differential verification across multiple adapter implementations to guarantee consistency.

---

## Installation

```bash
pip install pqblocks-acvp
```

Optional dependencies:
- For `pyca/cryptography` adapter: `pip install "cryptography>=41.0.0"`
- For `liboqs` adapter: system `liboqs.so` and `pip install liboqs-python`

---

## Usage

### Command Line Interface

```bash
# Run built-in golden conformance test session
python -m pqblocks_acvp.runner --golden

# Output results as structured JSON
python -m pqblocks_acvp.runner --golden --json

# Run against an external NIST ACVP JSON test file
python -m pqblocks_acvp.runner --corpus /path/to/internalProjection.json

# Export SPDX 2.3 license compliance manifest
python -m pqblocks_acvp.runner --spdx
```

### Python API

```python
from pqblocks_acvp.parser import ACVPParser
from pqblocks_acvp.harness import ConformanceHarness
from pqblocks_acvp.adapters.reference import ReferencePQCAdapter
from pqblocks_acvp.adapters.go_bridge import GoBridgeAdapter
from pqblocks_acvp.adapters.pyca import PyCAAdapter

# Parse an official NIST ACVP session
session = ACVPParser.parse_file("tests/vectors/ML-KEM-encapDecap-FIPS203/internalProjection.json")

# Configure target adapters
adapters = [
    ReferencePQCAdapter(),
    GoBridgeAdapter(),
    PyCAAdapter(),
]

# Run the test harness
harness = ConformanceHarness(adapters)
reports = harness.run_session(session)

for adapter_name, report in reports.items():
    print(f"Adapter: {adapter_name}")
    print(f"  Total Attempted: {report.total_attempted}")
    print(f"  Passed:          {report.passed}")
    print(f"  DVR:             {report.documented_validation_rejections}")
    print(f"  Unsupported:     {report.unsupported_operations}")
    print(f"  Mismatches:      {report.mismatches}")
    print(f"  Denominator OK:  {report.denominator_verified}")
```

---

## API Reference

### `pqblocks_acvp.harness`

- `ConformanceHarness(adapters: List[BasePQCAdapter])`: Test orchestrator managing cross-implementation execution.
  - `run_session(session: ACVPTestSession) -> Dict[str, ConformanceReport]`: Executes all test cases in the session across all configured adapters.
  - `run_case(test_case: TestCase) -> Dict[str, ExecutionResult]`: Executes a single test case across all configured adapters.
- `ConformanceReport`: Data class holding per-adapter metrics (`total_attempted`, `passed`, `documented_validation_rejections`, `unsupported_operations`, `adapter_errors`, `mismatches`, `results`).
  - `.denominator_verified -> bool`: Returns `True` if `total_attempted == passed + documented_validation_rejections + unsupported_operations + adapter_errors + mismatches`.
  - `.summary_dict() -> Dict[str, Any]`: Serializes the report summary to a Python dictionary.

### `pqblocks_acvp.parser`

- `ACVPParser`: Static parser for NIST ACVP JSON vector files.
  - `parse_file(path: str) -> ACVPTestSession`: Parses an ACVP JSON file from disk.
  - `parse_dict(data: Dict[str, Any]) -> ACVPTestSession`: Parses an in-memory ACVP dictionary.
- `TestCase(tcId, function, parameter_set, inputs, expected)`: Represents an individual test case.
- `TestGroup(tgId, algorithm, mode, parameter_set, function, test_type, test_cases)`: Represents a group of related test cases sharing common parameters.
- `ACVPTestSession(vsId, algorithm, groups)`: Top-level container for an ACVP validation session.

### `pqblocks_acvp.taxonomy`

- `TaxonomyCategory(Enum)`:
  - `PASS`: Implementation output matches expected NIST vector bit-for-bit.
  - `DOCUMENTED_VALIDATION_REJECTION`: Implementation correctly rejected malformed/invalid inputs per specification.
  - `UNSUPPORTED_OPERATION`: Target library does not implement the requested algorithm, mode, or key format.
  - `ADAPTER_INVOCATION_ERROR`: Communication, parsing, or runtime crash occurred.
  - `MISMATCH`: Implementation completed execution but returned incorrect cryptographic output.
- `TaxonomyClassifier`:
  - `classify(actual, expected, unsupported=False, validation_rejected=False, exit_code=0, error_msg="") -> TaxonomyCategory`: Classifies a test execution outcome.

### `pqblocks_acvp.reference`

- `MLKEMReferenceOracle`:
  - `keygen(parameter_set: str, d_hex: str, z_hex: str) -> Tuple[str, str]`: Generates `(ek, dk)` from 32-byte hex seeds `d` and `z`.
  - `encapsulate(parameter_set: str, ek_hex: str, m_hex: str) -> Tuple[str, str]`: Produces `(c, k)` ciphertext and shared key from public key `ek` and 32-byte seed `m`.
  - `decapsulate(parameter_set: str, dk_hex: str, c_hex: str) -> str`: Decapsulates ciphertext `c` using expanded secret key `dk` to produce shared key `k`.
- `MLDSAReferenceOracle`:
  - `verify(parameter_set: str, pk_hex: str, msg_hex: str, sig_hex: str, ctx_hex: str = "") -> bool`: Verifies an ML-DSA digital signature against public key `pk` and message `msg`.

### `pqblocks_acvp.adapters`

- `BasePQCAdapter(name: str)`: Abstract base class for all target adapters.
  - `supports_algorithm(parameter_set: str, function: str) -> bool`
  - `run(test_case: TestCase) -> ExecutionResult`
- `ReferencePQCAdapter`: In-process reference oracle adapter (built on `kyber-py` and `dilithium-py`).
- `GoBridgeAdapter`: Adapter interface for Go `crypto/mlkem` (bridges 2,400-byte expanded keys to Go internal decapsulation key representations).
- `PyCAAdapter`: Adapter for `pyca/cryptography` ML-KEM and ML-DSA implementations.
- `LibOQSAdapter`: Adapter for `liboqs` C-library key encapsulation and digital signature verification.

---

## Limitations

1. **Not a Cryptographic Implementation**: `pqblocks-acvp` is a test harness and conformance validator; it is not designed to perform cryptographic encryption or signature operations in high-throughput production environments.
2. **Third-Party Runtime Dependencies**: Testing external libraries (such as Go `crypto/mlkem` or C `liboqs`) requires those runtimes to be installed on the host system. When absent, the harness correctly records them as `UNSUPPORTED_OPERATION`.
3. **Validation Status**: `pqblocks-acvp` is self-verified against official NIST ACVP test vectors and FIPS 203/204/205 specifications. It is not an accredited NVLAP laboratory report or CMVP validation certificate.

---

## Security Notes

See [SECURITY_NOTES.md](SECURITY_NOTES.md) for details on memory safety, input handling, and side-channel considerations.

---

## Verification

Full verification evidence and test results are documented in:
- [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md)
- [TESTING.md](TESTING.md)
- [BENCHMARKS.md](BENCHMARKS.md)
- [EVIDENCE.md](EVIDENCE.md)

---

## Part of PQBlocks

`pqblocks-acvp` is part of the **PQBlocks** suite of post-quantum cryptographic primitives, tools, and verification engines.
License: Apache-2.0.
