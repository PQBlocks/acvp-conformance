# pqblocks-acvp

NIST ACVP conformance harness for FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), with a pure-Python reference oracle (kyber-py, dilithium-py) and partial adapters for pyca/cryptography (pure ML-DSA sigVer) and liboqs (ML-KEM decapsulation), plus a Go placeholder.
Use it when evaluating and verifying post-quantum cryptography implementations against official NIST ACVP test corpora without denominator shrinkage.
Standards implemented: NIST ACVP, FIPS 203 (ML-KEM), FIPS 204 (ML-DSA). SLH-DSA (FIPS 205) is not yet covered.

```bash
pip install git+https://github.com/PQBlocks/acvp-conformance
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
1. **5-way outcome taxonomy**: Every test case is categorized into exactly one of: `PASS`, `DOCUMENTED_VALIDATION_REJECTION`, `UNSUPPORTED_OPERATION`, `ADAPTER_INVOCATION_ERROR`, or `MISMATCH`.
2. **Strict Denominator Preservation**: The total attempted cases must strictly equal the sum of all taxonomy buckets:
   $$\text{Attempted} = \text{Passed} + \text{DVR} + \text{Unsupported} + \text{Errors} + \text{Mismatches}$$
3. **Adapters**: one `BasePQCAdapter` interface. An adapter that cannot consume an ACVP case (pyca's seed-only ML-KEM keys, liboqs' internal randomness) reports it as `UNSUPPORTED_OPERATION`. No key-format conversion is implemented.
4. **Re-execution helper** (`G7ReexecutionFramework`): samples cases and compares two adapters' outcome categories. It has only been run against the Go placeholder (agreement 0.0).

---

## Installation

```bash
pip install git+https://github.com/PQBlocks/acvp-conformance
```

Optional dependencies:
- For `pyca/cryptography` adapter: `pip install "cryptography>=47.0.0"`
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

# Print the fixed reference-component licence list (SPDX 2.3-shaped, not a full SPDX document)
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
- `GoBridgeAdapter`: placeholder for Go `crypto/mlkem`. No Go program is called; every case is reported `UNSUPPORTED_OPERATION`.
- `PyCAAdapter`: pyca/cryptography (≥ 47) ML-DSA external/pure signature verification; ML-KEM cases are reported unsupported.
- `LibOQSAdapter`: liboqs ML-KEM decapsulation only; encapsulation (no caller `m`) and ML-DSA are reported unsupported.

---

## Limitations

0. **Measured on the vendored corpus**: on `ML-KEM-encapDecap-FIPS203` (165 cases) the reference oracle gives 105 passed, 60 unsupported (key-check functions), 0 mismatches, 0 errors. The CLI text table has a Mismatch column; `--json` gives the full summary.

1. **Not a Cryptographic Implementation**: `pqblocks-acvp` is a test harness and conformance validator; it is not designed to perform cryptographic encryption or signature operations in high-throughput production environments.
2. **Third-Party Runtime Dependencies**: Testing external libraries (such as Go `crypto/mlkem` or C `liboqs`) requires those runtimes to be installed on the host system. When absent, the harness correctly records them as `UNSUPPORTED_OPERATION`.
3. **Validation Status**: `pqblocks-acvp` is self-verified against official NIST ACVP test vectors for FIPS 203 and FIPS 204 (SLH-DSA / FIPS 205 is not yet covered). It is not an accredited NVLAP laboratory report or CMVP validation certificate.

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
