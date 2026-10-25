# EVIDENCE: pqblocks-acvp

This document lists the primary cryptographic standards, protocol specifications, and official test vector sources underpinning `pqblocks-acvp`, together with a method-to-code traceability map.

---

## Primary Sources

1. **NIST FIPS 203**: *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (August 2024).
   - Publication: National Institute of Standards and Technology.
   - DOI: [10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)
   - Scope: Specification of ML-KEM-512, ML-KEM-768, and ML-KEM-1024; Algorithm 16 (KeyGen), Algorithm 17 (Encaps), Algorithm 18 (Decaps), and Section 7.3 (Decapsulation Key Format and Input Checks).

2. **NIST FIPS 204**: *Module-Lattice-Based Digital Signature Standard* (August 2024).
   - Publication: National Institute of Standards and Technology.
   - DOI: [10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)
   - Scope: Specification of ML-DSA-44, ML-DSA-65, and ML-DSA-87; pure and pre-hashed signature verification interfaces; context parameter length bound ($|ctx| \le 255$).

3. **NIST FIPS 205**: *Stateless Hash-Based Digital Signature Standard* (August 2024).
   - Publication: National Institute of Standards and Technology.
   - DOI: [10.6028/NIST.FIPS.205](https://doi.org/10.6028/NIST.FIPS.205)
   - Scope: Specification of SLH-DSA parameters, SHAKE and SHA-2 instantiations.

4. **NIST SP 800-205**: *Automated Cryptographic Validation Protocol (ACVP) Specification*.
   - Publication: National Institute of Standards and Technology.
   - URL: [https://csrc.nist.gov/publications/detail/sp/800-205/final](https://csrc.nist.gov/publications/detail/sp/800-205/final)
   - Scope: JSON schema and session exchange model for automated cryptographic algorithm testing.

5. **NIST ACVP-Server Test Corpora**:
   - Repository: [https://github.com/usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server)
   - Specific paths: `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json`, `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`.

---

## Method-to-Code Traceability Map

| Standard / Section | Cryptographic Method / Requirement | Implementation in `pqblocks-acvp` | Verified By |
|---|---|---|---|
| **FIPS 203 §6.1** | ML-KEM Key Generation (Alg 16) from random seeds $d$ and $z$ | `pqblocks_acvp.reference.MLKEMReferenceOracle.keygen` | `test_reference.py::test_mlkem_encap_decap_roundtrip` |
| **FIPS 203 §6.2** | ML-KEM Encapsulation (Alg 17) producing ciphertext $c$ and shared key $K$ | `pqblocks_acvp.reference.MLKEMReferenceOracle.encapsulate` | `test_official_vectors.py::test_mlkem_encapsulation_matches_nist` (60 KATs) |
| **FIPS 203 §6.3** | ML-KEM Decapsulation (Alg 18) producing shared key $K$ or implicit rejection $\bar{K}$ | `pqblocks_acvp.reference.MLKEMReferenceOracle.decapsulate` | `test_official_vectors.py::test_mlkem_decapsulation_matches_nist` (60 KATs) |
| **FIPS 203 §7.3** | Decapsulation input check ($H(ek)$ matching embedded $dk$ hash) | `pqblocks_acvp.reference.MLKEMReferenceOracle.decapsulate` | `test_reference.py::test_mlkem_decapsulation_rejects_inconsistent_dk` |
| **FIPS 203 Alg 18** | Implicit rejection key derivation: $\bar{K} = \text{SHAKE256}(z \parallel c, 32)$ | `pqblocks_acvp.reference.MLKEMReferenceOracle.decapsulate` | `test_edge_cases.py::test_e06_invalid_ciphertext_implicit_rejection` |
| **FIPS 204 §6.3** | ML-DSA Signature Verification (pure external interface) | `pqblocks_acvp.reference.MLDSAReferenceOracle.verify` | `test_official_vectors.py::test_mldsa_verify_matches_nist` (30 KATs) |
| **FIPS 204 §5.4** | Maximum context string length constraint: $|ctx| \le 255$ | `pqblocks_acvp.adapters.reference.ReferencePQCAdapter.execute_case` | `test_edge_cases.py::test_e15_mldsa_context_mismatch` |
| **ACVP Spec** | Parsing session, group, test case structure and test digests | `pqblocks_acvp.parser.ACVPParser` | `test_parser.py::test_parser_loads_json` |
| **Harness Rule** | Denominator preservation: $\text{Attempted} = \text{Pass} + \text{DVR} + \text{Unsupp} + \text{Err} + \text{Mismatch}$ | `pqblocks_acvp.harness.ConformanceReport.denominator_verified` | `test_harness.py::test_denominator_preservation` |
| **Taxonomy** | 5-way classification with explicit mismatch handling | `pqblocks_acvp.taxonomy.TaxonomyClassifier` | `test_taxonomy.py::test_accept_all_verifier_on_forged_signature_is_a_mismatch` |
| **Re-execution** | Differential sampling and agreement rate across adapters | `pqblocks_acvp.g7_framework.G7ReexecutionFramework` | `test_g7.py::test_g7_independent_reexecution` |
