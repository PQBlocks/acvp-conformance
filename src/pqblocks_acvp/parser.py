"""ACVP JSON Parser for NIST FIPS 203, 204, and 205 test vectors."""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TestCase:
    tcId: int
    function: str
    parameter_set: str
    inputs: Dict[str, Any]
    expected: Dict[str, Any]
    test_type: str = "AFT"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        blob = f"{self.tcId}:{self.function}:{self.parameter_set}:{sorted(self.inputs.items())}:{sorted(self.expected.items())}"
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class TestGroup:
    tgId: int
    algorithm: str
    mode: str
    parameter_set: str
    function: str
    test_type: str
    test_cases: List[TestCase] = field(default_factory=list)


@dataclass
class ACVPTestSession:
    vsId: int
    algorithm: str
    groups: List[TestGroup] = field(default_factory=list)

    @property
    def total_test_cases(self) -> int:
        return sum(len(g.test_cases) for g in self.groups)

    def compute_sha256(self) -> str:
        dump = json.dumps(
            [
                {
                    "tgId": g.tgId,
                    "cases": [c.tcId for c in g.test_cases],
                }
                for g in self.groups
            ],
            sort_keys=True,
        )
        return hashlib.sha256(dump.encode("utf-8")).hexdigest()


class ACVPParser:
    @staticmethod
    def parse_file(path: str) -> ACVPTestSession:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return ACVPParser.parse_dict(data)

    @staticmethod
    def parse_dict(data: Dict[str, Any]) -> ACVPTestSession:
        vsId = data.get("vsId", 1)
        algorithm = data.get("algorithm", "ML-KEM")
        test_groups_data = data.get("testGroups", [])
        groups = []

        for tg in test_groups_data:
            tgId = tg.get("tgId", 1)
            alg = tg.get("algorithm", algorithm)
            mode = tg.get("mode", "")
            param_set = tg.get("parameterSet", "ML-KEM-768")
            # ACVP sigVer/sigGen/keyGen groups carry no `function`: the file's top-level `mode`
            # names it. Defaulting to "encapsulation" sent every ML-DSA case down the KEM path.
            function = tg.get("function") or {"sigVer": "signatureVerification", "sigGen": "signatureGeneration",
                                              "keyGen": "keyGen"}.get(str(data.get("mode", "")), "encapsulation")
            test_type = tg.get("testType", "AFT")

            test_cases = []
            for tc in tg.get("tests", []):
                tcId = tc.get("tcId", 0)
                # Inputs vary by function
                inputs = {k: v for k, v in tc.items() if k not in ("tcId", "resultsArray", "testPassed", "k", "c", "sig")}
                # group-level variant flags decide which verification algorithm applies
                for flag in ("signatureInterface", "preHash", "externalMu"):
                    if flag in tg:
                        inputs["_" + flag] = tg[flag]
                expected = {}
                if "k" in tc:
                    expected["k"] = tc["k"]
                if "c" in tc:
                    expected["c"] = tc["c"]
                if "sig" in tc:
                    expected["sig"] = tc["sig"]
                if "testPassed" in tc:
                    expected["testPassed"] = tc["testPassed"]
                if "resultsArray" in tc:
                    expected["resultsArray"] = tc["resultsArray"]

                test_cases.append(
                    TestCase(
                        tcId=tcId,
                        function=function,
                        parameter_set=param_set,
                        inputs=inputs,
                        expected=expected,
                        test_type=test_type,
                    )
                )

            groups.append(
                TestGroup(
                    tgId=tgId,
                    algorithm=alg,
                    mode=mode,
                    parameter_set=param_set,
                    function=function,
                    test_type=test_type,
                    test_cases=test_cases,
                )
            )

        return ACVPTestSession(vsId=vsId, algorithm=algorithm, groups=groups)
