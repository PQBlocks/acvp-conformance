"""Tests for CLI Runner and Execution Modes."""

import json
from pqblocks_acvp.runner import main


def test_runner_spdx_flag(capsys):
    rc = main(["--spdx"])
    assert rc == 0
    captured = capsys.readouterr()
    manifest = json.loads(captured.out)
    assert manifest["spdxVersion"] == "SPDX-2.3"


def test_runner_golden_json_flag(capsys):
    rc = main(["--golden", "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "Reference-FIPS-Oracle" in data
    assert data["Reference-FIPS-Oracle"]["total_attempted"] == 4


def test_runner_default_cli_table(capsys):
    rc = main(["--golden"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "pqblocks-acvp Conformance Report" in captured.out


def test_mlkem_encapdecap_file_has_zero_mismatches():
    from pathlib import Path
    from pqblocks_acvp.parser import ACVPParser
    from pqblocks_acvp.harness import ConformanceHarness
    from pqblocks_acvp.adapters.reference import ReferencePQCAdapter

    path = Path(__file__).parent / "vectors" / "ML-KEM-encapDecap-FIPS203" / "internalProjection.json"
    rep = ConformanceHarness([ReferencePQCAdapter()]).run_session(ACVPParser.parse_file(str(path)))["Reference-FIPS-Oracle"]
    s = rep.summary_dict()
    assert s["mismatches"] == 0
    assert (rep.total_attempted, rep.passed, rep.unsupported_operations, rep.adapter_errors) == (165, 105, 60, 0)


def test_cli_table_has_mismatch_column(capsys):
    main(["--golden"])
    out = capsys.readouterr().out
    assert "Mismatch" in out.splitlines()[5]
