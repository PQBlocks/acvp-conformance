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
