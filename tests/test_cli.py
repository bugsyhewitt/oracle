"""CLI surface tests (criterion 2) — Z3-free via the mock boundary."""

import json
import os

import pytest

from oracle.cli import _gate_triggered, build_parser, main

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_help_lists_required_options(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    for token in ["--contract", "--input-type", "--check", "--max-depth", "--format"]:
        assert token in out


def test_check_choices_present():
    parser = build_parser()
    # ensure the full check vocabulary is accepted
    for chk in ["assertion", "overflow", "selfdestruct", "ether-leak", "storage-write", "all"]:
        ns = parser.parse_args(
            ["--contract", "x.bin", "--input-type", "bytecode", "--check", chk]
        )
        assert ns.check == chk


def test_max_depth_defaults_to_12():
    parser = build_parser()
    ns = parser.parse_args(["--contract", "x.bin", "--input-type", "bytecode"])
    assert ns.max_depth == 12


def test_sequence_depth_defaults_to_one():
    parser = build_parser()
    ns = parser.parse_args(["--contract", "x.bin", "--input-type", "bytecode"])
    assert ns.sequence_depth == 1


def test_sequence_depth_is_parsed():
    parser = build_parser()
    ns = parser.parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "--sequence-depth", "3"]
    )
    assert ns.sequence_depth == 3


def test_help_lists_sequence_depth(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--sequence-depth" in out


def test_sequence_depth_below_one_exits_2(capsys):
    rc = main(
        [
            "--contract",
            os.path.join(FIXTURES, "assertion-violation.sol"),
            "--input-type",
            "sol",
            "--check",
            "assertion",
            "--sequence-depth",
            "0",
        ]
    )
    assert rc == 2


def test_format_choices():
    parser = build_parser()
    ns = parser.parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "--format", "h1md"]
    )
    assert ns.format == "h1md"


def test_format_choice_sarif():
    parser = build_parser()
    ns = parser.parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "--format", "sarif"]
    )
    assert ns.format == "sarif"


def test_input_type_required():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--contract", "x.bin"])


def test_missing_contract_file_exits_2(capsys):
    rc = main(
        ["--contract", "/no/such/file.bin", "--input-type", "bytecode", "--check", "assertion"]
    )
    assert rc == 2


def test_coverage_flag_defaults_to_none():
    parser = build_parser()
    ns = parser.parse_args(["--contract", "x.bin", "--input-type", "bytecode"])
    assert ns.coverage is None


def test_coverage_flag_is_parsed():
    parser = build_parser()
    ns = parser.parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "--coverage", "cov.info"]
    )
    assert ns.coverage == "cov.info"


def test_help_lists_coverage(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--coverage" in out


def test_cli_coverage_writes_lcov_file(tmp_path, capsys):
    cov_path = tmp_path / "oracle.info"
    rc = main(
        [
            "--contract",
            os.path.join(FIXTURES, "assertion-violation.sol"),
            "--input-type",
            "sol",
            "--check",
            "assertion",
            "--format",
            "json",
            "--coverage",
            str(cov_path),
        ]
    )
    assert rc == 0
    # findings still go to stdout as usual
    err = capsys.readouterr().err
    assert "coverage:" in err
    # the LCOV file exists and is well-formed
    text = cov_path.read_text()
    assert text.startswith("TN:oracle\n")
    assert "SF:" in text
    assert "end_of_record" in text
    # at least one instruction must have been reached (hit count 1)
    assert any(line.endswith(",1") for line in text.splitlines() if line.startswith("DA:"))
    # LF/LH summary lines are present and LH <= LF
    lf = int([l for l in text.splitlines() if l.startswith("LF:")][0][3:])
    lh = int([l for l in text.splitlines() if l.startswith("LH:")][0][3:])
    assert 0 < lh <= lf


def test_cli_coverage_bad_path_exits_2(capsys):
    rc = main(
        [
            "--contract",
            os.path.join(FIXTURES, "assertion-violation.sol"),
            "--input-type",
            "sol",
            "--check",
            "assertion",
            "--coverage",
            "/no/such/dir/cov.info",
        ]
    )
    assert rc == 2


# --------------------------------------------------------------------------- #
# --fail-on severity exit-code gate
# --------------------------------------------------------------------------- #
def test_fail_on_defaults_to_none():
    parser = build_parser()
    ns = parser.parse_args(["--contract", "x.bin", "--input-type", "bytecode"])
    assert ns.fail_on == "none"


def test_fail_on_choices_parsed():
    parser = build_parser()
    for band in ["none", "low", "medium", "high"]:
        ns = parser.parse_args(
            ["--contract", "x.bin", "--input-type", "bytecode", "--fail-on", band]
        )
        assert ns.fail_on == band


def test_fail_on_rejects_unknown_band():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["--contract", "x.bin", "--input-type", "bytecode", "--fail-on", "critical"]
        )


def test_help_lists_fail_on(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--fail-on" in out


def test_gate_none_never_triggers():
    findings = [{"severity": "high"}, {"severity": "medium"}]
    assert _gate_triggered(findings, "none") is False


def test_gate_no_findings_never_triggers():
    assert _gate_triggered([], "high") is False
    assert _gate_triggered([], "low") is False


def test_gate_triggers_at_or_above_threshold():
    # high finding clears every band
    assert _gate_triggered([{"severity": "high"}], "high") is True
    assert _gate_triggered([{"severity": "high"}], "medium") is True
    assert _gate_triggered([{"severity": "high"}], "low") is True


def test_gate_does_not_trigger_below_threshold():
    # a medium finding must NOT trip a high-only gate
    assert _gate_triggered([{"severity": "medium"}], "high") is False
    # a low finding must NOT trip a medium gate
    assert _gate_triggered([{"severity": "low"}], "medium") is False


def test_gate_picks_highest_finding():
    findings = [{"severity": "low"}, {"severity": "high"}]
    assert _gate_triggered(findings, "high") is True


def test_gate_unknown_severity_is_weakest():
    # an unrecognised band is treated as rank 0 and never gates
    assert _gate_triggered([{"severity": "informational"}], "low") is False
    assert _gate_triggered([{"severity": ""}], "low") is False


def test_cli_fail_on_high_returns_1(capsys):
    # the assertion fixture yields a medium finding; gate on medium -> exit 1
    rc = main(
        [
            "--contract",
            os.path.join(FIXTURES, "assertion-violation.sol"),
            "--input-type",
            "sol",
            "--check",
            "assertion",
            "--fail-on",
            "medium",
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "fail-on:" in err


def test_cli_fail_on_above_findings_returns_0(capsys):
    # assertion_violation is medium; gating on high should NOT fail the build
    rc = main(
        [
            "--contract",
            os.path.join(FIXTURES, "assertion-violation.sol"),
            "--input-type",
            "sol",
            "--check",
            "assertion",
            "--fail-on",
            "high",
        ]
    )
    assert rc == 0
    # findings still emitted to stdout
    data = json.loads(capsys.readouterr().out)
    assert data["finding_count"] >= 1


def test_cli_fail_on_default_returns_0_with_findings(capsys):
    # default fail-on=none must preserve historical exit-0-on-success behaviour
    rc = main(
        [
            "--contract",
            os.path.join(FIXTURES, "assertion-violation.sol"),
            "--input-type",
            "sol",
            "--check",
            "assertion",
        ]
    )
    assert rc == 0


def test_cli_json_output_assertion(capsys):
    rc = main(
        [
            "--contract",
            os.path.join(FIXTURES, "assertion-violation.sol"),
            "--input-type",
            "sol",
            "--check",
            "assertion",
            "--format",
            "json",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["tool"] == "oracle"
    assert data["finding_count"] >= 1
    cats = [f["category"] for f in data["findings"]]
    assert "assertion_violation" in cats
