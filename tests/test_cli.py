"""CLI surface tests (criterion 2) — Z3-free via the mock boundary."""

import json
import os

import pytest

from oracle.cli import build_parser, main

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


def test_input_type_required():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--contract", "x.bin"])


def test_missing_contract_file_exits_2(capsys):
    rc = main(
        ["--contract", "/no/such/file.bin", "--input-type", "bytecode", "--check", "assertion"]
    )
    assert rc == 2


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
