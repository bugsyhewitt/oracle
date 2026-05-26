"""Report formatter tests (Z3-free)."""

import json

from oracle.report import format_h1md, format_json, format_report

SAMPLE = [
    {
        "category": "assertion_violation",
        "severity": "medium",
        "pc": 74,
        "op": "INVALID",
        "depth": 1,
        "trace": [{"pc": 0, "op": "CALLVALUE"}, {"pc": 74, "op": "INVALID"}],
        "trigger_input": {"calldata": "0x" + "00" * 32},
    }
]


def test_format_json_shape():
    out = format_json(SAMPLE, "x.sol")
    data = json.loads(out)
    assert data["tool"] == "oracle"
    assert data["contract"] == "x.sol"
    assert data["finding_count"] == 1
    assert data["findings"][0]["category"] == "assertion_violation"


def test_format_h1md_contains_sections():
    out = format_h1md(SAMPLE, "x.sol")
    assert "# oracle" in out
    assert "Assertion Violation" in out
    assert "Trigger input" in out
    assert "Execution trace" in out
    assert "INVALID" in out


def test_format_h1md_empty():
    out = format_h1md([], "x.sol")
    assert "No findings" in out


def test_format_report_dispatch():
    assert json.loads(format_report(SAMPLE, "x", "json"))["finding_count"] == 1
    assert "# oracle" in format_report(SAMPLE, "x", "h1md")
