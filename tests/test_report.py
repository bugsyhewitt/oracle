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

MULTI = [
    {
        "category": "reachable_selfdestruct",
        "severity": "high",
        "pc": 10,
        "op": "SELFDESTRUCT",
        "trace": [{"pc": 10, "op": "SELFDESTRUCT"}],
        "trigger_input": {},
    },
    {
        "category": "arbitrary_storage_write",
        "severity": "high",
        "pc": 20,
        "op": "SSTORE",
        "trace": [{"pc": 20, "op": "SSTORE"}],
        "trigger_input": {},
    },
    {
        "category": "integer_overflow",
        "severity": "medium",
        "pc": 30,
        "op": "ADD",
        "trace": [{"pc": 30, "op": "ADD"}],
        "trigger_input": {},
    },
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


def test_h1md_summary_block_banding_and_order():
    out = format_h1md(MULTI, "x.sol")
    summary = out.split("## 1.")[0]  # everything before the first finding section
    # Severity banding: highest band first, only non-zero bands.
    assert "## Summary" in summary
    assert "**Severity:** 2 High, 1 Medium" in summary
    # A jump table listing every finding precedes the detail sections.
    assert "| # | Severity | Finding | Opcode | pc |" in summary
    assert "| 1 | High | Reachable SELFDESTRUCT | `SELFDESTRUCT` | 10 |" in summary
    assert "| 3 | Medium | Integer Overflow | `ADD` | 30 |" in summary


def test_h1md_summary_appears_before_findings():
    out = format_h1md(MULTI, "x.sol")
    assert out.index("## Summary") < out.index("## 1.")


def test_h1md_summary_omits_zero_bands():
    # Single medium finding -> banding is just "1 Medium", no High/Low noise.
    out = format_h1md(SAMPLE, "x.sol")
    assert "**Severity:** 1 Medium" in out
    assert "High" not in out.split("## 1.")[0]


def test_h1md_empty_has_no_summary_block():
    out = format_h1md([], "x.sol")
    assert "## Summary" not in out
