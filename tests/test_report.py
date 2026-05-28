"""Report formatter tests (Z3-free)."""

import json

from oracle import __version__
from oracle.report import (
    format_coverage_lcov,
    format_h1md,
    format_json,
    format_report,
    format_sarif,
)

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


# ---------------------------------------------------------------------- #
# SARIF v2.1.0 formatter
# ---------------------------------------------------------------------- #
def test_sarif_top_level_shape():
    out = format_sarif(SAMPLE, "x.sol")
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert data["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(data["runs"]) == 1
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "oracle"
    assert driver["version"] == __version__


def test_sarif_one_result_per_finding():
    data = json.loads(format_sarif(MULTI, "x.sol"))
    results = data["runs"][0]["results"]
    assert len(results) == len(MULTI)
    rule_ids = [r["ruleId"] for r in results]
    assert rule_ids == [
        "reachable_selfdestruct",
        "arbitrary_storage_write",
        "integer_overflow",
    ]


def test_sarif_rules_are_deduplicated_per_category():
    dup = MULTI + [dict(MULTI[0])]  # second reachable_selfdestruct finding
    data = json.loads(format_sarif(dup, "x.sol"))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    # four findings but only three distinct categories => three rules
    assert sorted(rule_ids) == [
        "arbitrary_storage_write",
        "integer_overflow",
        "reachable_selfdestruct",
    ]
    # ...while every finding still produces its own result row
    assert len(data["runs"][0]["results"]) == 4


def test_sarif_level_maps_severity():
    data = json.loads(format_sarif(MULTI, "x.sol"))
    by_rule = {r["ruleId"]: r for r in data["runs"][0]["results"]}
    # high -> error, medium -> error (both are real reachable bugs)
    assert by_rule["reachable_selfdestruct"]["level"] == "error"
    assert by_rule["integer_overflow"]["level"] == "error"


def test_sarif_security_severity_property():
    data = json.loads(format_sarif(MULTI, "x.sol"))
    rules = {r["id"]: r for r in data["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["reachable_selfdestruct"]["properties"]["security-severity"] == "8.0"
    assert rules["integer_overflow"]["properties"]["security-severity"] == "5.0"


def test_sarif_location_uses_contract_uri_and_pc_line():
    data = json.loads(format_sarif(SAMPLE, "contracts/Vault.sol"))
    loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "contracts/Vault.sol"
    # pc 74 -> 1-based startLine 75
    assert loc["region"]["startLine"] == 75


def test_sarif_result_properties_carry_pc_and_opcode():
    data = json.loads(format_sarif(SAMPLE, "x.sol"))
    props = data["runs"][0]["results"][0]["properties"]
    assert props["pc"] == 74
    assert props["opcode"] == "INVALID"
    assert props["trigger_input"] == {"calldata": "0x" + "00" * 32}


def test_sarif_confidence_surfaces_when_present():
    finding = dict(SAMPLE[0])
    finding["confidence"] = "timeout"
    data = json.loads(format_sarif([finding], "x.sol"))
    result = data["runs"][0]["results"][0]
    assert result["properties"]["confidence"] == "timeout"
    assert "Confidence: timeout" in result["message"]["text"]


def test_sarif_empty_is_valid_run_with_no_results():
    data = json.loads(format_sarif([], "x.sol"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_rule_title_for_newer_detectors():
    finding = {
        "category": "reentrancy",
        "severity": "high",
        "pc": 5,
        "op": "CALL",
        "trace": [],
        "trigger_input": {},
    }
    data = json.loads(format_sarif([finding], "x.sol"))
    rule = data["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "reentrancy"
    assert "Reentrancy" in rule["shortDescription"]["text"]


def test_format_report_dispatch_sarif():
    out = format_report(SAMPLE, "x.sol", "sarif")
    assert json.loads(out)["version"] == "2.1.0"


# --------------------------------------------------------------------- #
# LCOV instruction-coverage formatter
# --------------------------------------------------------------------- #
COVERAGE = {
    "total_instructions": 4,
    "covered_instructions": 2,
    "coverage_pct": 50.0,
    "covered_pcs": [0, 5],
    "uncovered_pcs": [3, 9],
}


def test_lcov_header_and_footer():
    out = format_coverage_lcov(COVERAGE, "Vault.sol")
    lines = out.splitlines()
    assert lines[0] == "TN:oracle"
    assert lines[1] == "SF:Vault.sol"
    assert "end_of_record" in lines
    assert out.endswith("\n")


def test_lcov_da_lines_map_pc_to_line_and_hits():
    out = format_coverage_lcov(COVERAGE, "Vault.sol")
    da = [l for l in out.splitlines() if l.startswith("DA:")]
    # one DA line per instruction (covered + uncovered), sorted by pc
    assert da == ["DA:1,1", "DA:4,0", "DA:6,1", "DA:10,0"]


def test_lcov_summary_counts():
    out = format_coverage_lcov(COVERAGE, "Vault.sol")
    assert "LF:4" in out  # lines found = total instructions
    assert "LH:2" in out  # lines hit = covered instructions


def test_lcov_empty_contract():
    cov = {
        "total_instructions": 0,
        "covered_instructions": 0,
        "coverage_pct": 0.0,
        "covered_pcs": [],
        "uncovered_pcs": [],
    }
    out = format_coverage_lcov(cov, "Empty.sol")
    assert "LF:0" in out
    assert "LH:0" in out
    assert not any(l.startswith("DA:") for l in out.splitlines())


def test_lcov_all_covered_has_no_zero_hits():
    cov = {
        "total_instructions": 2,
        "covered_instructions": 2,
        "coverage_pct": 100.0,
        "covered_pcs": [0, 1],
        "uncovered_pcs": [],
    }
    out = format_coverage_lcov(cov, "Full.sol")
    da = [l for l in out.splitlines() if l.startswith("DA:")]
    assert all(l.endswith(",1") for l in da)
    assert "LH:2" in out and "LF:2" in out
