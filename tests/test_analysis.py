"""Analysis driver tests.

Default tests (Z3 mocked) validate finding SHAPE and detector dispatch.
`@pytest.mark.slow` tests invoke real Z3 against the fixtures and validate the
satisfiability / trigger_input contract (criteria 3-7).
"""

import os

import pytest

from oracle.analysis import analyze, compute_coverage
from oracle.compiler import load_runtime_bytecode
from oracle.laser.disassembler import Disassembly, parse_bytecode

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


# --------------------------------------------------------------------- #
# Default (Z3-mocked) tests: structure & dispatch
# --------------------------------------------------------------------- #
def test_assertion_finding_shape():
    findings = analyze(_bc("assertion-violation"), ["assertion"], max_depth=12)
    assert findings, "expected at least one assertion finding"
    f = findings[0]
    assert f["category"] == "assertion_violation"
    assert "severity" in f
    assert isinstance(f["trace"], list) and f["trace"]
    assert "trigger_input" in f
    assert all("op" in e and "pc" in e for e in f["trace"])


def test_overflow_finding_shape():
    findings = analyze(_bc("integer-overflow"), ["overflow"], max_depth=12)
    assert findings
    f = findings[0]
    assert f["category"] == "integer_overflow"
    assert "trace" in f and "trigger_input" in f


def test_selfdestruct_finding_shape():
    findings = analyze(_bc("reachable-selfdestruct"), ["selfdestruct"], max_depth=12)
    assert findings
    assert findings[0]["category"] == "reachable_selfdestruct"


def test_bytecode_input_mode_no_solc():
    # criterion 6: bytecode input from a shipped .bin, no solc involved
    with open(os.path.join(FIXTURES, "bytecode-selfdestruct.bin")) as fh:
        blob = fh.read()
    bc = parse_bytecode(blob)
    findings = analyze(bc, ["selfdestruct"], max_depth=12)
    assert findings
    assert findings[0]["category"] == "reachable_selfdestruct"


def test_unknown_check_raises():
    with pytest.raises(ValueError):
        analyze(_bc("assertion-violation"), ["bogus"], max_depth=12)


def test_all_checks_token_runs():
    findings = analyze(_bc("reachable-selfdestruct"), ["all"], max_depth=12)
    cats = {f["category"] for f in findings}
    assert "reachable_selfdestruct" in cats


def test_max_depth_prunes_deep_finding_mocked():
    # Even with Z3 mocked, the VM exploration honours max_depth, so the deep
    # finding's candidate is not even produced at shallow depth.
    shallow = analyze(_bc("deep-assertion"), ["assertion"], max_depth=4)
    deep = analyze(_bc("deep-assertion"), ["assertion"], max_depth=12)
    assert shallow == []
    assert len(deep) >= 1


# --------------------------------------------------------------------- #
# Instruction coverage (Z3-free: coverage is a property of exploration)
# --------------------------------------------------------------------- #
def test_coverage_shape():
    cov = compute_coverage(_bc("assertion-violation"), ["assertion"], max_depth=12)
    assert set(cov) == {
        "total_instructions",
        "covered_instructions",
        "coverage_pct",
        "covered_pcs",
        "uncovered_pcs",
    }
    assert cov["total_instructions"] > 0
    assert 0 < cov["covered_instructions"] <= cov["total_instructions"]
    assert 0.0 < cov["coverage_pct"] <= 100.0


def test_coverage_totals_match_disassembly():
    bc = _bc("assertion-violation")
    cov = compute_coverage(bc, ["assertion"], max_depth=12)
    total = len({i.pc for i in Disassembly(bc).instructions})
    assert cov["total_instructions"] == total
    # covered + uncovered partitions the full instruction set exactly once
    assert len(cov["covered_pcs"]) + len(cov["uncovered_pcs"]) == total
    assert set(cov["covered_pcs"]).isdisjoint(cov["uncovered_pcs"])
    assert cov["covered_instructions"] == len(cov["covered_pcs"])


def test_coverage_pcs_are_sorted_and_real_instructions():
    bc = _bc("reachable-selfdestruct")
    cov = compute_coverage(bc, ["selfdestruct"], max_depth=12)
    all_pcs = {i.pc for i in Disassembly(bc).instructions}
    assert cov["covered_pcs"] == sorted(cov["covered_pcs"])
    assert cov["uncovered_pcs"] == sorted(cov["uncovered_pcs"])
    # every reported pc is an actual instruction boundary (never a PUSH operand)
    for pc in cov["covered_pcs"] + cov["uncovered_pcs"]:
        assert pc in all_pcs


def test_coverage_deeper_depth_covers_at_least_as_much():
    bc = _bc("deep-assertion")
    shallow = compute_coverage(bc, ["assertion"], max_depth=4)
    deep = compute_coverage(bc, ["assertion"], max_depth=12)
    # raising the depth cap can only reach more (or equal) instructions
    assert deep["covered_instructions"] >= shallow["covered_instructions"]
    assert set(shallow["covered_pcs"]).issubset(deep["covered_pcs"])


def test_coverage_unknown_check_raises():
    with pytest.raises(ValueError):
        compute_coverage(_bc("assertion-violation"), ["bogus"], max_depth=12)


# --------------------------------------------------------------------- #
# Slow tests: real Z3
# --------------------------------------------------------------------- #
@pytest.mark.slow
def test_assertion_real_z3_trigger_input():
    findings = analyze(_bc("assertion-violation"), ["assertion"], max_depth=12)
    assert findings
    f = findings[0]
    assert f["category"] == "assertion_violation"
    assert f["trace"]
    # trigger_input must carry the symbolic input Z3 found
    assert "calldata" in f["trigger_input"]
    # the fixture triggers when arg == 66 (0x42)
    arg = f["trigger_input"].get("calldata_at_4", "")
    assert arg.endswith("42")


@pytest.mark.slow
def test_overflow_real_z3():
    findings = analyze(_bc("integer-overflow"), ["overflow"], max_depth=12)
    assert findings
    f = findings[0]
    assert f["category"] == "integer_overflow"
    assert f["trace"]
    assert "calldata" in f["trigger_input"]


@pytest.mark.slow
def test_selfdestruct_real_z3():
    findings = analyze(_bc("reachable-selfdestruct"), ["selfdestruct"], max_depth=12)
    assert findings
    assert findings[0]["category"] == "reachable_selfdestruct"
    assert findings[0]["trace"]


@pytest.mark.slow
def test_max_depth_real_z3():
    # criterion 7: depth 4 prunes, depth 12 finds
    shallow = analyze(_bc("deep-assertion"), ["assertion"], max_depth=4)
    deep = analyze(_bc("deep-assertion"), ["assertion"], max_depth=12)
    assert shallow == []
    assert len(deep) >= 1
    assert deep[0]["category"] == "assertion_violation"


@pytest.mark.slow
def test_bytecode_mode_real_z3():
    with open(os.path.join(FIXTURES, "bytecode-selfdestruct.bin")) as fh:
        blob = fh.read()
    findings = analyze(parse_bytecode(blob), ["selfdestruct"], max_depth=12)
    assert findings
    assert findings[0]["category"] == "reachable_selfdestruct"
