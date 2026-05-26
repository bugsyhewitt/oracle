"""Analysis driver tests.

Default tests (Z3 mocked) validate finding SHAPE and detector dispatch.
`@pytest.mark.slow` tests invoke real Z3 against the fixtures and validate the
satisfiability / trigger_input contract (criteria 3-7).
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.disassembler import parse_bytecode

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
