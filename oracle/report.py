"""Report formatters for oracle findings: JSON, HackerOne-style markdown, SARIF."""

from __future__ import annotations

import hashlib
import json
from typing import List

from oracle import __version__


def format_json(findings: List[dict], contract: str) -> str:
    payload = {
        "tool": "oracle",
        "contract": contract,
        "finding_count": len(findings),
        "findings": findings,
    }
    return json.dumps(payload, indent=2)


_SEVERITY_LABEL = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

_TITLE = {
    "assertion_violation": "Assertion Violation (reachable INVALID)",
    "integer_overflow": "Integer Overflow",
    "integer_underflow": "Integer Underflow (SWC-101)",
    "reachable_selfdestruct": "Reachable SELFDESTRUCT",
    "unprotected_selfdestruct": "Unprotected SELFDESTRUCT (SWC-106)",
    "unconstrained_ether_transfer": "Unconstrained Ether Transfer",
    "arbitrary_storage_write": "Arbitrary Storage Write",
    "reentrancy": "Reentrancy (check-effects-interactions violation)",
    "access_control_escalation": "Access Control Escalation",
    "tx_origin_authentication": "tx.origin Authentication (SWC-115)",
    "delegatecall_untrusted_callee": "Delegatecall to Untrusted Callee (SWC-112)",
    "unchecked_call_return": "Unchecked Call Return Value (SWC-104)",
    "dos_failed_call": "DoS with Failed Call (SWC-113)",
    "timestamp_dependence": "Block values as a proxy for time (SWC-116)",
    "unprotected_ether_withdrawal": "Unprotected Ether Withdrawal (SWC-105)",
    "block_gas_limit_dos": "DoS With Block Gas Limit (SWC-128)",
    "extcodesize_caller_check": "Bypassable EXTCODESIZE caller-type check",
    "strict_balance_equality": "Unexpected Ether Balance (SWC-132)",
    "blockhash_randomness": "Weak Randomness from Chain Attributes (SWC-120)",
    "transaction_order_dependence": "Transaction Order Dependence (SWC-114)",
    "arbitrary_jump": "Arbitrary Jump with Function Type Variable (SWC-127)",
    "prevrandao_randomness": "Weak Randomness from block.prevrandao (SWC-120)",
    "write_arbitrary_storage": "Write to Arbitrary Storage Location (SWC-124)",
    "signature_replay": "Missing Chain Bind for Signature (SWC-121)",
    "signature_malleability": "Signature Malleability (SWC-117)",
}

# Highest-to-lowest banding order used in the summary block.
_SEVERITY_ORDER = ["high", "medium", "low"]


def _summary_block(findings: List[dict]) -> List[str]:
    """A one-glance executive summary: severity banding + a per-finding table.

    Triage teams on HackerOne-style platforms read top-down and want the count
    breakdown ("2 High, 1 Medium") and a jump table before any detail. This is
    pure formatting over the findings already computed.
    """
    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    extra: dict = {}
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
        else:
            extra[sev] = extra.get(sev, 0) + 1

    # Banding line: "2 High, 1 Medium" — only non-zero bands, highest first.
    bands: List[str] = []
    for sev in _SEVERITY_ORDER:
        if counts[sev]:
            bands.append(f"{counts[sev]} {_SEVERITY_LABEL[sev]}")
    for sev, n in extra.items():
        bands.append(f"{n} {sev.title()}")
    banding = ", ".join(bands) if bands else "none"

    lines: List[str] = []
    lines.append("## Summary")
    lines.append("")
    lines.append(f"**Severity:** {banding}")
    lines.append("")
    lines.append("| # | Severity | Finding | Opcode | pc |")
    lines.append("|---|---|---|---|---|")
    for i, f in enumerate(findings, 1):
        title = _TITLE.get(f["category"], f["category"])
        sev = _SEVERITY_LABEL.get(
            str(f.get("severity", "")).lower(), str(f.get("severity", "")).title()
        )
        lines.append(
            f"| {i} | {sev} | {title} | `{f['op']}` | {f['pc']} |"
        )
    lines.append("")
    return lines


def format_h1md(findings: List[dict], contract: str) -> str:
    """HackerOne-style markdown report, one section per finding."""
    lines: List[str] = []
    lines.append(f"# oracle — symbolic analysis of `{contract}`")
    lines.append("")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append("")
    if not findings:
        lines.append("_No findings for the requested checks._")
        return "\n".join(lines) + "\n"

    lines.extend(_summary_block(findings))

    for i, f in enumerate(findings, 1):
        title = _TITLE.get(f["category"], f["category"])
        sev = _SEVERITY_LABEL.get(f["severity"], f["severity"].title())
        lines.append(f"## {i}. {title}")
        lines.append("")
        lines.append(f"**Severity:** {sev}")
        lines.append(f"**Category:** `{f['category']}`")
        lines.append(f"**Vulnerable opcode:** `{f['op']}` at pc `{f['pc']}`")
        confidence = f.get("confidence")
        if confidence == "timeout":
            lines.append(
                "**Confidence:** `timeout` — the solver query exceeded the "
                "per-query timeout; reachability is undecided and no trigger "
                "input could be produced. Re-run with a larger `--timeout` to "
                "confirm or dismiss."
            )
        elif confidence:
            lines.append(f"**Confidence:** `{confidence}`")
        validation = f.get("validation")
        if validation == "confirmed":
            lines.append(
                "**Validation:** `confirmed` — the trigger input was replayed "
                "concretely and reaches the vulnerable opcode."
            )
        elif validation == "unreachable":
            lines.append(
                "**Validation:** `unreachable` — concrete replay of the trigger "
                "input did not reach the vulnerable opcode; review as a "
                "possible false positive."
            )
        elif validation == "skipped":
            lines.append(
                "**Validation:** `skipped` — no replayable trigger input "
                "(e.g. an undecided/timeout finding)."
            )
        lines.append("")
        lines.append("### Trigger input")
        lines.append("")
        lines.append("The following symbolic transaction input triggers the bug:")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(f.get("trigger_input", {}), indent=2))
        lines.append("```")
        lines.append("")
        lines.append("### Execution trace")
        lines.append("")
        lines.append("EVM operations leading to the vulnerable state:")
        lines.append("")
        lines.append("```")
        for entry in f.get("trace", []):
            lines.append(f"  pc={entry['pc']:>5}  {entry['op']}")
        lines.append("```")
        lines.append("")
    return "\n".join(lines) + "\n"


# SARIF severities map onto the OASIS `level` enum. SARIF has no "high/medium"
# axis of its own — that nuance is carried in `properties.security-severity`
# (the convention GitHub code scanning reads to band alerts). oracle's "high"
# and "medium" both denote a real, reachable vulnerability, so both surface as
# `error`; anything weaker degrades to `warning`.
_SARIF_LEVEL = {
    "high": "error",
    "medium": "error",
    "low": "warning",
}

# GitHub code scanning bands alerts on a 0.0-10.0 numeric scale carried in
# `properties.security-severity`. These mirror the qualitative oracle bands.
_SARIF_SECURITY_SEVERITY = {
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
}


def _sarif_rules(findings: List[dict]) -> List[dict]:
    """One SARIF `reportingDescriptor` (rule) per distinct finding category.

    SARIF requires the driver to declare its rules once; each result then refers
    to a rule by `ruleId`. oracle uses the detector category as the stable
    `ruleId` so downstream tooling can suppress / triage by bug class.
    """
    rules: List[dict] = []
    seen = set()
    for f in findings:
        cat = f["category"]
        if cat in seen:
            continue
        seen.add(cat)
        sev = str(f.get("severity", "")).lower()
        rules.append(
            {
                "id": cat,
                "name": "".join(part.title() for part in cat.split("_")),
                "shortDescription": {"text": _TITLE.get(cat, cat)},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(sev, "warning")
                },
                "properties": {
                    "security-severity": _SARIF_SECURITY_SEVERITY.get(sev, "2.0"),
                    "tags": ["security", "smart-contract", "evm"],
                },
            }
        )
    return rules


# SARIF partialFingerprints key. The "/v1" suffix is the SARIF-recommended way
# to version a fingerprint scheme: if the algorithm ever changes, bump to /v2 so
# a consumer (GitHub code scanning) treats old and new fingerprints as distinct
# rather than silently re-keying every historical alert.
SARIF_FINGERPRINT_KEY = "oracleFindingHash/v1"


def _finding_fingerprint(finding: dict) -> str:
    """A stable, position-independent identity for a finding.

    GitHub Advanced Security (and any SARIF consumer) uses
    `result.partialFingerprints` to track an alert *across runs*: two results
    with the same fingerprint are the same logical finding, so a known bug is
    not re-reported as "new" — and is not lost from a baseline — when unrelated
    edits elsewhere in the contract shift program counters.

    oracle's raw `pc` is a poor identity for this: inserting a single opcode
    early in the contract renumbers every downstream pc, so a pc-keyed
    fingerprint would churn the entire alert set on any edit. Instead the
    fingerprint is derived from the finding's *semantic shape*:

      * the detector `category` (the bug class), and
      * the structural **opcode path** that reaches it — the ordered sequence of
        mnemonics in the execution trace, terminated by the vulnerable opcode.

    The opcode path is the control-flow signature of the bug: it is invariant
    under edits that do not change the path of opcodes leading to the sink, but
    changes when the actual reaching path changes (i.e. when it really is a
    different finding). Trace `pc`s are deliberately excluded — only the opcode
    sequence and category feed the hash — so the fingerprint is position-
    independent. The result is a hex SHA-256 digest, the form GitHub expects.

    [Worker decision: hash the opcode *sequence*, not the pcs. A pc-keyed hash
    re-flags every finding as new after a one-line edit (every pc shifts);
    hashing only the category + opcode path makes the identity track the bug's
    control-flow shape, which is what a triage baseline wants. SHA-256 hex is
    used (stdlib `hashlib`, no new dependency) because GitHub code scanning
    documents fingerprints as opaque strings and compares them verbatim.]
    """
    category = str(finding.get("category", ""))
    trace = finding.get("trace") or []
    ops = [str(step.get("op", "")) for step in trace if isinstance(step, dict)]
    # Always anchor on the vulnerable opcode even if the trace is empty (some
    # detectors record a terminal finding with a minimal trace).
    if not ops or ops[-1] != str(finding.get("op", "")):
        ops.append(str(finding.get("op", "")))
    signature = category + "\n" + ">".join(ops)
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()


def _sarif_result(finding: dict, contract: str) -> dict:
    """A single SARIF `result` for one oracle finding.

    The vulnerable opcode's program counter is exposed as the `region` so a
    SARIF viewer can point at the offending instruction; oracle works on EVM
    bytecode, so the artifact location is the contract file and the "line" is the
    program counter (the only stable, source-independent position oracle has).
    """
    cat = finding["category"]
    sev = str(finding.get("severity", "")).lower()
    title = _TITLE.get(cat, cat)
    pc = finding["pc"]
    op = finding["op"]

    message = f"{title}: reachable `{op}` at pc {pc}."
    confidence = finding.get("confidence")
    if confidence:
        message += f" Confidence: {confidence}."

    result = {
        "ruleId": cat,
        "level": _SARIF_LEVEL.get(sev, "warning"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": contract},
                    # SARIF requires a 1-based line; oracle maps the EVM program
                    # counter onto it (pc 0 -> line 1) so a position is always
                    # present and monotonic with execution order.
                    "region": {"startLine": pc + 1},
                }
            }
        ],
        "partialFingerprints": {
            # Position-independent identity so a SARIF consumer (GitHub code
            # scanning) tracks this alert across runs instead of re-flagging it
            # as new whenever an unrelated edit shifts program counters.
            SARIF_FINGERPRINT_KEY: _finding_fingerprint(finding),
        },
        "properties": {
            "pc": pc,
            "opcode": op,
            "depth": finding.get("depth"),
            "trigger_input": finding.get("trigger_input", {}),
        },
    }
    if confidence:
        result["properties"]["confidence"] = confidence
    if "validation" in finding:
        result["properties"]["validation"] = finding["validation"]
        result["properties"]["validated"] = finding.get("validated")
    return result


def format_sarif(findings: List[dict], contract: str) -> str:
    """SARIF v2.1.0 report — the OASIS static-analysis interchange format.

    SARIF is what GitHub Advanced Security code scanning, Azure DevOps, and most
    security dashboards ingest. Emitting it lets an oracle run drop straight into
    a CI `upload-sarif` step with no glue code, which is exactly the "clean,
    scriptable symbolic engine" niche oracle defends.

    This is pure formatting over the already-computed findings: no analysis
    logic, no new dependency, and the JSON-finding format is unchanged.
    """
    sarif = {
        "version": "2.1.0",
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "oracle",
                        "informationUri": "https://github.com/bugsyhewitt/oracle",
                        "version": __version__,
                        "rules": _sarif_rules(findings),
                    }
                },
                "results": [_sarif_result(f, contract) for f in findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def format_coverage_lcov(coverage: dict, contract: str) -> str:
    """Render instruction coverage as an LCOV tracefile.

    LCOV is the line-coverage interchange format `genhtml`, Codecov, Coveralls,
    and GitHub coverage actions all ingest — the same format Halmos v0.3.0 emits.
    oracle works on EVM bytecode, so each *instruction* is one coverage "line":
    the program counter maps to a 1-based line (`pc + 1`, consistent with the
    SARIF location mapping). A covered instruction has hit count `1`, an
    uncovered one `0`. This lets a CI run surface "oracle reached 62% of this
    contract's instructions" with no glue code, distinguishing a genuine
    all-clear from an exploration that pruned most of the contract.

    `coverage` is the dict returned by `analysis.compute_coverage`.
    """
    covered = set(coverage.get("covered_pcs", []))
    uncovered = set(coverage.get("uncovered_pcs", []))
    all_pcs = sorted(covered | uncovered)

    lines: List[str] = []
    lines.append("TN:oracle")
    lines.append(f"SF:{contract}")
    for pc in all_pcs:
        hits = 1 if pc in covered else 0
        # LCOV lines are 1-based; pc 0 -> line 1 (matches the SARIF mapping).
        lines.append(f"DA:{pc + 1},{hits}")
    lines.append(f"LF:{len(all_pcs)}")
    lines.append(f"LH:{len(covered)}")
    lines.append("end_of_record")
    return "\n".join(lines) + "\n"


def format_report(findings: List[dict], contract: str, fmt: str) -> str:
    if fmt == "json":
        return format_json(findings, contract)
    if fmt == "h1md":
        return format_h1md(findings, contract)
    if fmt == "sarif":
        return format_sarif(findings, contract)
    raise ValueError(f"unknown format: {fmt}")
