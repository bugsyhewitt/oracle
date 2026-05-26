"""Report formatters for oracle findings: JSON and HackerOne-style markdown."""

from __future__ import annotations

import json
from typing import List


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
    "reachable_selfdestruct": "Reachable SELFDESTRUCT",
    "unconstrained_ether_transfer": "Unconstrained Ether Transfer",
    "arbitrary_storage_write": "Arbitrary Storage Write",
}


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

    for i, f in enumerate(findings, 1):
        title = _TITLE.get(f["category"], f["category"])
        sev = _SEVERITY_LABEL.get(f["severity"], f["severity"].title())
        lines.append(f"## {i}. {title}")
        lines.append("")
        lines.append(f"**Severity:** {sev}")
        lines.append(f"**Category:** `{f['category']}`")
        lines.append(f"**Vulnerable opcode:** `{f['op']}` at pc `{f['pc']}`")
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


def format_report(findings: List[dict], contract: str, fmt: str) -> str:
    if fmt == "json":
        return format_json(findings, contract)
    if fmt == "h1md":
        return format_h1md(findings, contract)
    raise ValueError(f"unknown format: {fmt}")
