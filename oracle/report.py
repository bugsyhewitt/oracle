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
