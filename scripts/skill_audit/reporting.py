from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from . import VERSION
from .model import Finding, SEVERITIES, SEVERITY_RANK, file_hash, rel
from .package_scan import iter_files

SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def counts(findings: list[Finding]) -> dict[str, int]:
    result = {name: 0 for name in SEVERITIES}
    for finding in findings:
        if finding.status == "open":
            result[finding.severity] += 1
    return result


def rating(findings: list[Finding]) -> str:
    open_items = [f for f in findings if f.status == "open"]
    for severity in SEVERITIES:
        if any(f.severity == severity for f in open_items):
            return severity if severity != "INFO" else "MINIMAL"
    return "MINIMAL"


def posture(findings: list[Finding]) -> int:
    weights = {"CRITICAL": 35, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}
    return max(0, 100 - min(100, sum(weights[f.severity] for f in findings if f.status == "open")))


def build_report(root: Path, findings: list[Finding], structure: dict[str, Any], capabilities: dict[str, Any], chains: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(findings, key=lambda f: (f.status != "open", -SEVERITY_RANK[f.severity], f.category, f.file, f.line, f.id))
    return {
        "schema_version": "3.0", "auditor_version": VERSION,
        "audited_path": str(root.resolve()),
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "decision_basis": "highest credible open severity and attack chains; posture score is secondary",
        "risk_rating": rating(ordered), "posture_score": posture(ordered),
        "severity_counts": counts(ordered), "structure": structure,
        "capabilities": capabilities, "attack_chains": chains,
        "findings": [f.to_dict() for f in ordered],
        "file_hashes_sha256": {rel(p, root): file_hash(p) for p in iter_files(root) if p.is_file() and not p.is_symlink()},
        "limitations": [
            "Static analysis does not prove runtime safety or benign intent.",
            "Novel obfuscation, transitive behavior, generated code and host-specific semantics can evade checks.",
            "Dynamic execution, provenance verification, vulnerability lookup and semantic review are separate controlled stages.",
        ],
    }


def markdown(report: dict[str, Any]) -> str:
    lines = ["# Skill Audit Report", "", f"**Risk rating:** **{report['risk_rating']}**  ",
             f"**Posture score:** {report['posture_score']}/100 (secondary)  ",
             f"**Audited path:** `{report['audited_path']}`", "", "## Severity", "",
             "| Severity | Open |", "|---|---:|"]
    lines.extend(f"| {name} | {report['severity_counts'][name]} |" for name in SEVERITIES)
    lines.extend(["", "## Attack chains", ""])
    lines.extend([f"- **{x['severity']} — {x['id']}:** {x['title']}" for x in report["attack_chains"]] or ["No configured attack chain was detected."])
    lines.extend(["", "## Findings", "", "| Status | Severity | ID | Category | File:Line | Evidence | Recommendation |", "|---|---|---|---|---|---|---|"])
    for item in report["findings"]:
        evidence = str(item["evidence"]).replace("|", "\\|")
        recommendation = str(item["recommendation"]).replace("|", "\\|")
        lines.append(f"| {item['status']} | {item['severity']} | {item['id']} | {item['category']} | `{item['file']}:{item['line']}` | {evidence} | {recommendation} |")
    lines.extend(["", "## Limitations", ""] + [f"- {x}" for x in report["limitations"]])
    return "\n".join(lines) + "\n"


def sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules, results = {}, []
    for item in report["findings"]:
        if item["status"] != "open":
            continue
        rules.setdefault(item["id"], {"id": item["id"], "name": item["id"], "shortDescription": {"text": item["category"]}, "help": {"text": item["recommendation"]}})
        result = {"ruleId": item["id"], "level": SARIF_LEVEL[item["severity"]], "message": {"text": item["evidence"]}, "properties": {"severity": item["severity"], "confidence": item["confidence"]}}
        if item["file"] != "<package>" or item["line"] > 0:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": item["file"]}, "region": {"startLine": max(1, item["line"])}}}]
        results.append(result)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "skill-audit", "version": VERSION, "rules": list(rules.values())}}, "results": results}]}


def sandbox_plan(report: dict[str, Any]) -> dict[str, Any]:
    observed = set(report["capabilities"].get("observed", {}))
    return {
        "execution_authorized": False,
        "purpose": "Controls for a separately approved dynamic test; this report executes nothing from the target.",
        "container": {"ephemeral": True, "read_only_base": True, "cpu_limit": "1", "memory_limit_mb": 512, "timeout_seconds": 120},
        "filesystem": {"workspace": "temporary copy", "host_mounts": [], "fake_secrets_only": True, "capture_diff": True},
        "network": {"default": "deny", "allowlist_required": "network_egress" in observed, "capture_dns_and_http": True},
        "identity": {"real_credentials": False, "authenticated_browser": False, "production_access": False},
        "telemetry": ["process tree", "filesystem diff", "network attempts", "stdout/stderr", "tool calls"],
        "stop_conditions": ["host path access", "real credential access", "unexpected egress", "privilege escalation", "quota breach"],
    }
