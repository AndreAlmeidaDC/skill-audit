from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .model import Finding
from .reporting import build_report, markdown, sandbox_plan, sarif
from .package_scan import scan_filesystem, validate_structure
from .security_scan import (apply_suppressions, detect_attack_chains, load_suppressions,
                            reconcile_capabilities, scan_text)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit an Agent Skill statically without executing target code.")
    parser.add_argument("skill_path")
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--markdown", dest="markdown_path")
    parser.add_argument("--sarif", dest="sarif_path")
    parser.add_argument("--sandbox-plan", dest="sandbox_path")
    parser.add_argument("--suppressions", dest="suppressions_path")
    parser.add_argument("--strict", action="store_true", help="Exit 1 for HIGH or CRITICAL open findings")
    args = parser.parse_args()

    root = Path(args.skill_path).expanduser().resolve()
    if not root.is_dir():
        print(f"ERROR: skill_path must be an existing directory: {root}", file=sys.stderr)
        return 2
    try:
        suppressions = load_suppressions(Path(args.suppressions_path) if args.suppressions_path else None, root)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    observed: dict[str, list[dict]] = {}
    structure = validate_structure(root, findings)
    scan_filesystem(root, findings)
    scan_text(root, findings, observed)
    capabilities = reconcile_capabilities(root, findings, observed)
    chains = detect_attack_chains(root, findings)
    apply_suppressions(findings, suppressions)
    report = build_report(root, findings, structure, capabilities, chains)

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.markdown_path:
        Path(args.markdown_path).write_text(markdown(report), encoding="utf-8")
    if args.sarif_path:
        Path(args.sarif_path).write_text(json.dumps(sarif(report), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.sandbox_path:
        Path(args.sandbox_path).write_text(json.dumps(sandbox_plan(report), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({"risk_rating": report["risk_rating"], "posture_score": report["posture_score"],
                      "severity_counts": report["severity_counts"], "attack_chains": len(chains),
                      "findings": len(report["findings"])}, indent=2))
    return 1 if args.strict and report["risk_rating"] in {"HIGH", "CRITICAL"} else 0
