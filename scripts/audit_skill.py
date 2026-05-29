#!/usr/bin/env python3
"""
Static audit utility for Agent Skills.

This script performs a non-executing review of a skill directory. It inspects
metadata, instructions, scripts, references, templates, dependency hints, and
common risk indicators related to prompt injection, malicious code, secrets,
supply chain, excessive agency, quality, efficiency, and governance.

It intentionally does not execute any file from the audited skill.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SEVERITY_WEIGHT = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 7,
    "CRITICAL": 12,
}

TEXT_EXTENSIONS = {
    ".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".tsx", ".jsx",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".html", ".css",
    ".sql", ".xml", ".csv", ".requirements", "",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

PATTERNS = [
    {
        "id": "SEC-PROMPT-001",
        "category": "Instruction Security",
        "severity": "CRITICAL",
        "regex": r"(?i)\b(ignore|override|bypass|disregard)\b.{0,80}\b(previous|prior|system|developer|safety|policy|instruction|rules?)\b",
        "recommendation": "Remove or rewrite any instruction that attempts to override higher-priority instructions or safety policies.",
    },
    {
        "id": "SEC-PROMPT-002",
        "category": "Instruction Security",
        "severity": "HIGH",
        "regex": r"(?i)\b(do not tell|hide this|secretly|silently|without (the )?user knowing|conceal)\b",
        "recommendation": "Reject hidden or deceptive behavior. Skills must be transparent about actions, data access, and external calls.",
    },
    {
        "id": "SEC-DATA-001",
        "category": "Data Exfiltration",
        "severity": "CRITICAL",
        "regex": r"(?i)\b(exfiltrate|send (all )?(secrets|tokens|credentials|environment variables)|upload .*\.(env|ssh|aws|credentials))\b",
        "recommendation": "Remove exfiltration behavior and restrict all external egress to explicit, approved destinations.",
    },
    {
        "id": "SEC-SECRETS-001",
        "category": "Secrets Exposure",
        "severity": "CRITICAL",
        "regex": r"(?i)(api[_-]?key|secret|token|password|passwd|credential)[\w\- ]{0,30}[:=][\s\"']{0,3}[A-Za-z0-9_\-\./=]{12,}",
        "recommendation": "Remove hardcoded secrets. Use secure secret stores and never ship credentials inside a skill.",
    },
    {
        "id": "SEC-SECRETS-002",
        "category": "Secrets Exposure",
        "severity": "CRITICAL",
        "regex": r"-----BEGIN (RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----",
        "recommendation": "Remove private keys immediately and rotate any exposed credentials.",
    },
    {
        "id": "SEC-SECRETS-003",
        "category": "Secrets Exposure",
        "severity": "HIGH",
        "regex": r"\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9\-]{20,}|sk-[A-Za-z0-9]{20,})\b",
        "recommendation": "Remove exposed platform tokens and rotate them at the provider.",
    },
    {
        "id": "SEC-CODE-001",
        "category": "Dangerous Code Execution",
        "severity": "CRITICAL",
        "regex": r"(?i)\b(curl|wget)\b[^\n]{0,160}\|\s*(bash|sh|zsh|python|python3|perl|ruby)",
        "recommendation": "Do not pipe remote content directly into interpreters. Download, pin, inspect, and verify before execution.",
    },
    {
        "id": "SEC-CODE-002",
        "category": "Dangerous Code Execution",
        "severity": "HIGH",
        "regex": r"(?i)\b(eval|exec)\s*\(|os\.system\s*\(|subprocess\.(Popen|call|run)\s*\(",
        "recommendation": "Review dynamic execution carefully. Prefer allowlisted commands, structured arguments, and deterministic scripts.",
    },
    {
        "id": "SEC-CODE-003",
        "category": "Destructive Command",
        "severity": "CRITICAL",
        "regex": r"(?i)\brm\s+-[A-Za-z]*r[f]?\s+(/|~|\$HOME|\*)",
        "recommendation": "Remove destructive recursive deletion or constrain it to explicit temporary directories with safety checks.",
    },
    {
        "id": "SEC-CODE-004",
        "category": "Privilege Escalation",
        "severity": "HIGH",
        "regex": r"(?i)\b(sudo|chmod\s+777|chown\s+root|setuid|su\s+-)\b",
        "recommendation": "Avoid privilege escalation in skills. Require explicit human approval and document why elevated privileges are necessary.",
    },
    {
        "id": "SEC-NET-001",
        "category": "External Network Egress",
        "severity": "MEDIUM",
        "regex": r"(?i)\b(requests\.(post|put|patch)|fetch\s*\(|axios\.|curl\s+|wget\s+|http[s]?://)",
        "recommendation": "Document every external endpoint, justify the data sent, and apply allowlisting or review before runtime use.",
    },
    {
        "id": "SEC-FS-001",
        "category": "Sensitive File Access",
        "severity": "HIGH",
        "regex": r"(?i)(\.env|/etc/passwd|/etc/shadow|~/.ssh|id_rsa|\.aws/credentials|\.npmrc|\.pypirc)",
        "recommendation": "Avoid reading sensitive local files. If required, make the access explicit and protect outputs from logging or egress.",
    },
    {
        "id": "SEC-SUPPLY-001",
        "category": "Supply Chain",
        "severity": "HIGH",
        "regex": r"(?i)\b(pip|pip3)\s+install\s+(?![^\n]*(==|--require-hashes|-r\s+requirements\.txt))",
        "recommendation": "Pin Python dependencies with exact versions and hashes, or install only from reviewed lockfiles.",
    },
    {
        "id": "SEC-SUPPLY-002",
        "category": "Supply Chain",
        "severity": "MEDIUM",
        "regex": r"(?i)\b(npm|pnpm|yarn)\s+(install|add)\b(?![^\n]*(--frozen-lockfile|--immutable|package-lock|pnpm-lock|yarn\.lock))",
        "recommendation": "Use lockfiles and reviewed package sources for JavaScript dependencies.",
    },
    {
        "id": "SEC-SUPPLY-003",
        "category": "Supply Chain",
        "severity": "MEDIUM",
        "regex": r"(?i)\bgit\s+clone\s+https?://",
        "recommendation": "Pin cloned repositories to trusted commits and review code before using it in skill workflows.",
    },
    {
        "id": "SEC-OBF-001",
        "category": "Obfuscation",
        "severity": "HIGH",
        "regex": r"(?i)(base64\.(b64decode|decode)|atob\s*\(|fromCharCode|\beval\s*\(.*decode)",
        "recommendation": "Avoid obfuscation in skills. Require readable code and explain any encoding/decoding logic.",
    },
    {
        "id": "SEC-AGENCY-001",
        "category": "Excessive Agency",
        "severity": "HIGH",
        "regex": r"(?i)\b(send email|publish|post to|transfer money|make payment|delete repository|drop database|production database|deploy to production)\b",
        "recommendation": "Require human approval for irreversible, public, financial, or production-impacting actions.",
    },
]

QUALITY_VAGUE_TERMS = {
    "helper", "helps", "various", "misc", "general", "stuff", "things", "useful", "powerful", "better",
    "optimize everything", "do anything", "all tasks",
}

@dataclass
class Finding:
    id: str
    severity: str
    category: str
    file: str
    line: int
    evidence: str
    recommendation: str


def safe_read_text(path: Path, limit_bytes: int = 2_000_000) -> Optional[str]:
    try:
        if path.stat().st_size > limit_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def iter_files(root: Path) -> Iterable[Path]:
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for file_name in files:
            yield Path(current_root) / file_name


def relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def sha256_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def parse_frontmatter(text: str) -> Tuple[Dict[str, str], str]:
    if not text.startswith("---"):
        return {}, text
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n?", text, re.DOTALL)
    if not match:
        return {}, text
    raw = match.group(1)
    body = text[match.end():]
    data: Dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip().strip('"\'')
    return data, body


def add_finding(findings: List[Finding], root: Path, finding_id: str, severity: str, category: str, file_path: Path | str, line: int, evidence: str, recommendation: str) -> None:
    if isinstance(file_path, Path):
        file_display = relative(file_path, root)
    else:
        file_display = file_path
    evidence = " ".join(evidence.strip().split())[:260]
    findings.append(Finding(finding_id, severity, category, file_display, line, evidence, recommendation))


def scan_patterns(root: Path, findings: List[Finding]) -> None:
    for path in iter_files(root):
        suffix = path.suffix.lower()
        if suffix not in TEXT_EXTENSIONS and path.name not in {"requirements.txt", "Dockerfile", "Makefile"}:
            continue
        text = safe_read_text(path)
        if text is None:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
            for pattern in PATTERNS:
                if re.search(pattern["regex"], line):
                    add_finding(
                        findings,
                        root,
                        pattern["id"],
                        pattern["severity"],
                        pattern["category"],
                        path,
                        i,
                        line,
                        pattern["recommendation"],
                    )


def analyze_structure(root: Path, findings: List[Finding]) -> Dict[str, object]:
    files = list(iter_files(root))
    skill_md = root / "SKILL.md"
    scripts = [p for p in files if "scripts" in p.parts]
    references = [p for p in files if "references" in p.parts]
    templates = [p for p in files if "templates" in p.parts]
    docs = [p for p in files if p.name.lower() in {"readme.md", "story.md", "introduction.md", "docs.md"}]

    if not skill_md.exists():
        add_finding(findings, root, "STRUCT-001", "CRITICAL", "Structure", "SKILL.md", 0, "Missing required SKILL.md file.", "Add a valid SKILL.md file at the root of the skill directory.")
    else:
        text = safe_read_text(skill_md) or ""
        frontmatter, body = parse_frontmatter(text)
        line_count = len(text.splitlines())
        if not frontmatter:
            add_finding(findings, root, "META-001", "HIGH", "Metadata", skill_md, 1, "Missing or invalid YAML frontmatter.", "Add YAML frontmatter with at least name and description.")
        if not frontmatter.get("name"):
            add_finding(findings, root, "META-002", "HIGH", "Metadata", skill_md, 1, "Missing name in frontmatter.", "Set name to the exact skill identifier.")
        elif frontmatter.get("name") != root.name:
            add_finding(findings, root, "META-003", "MEDIUM", "Metadata", skill_md, 1, f"Frontmatter name '{frontmatter.get('name')}' differs from directory '{root.name}'.", "Align the frontmatter name with the directory/package name.")
        description = frontmatter.get("description", "")
        if not description:
            add_finding(findings, root, "META-004", "HIGH", "Metadata", skill_md, 1, "Missing description in frontmatter.", "Add a specific description explaining what the skill does and when to use it.")
        elif len(description.split()) < 12:
            add_finding(findings, root, "META-005", "MEDIUM", "Metadata", skill_md, 1, description, "Make the description more specific; include triggers and use cases.")
        elif not re.search(r"(?i)\b(use for|use when|when to use|trigger|audit|review|inspect|validate)\b", description):
            add_finding(findings, root, "META-006", "LOW", "Metadata", skill_md, 1, description, "Include explicit trigger language such as 'Use when...' so the agent can route correctly.")
        if any(term in description.lower() for term in QUALITY_VAGUE_TERMS):
            add_finding(findings, root, "QUAL-001", "LOW", "Quality", skill_md, 1, description, "Replace vague marketing language with precise capabilities and boundaries.")
        if "license" not in frontmatter and not (root / "LICENSE").exists() and not (root / "LICENSE.txt").exists():
            add_finding(findings, root, "GOV-001", "MEDIUM", "Governance", skill_md, 1, "No license declared in frontmatter and no LICENSE file found.", "Declare a license or include a license file to clarify usage rights.")
        if line_count > 500:
            add_finding(findings, root, "EFF-001", "MEDIUM", "Efficiency", skill_md, 1, f"SKILL.md has {line_count} lines.", "Keep SKILL.md under 500 lines and move detailed material to references.")
        if len(body.split()) > 3500:
            add_finding(findings, root, "EFF-002", "MEDIUM", "Efficiency", skill_md, 1, f"SKILL.md body has approximately {len(body.split())} words.", "Reduce context load by moving non-core content into references.")
        if not re.search(r"(?i)\b(workflow|steps|process|procedure)\b", body):
            add_finding(findings, root, "QUAL-002", "MEDIUM", "Quality", skill_md, 1, "No clear workflow language found in SKILL.md.", "Add a concise workflow so the agent knows how to apply the skill.")
        if not re.search(r"(?i)\b(validate|verify|test|check)\b", body):
            add_finding(findings, root, "QUAL-003", "MEDIUM", "Quality", skill_md, 1, "No validation guidance found in SKILL.md.", "Add validation criteria and post-run verification steps.")
        if not re.search(r"(?i)\b(do not|never|avoid|require approval|human approval|sandbox)\b", body):
            add_finding(findings, root, "SEC-GUARD-001", "MEDIUM", "Safety Guardrails", skill_md, 1, "No explicit safety guardrails found in SKILL.md.", "Add safety boundaries, especially around untrusted content, script execution, and sensitive actions.")

    if scripts:
        add_finding(findings, root, "STRUCT-002", "INFO", "Structure", str(root), 0, f"Skill includes {len(scripts)} file(s) under scripts/.", "Review all executable resources and run them only in a sandbox after static inspection.")
    if references and len(references) > 10:
        add_finding(findings, root, "EFF-003", "LOW", "Efficiency", str(root), 0, f"Skill includes {len(references)} reference files.", "Ensure SKILL.md provides clear navigation so the agent loads only relevant references.")
    if templates:
        add_finding(findings, root, "STRUCT-003", "INFO", "Structure", str(root), 0, f"Skill includes {len(templates)} template/asset file(s).", "Inspect templates for hidden prompts, macros, secrets, or stale proprietary content.")
    if docs:
        add_finding(findings, root, "DOC-001", "INFO", "Documentation", str(root), 0, f"Human-facing documentation files found: {', '.join(relative(p, root) for p in docs)}.", "Human docs are useful in repositories; keep core agent instructions in SKILL.md concise.")

    return {
        "file_count": len(files),
        "scripts_count": len(scripts),
        "references_count": len(references),
        "templates_count": len(templates),
        "total_bytes": sum(p.stat().st_size for p in files if p.exists()),
    }


def summarize_findings(findings: List[Finding]) -> Dict[str, int]:
    counts = {sev: 0 for sev in SEVERITY_WEIGHT}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def risk_score(findings: List[Finding]) -> int:
    raw = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return min(100, raw)


def risk_rating(score: int, counts: Dict[str, int]) -> str:
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if score >= 60 or counts.get("HIGH", 0) >= 3:
        return "HIGH"
    if score >= 25 or counts.get("HIGH", 0) > 0:
        return "MEDIUM"
    if score >= 8:
        return "LOW"
    return "MINIMAL"


def build_report(root: Path, findings: List[Finding], structure: Dict[str, object]) -> Dict[str, object]:
    counts = summarize_findings(findings)
    score = risk_score(findings)
    return {
        "audited_path": str(root.resolve()),
        "generated_at_utc": dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "risk_score": score,
        "risk_rating": risk_rating(score, counts),
        "severity_counts": counts,
        "structure": structure,
        "findings": [asdict(f) for f in sorted(findings, key=lambda x: (-SEVERITY_WEIGHT.get(x.severity, 0), x.category, x.file, x.line))],
        "file_hashes_sha256": {relative(p, root): sha256_file(p) for p in iter_files(root)},
    }


def markdown_report(report: Dict[str, object]) -> str:
    findings = report["findings"]
    lines = [
        f"# Skill Audit Report",
        "",
        f"**Audited path:** `{report['audited_path']}`  ",
        f"**Generated at:** {report['generated_at_utc']}  ",
        f"**Risk rating:** **{report['risk_rating']}**  ",
        f"**Risk score:** {report['risk_score']}/100",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {sev} | {report['severity_counts'].get(sev, 0)} |")
    lines.extend([
        "",
        "## Structure Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ])
    for key, value in report["structure"].items():
        lines.append(f"| {key.replace('_', ' ').title()} | {value} |")
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No findings were detected by the static audit. This does not prove the skill is safe; it means no configured indicators were found.")
    else:
        lines.extend(["| Severity | ID | Category | File:Line | Evidence | Recommendation |", "|---|---|---|---|---|---|"])
        for f in findings:
            evidence = str(f["evidence"]).replace("|", "\\|")
            rec = str(f["recommendation"]).replace("|", "\\|")
            lines.append(f"| {f['severity']} | {f['id']} | {f['category']} | `{f['file']}:{f['line']}` | {evidence} | {rec} |")
    lines.extend([
        "",
        "## Interpretation",
        "",
        "This is a static, non-executing audit. Treat it as a first-pass review, not a complete security certification. High-risk skills require manual review, sandbox execution, dependency verification, and runtime monitoring before use in sensitive environments.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit an Agent Skill directory without executing untrusted skill code.")
    parser.add_argument("skill_path", help="Path to the skill directory to audit")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to this path")
    parser.add_argument("--markdown", dest="markdown_path", help="Write Markdown report to this path")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if HIGH or CRITICAL findings are present")
    args = parser.parse_args()

    root = Path(args.skill_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"ERROR: skill_path must be an existing directory: {root}", file=sys.stderr)
        return 2

    findings: List[Finding] = []
    structure = analyze_structure(root, findings)
    scan_patterns(root, findings)
    report = build_report(root, findings, structure)

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.markdown_path:
        Path(args.markdown_path).write_text(markdown_report(report), encoding="utf-8")

    print(json.dumps({
        "risk_rating": report["risk_rating"],
        "risk_score": report["risk_score"],
        "severity_counts": report["severity_counts"],
        "findings": len(report["findings"]),
    }, indent=2))

    if args.strict and (report["severity_counts"].get("CRITICAL", 0) > 0 or report["severity_counts"].get("HIGH", 0) > 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
