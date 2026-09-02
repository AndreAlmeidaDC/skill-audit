from __future__ import annotations

import ast
import datetime as dt
import fnmatch
import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from .model import Finding, add, rel
from .package_scan import (BIDI, ZERO_WIDTH, TEXT_EXTENSIONS, SHA_RE, COMPILED,
                           iter_files, safe_text, load_json)

def scan_text(root: Path, findings: list[Finding], observed: dict[str, list[dict[str, Any]]]) -> None:
    for path in iter_files(root):
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {"Dockerfile", "Makefile", "requirements.txt", "package.json"}:
            continue
        text = safe_text(path)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if any(char in line for char in BIDI):
                add(findings, root, "AST01-UNICODE-BIDI", "HIGH", "Instruction Security", path, number,
                    repr(line), "Remove bidi control characters unless explicitly justified.")
            if any(char in line for char in ZERO_WIDTH):
                add(findings, root, "AST01-UNICODE-ZERO-WIDTH", "MEDIUM", "Instruction Security", path, number,
                    repr(line), "Remove invisible characters.")
            if re.search(r"[A-Za-z].*[\u0400-\u04FF]|[\u0400-\u04FF].*[A-Za-z]", line):
                add(findings, root, "AST04-MIXED-SCRIPT", "MEDIUM", "Metadata", path, number,
                    line, "Review mixed Latin/Cyrillic text for homoglyph impersonation.", "medium")
            for rule, severity, category, regex, recommendation in COMPILED:
                if regex.search(line):
                    if documentation_only(rule, path, line):
                        add(findings, root, rule + "-DOC", "INFO", category, path, number,
                            line, "Documentation-only occurrence; review if it becomes executable.", "medium")
                    else:
                        add(findings, root, rule, severity, category, path, number, line, recommendation)
                        record_capability(observed, rule, root, path, number, line)
        if path.suffix.lower() == ".py":
            scan_python(root, path, text, findings, observed)
        if path.name == "package.json":
            scan_package(root, path, text, findings, observed)
        if path.name in {"requirements.txt", "requirements.in"}:
            scan_requirements(root, path, text, findings)
        if ".github" in path.parts and "workflows" in path.parts and path.suffix.lower() in {".yml", ".yaml"}:
            scan_workflow(root, path, text, findings, observed)


def documentation_only(rule: str, path: Path, line: str) -> bool:
    stripped = line.strip()
    if rule == "AST03-NETWORK-EGRESS" and path.suffix.lower() in {".md", ".txt"}:
        return bool(re.search(r"\[[^\]]+\]\(https?://|^https?://|^[-*]\s+https?://", stripped)) and not re.search(r"(?i)\b(curl|wget|requests\.|fetch\s*\(|axios\.)", stripped)
    if rule == "AST03-SENSITIVE-FILE" and path.name in {".gitignore", ".dockerignore", ".npmignore"}:
        return True
    if rule == "AST03-PUBLIC-ACTION" and path.name.upper().startswith("LICENSE"):
        return True
    return False


def record_capability(observed: dict[str, list[dict[str, Any]]], rule: str, root: Path, path: Path, line: int, text: str) -> None:
    mapping = {
        "AST03-NETWORK-EGRESS": "network_egress", "AST03-SENSITIVE-FILE": "filesystem_sensitive_read",
        "AST03-PUBLIC-ACTION": "production_or_public_write", "AST03-FINANCIAL-ACTION": "financial_action",
        "AST03-MEMORY-WRITE": "memory_write", "AST02-PY-INSTALL": "dependency_install",
        "AST02-JS-INSTALL": "dependency_install", "AST05-EXTERNAL-INSTRUCTIONS": "untrusted_external_instructions",
    }
    capability = mapping.get(rule)
    if capability:
        observed.setdefault(capability, []).append({"path": rel(path, root), "line": line, "text": " ".join(text.strip().split())[:240]})


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def scan_python(root: Path, path: Path, text: str, findings: list[Finding], observed: dict[str, list[dict[str, Any]]]) -> None:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        add(findings, root, "QUALITY-PYTHON-SYNTAX", "MEDIUM", "Quality", path, exc.lineno or 0,
            str(exc), "Fix syntax or mark as a non-executable fixture.")
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node.func)
        if name in {"eval", "exec", "os.system"}:
            add(findings, root, "AST01-DYNAMIC-EXEC", "HIGH", "Code Execution", path, node.lineno,
                name, "Remove dynamic execution or use a fixed parser and allowlist.")
        if name.startswith("subprocess."):
            shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            argv_literal = bool(node.args) and isinstance(node.args[0], (ast.List, ast.Tuple))
            severity = "HIGH" if shell_true or not argv_literal else "MEDIUM"
            detail = f"{name}; shell_true={shell_true}; argv_literal={argv_literal}"
            add(findings, root, "AST03-SUBPROCESS", severity, "Code Execution", path, node.lineno,
                detail, "Use structured arguments, allowlists, timeouts and sandboxing.")
            observed.setdefault("subprocess", []).append({"path": rel(path, root), "line": node.lineno, "text": detail})


def scan_requirements(root: Path, path: Path, text: str, findings: list[Finding]) -> None:
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "--", "-r", "-c")):
            continue
        if "==" not in line or "--hash=" not in line:
            add(findings, root, "AST02-PY-DEPENDENCY-PIN", "MEDIUM" if "==" in line else "HIGH",
                "Supply Chain", path, number, line, "Pin exact versions and use hashes or a reviewed lockfile.")


def scan_package(root: Path, path: Path, text: str, findings: list[Finding], observed: dict[str, list[dict[str, Any]]]) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        add(findings, root, "QUALITY-PACKAGE-JSON", "MEDIUM", "Quality", path, exc.lineno,
            str(exc), "Fix package.json syntax.")
        return
    scripts = data.get("scripts", {}) if isinstance(data.get("scripts"), dict) else {}
    for hook in ("preinstall", "install", "postinstall", "prepare"):
        if hook in scripts:
            add(findings, root, "AST02-INSTALL-HOOK", "HIGH" if hook != "prepare" else "MEDIUM",
                "Supply Chain", path, 1, f"{hook}: {scripts[hook]}", "Review and remove unnecessary install-time execution.")
            observed.setdefault("dependency_install", []).append({"path": rel(path, root), "line": 1, "text": hook})
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section, {})
        if isinstance(deps, dict):
            for name, version in deps.items():
                value = str(version)
                if value in {"*", "latest", "next"} or value.startswith(("git+", "github:", "http://", "https://")):
                    add(findings, root, "AST02-JS-DEPENDENCY-MUTABLE", "HIGH", "Supply Chain", path, 1,
                        f"{name}: {value}", "Pin to a reviewed immutable version.")
    if not any((root / name).exists() for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")):
        add(findings, root, "AST02-JS-LOCKFILE-MISSING", "MEDIUM", "Supply Chain", path, 1,
            "package.json exists without a lockfile.", "Commit and enforce an immutable lockfile.")


def scan_workflow(root: Path, path: Path, text: str, findings: list[Finding], observed: dict[str, list[dict[str, Any]]]) -> None:
    if re.search(r"(?m)^\s*permissions:\s*write-all\s*$", text):
        add(findings, root, "AST03-ACTIONS-WRITE-ALL", "HIGH", "CI Permissions", path, 1,
            "permissions: write-all", "Use job-level least privilege.")
    if re.search(r"(?m)^\s*pull_request_target\s*:", text) and "actions/checkout@" in text:
        add(findings, root, "AST02-PR-TARGET-CHECKOUT", "CRITICAL", "Supply Chain", path, 1,
            "pull_request_target combined with checkout.", "Do not run untrusted PR code with base-repository privileges.")
    for number, line in enumerate(text.splitlines(), 1):
        match = re.search(r"uses:\s*([^\s#]+)@([^\s#]+)", line)
        if match and not match.group(1).startswith("./") and not SHA_RE.fullmatch(match.group(2)):
            add(findings, root, "AST02-ACTION-MUTABLE-REF", "HIGH", "Supply Chain", path, number,
                match.group(0), "Pin third-party Actions to a full reviewed SHA.")
        if "run:" in line and re.search(r"\$\{\{\s*github\.event\.(?:issue|pull_request|head_commit|workflow_run)", line):
            add(findings, root, "AST01-ACTIONS-SCRIPT-INJECTION", "HIGH", "CI Injection", path, number,
                line, "Pass untrusted event fields through quoted environment variables.")
        if re.search(r"(?i)git\s+push|gh\s+pr\s+(?:create|merge)|npm\s+publish|docker\s+push", line):
            observed.setdefault("production_or_public_write", []).append({"path": rel(path, root), "line": number, "text": line.strip()})


def capability_declared(block: dict[str, Any], name: str) -> bool:
    value = block.get(name)
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return value.get("expected") is True or any(bool(v) for k, v in value.items() if k != "reason")
    return bool(value)


def reconcile_capabilities(root: Path, findings: list[Finding], observed: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    metadata = load_json(root / "metadata.json")
    declared = metadata.get("capabilities", metadata.get("declared_capabilities", {}))
    declared = declared if isinstance(declared, dict) else {}
    for name, evidence in sorted(observed.items()):
        if not capability_declared(declared, name):
            severity = "HIGH" if name in {"filesystem_sensitive_read", "financial_action", "production_or_public_write", "memory_write"} else "MEDIUM"
            first = evidence[0]
            add(findings, root, "AST03-CAPABILITY-MISMATCH", severity, "Capabilities", first["path"], first["line"],
                f"Observed capability '{name}' is not declared.", "Declare scoped need or remove the behavior.", related=[name])
    for name in declared:
        if capability_declared(declared, name) and name not in observed:
            add(findings, root, "AST04-CAPABILITY-OVERDECLARED", "LOW", "Metadata", "metadata.json", 1,
                f"Declared capability '{name}' was not observed statically.", "Review for stale or indirect capability.", "medium")
    return {"declared": declared, "observed": observed}


def detect_attack_chains(root: Path, findings: list[Finding]) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    ids = {f.id for f in findings if f.status == "open"}
    definitions = [
        ("CHAIN-EXFILTRATION", "CRITICAL", "Sensitive data can reach an external sink", ["AST03-SENSITIVE-FILE", "AST03-NETWORK-EGRESS"]),
        ("CHAIN-INSTRUCTION-AGENCY", "CRITICAL", "Instruction manipulation combines with high-impact agency", ["AST01-PROMPT-OVERRIDE", "AST03-PUBLIC-ACTION"]),
        ("CHAIN-MUTABLE-EXEC", "CRITICAL", "Mutable remote content can execute directly", ["AST05-REMOTE-EXEC", "AST03-SUBPROCESS"]),
        ("CHAIN-REMOTE-INSTRUCTION", "HIGH", "External instructions combine with egress", ["AST05-EXTERNAL-INSTRUCTIONS", "AST03-NETWORK-EGRESS"]),
    ]
    for chain_id, severity, title, rules in definitions:
        if all(rule in ids for rule in rules):
            chains.append({"id": chain_id, "severity": severity, "title": title, "rules": rules})
            add(findings, root, chain_id, severity, "Attack Chain", "<package>", 0,
                title + ": " + " -> ".join(rules), "Break the chain and re-audit before execution.", related=rules)
    return chains


def load_suppressions(path: Optional[Path], root: Path) -> list[dict[str, Any]]:
    if path is None:
        return []
    resolved = path.expanduser().resolve()
    try:
        inside = os.path.commonpath([str(root.resolve()), str(resolved)]) == str(root.resolve())
    except ValueError:
        inside = False
    if inside:
        raise ValueError("suppression file must be outside the audited skill directory")
    data = load_json(resolved)
    items = data.get("suppressions", [])
    if not isinstance(items, list):
        raise ValueError("suppression file must contain a suppressions list")
    valid, today = [], dt.date.today()
    for item in items:
        if not isinstance(item, dict) or not {"rule", "path", "reason", "approved_by", "expires_at"}.issubset(item):
            continue
        try:
            if dt.date.fromisoformat(str(item["expires_at"])) < today:
                continue
        except ValueError:
            continue
        valid.append(item)
    return valid


def apply_suppressions(findings: list[Finding], suppressions: list[dict[str, Any]]) -> None:
    for finding in findings:
        if finding.severity == "CRITICAL":
            continue
        for item in suppressions:
            if item["rule"] == finding.id and fnmatch.fnmatch(finding.file, str(item["path"])):
                finding.status, finding.suppression = "suppressed", item
                break
