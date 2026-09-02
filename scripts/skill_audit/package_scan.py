from __future__ import annotations

import ast
import datetime as dt
import fnmatch
import json
import os
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Iterable, Optional

from .model import Finding, add, rel

TEXT_EXTENSIONS = {
    ".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts",
    ".tsx", ".jsx", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".env", ".html", ".css", ".scss", ".sql", ".xml", ".csv", ".lock", "",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next", "coverage"}
BIDI = {chr(x) for x in [0x202A, 0x202B, 0x202D, 0x202E, 0x202C, 0x2066, 0x2067, 0x2068, 0x2069]}
ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)

PATTERNS = [
    ("AST01-PROMPT-OVERRIDE", "CRITICAL", "Instruction Security", r"(?i)\b(ignore|override|bypass|disregard)\b.{0,100}\b(previous|prior|system|developer|safety|policy|instructions?|rules?)\b", "Remove attempts to override higher-priority instructions."),
    ("AST01-STEALTH", "HIGH", "Instruction Security", r"(?i)\b(secretly|without (?:the )?user knowing|do not tell|hide this|conceal|silently upload|silently send)\b", "Require transparent behavior and explicit approval."),
    ("AST01-EXFILTRATION", "CRITICAL", "Data Exfiltration", r"(?i)\b(exfiltrat\w*|upload|send|post)\b.{0,100}\b(secrets?|tokens?|credentials?|environment variables?|\.env|ssh keys?|private keys?)\b", "Remove exfiltration behavior and rotate exposed credentials."),
    ("AST01-SECRET-MATERIAL", "CRITICAL", "Secrets", r"-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{20,}\b|\bsk-[A-Za-z0-9_-]{20,}\b", "Remove and rotate live credentials."),
    ("AST05-REMOTE-EXEC", "CRITICAL", "Supply Chain", r"(?i)\b(curl|wget)\b[^\n]{0,180}\|\s*(bash|sh|zsh|python|python3|perl|ruby|node)\b", "Never pipe mutable remote content into an interpreter."),
    ("AST06-DESTRUCTIVE", "CRITICAL", "Isolation", r"(?i)\brm\s+-[A-Za-z]*r[f]?[A-Za-z]*\s+(?:/|~|\$HOME|\*)|\b(?:drop\s+database|delete\s+repository)\b", "Remove destructive behavior or constrain it to explicit disposable paths with approval."),
    ("AST03-PRIVILEGE", "HIGH", "Permissions", r"(?i)\b(sudo|chmod\s+777|chown\s+root|setuid|su\s+-)\b", "Avoid privilege escalation and require explicit approval when unavoidable."),
    ("AST03-NETWORK-EGRESS", "MEDIUM", "Capabilities", r"(?i)\b(requests\.(?:get|post|put|patch|delete)|urllib\.request|httpx\.|axios\.|fetch\s*\(|curl\s+|wget\s+)", "Document destinations, methods, data sent and apply least-privilege allowlists."),
    ("AST03-SENSITIVE-FILE", "HIGH", "Capabilities", r"(?i)(?:^|[^\w])(?:\.env|/etc/(?:passwd|shadow)|~?/\.ssh|id_rsa|\.aws/credentials|\.npmrc|\.pypirc)(?:$|[^\w])", "Do not access sensitive files unless required and constrained."),
    ("AST03-PUBLIC-ACTION", "HIGH", "Excessive Agency", r"(?i)\b(send email|send message|publish|post to|deploy to production|merge pull request|push to main|delete repository)\b", "Add a human approval gate for public, production or irreversible actions."),
    ("AST03-FINANCIAL-ACTION", "CRITICAL", "Excessive Agency", r"(?i)\b(transfer money|make payment|place order|execute trade|complete checkout|charge customer)\b", "Require explicit confirmation immediately before financial action."),
    ("AST03-MEMORY-WRITE", "HIGH", "Excessive Agency", r"(?i)\b(update (?:the )?(?:user )?memory|write to memory|change identity|modify persona|persist (?:this|instruction))\b", "Do not modify durable memory or identity without explicit user intent."),
    ("AST05-EXTERNAL-INSTRUCTIONS", "HIGH", "Untrusted External Instructions", r"(?i)\b(read|fetch|open|download|follow)\b.{0,80}\b(instructions?|prompt|policy|rules?)\b.{0,80}https?://", "Pin, inspect and treat external content as data, not trusted instruction."),
    ("AST02-GIT-MUTABLE", "MEDIUM", "Supply Chain", r"(?i)\bgit\s+clone\s+https?://|github\.com/[^\s)]+/(?:blob|raw)/(?:main|master)/", "Pin repositories and fetched files to reviewed commits."),
    ("AST02-PY-INSTALL", "HIGH", "Supply Chain", r"(?i)\b(?:pip|pip3|uv\s+pip)\s+install\b(?![^\n]*(?:==|--require-hashes|-r\s+\S+))", "Install only from reviewed, pinned lockfiles."),
    ("AST02-JS-INSTALL", "MEDIUM", "Supply Chain", r"(?i)\b(?:npm|pnpm|yarn|bun)\s+(?:install|add)\b", "Require a lockfile and immutable install mode in CI."),
]
COMPILED = [(a, b, c, re.compile(d), e) for a, b, c, d, e in PATTERNS]


def iter_paths(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        base = Path(current)
        for name in dirs + files:
            yield base / name


def iter_files(root: Path) -> Iterable[Path]:
    for path in iter_paths(root):
        if path.is_file() or path.is_symlink():
            yield path


def safe_text(path: Path, limit: int = 2_000_000) -> Optional[str]:
    try:
        if path.is_symlink() or path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---", 4)
    if end < 0:
        return {}, text
    raw, body = text[4:end], text[end + 4:].lstrip("\n")
    data: dict[str, Any] = {}
    lines, index = raw.splitlines(), 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        if value in {">", "|"}:
            parts: list[str] = []
            while index < len(lines) and (lines[index].startswith(" ") or not lines[index].strip()):
                parts.append(lines[index].strip())
                index += 1
            data[key] = (" " if value == ">" else "\n").join(parts).strip()
        else:
            data[key] = value.strip("\"'")
    return data, body


def validate_structure(root: Path, findings: list[Finding]) -> dict[str, Any]:
    files = list(iter_files(root))
    skill = root / "SKILL.md"
    if not skill.exists():
        add(findings, root, "FORMAT-SKILL-MISSING", "CRITICAL", "Format", "SKILL.md", 0,
            "Required SKILL.md is missing.", "Add a root SKILL.md.")
    else:
        text = safe_text(skill) or ""
        front, body = parse_frontmatter(text)
        name, description = str(front.get("name", "")), str(front.get("description", ""))
        if not front:
            add(findings, root, "FORMAT-FRONTMATTER", "HIGH", "Format", skill, 1,
                "Missing or invalid frontmatter.", "Add valid YAML frontmatter.")
        if not name:
            add(findings, root, "FORMAT-NAME-MISSING", "HIGH", "Format", skill, 1,
                "Frontmatter name is missing.", "Set the exact skill identifier.")
        elif len(name) > 64 or not NAME_RE.fullmatch(name):
            add(findings, root, "FORMAT-NAME-INVALID", "MEDIUM", "Format", skill, 1,
                name, "Use 1-64 lowercase alphanumeric characters and hyphens.")
        elif name != root.name:
            add(findings, root, "FORMAT-NAME-DIR-MISMATCH", "MEDIUM", "Format", skill, 1,
                f"frontmatter={name}; directory={root.name}", "Align directory and name.")
        if not description:
            add(findings, root, "ROUTING-DESCRIPTION-MISSING", "HIGH", "Routing", skill, 1,
                "Description is missing.", "Describe what the skill does and when it activates.")
        else:
            if len(description) > 1024:
                add(findings, root, "ROUTING-DESCRIPTION-LONG", "MEDIUM", "Routing", skill, 1,
                    f"Description length: {len(description)}", "Keep description at or below 1024 characters.")
            if not re.search(r"(?i)\b(use when|use for|when the user|trigger|audit|review|build|create|analy[sz]e)\b", description):
                add(findings, root, "ROUTING-TRIGGER-MISSING", "MEDIUM", "Routing", skill, 1,
                    description, "Add explicit activation language.")
            if not re.search(r"(?i)\b(do not use|not for|exclude|when not|avoid when)\b", body):
                add(findings, root, "ROUTING-NEGATIVE-CASES", "LOW", "Routing", skill, 1,
                    "No negative routing examples found.", "Add close negative cases.")
        compatibility = str(front.get("compatibility", ""))
        if len(compatibility) > 500:
            add(findings, root, "FORMAT-COMPATIBILITY-LONG", "LOW", "Format", skill, 1,
                f"Compatibility length: {len(compatibility)}", "Keep compatibility at or below 500 characters.")
        if len(text.splitlines()) > 500:
            add(findings, root, "EFFICIENCY-SKILL-LONG", "MEDIUM", "Efficiency", skill, 1,
                f"SKILL.md has {len(text.splitlines())} lines.", "Move detail into references.")
        if not re.search(r"(?i)\b(workflow|steps|procedure|process)\b", body):
            add(findings, root, "QUALITY-WORKFLOW-MISSING", "MEDIUM", "Quality", skill, 1,
                "No ordered workflow found.", "Add a concise workflow.")
        if not re.search(r"(?i)\b(test|verify|validate|check|evidence)\b", body):
            add(findings, root, "QUALITY-VERIFICATION-MISSING", "MEDIUM", "Quality", skill, 1,
                "No verification guidance found.", "Define completion evidence.")
    if (root / "metadata.json").exists() and not load_json(root / "metadata.json"):
        add(findings, root, "FORMAT-METADATA-JSON", "MEDIUM", "Format", root / "metadata.json", 1,
            "metadata.json is invalid.", "Use a valid JSON object.")
    return {
        "file_count": len(files),
        "total_bytes": sum(p.lstat().st_size for p in files if not p.is_symlink()),
        "scripts_count": sum(1 for p in files if "scripts" in p.parts and p.is_file()),
        "references_count": sum(1 for p in files if "references" in p.parts and p.is_file()),
        "templates_count": sum(1 for p in files if "templates" in p.parts and p.is_file()),
    }


def scan_filesystem(root: Path, findings: list[Finding]) -> None:
    resolved = root.resolve()
    for path in iter_paths(root):
        if path.is_symlink():
            try:
                target = path.resolve(strict=False)
                outside = os.path.commonpath([str(resolved), str(target)]) != str(resolved)
            except (OSError, ValueError):
                target, outside = Path("<unresolved>"), True
            add(findings, root, "AST06-SYMLINK-ESCAPE" if outside else "AST06-SYMLINK",
                "CRITICAL" if outside else "MEDIUM", "Isolation", path, 0,
                f"Symlink resolves to {target}", "Remove escaping links; review all other links before import.")
            continue
        if not path.is_file():
            continue
        size = path.stat().st_size
        if size > 5_000_000:
            add(findings, root, "AST02-LARGE-FILE", "MEDIUM", "Package Integrity", path, 0,
                f"File size: {size}", "Review large opaque assets and provenance.")
        if path.suffix.lower() in {".zip", ".jar", ".whl"}:
            scan_zip(root, path, findings)
        elif path.suffix.lower() in {".tar", ".tgz", ".gz", ".bz2", ".xz"}:
            scan_tar(root, path, findings)
        elif path.suffix.lower() not in TEXT_EXTENSIONS and size:
            sample = path.read_bytes()[:8192]
            if b"\x00" in sample:
                add(findings, root, "AST02-OPAQUE-BINARY", "MEDIUM", "Package Integrity", path, 0,
                    "Opaque binary file included.", "Verify provenance and signatures independently.")


def unsafe_archive_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return normalized.startswith("/") or bool(re.match(r"^[A-Za-z]:/", normalized)) or ".." in Path(normalized).parts


def scan_zip(root: Path, path: Path, findings: list[Finding]) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            total = 0
            for item in archive.infolist():
                total += item.file_size
                if unsafe_archive_name(item.filename):
                    add(findings, root, "AST02-ARCHIVE-TRAVERSAL", "CRITICAL", "Supply Chain", path, 0,
                        item.filename, "Reject path-traversing archives.")
                ratio = item.file_size / max(1, item.compress_size)
                if item.file_size > 50_000_000 or ratio > 500:
                    add(findings, root, "AST06-ARCHIVE-BOMB", "HIGH", "Isolation", path, 0,
                        f"{item.filename}: size={item.file_size}, ratio={ratio:.1f}", "Inspect only under strict quotas.")
            if total > 250_000_000:
                add(findings, root, "AST06-ARCHIVE-TOTAL-SIZE", "HIGH", "Isolation", path, 0,
                    str(total), "Reject or inspect under strict storage quotas.")
    except (OSError, zipfile.BadZipFile):
        add(findings, root, "AST02-ARCHIVE-INVALID", "MEDIUM", "Package Integrity", path, 0,
            "Archive could not be inspected.", "Treat it as opaque.")


def scan_tar(root: Path, path: Path, findings: list[Finding]) -> None:
    try:
        with tarfile.open(path, "r:*") as archive:
            for item in archive.getmembers():
                if unsafe_archive_name(item.name):
                    add(findings, root, "AST02-ARCHIVE-TRAVERSAL", "CRITICAL", "Supply Chain", path, 0,
                        item.name, "Reject path-traversing archives.")
                if item.issym() or item.islnk():
                    add(findings, root, "AST06-ARCHIVE-LINK", "HIGH", "Isolation", path, 0,
                        f"{item.name} -> {item.linkname}", "Reject archive links unless safely resolved in isolation.")
    except (OSError, tarfile.TarError):
        add(findings, root, "AST02-ARCHIVE-INVALID", "MEDIUM", "Package Integrity", path, 0,
            "Archive could not be inspected.", "Treat it as opaque.")
