from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional
import hashlib

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK = {name: value for value, name in enumerate(reversed(SEVERITIES))}


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    file: str
    line: int
    evidence: str
    recommendation: str
    confidence: str = "high"
    status: str = "open"
    suppression: Optional[dict[str, Any]] = None
    related: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def add(findings: list[Finding], root: Path, rule: str, severity: str, category: str,
        path: Path | str, line: int, evidence: str, recommendation: str,
        confidence: str = "high", related: Optional[list[str]] = None) -> None:
    target = rel(path, root) if isinstance(path, Path) else path
    clean = " ".join(str(evidence).strip().split())[:360]
    findings.append(Finding(rule, severity, category, target, line, clean,
                            recommendation, confidence, related=related or []))


def file_hash(path: Path) -> Optional[str]:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
