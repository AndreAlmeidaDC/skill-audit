#!/usr/bin/env python3
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "SKILL.md", "README.md", "CHANGELOG.md", "LICENSE", "metadata.json",
    "references/version-check.md", "references/risk-taxonomy.md",
    "references/reviewer-guide.md", "scripts/audit_skill.py",
    "scripts/test_audit_skill.py", "scripts/skill_audit/__init__.py",
    "scripts/skill_audit/model.py", "scripts/skill_audit/package_scan.py",
    "scripts/skill_audit/security_scan.py", "scripts/skill_audit/reporting.py", "scripts/skill_audit/cli.py",
]

def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)

missing = [name for name in REQUIRED if not (ROOT / name).exists()]
if missing:
    fail("missing files: " + ", ".join(missing))
metadata = json.loads((ROOT / "metadata.json").read_text(encoding="utf-8"))
skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
if metadata.get("version") != "2026.09.02" or "2026.09.02" not in skill:
    fail("version drift")
if metadata.get("security_model", {}).get("target_suppression_markers_allowed") is not False:
    fail("target suppression markers must be disabled")
if metadata.get("security_model", {}).get("critical_suppression_allowed") is not False:
    fail("critical suppressions must be disabled")
audit = (ROOT / "scripts/audit_skill.py").read_text(encoding="utf-8")
if "SELF_REFERENCE_MARKER" in audit or "SKILL-AUDIT-PATTERN-SOURCE" in audit:
    fail("target-controlled marker suppression returned")
if "demoted to INFO" in audit and "declared capability" in audit:
    fail("capability severity downgrade returned")
subprocess.run([sys.executable, "-m", "py_compile", str(ROOT / "scripts/audit_skill.py"), str(ROOT / "scripts/test_audit_skill.py"), str(ROOT / "scripts/skill_audit/model.py"), str(ROOT / "scripts/skill_audit/package_scan.py"), str(ROOT / "scripts/skill_audit/security_scan.py"), str(ROOT / "scripts/skill_audit/reporting.py"), str(ROOT / "scripts/skill_audit/cli.py")], check=True)
print("Validation passed")
