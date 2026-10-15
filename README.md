# skill-audit

Static and procedural review toolkit for Agent Skills.

Version `2026.10.15` (engine/report 3.1) retains severity and attack-chain review and adds explicit bounded coverage. A low finding count no longer hides omitted build directories, large text or opaque content.

## Coverage and limits

Check `coverage.complete` and `coverage.unexamined`, not just risk_rating. Exit 2 means incomplete coverage or invalid input even without `--strict`; exit 1 means strict HIGH/CRITICAL findings; exit 0 does not certify safety. Coverage findings cannot be suppressed.

All directories except `.git` are traversed, including build, dist, hidden files and dependencies. `.git` is explicitly unexamined repository metadata; use a clean distribution snapshot for admission. UTF-8 text is inspected regardless of extension. Hashes include eligible opaque files, but hashing does not mean their behavior was reviewed. Archive contents are never executed or treated as scanned; compressed TARs are not decompressed. ZIP and plain TAR metadata inspection remains separate from content review.

Bounds: 10,000 paths, 128 MB observed total size, 16 MB per hashed file, 2 MB per text file and 8,192 characters per line. ZIP metadata inspection accepts at most 2 MB input and limits reported members; TAR metadata iteration is bounded. Limit hits, binary/invalid UTF-8, links, read errors and target changes remain explicit. Pre/post inventories compare file hashes; they do not isolate hostile concurrent filesystem mutation. Keep an external timeout and a private, quiescent target. No new dependencies or dynamic target execution are introduced.

JSON, Markdown, SARIF and sandbox-plan outputs must be outside the audited tree. Schema 3.1 adds coverage while retaining findings and file_hashes_sha256; consumers must handle exit 2 and must not treat a missing/null hash as approval. Semantic false positives, including negated instructions, still require independent review; no blanket target-controlled negation suppression was added.

## What changed in v3

- A marker inside the audited package can no longer suppress findings.
- Target-declared capabilities are context only; they never reduce severity.
- Suppressions must be external, reviewed, expiring and remain visible.
- Added symlink escape, archive traversal/bomb, opaque binary, bidi/zero-width, mixed-script, install-hook, lockfile, mutable dependency and GitHub Actions checks.
- Added Python AST inspection for dynamic execution and subprocess behavior.
- Added declared-versus-observed capability comparison.
- Added attack-chain detection.
- Added SARIF output for code scanning and a non-executing sandbox plan.
- Added routing checks based on the Agent Skills specification.

## Usage

```bash
python3 scripts/audit_skill.py ./some-skill \
  --json audit.json \
  --markdown audit.md \
  --sarif audit.sarif \
  --sandbox-plan sandbox-plan.json
```

CI mode:

```bash
python3 scripts/audit_skill.py ./some-skill --strict
```

Run the regression suite:

```bash
python3 scripts/test_audit_skill.py
python3 scripts/validate_skill.py
```

## What it audits

- package structure and Agent Skills frontmatter;
- routing description and negative activation cases;
- Unicode control characters and mixed-script impersonation;
- symlinks, archives, path traversal and opaque files;
- prompt override, stealth, exfiltration and secret material;
- network, subprocess, filesystem, production, financial and memory capabilities;
- Python dynamic execution;
- Python and JavaScript dependency hygiene;
- GitHub Actions pinning, permissions and script-injection patterns;
- attack chains and capability mismatches.

## What it does not prove

A clean static report is not a security certification. The tool does not automatically execute the skill, validate dependency provenance against external databases, inspect every transitive package, or prove benign semantic intent.

## Safe dynamic testing

Dynamic testing is a separate, approval-gated stage. Use an ephemeral container, fake secrets, no host mounts, deny network by default, no authenticated browser, no production access and capture process/network/filesystem telemetry.

## Suppression format

Store exceptions outside the audited directory:

```json
{
  "suppressions": [
    {
      "rule": "AST02-JS-LOCKFILE-MISSING",
      "path": "fixtures/**",
      "reason": "Fixture intentionally demonstrates a missing lockfile",
      "approved_by": "security-owner",
      "expires_at": "2026-12-31"
    }
  ]
}
```

Critical findings cannot be suppressed.

## Governance

The canonical source is `AndreAlmeidaDC/skill-audit`. Updates require explicit consent. Security rules, suppression logic and severity changes require regression tests.
