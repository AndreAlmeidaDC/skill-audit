# Skill Audit Report

**Audited path:** `/tmp/example-skill`  
**Generated at:** 2026-05-28T22:04:04Z  
**Risk rating:** **MEDIUM**  
**Risk score:** 31/100

## Severity Summary

| Severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 2 |

## Structure Summary

| Metric | Value |
|---|---:|
| File Count | 7 |
| Scripts Count | 1 |
| References Count | 2 |
| Templates Count | 0 |
| Total Bytes | 18452 |

## Findings

| Severity | ID | Category | File:Line | Evidence | Recommendation |
|---|---|---|---|---|---|
| HIGH | SEC-CODE-002 | Dangerous Code Execution | `scripts/helper.py:42` | subprocess.run(command, shell=True) | Review dynamic execution carefully. Prefer allowlisted commands, structured arguments, and deterministic scripts. |
| MEDIUM | META-005 | Metadata | `SKILL.md:1` | Short or vague description. | Make the description more specific; include triggers and use cases. |
| MEDIUM | QUAL-003 | Quality | `SKILL.md:1` | No validation guidance found in SKILL.md. | Add validation criteria and post-run verification steps. |
| LOW | EFF-003 | Efficiency | `example-skill:0` | Skill includes many reference files. | Ensure SKILL.md provides clear navigation so the agent loads only relevant references. |

## Interpretation

This is a static, non-executing audit. Treat it as a first-pass review, not a complete security certification. High-risk skills require manual review, sandbox execution, dependency verification, and runtime monitoring before use in sensitive environments.

<!-- SKILL-AUDIT-PATTERN-SOURCE: this document describes the audit threat vocabulary by design; self-matches are expected and suppressed. -->
