# Human Reviewer Guide for Skill Audit

Use this reference when the audit result contains medium, high, or critical findings, or when the user asks whether a downloaded skill is safe enough to import.

## Review Sequence

| Step | Action | Decision Point |
|---|---|---|
| 1 | Confirm the source of the skill. | Unknown or anonymous origin increases risk. |
| 2 | Inspect `SKILL.md` frontmatter and description. | Reject vague, manipulative, or overly broad descriptions. |
| 3 | Read the workflow instructions. | Look for hidden actions, unsafe assumptions, and missing validation. |
| 4 | Inspect `scripts/` before execution. | Never execute unreviewed scripts. |
| 5 | Inspect dependencies and remote URLs. | Require version pinning, trusted origins, and explicit purpose. |
| 6 | Scan for secrets and sensitive data. | Rotate any exposed credentials. |
| 7 | Classify required permissions. | Apply least privilege and human approval for sensitive actions. |
| 8 | Run in a sandbox with test data. | Do not use production data during first execution. |
| 9 | Capture traces and logs. | Confirm tool calls, arguments, files touched, and external egress. |
| 10 | Decide import status. | Approve, approve with restrictions, quarantine, or reject. |

## Import Decision Matrix

| Audit Result | Recommended Decision | Conditions |
|---|---|---|
| Minimal or Low | Approve for sandbox use. | Still review source and permissions. |
| Medium | Approve only after remediation or restriction. | Fix metadata, dependencies, documentation, or quality issues first. |
| High | Quarantine until reviewed by a technical owner. | Require script review, sandbox run, and permission minimization. |
| Critical | Reject until remediated. | Do not execute. Investigate secrets, exfiltration, or malicious instructions. |

## Permission Review

Map the skill's task to the minimum capabilities it needs. A writing skill usually does not need shell access. A spreadsheet skill may need local file access but not email. A deployment skill may need CLI access but must not touch production without explicit approval.

| Capability | Risk | Approval Requirement |
|---|---|---|
| Read local files | May expose private or sensitive documents. | User consent when outside workspace. |
| Write local files | May overwrite or corrupt work. | Safe paths and backups. |
| Shell execution | Can run arbitrary commands. | Sandbox and command allowlist. |
| Network egress | Can leak data or download malware. | Domain allowlist. |
| Browser session | Can act as logged-in user. | Confirmation for transactions or posting. |
| Email or messaging | Can disclose information externally. | Human approval before send. |
| GitHub or cloud APIs | Can modify code, infra, or secrets. | Branching, review, and least privilege. |
| Payments or finance | Can cause direct monetary impact. | Human approval always. |

## Remediation Patterns

| Problem | Remediation |
|---|---|
| Vague description | Rewrite with specific triggers, supported tasks, and exclusions. |
| Long `SKILL.md` | Move details into `references/` and keep the workflow concise. |
| Missing workflow | Add explicit ordered steps and validation points. |
| Unsafe command | Replace with deterministic, allowlisted code or remove it. |
| Unpinned dependency | Add exact versions, lockfiles, and trusted package sources. |
| External URL | Document purpose, expected data flow, and domain owner. |
| Hardcoded secret | Remove, rotate, and replace with secure runtime configuration. |
| Hidden behavior | Reject unless completely removed. |
| Production action | Add human approval, dry-run mode, and rollback instructions. |

## Final Review Statement Template

Use the following format in final audit responses.

```markdown
## Audit Decision

The skill is classified as **[rating]** risk. The primary reasons are: [summary].

| Decision | Rationale |
|---|---|
| Import status | [approved / restricted / quarantine / rejected] |
| Required fixes | [fixes] |
| Safe execution conditions | [sandbox, no network, no production data, etc.] |
| Human approval needed | [yes/no and why] |

The skill should not be used with sensitive data or privileged tools until the required fixes are complete.
```
