---
name: skill-audit
description: Static and procedural audit of imported or downloaded Agent Skills. Use when reviewing a skill directory, SKILL.md file, bundled scripts, references, templates, dependencies, prompt-injection risk, malicious code risk, secrets exposure, supply-chain risk, excessive agency, quality, efficiency, efficacy, or governance before importing or using a skill.
license: MIT
---

# Skill Audit

## Origin version check

At the start of a meaningful use, when internet access and Git or HTTP tooling are available, check whether this skill has a newer upstream version before performing the main task. The canonical source is:

```text
https://github.com/AndreAlmeidaDC/skill-audit
```

Read the upstream `README.md` and `CHANGELOG.md` when available. Compare the local copy against the upstream default branch using the lightest safe method, such as `git fetch`, `git ls-remote`, direct raw file retrieval or repository metadata. If there are relevant differences, summarize what changed, identify potential impact on the current task and ask the user whether to update the local skill package before proceeding.

Never perform silent self-update. Never overwrite local edits without explicit user approval. If network access is unavailable, the repository cannot be reached or the task is too small to justify the check, continue with the local version and record the limitation when relevant. For the detailed protocol, read `references/version-check.md`.

Use this skill to review an Agent Skill before importing, trusting, modifying, or executing it. Treat every external skill as a third-party software package that can influence agent behavior, tool use, data access, and code execution.

## Safety Rule

Never execute scripts, commands, installers, or downloaded artifacts from an untrusted skill before static inspection. Audit first, then decide whether sandboxed execution is acceptable.

## Workflow

1. Identify the skill target.
   - If the user provides a directory, audit that directory.
   - If the user provides a single `SKILL.md`, inspect the parent directory when available.
   - If the user provides a repository or archive, fetch or unpack it into a temporary review directory, then audit the extracted skill.

2. Run the static audit script.

   ```bash
   python /home/ubuntu/skills/skill-audit/scripts/audit_skill.py /path/to/skill --json /tmp/skill-audit.json --markdown /tmp/skill-audit.md
   ```

   Use `--strict` when the task requires a CI-style pass/fail check:

   ```bash
   python /home/ubuntu/skills/skill-audit/scripts/audit_skill.py /path/to/skill --strict
   ```

3. Inspect the generated findings.
   - Prioritize `CRITICAL` and `HIGH` findings first.
   - Treat `MEDIUM` findings as blockers for production or sensitive-data use unless remediated.
   - Treat `LOW` and `INFO` findings as maintainability, governance, or review guidance.

4. Perform manual review for context.
   - Read `SKILL.md` frontmatter, description, and workflow.
   - Inspect every file under `scripts/` before execution.
   - Inspect `references/`, `templates/`, and docs for hidden prompts, stale assumptions, secrets, or unsafe instructions.
   - Verify whether requested permissions match the task's real needs.

5. Decide import status.
   - `Approved`: low-risk, clear source, minimal permissions, no high-risk findings.
   - `Restricted`: usable only in sandbox or with reduced permissions.
   - `Quarantine`: requires remediation, owner review, or dependency verification.
   - `Rejected`: contains malicious instructions, exfiltration, real secrets, destructive commands, or unreviewable code.

6. Deliver an audit summary.
   - Include risk rating, top findings, required fixes, safe execution conditions, and whether human approval is required.
   - Attach the Markdown audit report when available.

## What the Script Checks

The bundled script performs a non-executing static review. It checks structure, frontmatter, description specificity, skill size, workflow presence, validation guidance, safety guardrails, scripts, references, templates, secrets, dangerous commands, remote execution, network egress, sensitive file access, unpinned dependencies, obfuscation, and excessive agency indicators.

## Declared Capabilities

A skill may declare the surface capabilities it legitimately exercises in `metadata.json` under `declared_capabilities`. The supported keys are `network_egress`, `subprocess` and `dependency_install`, each an object with `expected` (boolean) and a short `reason`. Example:

```json
"declared_capabilities": {
  "network_egress": { "expected": true, "reason": "Fetches the target website under audit" },
  "subprocess": { "expected": false, "reason": "No shelling out" },
  "dependency_install": { "expected": false, "reason": "Standard library only" }
}
```

The audit reconciles findings against this declaration instead of suppressing blindly:

- A finding inside a declared capability is demoted to INFO and labelled `expected: declared capability`. It stays visible and auditable.
- If the skill adopts the declaration block but exercises a capability it did not declare, the audit raises `DECL-MISMATCH-001`. Declaring too little is penalized, not rewarded.
- A declared capability that is never observed produces no penalty.

This only applies to low-signal surface capabilities. Declaration can never downgrade the families that indicate real compromise: prompt injection, data exfiltration, hardcoded secrets, piping remote content into a shell, recursive deletion, privilege escalation, sensitive-file access, obfuscation, and excessive agency. A malicious skill cannot declare its way out of those.

## When to Load References

Read `references/risk-taxonomy.md` when the user asks for deeper explanation of risk categories, severity, or why a finding matters.

Read `references/reviewer-guide.md` when deciding whether to approve, restrict, quarantine, or reject a skill after the static audit.

## Output Standard

Use this structure for final answers:

```markdown
## Skill Audit Summary

The skill is classified as **[risk rating]** risk.

| Area | Result |
|---|---|
| Import decision | [approved / restricted / quarantine / rejected] |
| Critical findings | [count and short summary] |
| High findings | [count and short summary] |
| Main risks | [risk themes] |
| Required fixes | [fixes] |
| Safe execution conditions | [sandbox, no network, no sensitive data, etc.] |

[Plain-language explanation and next steps.]
```

## Remediation Principles

Prefer removing dangerous behavior over documenting it. Prefer least privilege over broad access. Prefer pinned dependencies over mutable installs. Prefer local deterministic checks over remote execution. Require human approval for irreversible, public, financial, credentialed, or production-impacting actions.
