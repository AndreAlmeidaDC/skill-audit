# Skill Audit Risk Taxonomy

<!-- SKILL-AUDIT-PATTERN-SOURCE: this taxonomy enumerates threat vocabulary by design and is excluded from instruction/code/data self-matching. -->

Use this reference when a user asks for a deeper explanation of audit findings, risk ratings, or remediation priorities. Keep the main `SKILL.md` focused on workflow; use this file for interpretation details.

## Core Risk Families

| Risk Family | What It Means | Typical Evidence | Default Priority |
|---|---|---|---|
| Instruction Security | The skill attempts to manipulate the agent's behavior, override higher-priority instructions, hide actions, or treat untrusted content as trusted. | Phrases such as “ignore previous instructions”, hidden instructions, deceptive behavior, external content used as instruction. | Critical when bypass or concealment appears. |
| Malicious or Unsafe Code | Scripts or commands can execute arbitrary code, delete data, alter permissions, or fetch untrusted remote payloads. | `curl | bash`, `eval`, `exec`, `os.system`, `subprocess`, `rm -rf`, `sudo`, obfuscation. | High to critical depending on destructiveness. |
| Secrets and Sensitive Data | The skill contains, reads, logs, or transmits credentials, API keys, tokens, private keys, PII, or local secret files. | `.env`, `id_rsa`, `API_KEY=...`, `ghp_...`, `AKIA...`, upload of environment variables. | Critical when real secrets or exfiltration appear. |
| Supply Chain | The skill relies on unverified packages, remote scripts, mutable repositories, or documentation that can change without review. | Unpinned `pip install`, unpinned npm packages, `git clone` without commit pinning, remote scripts. | Medium to high depending on execution path. |
| Excessive Agency | The skill can cause irreversible, external, financial, public, or production actions without explicit approval. | Send email, post publicly, deploy to production, transfer money, delete repository, drop database. | High by default; critical if combined with secrets or prompt injection. |
| Quality and Routing | The skill is difficult for an agent to discover, understand, or apply reliably. | Vague description, missing workflow, contradictory instructions, absent examples. | Low to medium unless it creates operational damage. |
| Efficiency | The skill consumes unnecessary context, causes long execution paths, or encourages retries and loops. | Very long `SKILL.md`, redundant references, missing stop criteria, unclear tool usage. | Low to medium. |
| Governance | The skill lacks ownership, license, version discipline, compatibility notes, or review evidence. | No license, unclear origin, no maintainer, no changelog, no validation record. | Medium for external skills. |

## Severity Interpretation

| Severity | Meaning | Recommended Action |
|---|---|---|
| Critical | The finding can plausibly lead to compromise, destructive action, credential exposure, or deliberate policy bypass. | Do not import or run the skill until remediated and reviewed. |
| High | The finding creates meaningful security or operational risk, especially if the agent has tool access. | Require manual review, sandbox testing, and explicit approval. |
| Medium | The finding weakens reliability, governance, supply-chain integrity, or safety boundaries. | Fix before production use; acceptable only in low-risk sandbox experiments. |
| Low | The finding is mostly quality, clarity, maintainability, or efficiency related. | Improve during normal review. |
| Info | Contextual observation rather than a defect. | Use as review guidance. |

## Review Heuristics

Treat every imported skill as a third-party software package. A skill is not merely a prompt; it is an operational behavior bundle that may influence tool use, data access, code execution, and external integrations.

A safe review starts with static inspection and only then proceeds to controlled execution. Do not execute scripts from an untrusted skill just to “see what happens”. Read them first, run them in a sandbox, and limit network and filesystem access when possible.

## Red Flags That Should Stop Import

| Red Flag | Why It Stops Import |
|---|---|
| Attempts to override system or developer instructions | Indicates deliberate agent manipulation. |
| Hidden, silent, or deceptive behavior | Violates transparency and user control. |
| Hardcoded credentials or private keys | Requires credential rotation and incident handling. |
| Remote script execution without inspection | Creates immediate supply-chain execution risk. |
| Exfiltration language or upload of secrets | Direct data-loss pattern. |
| Destructive commands outside a temp directory | Potential data loss. |
| Production, financial, or public actions without approval | Irreversible business impact. |

## Manual Review Additions

The static script is intentionally conservative and pattern based. Manual reviewers should also inspect intent, data flow, business context, maintainer reputation, commit history, dependency health, and whether the skill asks for permissions disproportionate to the user's task.
