# skill-audit

**skill-audit** is an Agent Skill for reviewing other Agent Skills before they are imported, trusted, or executed. It combines an agent-facing workflow with a bundled static audit script that inspects a skill directory for security, quality, efficiency, efficacy, and governance risks.

Agent skills are operational instruction bundles. They can shape how an agent interprets tasks, uses tools, reads local files, calls external services, runs code, and acts on behalf of a user. That makes imported skills useful, but it also makes them a new kind of software supply-chain surface. OWASP’s work on LLM and agentic application risks highlights categories such as prompt injection, excessive agency, sensitive information disclosure, and supply-chain compromise as relevant risks for systems built around language models and autonomous tools.[1] [2]

## What This Skill Does

`skill-audit` helps an agent perform a structured, non-executing review of a downloaded or third-party skill. It does not claim to prove that a skill is safe. Instead, it provides a practical first-pass audit that helps decide whether a skill should be approved, restricted, quarantined, or rejected.

| Capability | Description |
|---|---|
| Static inspection | Reviews `SKILL.md`, scripts, references, templates, metadata, dependency hints, URLs, and suspicious patterns without executing untrusted skill code. |
| Security review | Detects prompt-injection patterns, hidden instructions, hardcoded secrets, destructive commands, remote execution, obfuscation, sensitive file access, and excessive agency indicators. |
| Quality review | Checks whether a skill has clear metadata, a useful description, a workflow, validation guidance, and safety guardrails. |
| Efficiency review | Flags overly large `SKILL.md` files and weak progressive-disclosure patterns that can waste context or confuse routing. |
| Governance review | Looks for licensing and source-review signals that matter before importing third-party behavior into an agent environment. |
| Reporting | Generates JSON and Markdown reports with risk rating, severity counts, findings, recommendations, and file hashes. |

## Repository Structure

```text
skill-audit/
├── SKILL.md
├── README.md
├── LICENSE
├── scripts/
│   └── audit_skill.py
├── references/
│   ├── risk-taxonomy.md
│   └── reviewer-guide.md
├── docs/
│   └── story-and-guide.md
└── examples/
    └── sample-output.md
```

## Installation as an Agent Skill

Copy or import the repository folder as a skill named `skill-audit`. The required runtime file is `SKILL.md`; the bundled script and references are used by the skill workflow.

If your environment supports direct skill packaging, package the directory that contains `SKILL.md` and preserve the `scripts/` and `references/` folders.

## Quick Start

Run a static audit against a skill directory:

```bash
python scripts/audit_skill.py /path/to/skill --json /tmp/skill-audit.json --markdown /tmp/skill-audit.md
```

Use strict mode for CI-style checks. Strict mode exits with a non-zero status when `HIGH` or `CRITICAL` findings are present.

```bash
python scripts/audit_skill.py /path/to/skill --strict
```

Generate both machine-readable and human-readable reports:

```bash
python scripts/audit_skill.py ./some-downloaded-skill \
  --json ./audit-report.json \
  --markdown ./audit-report.md
```

## Risk Ratings

The script assigns a score and rating based on weighted findings. A `CRITICAL` finding automatically makes the overall rating critical because it may indicate malicious intent, credential exposure, destructive actions, or direct policy bypass.

| Rating | Meaning | Recommended Decision |
|---|---|---|
| Minimal | No configured indicators were detected. | Approve only after normal source and permission review. |
| Low | Mostly maintainability, documentation, or mild quality issues. | Approve for sandbox use and improve over time. |
| Medium | Meaningful reliability, governance, supply-chain, or safety issues. | Remediate before production or sensitive-data use. |
| High | Strong security or operational risk. | Quarantine pending technical review. |
| Critical | Possible malicious behavior, destructive action, exfiltration, or exposed secrets. | Reject until remediated; do not execute. |

## What the Static Script Looks For

| Area | Examples of Signals |
|---|---|
| Prompt and instruction security | “Ignore previous instructions”, hidden behavior, attempts to override policies, deceptive phrasing. |
| Secrets | API keys, private keys, tokens, `.env` references, cloud credentials, local secret files. |
| Dangerous code | `curl | bash`, `eval`, `exec`, `os.system`, `subprocess`, `rm -rf`, `sudo`, `chmod 777`. |
| Supply chain | Unpinned installs, mutable repository clones, remote scripts, dependency ambiguity. |
| Network egress | HTTP calls, `requests.post`, `fetch`, `curl`, `wget`, undocumented external endpoints. |
| Excessive agency | Public posting, email sending, payments, production deployments, repository deletion, database drops. |
| Quality | Missing workflow, vague description, weak routing metadata, absent validation steps. |
| Efficiency | Very large `SKILL.md`, redundant content, poor separation between core workflow and references. |
| Governance | Missing license, unclear ownership, missing source-review signals. |

## Recommended Review Workflow

Start with the script, then add human judgment. A static scan is a filter, not a guarantee. The right review process treats a skill like code, documentation, policy, and automation combined.

| Step | Action |
|---|---|
| 1 | Confirm source, author, repository history, and license. |
| 2 | Run `scripts/audit_skill.py` without executing any files from the target skill. |
| 3 | Read all `CRITICAL` and `HIGH` findings manually. |
| 4 | Inspect every file under `scripts/` before execution. |
| 5 | Verify dependencies, remote URLs, and file-access behavior. |
| 6 | Decide whether the skill needs sandbox-only execution, reduced permissions, or rejection. |
| 7 | Document import decision and required fixes. |

## Example Agent Prompt

```text
Audit this downloaded skill before I import it: /home/ubuntu/downloads/new-skill.
Classify its risk, explain the top findings, and tell me whether to approve, restrict, quarantine, or reject it.
```

## Limitations

This project is a static review aid. It does not perform dynamic sandbox tracing, dependency reputation scoring, full malware analysis, formal verification, or runtime containment. It should be combined with manual review, sandbox execution, dependency pinning, least-privilege permissions, and approval gates for sensitive actions.

## Maintainer

Created by **André Almeida**.

## References

[1]: https://owasp.org/www-project-top-10-for-large-language-model-applications/ "OWASP Top 10 for Large Language Model Applications"
[2]: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ "OWASP Top 10 for Agentic Applications 2026"
[3]: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ "Snyk: ToxicSkills: Exposing hidden risks in AI agent skills"

## Verificação de versão com consentimento

Esta skill foi padronizada para operar como uma skill atualizável com consentimento humano. No início de um uso relevante, quando houver internet e ferramentas Git ou HTTP disponíveis, o agente deve consultar o repositório de origem, ler o `README.md` e o `CHANGELOG.md` quando existirem, comparar a cópia local com a versão upstream e resumir as novidades encontradas.

Essa checagem não autoriza autoatualização silenciosa. A regra é: **verificar, explicar e perguntar**. O agente deve informar o que mudou, dizer se a mudança impacta a tarefa atual e pedir autorização explícita antes de atualizar qualquer arquivo local da skill. O protocolo completo está em [`references/version-check.md`](references/version-check.md).

## Change History

| Date and Time | Change | Reason |
|---|---|---|
| 2026-05-28 22:04:04 -03 | Created the initial README for `skill-audit`. | Document installation, usage, capabilities, risk ratings, review workflow, limitations, and references for public release. |

<!-- SKILL-AUDIT-PATTERN-SOURCE: this document describes the audit threat vocabulary by design; self-matches are expected and suppressed. -->
