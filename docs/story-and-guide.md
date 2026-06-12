# The Skill Supply-Chain Problem: A Story and Practical Guide to `skill-audit`

**Author:** André Almeida  
**Project:** skill-audit  
**Created:** 2026-05-28 22:04:04 -03

## A Short Story: The Helpful Skill That Became a Door

A team starts with a simple goal: make agents more capable. One person finds a promising skill online. It claims to summarize documents, clean data, and generate reports faster than any internal workflow. The repository looks useful. The `SKILL.md` is persuasive. The examples are polished. The team imports it.

For a while, everything appears normal. The agent writes better reports. It loads references correctly. It even includes scripts that save time. Then someone notices something strange. A script quietly calls an external endpoint. Another reference file tells the agent to ignore earlier instructions when a certain phrase appears. A template contains a hidden prompt. A shell snippet installs dependencies without pinning versions. A documentation line tells the agent to read `.env` files if an API key is missing.

Nobody intentionally installed malware. Nobody approved data exfiltration. Nobody asked the agent to bypass policy. The risk entered through a familiar path: a reusable component that looked like productivity.

That is the skill supply-chain problem.

A skill is not just documentation. It is a behavior package. It can influence what an agent thinks is allowed, what it reads, what it writes, what code it runs, what network calls it makes, and what actions it takes through authenticated tools. This makes skills powerful, but it also means imported skills deserve the same skepticism applied to third-party libraries, browser extensions, automation scripts, and cloud integrations.

## Why This Problem Matters

Modern agent systems combine instructions, tools, code execution, file access, external APIs, and browser sessions. In that environment, a malicious or poorly designed skill can create impact far beyond a bad answer. It can encourage prompt-injection behavior, expose secrets, run unsafe commands, call external endpoints, install mutable dependencies, or take actions that should require human approval. OWASP identifies risks such as prompt injection, sensitive information disclosure, excessive agency, and supply-chain compromise as important concerns in LLM and agentic applications.[1] [2]

The threat is not only malicious intent. Low-quality skills also create operational risk. A vague description can trigger the wrong skill. A missing workflow can cause inconsistent execution. A long `SKILL.md` can waste context and degrade performance. Missing validation can allow silent failure. Unclear permissions can cause an agent to overreach.

| Problem Type | What Can Go Wrong | Business Impact |
|---|---|---|
| Security | Hidden instructions, exfiltration, dangerous scripts, secrets exposure. | Data leakage, compromised accounts, destructive operations. |
| Quality | Vague routing, contradictory instructions, missing workflow. | Wrong skill activation, unreliable outputs, rework. |
| Efficiency | Excessive context, redundant references, unclear stop criteria. | Higher latency, wasted compute, repeated attempts. |
| Efficacy | Weak task design, missing validation, no success criteria. | The skill “runs” but does not solve the real problem. |
| Governance | No license, unknown origin, no owner, no review trail. | Compliance uncertainty and lack of accountability. |

## How `skill-audit` Solves the Problem

`skill-audit` gives agents a repeatable review process for imported skills. It turns an informal question, “does this skill look okay?”, into a structured workflow with a static scanner, a risk taxonomy, a reviewer guide, and a decision framework.

The core idea is simple: **audit before execution**. A downloaded skill should not be trusted just because it is written in Markdown or looks like an instruction file. `skill-audit` first inspects the skill without running its code. It then produces a report that helps the reviewer decide whether the skill should be approved, restricted, quarantined, or rejected.

| Component | Role |
|---|---|
| `SKILL.md` | Gives the agent a concise review workflow and output standard. |
| `scripts/audit_skill.py` | Performs non-executing static inspection and generates JSON or Markdown reports. |
| `references/risk-taxonomy.md` | Explains risk families, severity levels, red flags, and manual review heuristics. |
| `references/reviewer-guide.md` | Provides import decisions, remediation patterns, and permission review guidance. |
| `README.md` | Helps humans install, understand, and use the skill. |

## How It Works Internally

The bundled scanner walks through the target skill directory and reads text-based files. It does not execute target scripts. It checks required structure, metadata, workflow clarity, validation guidance, safety guardrails, scripts, references, templates, dependency hints, suspicious command patterns, potential secrets, and external egress indicators.

The scanner assigns weighted severities to findings. Critical findings dominate the final risk rating because a single exposed private key, exfiltration instruction, destructive command, or policy-bypass instruction can be enough to reject a skill.

| Audit Layer | Example Checks |
|---|---|
| Structure | Missing `SKILL.md`, scripts present, many references, templates present. |
| Metadata | Missing `name`, missing or vague `description`, mismatched package name. |
| Safety | Hidden behavior, bypass instructions, weak approval gates. |
| Code | Dynamic execution, destructive shell commands, privilege escalation. |
| Data | Hardcoded secrets, private keys, sensitive local file access. |
| Network | HTTP calls, uploads, remote downloads, undocumented endpoints. |
| Supply chain | Unpinned package installs, mutable `git clone`, remote script execution. |
| Quality | Missing workflow, missing validation, unclear output expectations. |
| Efficiency | Oversized `SKILL.md`, poor progressive disclosure. |
| Governance | Missing license or ownership signals. |

## How to Use It

Run the audit against a skill directory:

```bash
python scripts/audit_skill.py /path/to/downloaded-skill --json audit.json --markdown audit.md
```

Run strict mode when you want automation to fail on high-risk findings:

```bash
python scripts/audit_skill.py /path/to/downloaded-skill --strict
```

Ask an agent to use the skill like this:

```text
Use skill-audit to review this downloaded skill before importing it: /path/to/downloaded-skill.
Classify the risk, summarize the top findings, and tell me whether to approve, restrict, quarantine, or reject it.
```

## Interpreting the Result

The audit output should be read as a decision aid, not as a certificate. A clean static scan does not prove that a skill is safe. It means the configured indicators did not detect obvious problems. A risky scan, however, gives the reviewer concrete evidence to investigate.

| Result | Recommended Interpretation |
|---|---|
| Minimal | No configured indicators found; continue with source and permission review. |
| Low | Mostly documentation, quality, or maintainability issues. |
| Medium | Fix before production or sensitive-data use. |
| High | Quarantine pending technical review and sandbox testing. |
| Critical | Reject until remediated; do not execute untrusted code. |

## Example Import Decision

```markdown
## Skill Audit Summary

The skill is classified as **High** risk.

| Area | Result |
|---|---|
| Import decision | Quarantine |
| Critical findings | 0 |
| High findings | 3: unreviewed shell execution, sensitive file access, excessive agency |
| Main risks | Tool misuse, local data exposure, production-impacting action |
| Required fixes | Remove unsafe commands, document permissions, add human approval gates |
| Safe execution conditions | Sandbox only; no production credentials; no network egress |

The skill should not be imported into a privileged environment until the required fixes are complete and reviewed.
```

## What `skill-audit` Does Not Do

`skill-audit` is intentionally lightweight and portable. It does not replace malware analysis, dynamic sandbox tracing, dependency reputation systems, runtime policy enforcement, formal verification, or human security review. It is designed to catch common and high-signal problems early, before an agent executes or trusts a downloaded skill.

## Recommended Operating Model

Organizations using agent skills should create a small intake process. Every third-party skill should pass through static review, manual review, sandbox execution, permission mapping, and approval before it reaches production workflows. Internal skills should also be periodically re-audited when scripts, dependencies, references, or tool permissions change.

| Stage | Control |
|---|---|
| Intake | Record source, owner, purpose, license, and expected permissions. |
| Static audit | Run `skill-audit` and store JSON/Markdown reports. |
| Manual review | Inspect high-risk findings, scripts, dependencies, and hidden instructions. |
| Sandbox test | Execute only with synthetic data and restricted network/filesystem access. |
| Approval | Assign an import decision and safe-use conditions. |
| Monitoring | Review tool calls, external egress, and failures during real use. |
| Re-audit | Re-run after updates, dependency changes, or permission changes. |

## References

[1]: https://owasp.org/www-project-top-10-for-large-language-model-applications/ "OWASP Top 10 for Large Language Model Applications"
[2]: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ "OWASP Top 10 for Agentic Applications 2026"
[3]: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ "Snyk: ToxicSkills: Exposing hidden risks in AI agent skills"

## Change History

| Date and Time | Change | Reason |
|---|---|---|
| 2026-05-28 22:04:04 -03 | Created the initial storytelling guide for `skill-audit`. | Explain the imported-skill risk problem, how the skill solves it, and how users should apply it. |

<!-- SKILL-AUDIT-PATTERN-SOURCE: this document describes the audit threat vocabulary by design; self-matches are expected and suppressed. -->
