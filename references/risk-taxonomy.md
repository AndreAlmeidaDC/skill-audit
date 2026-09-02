# Risk taxonomy

The taxonomy follows the skill lifecycle rather than a flat list of suspicious strings.

| Family | Main question | Examples |
|---|---|---|
| Malicious instructions | Can the package manipulate higher-priority behavior or hide actions? | override prompts, stealth, exfiltration |
| Supply chain | Can mutable or unverified content become executable? | remote scripts, mutable actions, install hooks, unpinned dependencies |
| Excessive capability | Does observed access exceed the task's need or declaration? | sensitive files, network, production, finance, memory |
| Metadata and routing | Can identity, description or metadata misroute or impersonate? | vague triggers, name mismatch, homoglyphs |
| External instructions | Does mutable outside content become operational instruction? | “follow the rules at this URL” |
| Isolation | Can content escape the package or runtime boundary? | symlinks, archive traversal, privilege escalation |
| Update drift | Can reviewed behavior change without a new review? | branches, tags, floating versions, silent update |
| Scanning gaps | Is the package relying on encodings, generated code or semantics that patterns miss? | bidi, base64, opaque binaries, transitive code |
| Governance | Is ownership, provenance, approval, revocation or evidence missing? | no source, no changelog, no review trail |
| Cross-platform reuse | Did a port lose host-specific security metadata or constraints? | dropped allowed-tools, browser or shell expansion |

## Decision principle

The highest credible open finding and attack chains dominate the decision. A numeric posture score is secondary and cannot cancel a critical path.

## Evidence confidence

- `high`: direct file, AST or package evidence;
- `medium`: contextual pattern or inferred capability;
- `low`: hypothesis requiring manual or dynamic validation.
