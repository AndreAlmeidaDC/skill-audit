# Reviewer guide

## Review sequence

1. Confirm source, owner, commit or archive hash.
2. Inspect package integrity before reading instructions as trusted content.
3. Validate `SKILL.md` identity, description, compatibility and allowed tools.
4. Read every executable file and install hook.
5. Compare declared, observed and necessary capabilities.
6. Trace data from sources to sinks.
7. Review dependencies, lockfiles, workflows and external instructions.
8. Examine multi-signal attack chains.
9. Decide whether static evidence is enough or a sandbox is required.
10. Record residual risk, scope and expiry of any exception.

## Import decisions

| Decision | Meaning |
|---|---|
| approved | No blocking finding; capabilities and provenance fit the intended use. |
| restricted | Use only with reduced tools, data, network or filesystem scope. |
| quarantine | Do not import into a privileged environment until remediated and re-reviewed. |
| rejected | Malicious, destructive, credential-stealing or fundamentally unreviewable behavior. |

## Dynamic test boundary

Dynamic testing is a new approval decision. Use fake secrets and canaries, an ephemeral filesystem, denied network by default, no production credentials, no authenticated browser, resource limits and full telemetry. A sandbox run does not authorize production use.
