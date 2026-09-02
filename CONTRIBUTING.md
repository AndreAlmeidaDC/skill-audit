# Contributing

## Required workflow

1. Create a branch.
2. Add or update a regression fixture before changing security behavior.
3. Run `python3 scripts/validate_skill.py`.
4. Run `python3 scripts/test_audit_skill.py`.
5. Update `metadata.json`, `SKILL.md` and `CHANGELOG.md` together.
6. Open a pull request describing detection impact, false-positive risk and residual blind spots.

## Security rules

- Target-controlled content must never disable or downgrade a rule.
- Critical findings cannot be suppressed.
- New suppressions must be external, reviewed, expiring and visible.
- Capability declarations are context, not trust.
- Any severity change requires a regression test.
- Any new parser must be bounded against large or malformed input.
- Dynamic execution is outside the static scanner and remains approval-gated.

## Source rules

Use primary specifications and official security guidance. Record the date when behavior is volatile. Do not convert vendor claims into independent proof.
