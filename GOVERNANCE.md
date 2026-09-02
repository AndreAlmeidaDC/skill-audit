# Governance

## Scope

This repository provides a static and procedural review pipeline for Agent Skills. It does not certify safety and does not automatically execute audited packages.

## Decision ownership

- The scanner produces evidence and a provisional risk rating.
- A human or independent security owner approves privileged import or dynamic testing.
- Production, financial, credentialed and public actions remain outside automatic approval.

## Change control

Changes to detection, severity, suppression, capability mapping, attack chains or sandbox policy require regression tests and pull-request review.

## Suppression governance

Suppressions live outside the audited target, identify an approver and reason, expire, remain visible, and cannot apply to critical findings.

## Update policy

The skill may check its canonical public repository for a newer version. It never executes remote update code, self-updates silently or overwrites local changes without consent.

## Author

André Almeida
