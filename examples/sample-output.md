# Sample output

```json
{
  "risk_rating": "HIGH",
  "posture_score": 71,
  "severity_counts": {
    "CRITICAL": 0,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0
  },
  "attack_chains": [
    {
      "id": "CHAIN-REMOTE-INSTRUCTION",
      "severity": "HIGH",
      "title": "External instructions combine with egress",
      "rules": [
        "AST05-EXTERNAL-INSTRUCTIONS",
        "AST03-NETWORK-EGRESS"
      ]
    }
  ]
}
```

Interpretation:

- `HIGH` controls the import decision because it is the highest credible open severity.
- `71/100` is a secondary posture indicator, not a probability of compromise.
- The attack chain explains why individually moderate signals combine into a stronger risk.
- A clean report would still require provenance review before privileged execution.
