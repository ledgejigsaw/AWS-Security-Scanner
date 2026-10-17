# Finding evidence quality checks

`aws_security_scanner.finding_quality.validate_finding_quality(findings)` performs non-mutating checks for missing check IDs, missing resource scope, missing remediation, missing or placeholder evidence, and evidence that resembles a credential or private key.

The output is a quality report, not a security finding and not a verdict that an existing finding is correct or incorrect. Raw evidence and resource identifiers are intentionally omitted from diagnostic output. If a credential-like value is detected, redact it at its source; the validator does not modify the original finding. Secret detection is pattern-based and cannot guarantee detection of all sensitive values.

Example:

```python
from aws_security_scanner.finding_quality import validate_finding_quality

quality_report = validate_finding_quality(findings)
```