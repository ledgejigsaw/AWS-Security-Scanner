# Security rule specification template

Copy this template into an issue or pull request description when proposing a new rule.

## Rule identity

- **Proposed check ID:** `SERVICE-NNN`
- **AWS service / domain:**
- **Normalised resource type:**
- **Proposed severity:** CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Category:**

## Security rationale

- **Threat or failure mode:**
- **Security impact:**
- **Evidence required to confirm the condition:**
- **Why this severity is appropriate:**
- **Expected false positives / accepted use cases:**

## Detection semantics

- **Insecure state:** What exact observed values trigger the rule?
- **Safe state:** Which observed values should not trigger it?
- **Unknown/incomplete state:** What happens when data is missing, denied, malformed or unsupported?
- **Policy override:** Is the baseline organisation-dependent?
- **Known limitations:** What does the rule not prove?

## Discovery and data handling

- **Required read-only AWS API operations:**
- **Pagination behaviour:**
- **Minimum IAM permissions:**
- **Sensitive data collected:** Must be none unless explicitly justified and reviewed.
- **Source normalisation:** Which attributes are added to `Resource`?
- **Failure semantics:** How are access denied, throttling and partial results represented?

## Finding contract

- **Title:**
- **Description:**
- **Evidence format:**
- **Remediation:**
- **Documentation references:**

## Test plan

- [ ] Confirmed insecure state generates the expected finding.
- [ ] Safe state generates no finding.
- [ ] Missing or unknown state does not create an unsupported finding.
- [ ] Malformed input does not crash the scan.
- [ ] Provider pagination is tested if relevant.
- [ ] API errors/permission failures are tested if relevant.
- [ ] Rule is registered and unique check IDs are verified.
- [ ] CLI/integration path is tested.
- [ ] README coverage and rule count are updated.
- [ ] Tests run without AWS credentials or network access.

## Acceptance criteria

Write observable, testable outcomes. Avoid acceptance criteria such as “works correctly” or “secure by default” without a specific behaviour to verify.
