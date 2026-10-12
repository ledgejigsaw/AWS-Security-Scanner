# Developing a security rule

## Principles

A rule should be narrowly scoped, evidence-based, deterministic and safe to run against incomplete discovery data. Keep service/API calls in the provider layer and security decisions in rule modules wherever practical.

## Rule metadata

Rules are declared with the `rule_for` decorator in `aws_security_scanner.rules.decorators`. Metadata includes:

- `resource_type`: normalised resource type accepted by the rule.
- `check_id`: stable identifier such as `S3-001`.
- `service` and `category`.
- Default `severity`.
- A concise `title`, explanatory `description` and actionable `remediation`.

The rule must be imported and added to `get_all_rules()` in `rules/registry.py`; defining a function alone does not make it part of the active rule set.

## Detection guidance

1. Prefer explicit evidence from collected attributes.
2. Distinguish a confirmed insecure setting from a missing or unknown value.
3. Do not label absence of data as proof of a vulnerability unless the rule is specifically designed to detect missing configuration and the source semantics support that conclusion.
4. Avoid destructive actions or write APIs. Rules should assess configuration, not remediate it.
5. Include evidence that explains why the finding was generated.
6. Choose severity based on impact and exposure; informational observations should not be described as confirmed vulnerabilities.
7. Add positive and negative tests, including incomplete metadata where relevant.

## Suggested implementation checklist

- [ ] Add or update a service-specific rule module.
- [ ] Declare complete metadata using `rule_for`.
- [ ] Construct findings consistently with the existing `Finding` model.
- [ ] Register the rule in `rules/registry.py`.
- [ ] Add tests for insecure, secure and unknown/incomplete states.
- [ ] Add or update provider tests if discovery or normalisation changes.
- [ ] Update README service coverage and registered-rule counts when applicable.
- [ ] Update this documentation if the shared rule-development process changes.
- [ ] Run `pytest -q` and review GitHub Actions before merging.
