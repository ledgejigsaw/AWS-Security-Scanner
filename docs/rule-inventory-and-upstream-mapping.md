# Rule inventory and upstream mapping

Generate the deterministic inventory and validate the versioned mapping ledger:

```bash
python scripts/export_rule_inventory.py --output reports/rule-inventory.json
python scripts/export_upstream_rule_mapping.py --output reports/upstream-rule-mapping.json
python scripts/validate_upstream_rule_mapping.py
```

The inventory includes rule source paths, statically observed attribute-key references, and test files mentioning each stable check ID. These are audit aids, not proof that all secure, insecure, unknown and error branches are covered.

`upstream-rule-mapping.json` is the check-level ledger. Initial rows deliberately remain `not-reviewed`; no equivalence is inferred from similar titles. An `equivalent` row must identify the scanner check, upstream project/check, URL, pinned version and rationale. Keep Checkov IaC mappings separate from Prowler/ScoutSuite live-account controls where the evidence is not comparable.

Run the validator after changing the registry or ledger. The ledger is not a claim of full parity; its purpose is to make gaps, provenance and review status explicit.
