# Implementation notes

Run python scripts/check_rule_inventory_drift.py from the repository root. The command checks that every registered rule has a stable unique ID and compares the README's labelled total with the current registry count. It exits non-zero with a direct diagnostic when the total is stale or missing. It is offline and requires no AWS credentials.

This is a narrow count-drift check; it does not prove semantic rule coverage, per-service documentation, upstream mappings or test coverage.
