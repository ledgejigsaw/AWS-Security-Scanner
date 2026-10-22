"""Fail-fast check for drift between the rule registry and README totals."""
from __future__ import annotations
import re, sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
from aws_security_scanner.rules.registry import get_all_rules  # noqa: E402

def registered_rule_count() -> int:
    rules = get_all_rules()
    ids = []
    for rule in rules:
        metadata = getattr(rule, "metadata", None)
        if metadata is None or not getattr(metadata, "check_id", None):
            raise ValueError(f"Rule {getattr(rule, '__name__', '<unknown>')} has no stable check ID.")
        ids.append(metadata.check_id)
    duplicates = sorted({value for value in ids if ids.count(value) > 1})
    if duplicates:
        raise ValueError("Duplicate registered rule IDs: " + ", ".join(duplicates))
    return len(ids)

def check_readme_count(readme: str, expected: int) -> list[str]:
    values = [int(value) for value in re.findall(r"\*\*(\d+) registered security rules\*\*", readme, re.I)]
    if not values:
        return ["README has no labelled registered-rule total."]
    return [f"README reports {value} registered rules; registry contains {expected}."
            for value in values if value != expected]

def main() -> int:
    try:
        expected = registered_rule_count()
        errors = check_readme_count((_ROOT / "README.md").read_text(encoding="utf-8"), expected)
    except (OSError, ValueError) as exc:
        print(f"Rule inventory check failed: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print("ERROR: " + error, file=sys.stderr)
        return 1
    print(f"Rule inventory documentation is consistent ({expected} registered rules).")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
