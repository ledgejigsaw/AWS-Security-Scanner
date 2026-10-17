import json
import subprocess
import sys
from pathlib import Path


def test_rule_inventory_export_is_sorted_and_complete():
    script = Path(__file__).resolve().parents[1] / "scripts" / "export_rule_inventory.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        capture_output=True,
        text=True,
    )
    inventory = json.loads(result.stdout)

    assert inventory["schema_version"] == "1.0.0"
    assert inventory["inventory_kind"] == "registered_rule_metadata"
    assert inventory["rule_count"] == len(inventory["rules"])
    ids = [rule["check_id"] for rule in inventory["rules"]]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))
    assert all(
        rule["service"]
        and rule["resource_type"]
        and rule["severity"]
        and rule["title"]
        and rule["description"]
        and rule["remediation"]
        for rule in inventory["rules"]
    )
