# Relationship-aware attack-path candidates

`aws_security_scanner.attack_paths.find_attack_path_candidates` consumes the existing resource-graph JSON structure and identifies bounded paths from configured entry findings to configured target findings or resource types.

This is an analyst-triage aid, not an exploitability verdict. The graph contains recorded resource relationships; it does not prove that a network route is reachable, that effective IAM permissions permit an action, or that a runtime exploit exists. The caller must explicitly choose entry and target check IDs/types. Paths are deterministic, simple (no repeated nodes), and bounded by `max_depth` and `max_paths`.

Example:

```python
from aws_security_scanner.attack_paths import find_attack_path_candidates

candidates = find_attack_path_candidates(
    graph_json,
    entry_check_ids={"NET-ENTRY"},
    target_check_ids={"DATA-SENSITIVE"},
    max_depth=6,
    max_paths=100,
)
```

Validate each candidate against network reachability, policy context, and runtime evidence before making a risk determination. An absent graph edge is not evidence of isolation.