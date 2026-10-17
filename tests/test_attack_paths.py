from aws_security_scanner.attack_paths import find_attack_path_candidates


def graph_fixture():
    return {
        "nodes": [
            {"id": "edge", "resource_type": "aws_lb", "findings": [{"check_id": "NET-ENTRY", "severity": "HIGH"}]},
            {"id": "role", "resource_type": "aws_iam_role", "findings": []},
            {"id": "data", "resource_type": "aws_s3_bucket", "findings": [{"check_id": "DATA-SENSITIVE", "severity": "HIGH"}]},
            {"id": "island", "resource_type": "aws_s3_bucket", "findings": [{"check_id": "DATA-SENSITIVE", "severity": "HIGH"}]},
        ],
        "edges": [
            {"source": "edge", "target": "role", "relationship": "role"},
            {"source": "role", "target": "data", "relationship": "bucket"},
            {"source": "role", "target": "edge", "relationship": "cycle"},
        ],
    }


def test_finds_only_explicit_entry_to_sensitive_target_path():
    paths = find_attack_path_candidates(graph_fixture(), entry_check_ids={"NET-ENTRY"}, target_check_ids={"DATA-SENSITIVE"})
    assert len(paths) == 1
    assert paths[0]["node_ids"] == ["edge", "role", "data"]
    assert paths[0]["classification"] == "potential_attack_path_candidate"
    assert paths[0]["confidence"] == "unverified_relationship_path"


def test_unconnected_sensitive_resource_is_not_reported():
    paths = find_attack_path_candidates(graph_fixture(), entry_check_ids={"NET-ENTRY"}, target_resource_types={"aws_s3_bucket"})
    assert [item["target_node"] for item in paths] == ["data"]


def test_cycles_are_safe_and_depth_and_count_are_bounded():
    graph = graph_fixture()
    graph["edges"].append({"source": "data", "target": "role", "relationship": "back"})
    assert len(find_attack_path_candidates(graph, entry_check_ids={"NET-ENTRY"}, target_check_ids={"DATA-SENSITIVE"}, max_depth=1)) == 0
    assert len(find_attack_path_candidates(graph, entry_check_ids={"NET-ENTRY"}, target_check_ids={"DATA-SENSITIVE"}, max_paths=1)) == 1


def test_invalid_limits_are_rejected():
    try:
        find_attack_path_candidates(graph_fixture(), entry_check_ids={"NET-ENTRY"}, max_depth=0)
    except ValueError as error:
        assert "positive" in str(error)
    else:
        raise AssertionError("expected ValueError")
