from aws_security_scanner.multi_region import classify_regions, scan_regions


def test_region_classification_excludes_opt_in_disabled_regions():
    enabled, skipped = classify_regions({
        "Regions": [
            {"RegionName": "eu-west-2", "OptInStatus": "opt-in-not-required"},
            {"RegionName": "ap-east-1", "OptInStatus": "not-opted-in"},
            {"RegionName": "me-central-1", "OptInStatus": "opted-in"},
        ]
    })
    assert [item.name for item in enabled] == ["eu-west-2", "me-central-1"]
    assert [item.name for item in skipped] == ["ap-east-1"]


def test_one_region_failure_does_not_discard_successful_regions():
    def scan(region):
        if region == "us-east-1":
            raise PermissionError("sensitive message must not be reported")
        return [{"region": region}]

    result = scan_regions(["eu-west-2", "us-east-1"], scan)
    assert result["status"] == "incomplete"
    assert result["regions_attempted"] == ["eu-west-2", "us-east-1"]
    assert result["regions_failed"] == ["us-east-1"]
    assert result["resources"] == [{"region": "eu-west-2"}]
    assert "sensitive message" not in str(result)


def test_global_discovery_runs_once_not_per_region():
    calls = []
    result = scan_regions(
        ["eu-west-2", "us-east-1", "eu-west-2"],
        lambda region: [{"region": region}],
        global_scan=lambda: calls.append("global") or [{"scope": "global"}],
    )
    assert calls == ["global"]
    assert result["global_discovery"]["resources_discovered"] == 1
    assert len(result["regions"]) == 2


def test_global_failure_marks_result_incomplete_but_keeps_regional_data():
    result = scan_regions(
        ["eu-west-2"],
        lambda region: [{"region": region}],
        global_scan=lambda: (_ for _ in ()).throw(RuntimeError("private details")),
    )
    assert result["status"] == "incomplete"
    assert result["resources"] == [{"region": "eu-west-2"}]
    assert result["global_discovery"]["status"] == "failed"
    assert "private details" not in str(result)
