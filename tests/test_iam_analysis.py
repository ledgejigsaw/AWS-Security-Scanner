from aws_security_scanner.iam_analysis import analyze_iam_policy


def test_normalizes_single_statement_and_flags_wildcard_admin_grant():
    result = analyze_iam_policy({"Statement": {"Effect": "Allow", "Action": ["iam:PassRole", "s3:GetObject"], "Resource": "*"}}, policy_source="identity_policy")
    statement = result["statements"][0]
    assert statement["status"] == "broad_or_high_risk_allow_review"
    assert "wildcard_resource" in statement["flags"]
    assert "iam:PassRole" in statement["high_risk_actions"]
    assert statement["policy_source"] == "identity_policy"


def test_explicit_deny_and_condition_are_not_flattened_to_allow():
    result = analyze_iam_policy({"Statement": [
        {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "true"}}},
    ]})
    assert result["statements"][0]["status"] == "explicit_deny_statement"
    assert result["statements"][1]["status"] == "conditional_allow_requires_evaluation"
    assert "condition_requires_evaluation" in result["statements"][1]["flags"]


def test_not_action_and_not_resource_require_contextual_review():
    statement = analyze_iam_policy({"Statement": {"Effect": "Allow", "NotAction": ["iam:DeleteUser"], "NotResource": "arn:aws:s3:::restricted"}})["statements"][0]
    assert statement["status"] == "context_dependent_allow_review"
    assert "not_action_requires_contextual_review" in statement["flags"]
    assert "not_resource_requires_contextual_review" in statement["flags"]


def test_invalid_policy_inputs_are_reported_not_crashed():
    assert analyze_iam_policy("{not json") ["status"] == "invalid"
    assert analyze_iam_policy(["not", "a", "document"])["diagnostics"] == ["policy_document_not_object"]


def test_source_context_is_preserved_and_full_effective_access_is_not_claimed():
    result = analyze_iam_policy({"Statement": []}, policy_source="service_control_policy")
    assert result["policy_source"] == "service_control_policy"
    assert any("not effective permissions" in item for item in result["limitations"])
