from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.eks_rules import (
    check_eks_audit_logging_disabled,
    check_eks_public_endpoint_review,
    check_eks_unrestricted_public_endpoint,
)


def cluster(**attributes):
    defaults = {
        "endpoint_public_access": True,
        "endpoint_private_access": True,
        "public_access_cidrs": ["10.0.0.0/8"],
        "control_plane_logging_metadata_available": True,
        "control_plane_log_types_enabled": ["api", "audit"],
    }
    defaults.update(attributes)
    return Resource(
        resource_type="aws_eks_cluster",
        resource_id="example",
        attributes=defaults,
        source="aws",
        region="eu-west-2",
    )


def test_eks_unrestricted_public_endpoint_detects_ipv4_and_ipv6_wildcards():
    assert check_eks_unrestricted_public_endpoint(
        cluster(public_access_cidrs=["0.0.0.0/0"])
    )[0].check_id == "EKS-001"
    assert check_eks_unrestricted_public_endpoint(
        cluster(public_access_cidrs=["::/0"])
    )[0].check_id == "EKS-001"


def test_eks_unrestricted_public_endpoint_ignores_restricted_or_unknown_states():
    assert check_eks_unrestricted_public_endpoint(
        cluster(public_access_cidrs=["10.0.0.0/8"])
    ) == []
    assert check_eks_unrestricted_public_endpoint(
        cluster(endpoint_public_access=False, public_access_cidrs=["0.0.0.0/0"])
    ) == []
    assert check_eks_unrestricted_public_endpoint(
        cluster(public_access_cidrs=None)
    ) == []


def test_eks_audit_logging_detects_explicit_missing_audit_type_only():
    assert check_eks_audit_logging_disabled(
        cluster(control_plane_log_types_enabled=["api"])
    )[0].check_id == "EKS-002"
    assert check_eks_audit_logging_disabled(
        cluster(control_plane_logging_metadata_available=False, control_plane_log_types_enabled=[])
    ) == []
    assert check_eks_audit_logging_disabled(cluster()) == []


def test_eks_public_endpoint_review_requires_explicitly_disabled_private_access():
    assert check_eks_public_endpoint_review(
        cluster(endpoint_private_access=False)
    )[0].check_id == "EKS-003"
    assert check_eks_public_endpoint_review(
        cluster(endpoint_private_access=True)
    ) == []
    assert check_eks_public_endpoint_review(
        cluster(endpoint_private_access=None)
    ) == []
