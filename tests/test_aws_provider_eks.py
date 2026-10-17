from aws_security_scanner.providers.aws import AWSProvider


class FakeEKS:
    def __init__(self):
        self.describe_calls = []

    def list_clusters(self, **kwargs):
        if "nextToken" not in kwargs:
            return {"clusters": ["cluster-a"], "nextToken": "page-2"}
        assert kwargs["nextToken"] == "page-2"
        return {"clusters": ["cluster-b"]}

    def describe_cluster(self, *, name):
        self.describe_calls.append(name)
        return {
            "cluster": {
                "name": name,
                "arn": f"arn:aws:eks:eu-west-2:111111111111:cluster/{name}",
                "status": "ACTIVE",
                "version": "1.31",
                "resourcesVpcConfig": {
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                    "publicAccessCidrs": ["0.0.0.0/0"],
                    "clusterSecurityGroupId": "sg-cluster",
                    "securityGroupIds": ["sg-extra"],
                    "subnetIds": ["subnet-a", "subnet-b"],
                },
                "logging": {
                    "clusterLogging": [
                        {"types": ["api", "audit"], "enabled": name == "cluster-a"}
                    ]
                },
                "encryptionConfig": [],
            }
        }


def test_eks_discovery_paginates_and_preserves_security_metadata():
    provider = object.__new__(AWSProvider)
    provider.region = "eu-west-2"
    provider.eks_client = FakeEKS()

    resources = provider.discover_eks_clusters()

    assert [item.resource_id for item in resources] == ["cluster-a", "cluster-b"]
    assert provider.eks_client.describe_calls == ["cluster-a", "cluster-b"]
    first = resources[0]
    assert first.attributes["endpoint_public_access"] is True
    assert first.attributes["endpoint_private_access"] is False
    assert first.attributes["public_access_cidrs"] == ["0.0.0.0/0"]
    assert first.attributes["control_plane_log_types_enabled"] == ["api", "audit"]
    assert first.attributes["control_plane_logging_metadata_available"] is True
    assert first.region == "eu-west-2"
