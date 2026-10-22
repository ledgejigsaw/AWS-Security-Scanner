"""Read-only metadata discovery helpers for high-value AWS data services.

No customer records, SQL rows, cache values, messages or backup payloads are read.
These helpers are additive; callers must surface API errors as incomplete coverage.
"""
from __future__ import annotations
from typing import Any, Callable
from aws_security_scanner.models.resource import Resource

def _pages(call: Callable[..., dict[str, Any]], result_key: str, *, max_pages: int,
           marker_key: str = "Marker", next_key: str = "Marker") -> tuple[list[dict[str, Any]], bool]:
    if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages < 1:
        raise ValueError("max_pages must be a positive integer")
    token, seen, items = None, set(), []
    for _ in range(max_pages):
        response = call(**({marker_key: token} if token else {}))
        values = response.get(result_key, [])
        if not isinstance(values, list):
            raise ValueError(f"AWS API returned malformed {result_key}")
        items.extend(item for item in values if isinstance(item, dict))
        token = response.get(next_key)
        if not token:
            return items, True
        if not isinstance(token, str) or token in seen:
            raise RuntimeError(f"AWS API returned a repeated or invalid {next_key}")
        seen.add(token)
    return items, False

def discover_opensearch_domains(client: Any, *, region: str, max_pages: int = 100) -> list[Resource]:
    names, complete = _pages(client.list_domain_names, "DomainNames", max_pages=max_pages,
                             marker_key="NextToken", next_key="NextToken")
    values = sorted({x.get("DomainName") for x in names if isinstance(x.get("DomainName"), str)})
    resources = []
    for offset in range(0, len(values), 5):
        response = client.describe_domains(DomainNames=values[offset:offset + 5])
        for item in response.get("DomainStatusList", []):
            if not isinstance(item, dict) or not isinstance(item.get("DomainName"), str):
                continue
            resources.append(Resource("aws_opensearch_domain", item["DomainName"], {
                "arn": item.get("ARN"), "engine_version": item.get("EngineVersion"),
                "endpoint": item.get("Endpoint"), "vpc_options": item.get("VPCOptions"),
                "encryption_at_rest": item.get("EncryptionAtRestOptions"),
                "node_to_node_encryption": item.get("NodeToNodeEncryptionOptions"),
                "enforce_https": (item.get("DomainEndpointOptions") or {}).get("EnforceHTTPS"),
                "processing": item.get("Processing"), "discovery_complete": complete,
            }, "aws", region=region))
    return sorted(resources, key=lambda x: x.resource_id)

def discover_redshift_clusters(client: Any, *, region: str, max_pages: int = 100) -> list[Resource]:
    items, complete = _pages(client.describe_clusters, "Clusters", max_pages=max_pages)
    resources = []
    for item in items:
        name = item.get("ClusterIdentifier")
        if isinstance(name, str) and name:
            resources.append(Resource("aws_redshift_cluster", name, {
                "status": item.get("ClusterStatus"), "publicly_accessible": item.get("PubliclyAccessible"),
                "encrypted": item.get("Encrypted"), "kms_key_id": item.get("KmsKeyId"),
                "endpoint": item.get("Endpoint"), "vpc_id": item.get("VpcId"),
                "logging_status": item.get("LoggingStatus"), "discovery_complete": complete,
            }, "aws", region=region))
    return sorted(resources, key=lambda x: x.resource_id)

def discover_elasticache_clusters(client: Any, *, region: str, max_pages: int = 100) -> list[Resource]:
    items, complete = _pages(client.describe_cache_clusters, "CacheClusters", max_pages=max_pages)
    resources = []
    for item in items:
        name = item.get("CacheClusterId")
        if isinstance(name, str) and name:
            resources.append(Resource("aws_elasticache_cluster", name, {
                "status": item.get("CacheClusterStatus"), "engine": item.get("Engine"),
                "engine_version": item.get("EngineVersion"),
                "at_rest_encryption_enabled": item.get("AtRestEncryptionEnabled"),
                "transit_encryption_enabled": item.get("TransitEncryptionEnabled"),
                "auth_token_enabled": item.get("AuthTokenEnabled"), "network_type": item.get("NetworkType"),
                "security_groups": item.get("SecurityGroups"), "discovery_complete": complete,
            }, "aws", region=region))
    return sorted(resources, key=lambda x: x.resource_id)

def discover_msk_clusters(client: Any, *, region: str, max_pages: int = 100) -> list[Resource]:
    items, complete = _pages(client.list_clusters_v2, "ClusterInfoList", max_pages=max_pages,
                             marker_key="NextToken", next_key="NextToken")
    resources = []
    for item in items:
        arn = item.get("ClusterArn")
        if not isinstance(arn, str) or not arn:
            continue
        details = client.describe_cluster_v2(ClusterArn=arn).get("ClusterInfo", {})
        if not isinstance(details, dict):
            details = {}
        broker = details.get("BrokerNodeGroupInfo") or {}
        connectivity = broker.get("ConnectivityInfo") or {}
        resources.append(Resource("aws_msk_cluster", arn, {
            "cluster_name": details.get("ClusterName") or item.get("ClusterName"),
            "cluster_type": details.get("ClusterType"), "state": details.get("State"),
            "encryption_info": details.get("EncryptionInfo"),
            "public_access": connectivity.get("PublicAccess"),
            "discovery_complete": complete,
        }, "aws", region=region))
    return sorted(resources, key=lambda x: x.resource_id)

def discover_backup_inventory(client: Any, *, region: str, max_pages: int = 100) -> list[Resource]:
    resources = []
    for api_name, result_key, resource_type in (
        ("list_backup_vaults", "BackupVaultList", "aws_backup_vault"),
        ("list_backup_plans", "BackupPlansList", "aws_backup_plan"),
        ("list_protected_resources", "Results", "aws_backup_protected_resource"),
    ):
        items, complete = _pages(getattr(client, api_name), result_key, max_pages=max_pages,
                                 marker_key="NextToken", next_key="NextToken")
        for index, item in enumerate(items):
            identity = (item.get("BackupVaultArn") or item.get("BackupPlanArn") or item.get("ResourceArn")
                        or item.get("BackupVaultName") or item.get("BackupPlanId") or item.get("ResourceName")
                        or f"{resource_type}:{index}")
            resources.append(Resource(resource_type, str(identity), {
                "inventory_record": item, "discovery_complete": complete,
            }, "aws", region=region))
    return sorted(resources, key=lambda x: (x.resource_type, x.resource_id))
