import csv
import io
import json
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from aws_security_scanner.models.resource import Resource


class CredentialReportUnavailableError(RuntimeError):
    """Raised when IAM credential-report data is not ready or incomplete."""


class AWSProvider:
    """Discover AWS resources using read-only boto3 clients."""

    def __init__(
        self,
        s3_client: Any | None = None,
        iam_client: Any | None = None,
        ec2_client: Any | None = None,
        cloudtrail_client: Any | None = None,
        kms_client: Any | None = None,
        region: str | None = "eu-west-2",
    ):
        self.region = region

        self.s3_client = s3_client or boto3.client(
            "s3",
            region_name=region,
    )

        self.iam_client = iam_client or boto3.client(
            "iam",
            region_name=region,
    )

        self.ec2_client = ec2_client or boto3.client(
            "ec2",
            region_name=region,
        )
        self.cloudtrail_client = cloudtrail_client or boto3.client(
            "cloudtrail",
            region_name=region,
        )
        self.kms_client = kms_client or boto3.client(
            "kms",
            region_name=region,
        )

    def _collect_pages(
        self,
        method: Any,
        result_key: str,
        *,
        request_token: str = "NextToken",
        response_token: str = "NextToken",
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Collect every page from AWS APIs that use continuation tokens."""
        items: list[dict[str, Any]] = []
        token = None

        while True:
            request = dict(kwargs)
            if token:
                request[request_token] = token

            response = method(**request)
            items.extend(response.get(result_key, []))

            if response.get("IsTruncated"):
                next_token = response.get(response_token)
                if not next_token:
                    raise RuntimeError(
                        f"AWS API {getattr(method, '__name__', method)!s} "
                        "reported truncated results without a continuation token."
                    )
            else:
                next_token = response.get(response_token)
                if not next_token:
                    break

            if next_token == token:
                raise RuntimeError(
                    f"AWS API {getattr(method, '__name__', method)!s} "
                    "returned a repeated continuation token."
                )
            token = next_token

        return items

    def discover_s3_buckets(self) -> list[Resource]:
        """Discover S3 buckets and their security configuration."""

        buckets = self._collect_pages(
            self.s3_client.list_buckets,
            "Buckets",
            request_token="ContinuationToken",
            response_token="NextContinuationToken",
        )

        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            attributes = bucket.copy()

            attributes["encryption"] = (
                self._get_bucket_encryption(bucket_name)
            )

            attributes["versioning"] = (
                self._get_bucket_versioning(bucket_name)
            )

            attributes["block_public_access"] = (
                self._get_block_public_access(bucket_name)
            )

            attributes["logging"] = (
                self._get_bucket_logging(bucket_name)
            )

            attributes["bucket_policy"] = (
                self._get_bucket_policy(bucket_name)
            )

            resources.append(
                Resource(
                    resource_type="aws_s3_bucket",
                    resource_id=bucket_name,
                    attributes=attributes,
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_ec2_instances(self) -> list[Resource]:
        """Discover EC2 instances and normalise security attributes."""

        resources = []

        reservations = self._collect_pages(
            self.ec2_client.describe_instances, "Reservations"
        )

        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]

                metadata_options = instance.get(
                    "MetadataOptions",
                    {},
                )

                attributes = {
                    "instance_type": instance.get("InstanceType"),
                    "state": instance.get("State", {}).get("Name"),
                    "public_ip_address": instance.get(
                        "PublicIpAddress"
                    ),
                    "private_ip_address": instance.get(
                        "PrivateIpAddress"
                    ),
                    "subnet_id": instance.get("SubnetId"),
                    "vpc_id": instance.get("VpcId"),
                    "metadata_options": {
                        "http_tokens": metadata_options.get(
                            "HttpTokens"
                        ),
                    },
                    "security_group_ids": [
                        group["GroupId"]
                        for group in instance.get(
                            "SecurityGroups",
                            [],
                        )
                    ],
                }

                resources.append(
                    Resource(
                        resource_type="aws_instance",
                        resource_id=instance_id,
                        attributes=attributes,
                        source="aws",
                        region=self.region,
                    )
                )

        return resources

    def discover_iam_policies(self) -> list[Resource]:
    
        resources = []
        marker = None

        while True:
            if marker:
                response = self.iam_client.list_policies(
                    Scope="Local",
                    Marker=marker,
                )
            else:
                response = self.iam_client.list_policies(
                    Scope="Local",
                )

            for policy in response.get("Policies", []):
                policy_name = policy["PolicyName"]
                policy_arn = policy["Arn"]
                version_id = policy["DefaultVersionId"]

                version_response = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id,
                )

                policy_document = version_response[
                    "PolicyVersion"
                ]["Document"]

                resources.append(
                    Resource(
                        resource_type="aws_iam_policy",
                        resource_id=policy_name,
                        attributes={
                            "policy_document": policy_document,
                        },
                        source="aws",
                        region=self.region,
                    )
                )

            if not response.get("IsTruncated"):
                break

            marker = response.get("Marker")

        return resources

    def discover_iam_roles(self) -> list[Resource]:
        """Discover IAM roles and their trust policies."""

        resources = []
        marker = None

        while True:
            if marker:
                response = self.iam_client.list_roles(
                    Marker=marker,
                )
            else:
                response = self.iam_client.list_roles()

            for role in response.get("Roles", []):
                role_name = role["RoleName"]

                assume_role_policy = role.get(
                    "AssumeRolePolicyDocument"
                )

                resources.append(
                    Resource(
                        resource_type="aws_iam_role",
                        resource_id=role_name,
                        attributes={
                            "assume_role_policy_document": assume_role_policy,
                            "create_date": (
                                role.get("CreateDate").isoformat()
                                if isinstance(role.get("CreateDate"), datetime)
                                else role.get("CreateDate")
                            ),
                            "last_used_date": (
                                role.get("RoleLastUsed", {}).get("LastUsedDate").isoformat()
                                if isinstance(role.get("RoleLastUsed", {}).get("LastUsedDate"), datetime)
                                else role.get("RoleLastUsed", {}).get("LastUsedDate")
                            ),
                        },
                        source="aws",
                        region=self.region,
                    )
                )

            if not response.get("IsTruncated"):
                break

            marker = response.get("Marker")

        return resources



    def discover_iam_account(self) -> list[Resource]:
        """Discover account-level IAM security settings from the credential report."""
        report = self.discover_iam_credential_report()
        root = report.get("<root_account>")
        if root is None:
            raise CredentialReportUnavailableError(
                "IAM credential report did not contain the <root_account> row; "
                "root-account checks cannot be evaluated reliably."
            )

        def report_bool(value: str | None) -> bool | None:
            if value == "true":
                return True
            if value == "false":
                return False
            return None

        return [Resource(
            resource_type="aws_iam_account",
            resource_id="root",
            attributes={
                "root_mfa_enabled": report_bool(root.get("mfa_active")),
                "root_access_key_1_active": report_bool(root.get("access_key_1_active")),
                "root_access_key_2_active": report_bool(root.get("access_key_2_active")),
            },
            source="aws",
            region=None,
        )]

    def _get_bucket_encryption(self, bucket_name: str) -> bool:
        """Return whether server-side encryption is configured."""

        try:
            response = self.s3_client.get_bucket_encryption(
                Bucket=bucket_name
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")

            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                return False

            raise

        return bool(response.get("ServerSideEncryptionConfiguration"))

    def _get_bucket_versioning(self, bucket_name: str) -> bool:
        """Return whether versioning is enabled for an S3 bucket."""

        try:
            response = self.s3_client.get_bucket_versioning(
                Bucket=bucket_name
            )
        except ClientError:
            return False

        return response.get("Status") == "Enabled"

    def _get_block_public_access(
    self,
    bucket_name: str,
) -> bool:
        """Return whether S3 Block Public Access is fully enabled."""

        try:
            response = self.s3_client.get_public_access_block(
                Bucket=bucket_name
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")

            if error_code == "NoSuchPublicAccessBlockConfiguration":
                return False

            raise

        configuration = response.get(
            "PublicAccessBlockConfiguration",
            {},
        )

        return all(
            configuration.get(setting) is True
            for setting in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )

    def _get_bucket_logging(
        self,
        bucket_name: str,
    ) -> bool:
        """Return whether S3 server access logging is enabled."""

        try:
            response = self.s3_client.get_bucket_logging(
                Bucket=bucket_name
            )
        except ClientError:
            return False

        return bool(response.get("LoggingEnabled"))

    def _get_bucket_policy(
        self,
        bucket_name: str,
    ) -> dict | None:
        """Return the S3 bucket policy as a dictionary."""

        try:
            response = self.s3_client.get_bucket_policy(
                Bucket=bucket_name
            )
        except ClientError:
            return None

        policy = response.get("Policy")

        if not isinstance(policy, str):
            return None

        return json.loads(policy)


    def discover_security_groups(self) -> list[Resource]:
        """Discover EC2 security groups and normalise network rules."""

        resources = []

        security_groups = self._collect_pages(
            self.ec2_client.describe_security_groups, "SecurityGroups"
        )

        for security_group in security_groups:
            group_id = security_group["GroupId"]

            ingress_rules = []

            for permission in security_group.get(
                "IpPermissions",
                [],
            ):
                protocol = permission.get("IpProtocol")

                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")

                    if cidr:
                        ingress_rules.append(
                            {
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr,
                            }
                        )

                for ipv6_range in permission.get(
                    "Ipv6Ranges",
                    [],
                ):
                    cidr = ipv6_range.get("CidrIpv6")

                    if cidr:
                        ingress_rules.append(
                            {
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr,
                            }
                        )

            egress_rules = []

            for permission in security_group.get(
                "IpPermissionsEgress",
                [],
            ):
                protocol = permission.get("IpProtocol")

                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")

                    if cidr:
                        egress_rules.append(
                            {
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr,
                            }
                        )

                for ipv6_range in permission.get(
                    "Ipv6Ranges",
                    [],
                ):
                    cidr = ipv6_range.get("CidrIpv6")

                    if cidr:
                        egress_rules.append(
                            {
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr,
                            }
                        )

            attributes = {
                "group_name": security_group.get("GroupName"),
                "vpc_id": security_group.get("VpcId"),
                "ingress_rules": ingress_rules,
                "egress_rules": egress_rules,
            }

            resources.append(
                Resource(
                    resource_type="aws_security_group",
                    resource_id=group_id,
                    attributes=attributes,
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_vpcs(self) -> list[Resource]:
        """Discover VPCs and normalise network attributes."""

        resources = []

        vpcs = self._collect_pages(
            self.ec2_client.describe_vpcs, "Vpcs"
        )

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]

            attributes = {
                "cidr_block": vpc.get("CidrBlock"),
                "is_default": vpc.get("IsDefault", False),
            }

            resources.append(
                Resource(
                    resource_type="aws_vpc",
                    resource_id=vpc_id,
                    attributes=attributes,
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_subnets(self) -> list[Resource]:
        """Discover subnets and normalise network attributes."""

        resources = []

        subnets = self._collect_pages(
            self.ec2_client.describe_subnets, "Subnets"
        )

        for subnet in subnets:
            subnet_id = subnet["SubnetId"]

            attributes = {
                "vpc_id": subnet.get("VpcId"),
                "cidr_block": subnet.get("CidrBlock"),
                "availability_zone": subnet.get("AvailabilityZone"),
                "map_public_ip_on_launch": subnet.get(
                    "MapPublicIpOnLaunch"
                ),
            }

            resources.append(
                Resource(
                    resource_type="aws_subnet",
                    resource_id=subnet_id,
                    attributes=attributes,
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_route_tables(self) -> list[Resource]:
        """Discover route tables and normalise routing attributes."""

        resources = []

        route_tables = self._collect_pages(
            self.ec2_client.describe_route_tables, "RouteTables"
        )

        for route_table in route_tables:
            route_table_id = route_table["RouteTableId"]

            routes = []

            for route in route_table.get("Routes", []):
                routes.append(
                    {
                        "destination_cidr": route.get("DestinationCidrBlock"),
                        "destination_ipv6": route.get(
                            "DestinationIpv6CidrBlock"
                        ),
                        "gateway_id": route.get("GatewayId"),
                        "nat_gateway_id": route.get("NatGatewayId"),
                        "instance_id": route.get("InstanceId"),
                        "state": route.get("State"),
                    }
                )

            associations = []

            for association in route_table.get(
                "Associations",
                [],
            ):
                associations.append(
                    {
                        "subnet_id": association.get("SubnetId"),
                        "main": association.get("Main", False),
                        "association_id": association.get(
                            "RouteTableAssociationId"
                        ),
                    }
                )

            attributes = {
                "vpc_id": route_table.get("VpcId"),
                "routes": routes,
                "associations": associations,
            }

            resources.append(
                Resource(
                    resource_type="aws_route_table",
                    resource_id=route_table_id,
                    attributes=attributes,
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_network_acls(self) -> list[Resource]:
        """Discover network ACLs and normalise network rules."""

        resources = []

        network_acls = self._collect_pages(
            self.ec2_client.describe_network_acls, "NetworkAcls"
        )

        for network_acl in network_acls:
            network_acl_id = network_acl["NetworkAclId"]

            entries = []

            for entry in network_acl.get("Entries", []):
                entries.append(
                    {
                        "egress": entry.get("Egress", False),
                        "rule_number": entry.get("RuleNumber"),
                        "protocol": entry.get("Protocol"),
                        "rule_action": entry.get("RuleAction"),
                        "cidr_block": entry.get("CidrBlock"),
                        "ipv6_cidr_block": entry.get(
                            "Ipv6CidrBlock"
                        ),
                        "from_port": entry.get("PortRange", {}).get(
                            "From"
                        ),
                        "to_port": entry.get("PortRange", {}).get(
                            "To"
                        ),
                    }
                )

            associations = []

            for association in network_acl.get(
                "Associations",
                [],
            ):
                associations.append(
                    {
                        "subnet_id": association.get("SubnetId"),
                        "association_id": association.get(
                            "NetworkAclAssociationId"
                        ),
                    }
                )

            attributes = {
                "vpc_id": network_acl.get("VpcId"),
                "is_default": network_acl.get("IsDefault", False),
                "entries": entries,
                "associations": associations,
            }

            resources.append(
                Resource(
                    resource_type="aws_network_acl",
                    resource_id=network_acl_id,
                    attributes=attributes,
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_flow_logs(self) -> list[Resource]:
        """Discover VPC flow logs and normalise logging attributes."""

        resources = []

        flow_logs = self._collect_pages(
            self.ec2_client.describe_flow_logs, "FlowLogs"
        )

        for flow_log in flow_logs:
            flow_log_id = flow_log["FlowLogId"]

            attributes = {
                "resource_id": flow_log.get("ResourceId"),
                "resource_type": flow_log.get("ResourceType"),
                "traffic_type": flow_log.get("TrafficType"),
                "log_destination_type": flow_log.get(
                    "LogDestinationType"
                ),
                "log_destination": flow_log.get(
                    "LogDestination"
                ),
                "deliver_logs_status": flow_log.get(
                    "DeliverLogsStatus"
                ),
            }

            resources.append(
                Resource(
                    resource_type="aws_flow_log",
                    resource_id=flow_log_id,
                    attributes=attributes,
                    source="aws",
                    region=self.region,
                )
            )

        return resources


    def discover_iam_users(self) -> list[Resource]:
        """Discover IAM users and normalise security-relevant attributes."""
        users = []
        marker = None
        while True:
            response = (
                self.iam_client.list_users(Marker=marker)
                if marker
                else self.iam_client.list_users()
            )
            users.extend(response.get("Users", []))
            if not response.get("IsTruncated"):
                break
            marker = response.get("Marker")

        credential_report = self.discover_iam_credential_report()
        resources = []
        for user in users:
            username = user["UserName"]
            report = credential_report.get(username, {})
            mfa_devices = self._collect_pages(
                self.iam_client.list_mfa_devices,
                "MFADevices",
                request_token="Marker",
                response_token="Marker",
                UserName=username,
            )
            access_key_metadata = self._collect_pages(
                self.iam_client.list_access_keys,
                "AccessKeyMetadata",
                request_token="Marker",
                response_token="Marker",
                UserName=username,
            )
            access_keys = []

            for key in access_key_metadata:
                key_id = key.get("AccessKeyId")
                last_used_response = (
                    self.iam_client.get_access_key_last_used(AccessKeyId=key_id)
                    if key_id else {}
                )
                last_used = last_used_response.get("AccessKeyLastUsed", {})
                created_at = key.get("CreateDate")
                last_used_date = last_used.get("LastUsedDate")
                access_keys.append({
                    "access_key_id": key_id,
                    "status": key.get("Status"),
                    "created_at": created_at.isoformat() if isinstance(created_at, datetime) else created_at,
                    "last_used_date": last_used_date.isoformat() if isinstance(last_used_date, datetime) else last_used_date,
                    "last_used_service": last_used.get("ServiceName"),
                    "last_used_region": last_used.get("Region"),
                })

            inline_policies = []
            policy_marker = None
            while True:
                policy_response = (
                    self.iam_client.list_user_policies(UserName=username, Marker=policy_marker)
                    if policy_marker
                    else self.iam_client.list_user_policies(UserName=username)
                )
                for policy_name in policy_response.get("PolicyNames", []):
                    policy = self.iam_client.get_user_policy(
                        UserName=username,
                        PolicyName=policy_name,
                    )
                    inline_policies.append({
                        "policy_name": policy_name,
                        "policy_document": policy.get("PolicyDocument", {}),
                    })
                if not policy_response.get("IsTruncated"):
                    break
                policy_marker = policy_response.get("Marker")

            password_enabled_value = report.get("password_enabled")
            password_enabled = (
                password_enabled_value.lower() == "true"
                if password_enabled_value in {"true", "false"}
                else None
            )
            password_last_used = report.get("password_last_used")
            if password_last_used in {None, "", "N/A", "no_information", "not_supported"}:
                password_last_used = None

            resources.append(Resource(
                resource_type="aws_iam_user",
                resource_id=username,
                attributes={
                    "user_name": username,
                    "user_id": user.get("UserId"),
                    "arn": user.get("Arn"),
                    "path": user.get("Path"),
                    "mfa_enabled": bool(mfa_devices),
                    "access_keys": access_keys,
                    "password_enabled": password_enabled,
                    "password_last_used": password_last_used,
                    "password_last_changed": report.get("password_last_changed"),
                    "inline_policies": inline_policies,
                },
                source="aws",
                region=None,
            ))
        return resources

    def discover_iam_credential_report(self) -> dict[str, dict[str, str]]:
        """Retrieve the IAM credential report indexed by username."""
        try:
            response = self.iam_client.get_credential_report()
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code == "CredentialReportNotPresent":
                generation = self.iam_client.generate_credential_report()
                state = generation.get("State", "unknown")
                raise CredentialReportUnavailableError(
                    "IAM credential report does not exist. Requested generation "
                    f"(state: {state}); rerun the scan after AWS finishes generating it."
                ) from error
            if code in {"CredentialReportNotReady", "CredentialReportExpired", "ReportInProgress"}:
                raise CredentialReportUnavailableError(
                    f"IAM credential report is unavailable ({code}). "
                    "Rerun the scan after the report is ready."
                ) from error
            raise

        content = response.get("Content", b"")
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        if not content:
            raise CredentialReportUnavailableError(
                "AWS returned an empty IAM credential report; refusing to "
                "treat unavailable credential data as a clean result."
            )

        report = {
            row["user"]: row
            for row in csv.DictReader(io.StringIO(content))
            if row.get("user")
        }
        if not report:
            raise CredentialReportUnavailableError(
                "AWS returned an IAM credential report with no user rows; "
                "refusing to treat incomplete credential data as a clean result."
            )
        return report


    def discover_cloudtrail_trails(self) -> list[Resource]:
        """Discover CloudTrail trails and their logging status."""
        trails = self._collect_pages(
            self.cloudtrail_client.describe_trails,
            "trailList",
            includeShadowTrails=False,
        )
        resources = []

        for trail in trails:
            trail_name = trail.get("Name") or trail.get("TrailARN")
            trail_arn = trail.get("TrailARN") or trail_name
            if not trail_name:
                continue

            status = self.cloudtrail_client.get_trail_status(Name=trail_arn)
            resources.append(
                Resource(
                    resource_type="aws_cloudtrail_trail",
                    resource_id=trail_arn,
                    attributes={
                        "name": trail_name,
                        "trail_arn": trail_arn,
                        "is_multi_region_trail": trail.get(
                            "IsMultiRegionTrail", False
                        ),
                        "is_organization_trail": trail.get(
                            "IsOrganizationTrail", False
                        ),
                        "log_file_validation_enabled": trail.get(
                            "LogFileValidationEnabled", False
                        ),
                        "kms_key_id": trail.get("KmsKeyId"),
                        "s3_bucket_name": trail.get("S3BucketName"),
                        "home_region": trail.get("HomeRegion"),
                        "is_logging": status.get("IsLogging"),
                        "latest_delivery_error": status.get("LatestDeliveryError"),
                    },
                    source="aws",
                    region=trail.get("HomeRegion") or self.region,
                )
            )

        return resources

    def discover_kms_keys(self) -> list[Resource]:
        """Discover KMS keys and rotation/state metadata."""
        key_ids = self._collect_pages(
            self.kms_client.list_keys,
            "Keys",
            request_token="Marker",
            response_token="NextMarker",
        )
        resources = []

        for key in key_ids:
            key_id = key.get("KeyId")
            if not key_id:
                continue

            metadata = self.kms_client.describe_key(KeyId=key_id).get(
                "KeyMetadata", {}
            )
            key_manager = metadata.get("KeyManager")
            key_spec = metadata.get("KeySpec", metadata.get("CustomerMasterKeySpec"))
            key_usage = metadata.get("KeyUsage")
            is_rotation_applicable = (
                key_manager == "CUSTOMER"
                and key_usage == "ENCRYPT_DECRYPT"
                and isinstance(key_spec, str)
                and key_spec.startswith("SYMMETRIC")
            )
            rotation_enabled = (
                self.kms_client.get_key_rotation_status(KeyId=key_id).get(
                    "KeyRotationEnabled"
                )
                if is_rotation_applicable
                else None
            )

            policy_response = self.kms_client.get_key_policy(
                KeyId=key_id,
                PolicyName="default",
            )
            policy_document = policy_response.get("Policy")
            if isinstance(policy_document, str):
                try:
                    policy_document = json.loads(policy_document)
                except json.JSONDecodeError:
                    policy_document = None
            else:
                policy_document = None

            resources.append(
                Resource(
                    resource_type="aws_kms_key",
                    resource_id=metadata.get("Arn") or key_id,
                    attributes={
                        "key_id": key_id,
                        "arn": metadata.get("Arn"),
                        "key_manager": key_manager,
                        "key_spec": key_spec,
                        "key_usage": key_usage,
                        "key_state": metadata.get("KeyState"),
                        "rotation_applicable": is_rotation_applicable,
                        "rotation_enabled": rotation_enabled,
                        "description": metadata.get("Description"),
                        "key_policy": policy_document,
                    },
                    source="aws",
                    region=metadata.get("Arn", "").split(":")[3]
                    if metadata.get("Arn") and len(metadata.get("Arn", "").split(":")) > 3
                    else self.region,
                )
            )

        return resources
