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
        rds_client: Any | None = None,
        lambda_client: Any | None = None,
        secretsmanager_client: Any | None = None,
        ecr_client: Any | None = None,
        dynamodb_client: Any | None = None,
        sqs_client: Any | None = None,
        sns_client: Any | None = None,
        apigateway_client: Any | None = None,
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
        self.rds_client = rds_client or boto3.client(
            "rds",
            region_name=region,
        )
        self.lambda_client = lambda_client or boto3.client(
            "lambda",
            region_name=region,
        )
        self.secretsmanager_client = secretsmanager_client or boto3.client(
            "secretsmanager",
            region_name=region,
        )
        self.ecr_client = ecr_client or boto3.client(
            "ecr",
            region_name=region,
        )
        self.dynamodb_client = dynamodb_client or boto3.client(
            "dynamodb",
            region_name=region,
        )
        self.sqs_client = sqs_client or boto3.client(
            "sqs",
            region_name=region,
        )
        self.sns_client = sns_client or boto3.client(
            "sns",
            region_name=region,
        )
        self.apigateway_client = apigateway_client or boto3.client(
            "apigateway",
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


    def discover_secrets_manager_secrets(self) -> list[Resource]:
        """Discover secret metadata and resource policies without retrieving values."""
        secrets = self._collect_pages(
            self.secretsmanager_client.list_secrets,
            "SecretList",
            request_token="NextToken",
            response_token="NextToken",
        )
        resources = []

        for secret in secrets:
            secret_id = secret.get("ARN") or secret.get("Name")
            if not secret_id:
                continue

            details = self.secretsmanager_client.describe_secret(
                SecretId=secret_id,
            )
            resource_policy = None
            try:
                policy_response = self.secretsmanager_client.get_resource_policy(
                    SecretId=secret_id,
                )
                policy_document = policy_response.get("ResourcePolicy")
                if isinstance(policy_document, str):
                    try:
                        resource_policy = json.loads(policy_document)
                    except json.JSONDecodeError:
                        resource_policy = None
                elif isinstance(policy_document, dict):
                    resource_policy = policy_document
            except ClientError as error:
                error_code = error.response.get("Error", {}).get("Code")
                if error_code not in {"ResourceNotFoundException", "ResourceNotFound"}:
                    raise

            name = details.get("Name") or secret.get("Name") or secret_id
            attributes = {
                "arn": details.get("ARN") or secret.get("ARN"),
                "name": name,
                "rotation_enabled": details.get("RotationEnabled"),
                "kms_key_id": details.get("KmsKeyId") or secret.get("KmsKeyId"),
                "owning_service": details.get("OwningService") or secret.get("OwningService"),
                "resource_policy": resource_policy,
            }
            resources.append(
                Resource(
                    resource_type="aws_secretsmanager_secret",
                    resource_id=name,
                    attributes=attributes,
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_ecr_repositories(self) -> list[Resource]:
        """Discover ECR repository security metadata without downloading images."""
        repositories = self._collect_pages(
            self.ecr_client.describe_repositories,
            "repositories",
            request_token="nextToken",
            response_token="nextToken",
        )
        resources = []

        for repository in repositories:
            repository_name = repository.get("repositoryName")
            if not repository_name:
                continue

            scanning = repository.get("imageScanningConfiguration")
            if not isinstance(scanning, dict):
                scanning = {}
            encryption = repository.get("encryptionConfiguration")
            if not isinstance(encryption, dict):
                encryption = {}

            resources.append(
                Resource(
                    resource_type="aws_ecr_repository",
                    resource_id=repository_name,
                    attributes={
                        "arn": repository.get("repositoryArn"),
                        "name": repository_name,
                        "uri": repository.get("repositoryUri"),
                        "image_tag_mutability": repository.get("imageTagMutability"),
                        "scan_on_push": scanning.get("scanOnPush"),
                        "encryption_type": encryption.get("encryptionType"),
                        "kms_key": encryption.get("kmsKey"),
                    },
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_sqs_queues(self) -> list[Resource]:
        """Discover SQS queue metadata and access/encryption configuration."""
        queue_urls = self._collect_pages(
            self.sqs_client.list_queues, "QueueUrls",
            request_token="NextToken", response_token="NextToken",
        )
        resources = []
        for queue_url in queue_urls:
            if not isinstance(queue_url, str) or not queue_url:
                continue
            response = self.sqs_client.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["All"],
            )
            attributes = response.get("Attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}
            queue_name = queue_url.rstrip("/").rsplit("/", 1)[-1]
            kms_key = attributes.get("KmsMasterKeyId")
            sqs_managed = attributes.get("SqsManagedSseEnabled")
            if kms_key or str(sqs_managed).lower() == "true":
                encryption_enabled = True
            elif attributes.get("QueueArn"):
                encryption_enabled = False
            else:
                encryption_enabled = None
            resources.append(Resource(
                resource_type="aws_sqs_queue", resource_id=queue_name,
                attributes={
                    "arn": attributes.get("QueueArn"), "url": queue_url,
                    "name": queue_name, "policy": attributes.get("Policy"),
                    "encryption_enabled": encryption_enabled,
                    "kms_key_id": kms_key,
                    "sqs_managed_sse_enabled": (
                        str(sqs_managed).lower() == "true"
                        if sqs_managed is not None else None
                    ),
                    "dead_letter_target_arn": self._queue_dead_letter_target(
                        attributes.get("RedrivePolicy")
                    ),
                }, source="aws", region=self.region,
            ))
        return resources

    @staticmethod
    def _queue_dead_letter_target(value: Any) -> str | None:
        """Extract the dead-letter target ARN from an SQS redrive policy."""
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                return None
        if not isinstance(value, dict):
            return None
        target = value.get("deadLetterTargetArn")
        return target if isinstance(target, str) else None

    def discover_sns_topics(self) -> list[Resource]:
        """Discover SNS topic attributes without publishing or subscribing."""
        topics = self._collect_pages(
            self.sns_client.list_topics, "Topics",
            request_token="NextToken", response_token="NextToken",
        )
        resources = []
        for topic in topics:
            if not isinstance(topic, dict):
                continue
            topic_arn = topic.get("TopicArn")
            if not isinstance(topic_arn, str) or not topic_arn:
                continue
            response = self.sns_client.get_topic_attributes(TopicArn=topic_arn)
            attributes = response.get("Attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}
            topic_name = topic_arn.rsplit(":", 1)[-1]
            kms_key = attributes.get("KmsMasterKeyId")
            if kms_key:
                encryption_enabled = True
            elif attributes.get("TopicArn"):
                encryption_enabled = False
            else:
                encryption_enabled = None
            resources.append(Resource(
                resource_type="aws_sns_topic", resource_id=topic_name,
                attributes={
                    "arn": topic_arn, "name": topic_name,
                    "policy": attributes.get("Policy"),
                    "encryption_enabled": encryption_enabled,
                    "kms_master_key_id": kms_key,
                }, source="aws", region=self.region,
            ))
        return resources

    def discover_api_gateway_rest_apis(self) -> list[Resource]:
        """Discover API Gateway REST APIs, method auth and stage access logging.

        HTTP APIs (API Gateway v2) are intentionally out of scope for this initial
        implementation. No API requests are invoked and no configuration is changed.
        """
        apis = self._collect_pages(
            self.apigateway_client.get_rest_apis,
            "items",
            request_token="position",
            response_token="position",
        )
        resources: list[Resource] = []
        for api in apis:
            api_id = api.get("id")
            if not api_id:
                continue
            api_name = api.get("name") or api_id
            policy = api.get("policy")
            api_resources = self._collect_pages(
                self.apigateway_client.get_resources,
                "items",
                request_token="position",
                response_token="position",
                restApiId=api_id,
            )
            methods: list[dict[str, Any]] = []
            for api_resource in api_resources:
                path = api_resource.get("path")
                resource_methods = api_resource.get("resourceMethods", {})
                if not isinstance(resource_methods, dict):
                    continue
                for http_method in resource_methods:
                    method_response = self.apigateway_client.get_method(
                        restApiId=api_id,
                        resourceId=api_resource.get("id"),
                        httpMethod=http_method,
                    )
                    methods.append({
                        "path": path,
                        "http_method": http_method,
                        "authorization_type": method_response.get("authorizationType"),
                        "authorizer_id": method_response.get("authorizerId"),
                        "api_key_required": method_response.get("apiKeyRequired"),
                    })

            stages_response = self.apigateway_client.get_stages(restApiId=api_id)
            stages = stages_response.get("item", [])
            if not isinstance(stages, list):
                stages = []
            for stage in stages:
                stage_name = stage.get("stageName")
                if not stage_name:
                    continue
                access_log_settings = stage.get("accessLogSettings")
                if not isinstance(access_log_settings, dict):
                    access_log_settings = {}
                resources.append(Resource(
                    resource_type="aws_api_gateway_stage",
                    resource_id=f"{api_id}:{stage_name}",
                    attributes={
                        "api_id": api_id,
                        "api_name": api_name,
                        "stage_name": stage_name,
                        "endpoint_configuration": api.get("endpointConfiguration", {}),
                        "resource_policy": policy,
                        "methods": methods,
                        "access_log_destination_arn": access_log_settings.get("destinationArn"),
                        "access_log_format": access_log_settings.get("format"),
                        "access_logging_enabled": bool(
                            access_log_settings.get("destinationArn")
                            and access_log_settings.get("format")
                        ),
                        "method_settings": stage.get("methodSettings", {}),
                        "stage_logging_level": (
                            stage.get("methodSettings", {}).get("*/*", {}).get("loggingLevel")
                            if isinstance(stage.get("methodSettings", {}), dict)
                            and isinstance(stage.get("methodSettings", {}).get("*/*", {}), dict)
                            else None
                        ),
                    },
                    source="aws",
                    region=self.region,
                ))
        return resources

    def discover_dynamodb_tables(self) -> list[Resource]:
        """Discover DynamoDB table security metadata without reading table items."""
        table_names = self._collect_pages(
            self.dynamodb_client.list_tables,
            "TableNames",
            request_token="ExclusiveStartTableName",
            response_token="LastEvaluatedTableName",
        )
        resources = []

        for table_summary in table_names:
            table_name = table_summary.get("TableName") if isinstance(table_summary, dict) else table_summary
            if not table_name:
                continue

            response = self.dynamodb_client.describe_table(TableName=table_name)
            table = response.get("Table", {})
            if not isinstance(table, dict):
                table = {}

            backups = self.dynamodb_client.describe_continuous_backups(
                TableName=table_name,
            )
            backup_description = backups.get("ContinuousBackupsDescription", {})
            if not isinstance(backup_description, dict):
                backup_description = {}
            pitr_description = backup_description.get(
                "PointInTimeRecoveryDescription", {}
            )
            if not isinstance(pitr_description, dict):
                pitr_description = {}

            encryption = table.get("SSEDescription", {})
            if not isinstance(encryption, dict):
                encryption = {}

            resources.append(
                Resource(
                    resource_type="aws_dynamodb_table",
                    resource_id=table_name,
                    attributes={
                        "arn": table.get("TableArn"),
                        "name": table_name,
                        "status": table.get("TableStatus"),
                        "point_in_time_recovery_status": pitr_description.get(
                            "PointInTimeRecoveryStatus"
                        ),
                        "sse_status": encryption.get("Status"),
                        "sse_type": encryption.get("SSEType"),
                        "kms_key_arn": encryption.get("KMSMasterKeyArn"),
                        "deletion_protection_enabled": table.get(
                            "DeletionProtectionEnabled"
                        ),
                    },
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_lambda_functions(self) -> list[Resource]:
        """Discover Lambda functions, URL authentication and resource policies."""
        functions = self._collect_pages(
            self.lambda_client.list_functions,
            "Functions",
            request_token="Marker",
            response_token="NextMarker",
        )
        resources = []

        for function in functions:
            function_name = function.get("FunctionName")
            if not function_name:
                continue

            function_url_auth_type = None
            url_configs = self._collect_pages(
                self.lambda_client.list_function_url_configs,
                "FunctionUrlConfigs",
                request_token="Marker",
                response_token="NextMarker",
                FunctionName=function_name,
            )
            if url_configs:
                function_url_auth_type = url_configs[0].get("AuthType")

            resource_policy = None
            try:
                policy_response = self.lambda_client.get_policy(
                    FunctionName=function_name,
                )
                policy_document = policy_response.get("Policy")
                if isinstance(policy_document, str):
                    try:
                        resource_policy = json.loads(policy_document)
                    except json.JSONDecodeError:
                        resource_policy = None
                elif isinstance(policy_document, dict):
                    resource_policy = policy_document
            except ClientError as error:
                error_code = error.response.get("Error", {}).get("Code")
                if error_code not in {"ResourceNotFoundException", "ResourceNotFound"}:
                    raise

            resources.append(
                Resource(
                    resource_type="aws_lambda_function",
                    resource_id=function_name,
                    attributes={
                        "runtime": function.get("Runtime"),
                        "handler": function.get("Handler"),
                        "role": function.get("Role"),
                        "state": function.get("State"),
                        "function_url_auth_type": function_url_auth_type,
                        "resource_policy": resource_policy,
                    },
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_rds_instances(self) -> list[Resource]:
        """Discover RDS DB instances and normalise security attributes."""
        instances = self._collect_pages(
            self.rds_client.describe_db_instances,
            "DBInstances",
            request_token="Marker",
            response_token="Marker",
        )
        resources = []

        for instance in instances:
            instance_id = instance.get("DBInstanceIdentifier")
            if not instance_id:
                continue

            resources.append(
                Resource(
                    resource_type="aws_db_instance",
                    resource_id=instance_id,
                    attributes={
                        "engine": instance.get("Engine"),
                        "status": instance.get("DBInstanceStatus"),
                        "storage_encrypted": instance.get("StorageEncrypted"),
                        "publicly_accessible": instance.get("PubliclyAccessible"),
                        "backup_retention_period": instance.get("BackupRetentionPeriod"),
                        "deletion_protection": instance.get("DeletionProtection"),
                        "multi_az": instance.get("MultiAZ"),
                        "endpoint_address": (
                            instance.get("Endpoint", {}).get("Address")
                            if isinstance(instance.get("Endpoint"), dict)
                            else None
                        ),
                    },
                    source="aws",
                    region=self.region,
                )
            )

        return resources

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
