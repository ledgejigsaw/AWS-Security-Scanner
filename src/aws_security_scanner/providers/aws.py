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
        apigatewayv2_client: Any | None = None,
        ecs_client: Any | None = None,
        cloudfront_client: Any | None = None,
        wafv2_client: Any | None = None,
        wafv2_global_client: Any | None = None,
        elbv2_client: Any | None = None,
        securityhub_client: Any | None = None,
        guardduty_client: Any | None = None,
        config_client: Any | None = None,
        session: Any | None = None,
        accessanalyzer_client: Any | None = None,
        macie_client: Any | None = None,
        s3control_client: Any | None = None,
        sts_client: Any | None = None,
        inspector2_client: Any | None = None,
        eks_client: Any | None = None,
        logs_client: Any | None = None,
        cloudwatch_client: Any | None = None,
        efs_client: Any | None = None,
    ):
        self.region = region
        # Preserve the existing boto3.client path for single-account scans;
        # cross-account scans supply an in-memory session with assumed-role credentials.
        self._client = session.client if session is not None else boto3.client

        self.s3_client = s3_client or self._client(
            "s3",
            region_name=region,
    )

        self.iam_client = iam_client or self._client(
            "iam",
            region_name=region,
    )

        self.ec2_client = ec2_client or self._client(
            "ec2",
            region_name=region,
        )
        self.cloudtrail_client = cloudtrail_client or self._client(
            "cloudtrail",
            region_name=region,
        )
        self.kms_client = kms_client or self._client(
            "kms",
            region_name=region,
        )
        self.rds_client = rds_client or self._client(
            "rds",
            region_name=region,
        )
        self.lambda_client = lambda_client or self._client(
            "lambda",
            region_name=region,
        )
        self.secretsmanager_client = secretsmanager_client or self._client(
            "secretsmanager",
            region_name=region,
        )
        self.ecr_client = ecr_client or self._client(
            "ecr",
            region_name=region,
        )
        self.dynamodb_client = dynamodb_client or self._client(
            "dynamodb",
            region_name=region,
        )
        self.sqs_client = sqs_client or self._client(
            "sqs",
            region_name=region,
        )
        self.sns_client = sns_client or self._client(
            "sns",
            region_name=region,
        )
        self.apigateway_client = apigateway_client or self._client(
            "apigateway",
            region_name=region,
        )
        self.apigatewayv2_client = apigatewayv2_client or self._client(
            "apigatewayv2",
            region_name=region,
        )
        self.ecs_client = ecs_client or self._client(
            "ecs",
            region_name=region,
        )
        # CloudFront and CloudFront-scope WAF are global; WAF global APIs use us-east-1.
        self.cloudfront_client = cloudfront_client or self._client("cloudfront")
        self.wafv2_client = wafv2_client or self._client("wafv2", region_name=region)
        self.wafv2_global_client = wafv2_global_client or self._client("wafv2", region_name="us-east-1")
        self.elbv2_client = elbv2_client or self._client("elbv2", region_name=region)
        self.securityhub_client = securityhub_client or self._client("securityhub", region_name=region)
        self.guardduty_client = guardduty_client or self._client("guardduty", region_name=region)
        self.config_client = config_client or self._client("config", region_name=region)
        self.accessanalyzer_client = accessanalyzer_client or self._client("accessanalyzer", region_name=region)
        self.macie_client = macie_client or self._client("macie2", region_name=region)
        self.s3control_client = s3control_client or self._client("s3control", region_name=region)
        # STS is only needed for account-scoped checks; create it lazily to avoid
        # changing client construction for scans that do not need account identity.
        self.sts_client = sts_client
        self.inspector2_client = inspector2_client or self._client("inspector2", region_name=region)
        self.eks_client = eks_client or self._client("eks", region_name=region)
        self.logs_client = logs_client or self._client("logs", region_name=region)
        self.cloudwatch_client = cloudwatch_client or self._client("cloudwatch", region_name=region)
        self.efs_client = efs_client or self._client("efs", region_name=region)

    def _collect_pages(
        self,
        method: Any,
        result_key: str,
        *,
        request_token: str = "NextToken",
        response_token: str = "NextToken",
        max_pages: int = 1000,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Collect pages with a hard bound and reject incomplete pagination."""
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages < 1:
            raise ValueError("max_pages must be a positive integer.")

        items: list[dict[str, Any]] = []
        token = None
        page_count = 0

        while True:
            request = dict(kwargs)
            if token:
                request[request_token] = token

            response = method(**request)
            page_count += 1
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
            if page_count >= max_pages:
                raise RuntimeError(
                    f"AWS API {getattr(method, '__name__', method)!s} "
                    f"exceeded the pagination limit of {max_pages} pages; "
                    "discovery is incomplete."
                )
            token = next_token

        return items

    def discover_s3_account_public_access_block(self) -> list[Resource]:
        """Discover account-level S3 Block Public Access without changing it."""
        sts_client = self.sts_client or self._client("sts", region_name=self.region)
        identity = sts_client.get_caller_identity()
        account_id = identity.get("Account")
        if not isinstance(account_id, str) or not account_id.isdigit() or len(account_id) != 12:
            raise RuntimeError("STS GetCallerIdentity did not return a valid AWS account ID.")

        try:
            response = self.s3control_client.get_public_access_block(AccountId=account_id)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code != "NoSuchPublicAccessBlockConfiguration":
                # Access denied and unexpected errors must not look like a safe state.
                raise
            configuration = None
        else:
            configuration = response.get("PublicAccessBlockConfiguration")
            if not isinstance(configuration, dict):
                configuration = None

        fields = {
            "BlockPublicAcls": "block_public_acls",
            "IgnorePublicAcls": "ignore_public_acls",
            "BlockPublicPolicy": "block_public_policy",
            "RestrictPublicBuckets": "restrict_public_buckets",
        }
        attributes: dict[str, Any] = {
            "configured": configuration is not None,
        }
        for api_name, attribute_name in fields.items():
            attributes[attribute_name] = (
                configuration.get(api_name)
                if configuration is not None
                else False
            )
        return [
            Resource(
                resource_type="aws_s3_account_public_access_block",
                resource_id=account_id,
                attributes=attributes,
                source="aws",
                region=None,
                account_id=account_id,
            )
        ]

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
            attributes["acl"] = self._get_bucket_acl(bucket_name)
            attributes["object_ownership"] = self._get_bucket_object_ownership(
                bucket_name
            )
            attributes["versioning_configuration"] = (
                self._get_bucket_versioning_configuration(bucket_name)
            )
            attributes["lifecycle_configuration"] = (
                self._get_bucket_lifecycle_configuration(bucket_name)
            )
            attributes["object_lock_configuration"] = (
                self._get_bucket_object_lock_configuration(bucket_name)
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
                    "monitoring_state": instance.get("Monitoring", {}).get("State"),
                    "instance_profile_arn": instance.get("IamInstanceProfile", {}).get("Arn"),
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


    def discover_ebs_volumes(self) -> list[Resource]:
        """Discover EBS volume encryption and attachment metadata."""
        volumes = self._collect_pages(self.ec2_client.describe_volumes, "Volumes")
        resources = []
        for volume in volumes:
            volume_id = volume.get("VolumeId")
            if not volume_id:
                continue
            resources.append(Resource(
                resource_type="aws_ebs_volume",
                resource_id=volume_id,
                attributes={
                    "encrypted": volume.get("Encrypted"),
                    "kms_key_id": volume.get("KmsKeyId"),
                    "state": volume.get("State"),
                    "volume_type": volume.get("VolumeType"),
                    "size_gib": volume.get("Size"),
                    "attached_instance_ids": [
                        attachment.get("InstanceId")
                        for attachment in volume.get("Attachments", [])
                        if attachment.get("InstanceId")
                    ],
                },
                source="aws",
                region=self.region,
            ))
        return resources

    def discover_ebs_snapshots(self) -> list[Resource]:
        """Discover owned EBS snapshots and public create-volume permissions."""
        snapshots = self._collect_pages(
            self.ec2_client.describe_snapshots,
            "Snapshots",
            OwnerIds=["self"],
        )
        resources = []
        for snapshot in snapshots:
            snapshot_id = snapshot.get("SnapshotId")
            if not snapshot_id:
                continue
            public = None
            try:
                permissions = self._collect_pages(
                    self.ec2_client.describe_snapshot_attribute,
                    "CreateVolumePermissions",
                    SnapshotId=snapshot_id,
                    Attribute="createVolumePermission",
                )
                public = any(
                    permission.get("Group") == "all"
                    for permission in permissions
                    if isinstance(permission, dict)
                )
            except ClientError as error:
                code = error.response.get("Error", {}).get("Code", "")
                if code not in {"UnauthorizedOperation", "AccessDenied", "AccessDeniedException"}:
                    raise
            resources.append(Resource(
                resource_type="aws_ebs_snapshot",
                resource_id=snapshot_id,
                attributes={
                    "encrypted": snapshot.get("Encrypted"),
                    "kms_key_id": snapshot.get("KmsKeyId"),
                    "state": snapshot.get("State"),
                    "volume_id": snapshot.get("VolumeId"),
                    "public": public,
                    "owner_id": snapshot.get("OwnerId"),
                },
                source="aws",
                region=self.region,
            ))
        return resources

    def discover_amis(self) -> list[Resource]:
        """Discover owned AMIs and their public launch-permission state."""
        images = self._collect_pages(
            self.ec2_client.describe_images,
            "Images",
            Owners=["self"],
        )
        resources: list[Resource] = []
        for image in images:
            image_id = image.get("ImageId")
            if not isinstance(image_id, str) or not image_id:
                continue
            public: bool | None = None
            try:
                permissions = self._collect_pages(
                    self.ec2_client.describe_image_attribute,
                    "LaunchPermissions",
                    ImageId=image_id,
                    Attribute="launchPermission",
                )
                public = any(
                    permission.get("Group") == "all"
                    for permission in permissions
                    if isinstance(permission, dict)
                )
            except ClientError as error:
                code = error.response.get("Error", {}).get("Code", "")
                if code not in {"UnauthorizedOperation", "AccessDenied", "AccessDeniedException"}:
                    raise
            resources.append(Resource(
                resource_type="aws_ami",
                resource_id=image_id,
                attributes={
                    "name": image.get("Name"),
                    "state": image.get("State"),
                    "public": public,
                    "owner_id": image.get("OwnerId"),
                    "creation_date": image.get("CreationDate"),
                },
                source="aws",
                region=self.region,
            ))
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

    def _get_bucket_acl(self, bucket_name: str) -> dict | None:
        """Return normalised bucket ACL grants, or None when not observable."""
        try:
            response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
        except ClientError:
            return None

        raw_grants = response.get("Grants", [])
        if not isinstance(raw_grants, list):
            return None

        grants = []
        for grant in raw_grants:
            if not isinstance(grant, dict):
                continue
            grantee = grant.get("Grantee", {})
            if not isinstance(grantee, dict):
                grantee = {}
            grants.append({
                "grantee": {
                    "type": grantee.get("Type"),
                    "uri": grantee.get("URI"),
                    "id": grantee.get("ID"),
                },
                "permission": grant.get("Permission"),
            })
        return {"grants": grants}

    def _get_bucket_object_ownership(self, bucket_name: str) -> str | None:
        """Return the configured Object Ownership mode when observable."""
        try:
            response = self.s3_client.get_bucket_ownership_controls(
                Bucket=bucket_name
            )
        except ClientError:
            return None

        controls = response.get("OwnershipControls", {})
        if not isinstance(controls, dict):
            return None
        rules = controls.get("Rules", [])
        if not isinstance(rules, list) or not rules or not isinstance(rules[0], dict):
            return None
        ownership = rules[0].get("ObjectOwnership")
        return ownership if isinstance(ownership, str) else None

    def _get_bucket_versioning_configuration(
        self, bucket_name: str
    ) -> dict | None:
        """Return versioning and MFA Delete status without changing the bucket."""
        try:
            response = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
        except ClientError:
            return None

        status = response.get("Status")
        if status not in {"Enabled", "Suspended"}:
            return None
        mfa_delete = response.get("MFADelete", "Disabled")
        if mfa_delete not in {"Enabled", "Disabled"}:
            mfa_delete = None
        return {
            "status": status,
            "mfa_delete": mfa_delete,
        }

    def _get_bucket_lifecycle_configuration(self, bucket_name: str) -> dict[str, Any]:
        """Return lifecycle posture with explicit configured/absent/unknown states."""
        try:
            response = self.s3_client.get_bucket_lifecycle_configuration(
                Bucket=bucket_name
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")
            if error_code == "NoSuchLifecycleConfiguration":
                return {"status": "NOT_CONFIGURED", "rules": []}
            # Access denied and unexpected API failures are not equivalent to
            # missing lifecycle configuration.
            return {"status": "UNKNOWN", "rules": []}

        raw_rules = response.get("Rules")
        if not isinstance(raw_rules, list):
            return {"status": "UNKNOWN", "rules": []}
        rules = []
        for rule in raw_rules:
            if not isinstance(rule, dict):
                continue
            noncurrent = rule.get("NoncurrentVersionExpiration")
            expiration = rule.get("Expiration")
            rules.append({
                "status": rule.get("Status"),
                "id": rule.get("ID"),
                "has_noncurrent_version_expiration": isinstance(noncurrent, dict)
                and bool(noncurrent),
                "has_expiration": isinstance(expiration, dict) and bool(expiration),
            })
        return {"status": "CONFIGURED", "rules": rules}

    def _get_bucket_object_lock_configuration(
        self, bucket_name: str
    ) -> dict[str, Any]:
        """Return Object Lock state without reading or modifying bucket objects."""
        try:
            response = self.s3_client.get_object_lock_configuration(
                Bucket=bucket_name
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")
            if error_code in {
                "ObjectLockConfigurationNotFoundError",
                "NoSuchObjectLockConfiguration",
            }:
                return {
                    "status": "NOT_CONFIGURED",
                    "enabled": False,
                    "default_retention": None,
                }
            # Permission failures and unexpected errors must remain unknown.
            return {
                "status": "UNKNOWN",
                "enabled": None,
                "default_retention": None,
            }

        configuration = response.get("ObjectLockConfiguration")
        if not isinstance(configuration, dict):
            return {
                "status": "UNKNOWN",
                "enabled": None,
                "default_retention": None,
            }

        enabled = configuration.get("ObjectLockEnabled")
        if enabled not in {"Enabled", "Disabled"}:
            return {
                "status": "UNKNOWN",
                "enabled": None,
                "default_retention": None,
            }

        rule = configuration.get("Rule")
        default_retention = None
        if isinstance(rule, dict):
            raw_retention = rule.get("DefaultRetention")
            if isinstance(raw_retention, dict):
                mode = raw_retention.get("Mode")
                days = raw_retention.get("Days")
                years = raw_retention.get("Years")
                default_retention = {
                    "mode": mode,
                    "days": days,
                    "years": years,
                }

        return {
            "status": "CONFIGURED",
            "enabled": enabled == "Enabled",
            "default_retention": default_retention,
        }

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

    def discover_api_gateway_http_apis(self) -> list[Resource]:
        """Discover API Gateway HTTP APIs, routes and stage access logging."""
        apis = self._collect_pages(
            self.apigatewayv2_client.get_apis,
            "Items",
            request_token="NextToken",
            response_token="NextToken",
        )
        resources: list[Resource] = []
        for api in apis:
            if not isinstance(api, dict) or api.get("ProtocolType") != "HTTP":
                continue
            api_id = api.get("ApiId")
            if not isinstance(api_id, str) or not api_id:
                continue
            routes = self._collect_pages(
                self.apigatewayv2_client.get_routes,
                "Items",
                request_token="NextToken",
                response_token="NextToken",
                ApiId=api_id,
            )
            normalised_routes = [
                {
                    "route_key": route.get("RouteKey"),
                    "authorization_type": route.get("AuthorizationType"),
                    "authorizer_id": route.get("AuthorizerId"),
                }
                for route in routes if isinstance(route, dict)
            ]
            stages = self._collect_pages(
                self.apigatewayv2_client.get_stages,
                "Items",
                request_token="NextToken",
                response_token="NextToken",
                ApiId=api_id,
            )
            for stage in stages:
                if not isinstance(stage, dict) or not stage.get("StageName"):
                    continue
                access_log = stage.get("AccessLogSettings")
                if not isinstance(access_log, dict):
                    access_log = {}
                destination = access_log.get("DestinationArn")
                fmt = access_log.get("Format")
                resources.append(Resource(
                    resource_type="aws_api_gateway_http_api_stage",
                    resource_id=f"{api_id}:{stage['StageName']}",
                    attributes={
                        "api_id": api_id,
                        "api_name": api.get("Name") or api_id,
                        "stage_name": stage["StageName"],
                        "api_endpoint": api.get("ApiEndpoint"),
                        "protocol_type": api.get("ProtocolType"),
                        "disable_execute_api_endpoint": api.get("DisableExecuteApiEndpoint"),
                        "cors_configuration": api.get("CorsConfiguration"),
                        "routes": normalised_routes,
                        "access_log_destination_arn": destination,
                        "access_log_format": fmt,
                        "access_logging_enabled": bool(destination and fmt),
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
                        "code_signing_config_arn": function.get("CodeSigningConfigArn"),
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
                        "certificate_valid_till": (
                            instance.get("CertificateDetails", {}).get("ValidTill")
                            if isinstance(instance.get("CertificateDetails"), dict)
                            else None
                        ),
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
            selector_state = "unknown"
            event_selectors: list[dict[str, Any]] = []
            advanced_selectors: list[dict[str, Any]] = []
            selector_method = getattr(self.cloudtrail_client, "get_event_selectors", None)
            if callable(selector_method):
                try:
                    selector_response = selector_method(TrailName=trail_arn)
                    if isinstance(selector_response, dict):
                        raw_basic = selector_response.get("EventSelectors", [])
                        raw_advanced = selector_response.get("AdvancedEventSelectors", [])
                        if isinstance(raw_basic, list) and isinstance(raw_advanced, list):
                            event_selectors = [item for item in raw_basic if isinstance(item, dict)]
                            advanced_selectors = [item for item in raw_advanced if isinstance(item, dict)]
                            selector_state = "success"
                except ClientError as error:
                    code = error.response.get("Error", {}).get("Code", "")
                    if code not in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
                        raise
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
                        "cloudwatch_logs_log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                        "cloudwatch_logs_role_arn": trail.get("CloudWatchLogsRoleArn"),
                        "event_selector_discovery": selector_state,
                        "event_selectors": event_selectors,
                        "advanced_event_selectors": advanced_selectors,
                        "management_events_logged": (
                            any(item.get("IncludeManagementEvents") is True for item in event_selectors)
                            if selector_state == "success" and event_selectors else None
                        ),
                        "data_event_selector_count": (
                            sum(len(item.get("DataResources", [])) for item in event_selectors if isinstance(item.get("DataResources", []), list)) + len(advanced_selectors)
                            if selector_state == "success" else None
                        ),
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

            grants: list[dict[str, Any]] = []
            grant_discovery = "success"
            marker = None
            seen_markers: set[str] = set()
            for _page in range(10):
                request: dict[str, Any] = {"KeyId": key_id, "Limit": 100}
                if marker:
                    request["Marker"] = marker
                try:
                    page = self.kms_client.list_grants(**request)
                except ClientError as error:
                    code = error.response.get("Error", {}).get("Code", "")
                    if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
                        grant_discovery = "unknown"
                        grants = []
                        break
                    raise
                if not isinstance(page, dict) or not isinstance(page.get("Grants", []), list):
                    grant_discovery = "unknown"
                    grants = []
                    break
                for grant in page.get("Grants", []):
                    if isinstance(grant, dict):
                        grants.append({key: grant[key] for key in (
                            "GrantId", "GranteePrincipal", "Operations",
                            "RetiringPrincipal", "Constraints",
                        ) if key in grant})
                if not page.get("Truncated"):
                    break
                next_marker = page.get("NextMarker")
                if not isinstance(next_marker, str) or not next_marker or next_marker in seen_markers:
                    grant_discovery = "unknown"
                    grants = []
                    break
                seen_markers.add(next_marker)
                marker = next_marker
            else:
                grant_discovery = "unknown"
                grants = []

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
                        "grants": grants,
                        "grant_discovery": grant_discovery,
                    },
                    source="aws",
                    region=metadata.get("Arn", "").split(":")[3]
                    if metadata.get("Arn") and len(metadata.get("Arn", "").split(":")) > 3
                    else self.region,
                )
            )

        return resources


    def discover_ecs_task_definitions(self) -> list[Resource]:
        """Discover active ECS task-definition security settings."""
        task_definition_arns = self._collect_pages(
            self.ecs_client.list_task_definitions,
            "taskDefinitionArns",
            request_token="nextToken",
            response_token="nextToken",
            status="ACTIVE",
            sort="DESC",
        )
        resources: list[Resource] = []
        for task_definition_arn in task_definition_arns:
            if not isinstance(task_definition_arn, str) or not task_definition_arn:
                continue
            response = self.ecs_client.describe_task_definition(taskDefinition=task_definition_arn)
            task_definition = response.get("taskDefinition", {})
            if not isinstance(task_definition, dict):
                continue
            definition_arn = task_definition.get("taskDefinitionArn") or task_definition_arn
            containers = task_definition.get("containerDefinitions", [])
            if not isinstance(containers, list):
                containers = []
            normalized_containers = []
            for container in containers:
                if not isinstance(container, dict):
                    continue
                normalized_containers.append({
                    "name": container.get("name"),
                    "image": container.get("image"),
                    "privileged": container.get("privileged"),
                    "user": container.get("user"),
                    "readonly_root_filesystem": container.get("readonlyRootFilesystem"),
                    "essential": container.get("essential"),
                })
            resources.append(Resource(
                resource_type="aws_ecs_task_definition",
                resource_id=definition_arn,
                attributes={
                    "arn": definition_arn,
                    "family": task_definition.get("family"),
                    "revision": task_definition.get("revision"),
                    "status": task_definition.get("status"),
                    "network_mode": task_definition.get("networkMode"),
                    "requires_compatibilities": task_definition.get("requiresCompatibilities", []),
                    "task_role_arn": task_definition.get("taskRoleArn"),
                    "execution_role_arn": task_definition.get("executionRoleArn"),
                    "containers": normalized_containers,
                },
                source="aws",
                region=self.region,
            ))
        return resources

    def discover_ecs_services(self) -> list[Resource]:
        """Discover ECS service deployment and public-IP assignment metadata."""
        cluster_arns = self._collect_pages(
            self.ecs_client.list_clusters,
            "clusterArns",
            request_token="nextToken",
            response_token="nextToken",
        )
        resources: list[Resource] = []
        for cluster_arn in cluster_arns:
            if not isinstance(cluster_arn, str) or not cluster_arn:
                continue
            service_arns = self._collect_pages(
                self.ecs_client.list_services,
                "serviceArns",
                request_token="nextToken",
                response_token="nextToken",
                cluster=cluster_arn,
            )
            for offset in range(0, len(service_arns), 10):
                batch = service_arns[offset:offset + 10]
                response = self.ecs_client.describe_services(cluster=cluster_arn, services=batch)
                for service in response.get("services", []):
                    if not isinstance(service, dict):
                        continue
                    service_arn = service.get("serviceArn")
                    if not service_arn:
                        continue
                    network_configuration = service.get("networkConfiguration", {})
                    if not isinstance(network_configuration, dict):
                        network_configuration = {}
                    awsvpc_configuration = network_configuration.get("awsvpcConfiguration", {})
                    if not isinstance(awsvpc_configuration, dict):
                        awsvpc_configuration = {}
                    resources.append(Resource(
                        resource_type="aws_ecs_service",
                        resource_id=service_arn,
                        attributes={
                            "arn": service_arn,
                            "name": service.get("serviceName"),
                            "cluster_arn": service.get("clusterArn") or cluster_arn,
                            "status": service.get("status"),
                            "launch_type": service.get("launchType"),
                            "task_definition": service.get("taskDefinition"),
                            "desired_count": service.get("desiredCount"),
                            "assign_public_ip": awsvpc_configuration.get("assignPublicIp"),
                            "subnets": awsvpc_configuration.get("subnets", []),
                            "security_groups": awsvpc_configuration.get("securityGroups", []),
                        },
                        source="aws",
                        region=self.region,
                    ))
        return resources



    def discover_eks_clusters(self) -> list[Resource]:
        """Discover EKS control-plane posture without reading workloads or secrets."""
        cluster_names = self._collect_pages(
            self.eks_client.list_clusters,
            "clusters",
            request_token="nextToken",
            response_token="nextToken",
        )
        resources: list[Resource] = []
        for name in cluster_names:
            if not isinstance(name, str) or not name:
                continue
            response = self.eks_client.describe_cluster(name=name)
            cluster = response.get("cluster", {}) if isinstance(response, dict) else {}
            if not isinstance(cluster, dict):
                continue
            cluster_name = cluster.get("name") or name
            vpc_config = cluster.get("resourcesVpcConfig", {})
            if not isinstance(vpc_config, dict):
                vpc_config = {}
            endpoint_config = cluster.get("accessConfig", {})
            if not isinstance(endpoint_config, dict):
                endpoint_config = {}
            logging_config = cluster.get("logging", {})
            if not isinstance(logging_config, dict):
                logging_config = {}
            enabled_types = []
            for item in logging_config.get("clusterLogging", []) or []:
                if not isinstance(item, dict) or item.get("enabled") is not True:
                    continue
                for log_type in item.get("types", []) or []:
                    if isinstance(log_type, str):
                        enabled_types.append(log_type)
            encryption_config = cluster.get("encryptionConfig", [])
            resources.append(Resource(
                resource_type="aws_eks_cluster",
                resource_id=str(cluster_name),
                attributes={
                    "name": cluster_name,
                    "arn": cluster.get("arn"),
                    "status": cluster.get("status"),
                    "version": cluster.get("version"),
                    "role_arn": cluster.get("roleArn"),
                    "endpoint_public_access": vpc_config.get("endpointPublicAccess"),
                    "endpoint_private_access": vpc_config.get("endpointPrivateAccess"),
                    "public_access_cidrs": vpc_config.get("publicAccessCidrs", []),
                    "cluster_security_group_id": vpc_config.get("clusterSecurityGroupId"),
                    "security_group_ids": vpc_config.get("securityGroupIds", []),
                    "subnet_ids": vpc_config.get("subnetIds", []),
                    "control_plane_log_types_enabled": sorted(set(enabled_types)),
                    "control_plane_logging_metadata_available": isinstance(cluster.get("logging"), dict),
                    "control_plane_log_types_observed": sorted({
                        log_type
                        for item in (logging_config.get("clusterLogging", []) or [])
                        if isinstance(item, dict)
                        for log_type in (item.get("types", []) or [])
                        if isinstance(log_type, str)
                    }),
                    "encryption_config": encryption_config,
                    "encryption_configured": bool(encryption_config),
                    "authentication_mode": endpoint_config.get("authenticationMode"),
                },
                source="aws",
                region=self.region,
            ))
        return resources


    def discover_cloudwatch_log_groups(self) -> list[Resource]:
        """Discover CloudWatch Logs group metadata without reading log events."""
        groups = self._collect_pages(
            self.logs_client.describe_log_groups,
            "logGroups",
            request_token="nextToken",
            response_token="nextToken",
        )
        resources: list[Resource] = []
        for group in groups:
            if not isinstance(group, dict):
                continue
            name = group.get("logGroupName")
            if not isinstance(name, str) or not name:
                continue
            resources.append(Resource(
                resource_type="aws_cloudwatch_log_group",
                resource_id=name,
                attributes={
                    "name": name,
                    "arn": group.get("arn") or group.get("logGroupArn"),
                    "retention_in_days": group.get("retentionInDays"),
                    "kms_key_id": group.get("kmsKeyId"),
                    "stored_bytes": group.get("storedBytes"),
                    "creation_time": group.get("creationTime"),
                },
                source="aws",
                region=self.region,
            ))
        return resources

    def discover_cloudwatch_alarms(self) -> list[Resource]:
        """Discover CloudWatch alarm configuration, not alarm history or log contents."""
        alarms = self._collect_pages(
            self.cloudwatch_client.describe_alarms,
            "MetricAlarms",
        )
        resources: list[Resource] = []
        for alarm in alarms:
            if not isinstance(alarm, dict):
                continue
            name = alarm.get("AlarmName")
            if not isinstance(name, str) or not name:
                continue
            resources.append(Resource(
                resource_type="aws_cloudwatch_metric_alarm",
                resource_id=name,
                attributes={
                    "name": name,
                    "arn": alarm.get("AlarmArn"),
                    "namespace": alarm.get("Namespace"),
                    "metric_name": alarm.get("MetricName"),
                    "actions_enabled": alarm.get("ActionsEnabled"),
                    "alarm_actions": alarm.get("AlarmActions", []),
                    "ok_actions": alarm.get("OKActions", []),
                    "insufficient_data_actions": alarm.get("InsufficientDataActions", []),
                    "state_value": alarm.get("StateValue"),
                    "comparison_operator": alarm.get("ComparisonOperator"),
                    "threshold": alarm.get("Threshold"),
                    "period": alarm.get("Period"),
                    "evaluation_periods": alarm.get("EvaluationPeriods"),
                },
                source="aws",
                region=self.region,
            ))
        return resources


    def discover_efs_file_systems(self) -> list[Resource]:
        """Discover EFS file systems, mount-target metadata and access points."""
        file_systems = self._collect_pages(
            self.efs_client.describe_file_systems,
            "FileSystems",
            request_token="Marker",
            response_token="NextMarker",
        )
        resources: list[Resource] = []
        for file_system in file_systems:
            if not isinstance(file_system, dict):
                continue
            file_system_id = file_system.get("FileSystemId")
            if not isinstance(file_system_id, str) or not file_system_id:
                continue
            mount_targets = self._collect_pages(
                self.efs_client.describe_mount_targets,
                "MountTargets",
                request_token="Marker",
                response_token="NextMarker",
                FileSystemId=file_system_id,
            )
            mount_target_details = []
            for target in mount_targets:
                if not isinstance(target, dict):
                    continue
                target_id = target.get("MountTargetId")
                security_groups = []
                if isinstance(target_id, str) and target_id:
                    response = self.efs_client.describe_mount_target_security_groups(
                        MountTargetId=target_id
                    )
                    security_groups = response.get("SecurityGroups", []) if isinstance(response, dict) else []
                mount_target_details.append({
                    "mount_target_id": target_id,
                    "subnet_id": target.get("SubnetId"),
                    "network_interface_id": target.get("NetworkInterfaceId"),
                    "lifecycle_state": target.get("LifeCycleState"),
                    "security_group_ids": sorted(
                        item for item in security_groups if isinstance(item, str)
                    ) if isinstance(security_groups, list) else [],
                })
            access_points = self._collect_pages(
                self.efs_client.describe_access_points,
                "AccessPoints",
                request_token="Marker",
                response_token="NextMarker",
                FileSystemId=file_system_id,
            )
            resources.append(Resource(
                resource_type="aws_efs_file_system",
                resource_id=file_system_id,
                attributes={
                    "file_system_id": file_system_id,
                    "name": file_system.get("Name"),
                    "arn": file_system.get("FileSystemArn"),
                    "encrypted": file_system.get("Encrypted"),
                    "kms_key_id": file_system.get("KmsKeyId"),
                    "performance_mode": file_system.get("PerformanceMode"),
                    "throughput_mode": file_system.get("ThroughputMode"),
                    "lifecycle_state": file_system.get("LifeCycleState"),
                    "mount_targets": mount_target_details,
                    "access_points": [
                        {
                            "access_point_id": item.get("AccessPointId"),
                            "arn": item.get("AccessPointArn"),
                            "posix_user": item.get("PosixUser"),
                            "root_directory": item.get("RootDirectory"),
                            "lifecycle_state": item.get("LifeCycleState"),
                        }
                        for item in access_points if isinstance(item, dict)
                    ],
                },
                source="aws",
                region=self.region,
            ))
            for access_point in access_points:
                if not isinstance(access_point, dict):
                    continue
                access_point_id = access_point.get("AccessPointId")
                if not isinstance(access_point_id, str) or not access_point_id:
                    continue
                resources.append(Resource(
                    resource_type="aws_efs_access_point",
                    resource_id=access_point_id,
                    attributes={
                        "access_point_id": access_point_id,
                        "arn": access_point.get("AccessPointArn"),
                        "file_system_id": file_system_id,
                        "posix_user": access_point.get("PosixUser"),
                        "root_directory": access_point.get("RootDirectory"),
                        "lifecycle_state": access_point.get("LifeCycleState"),
                    },
                    source="aws",
                    region=self.region,
                ))
        return resources

    def discover_cloudfront_distributions(self) -> list[Resource]:
        """Discover CloudFront distribution security metadata without contacting origins."""
        distributions: list[dict[str, Any]] = []
        marker: str | None = None
        while True:
            request = {"Marker": marker} if marker else {}
            response = self.cloudfront_client.list_distributions(**request)
            distribution_list = response.get("DistributionList", {})
            if not isinstance(distribution_list, dict):
                break
            items = distribution_list.get("Items", [])
            if isinstance(items, list):
                distributions.extend(item for item in items if isinstance(item, dict))
            if not distribution_list.get("IsTruncated"):
                break
            next_marker = distribution_list.get("NextMarker")
            if not isinstance(next_marker, str) or not next_marker:
                raise RuntimeError(
                    "CloudFront reported truncated results without a NextMarker."
                )
            if next_marker == marker:
                raise RuntimeError("CloudFront returned a repeated pagination marker.")
            marker = next_marker

        resources: list[Resource] = []
        for distribution in distributions:
            distribution_id = distribution.get("Id")
            if not isinstance(distribution_id, str) or not distribution_id:
                continue
            default_behavior = distribution.get("DefaultCacheBehavior", {})
            if not isinstance(default_behavior, dict):
                default_behavior = {}
            cache_behaviors = distribution.get("CacheBehaviors", {})
            if not isinstance(cache_behaviors, dict):
                cache_behaviors = {}
            behavior_items = cache_behaviors.get("Items", [])
            if not isinstance(behavior_items, list):
                behavior_items = []
            behaviors = [default_behavior]
            behaviors.extend(item for item in behavior_items if isinstance(item, dict))

            origins_container = distribution.get("Origins", {})
            if not isinstance(origins_container, dict):
                origins_container = {}
            origins_items = origins_container.get("Items", [])
            if not isinstance(origins_items, list):
                origins_items = []
            origins = []
            for origin in origins_items:
                if not isinstance(origin, dict):
                    continue
                s3_origin_config = origin.get("S3OriginConfig", {})
                if not isinstance(s3_origin_config, dict):
                    s3_origin_config = {}
                origin_access_control_id = origin.get("OriginAccessControlId")
                origin_access_identity = s3_origin_config.get("OriginAccessIdentity")
                origins.append({
                    "id": origin.get("Id"),
                    "domain_name": origin.get("DomainName"),
                    "origin_type": (
                        "s3"
                        if isinstance(origin.get("DomainName"), str)
                        and ".s3" in origin.get("DomainName", "").lower()
                        else "custom"
                    ),
                    "origin_access_control_id": origin_access_control_id or None,
                    "origin_access_identity_configured": bool(origin_access_identity),
                })

            viewer_protocol_policies = [
                item.get("ViewerProtocolPolicy")
                for item in behaviors
                if isinstance(item.get("ViewerProtocolPolicy"), str)
            ]
            viewer_certificate = distribution.get("ViewerCertificate", {})
            if not isinstance(viewer_certificate, dict):
                viewer_certificate = {}
            logging = distribution.get("Logging", {})
            if not isinstance(logging, dict):
                logging = {}

            resources.append(Resource(
                resource_type="aws_cloudfront_distribution",
                resource_id=distribution_id,
                attributes={
                    "arn": distribution.get("ARN"),
                    "domain_name": distribution.get("DomainName"),
                    "enabled": distribution.get("Enabled"),
                    "status": distribution.get("Status"),
                    "web_acl_id": distribution.get("WebACLId") or None,
                    "viewer_protocol_policies": viewer_protocol_policies,
                    "minimum_protocol_version": viewer_certificate.get("MinimumProtocolVersion"),
                    "logging_enabled": logging.get("Enabled") if "Enabled" in logging else None,
                    "origins": origins,
                },
                source="aws",
                region=None,
            ))
        return resources


    def discover_waf_web_acls(self, scope: str = "REGIONAL") -> list[Resource]:
        """Discover WAFv2 ACLs and normalise managed/rate-based rule coverage."""
        if scope not in {"REGIONAL", "CLOUDFRONT"}:
            raise ValueError("WAF scope must be REGIONAL or CLOUDFRONT.")
        client = self.wafv2_global_client if scope == "CLOUDFRONT" else self.wafv2_client
        summaries = self._collect_pages(
            client.list_web_acls,
            "WebACLs",
            request_token="NextMarker",
            response_token="NextMarker",
            Scope=scope,
            Limit=100,
        )
        resources: list[Resource] = []
        for summary in summaries:
            name = summary.get("Name")
            acl_id = summary.get("Id")
            if not isinstance(name, str) or not name or not isinstance(acl_id, str) or not acl_id:
                continue
            response = client.get_web_acl(Name=name, Scope=scope, Id=acl_id)
            acl = response.get("WebACL", {})
            if not isinstance(acl, dict):
                continue
            rules = acl.get("Rules", [])
            if not isinstance(rules, list):
                rules = []
            managed_count = 0
            rate_based_count = 0
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                statement = rule.get("Statement", {})
                if not isinstance(statement, dict):
                    continue
                if "ManagedRuleGroupStatement" in statement:
                    managed_count += 1
                if "RateBasedStatement" in statement:
                    rate_based_count += 1
            default_action = acl.get("DefaultAction", {})
            if not isinstance(default_action, dict):
                default_action = {}
            resources.append(Resource(
                resource_type="aws_wafv2_web_acl",
                resource_id=acl.get("ARN") or acl_id,
                attributes={
                    "name": name,
                    "id": acl_id,
                    "arn": acl.get("ARN"),
                    "scope": scope,
                    "rule_count": len(rules),
                    "managed_rule_group_count": managed_count,
                    "rate_based_rule_count": rate_based_count,
                    "default_action": "allow" if "Allow" in default_action else (
                        "block" if "Block" in default_action else None
                    ),
                },
                source="aws",
                region=None if scope == "CLOUDFRONT" else self.region,
            ))
        return resources

    def discover_application_load_balancers(self) -> list[Resource]:
        """Discover ALBs and observed WAF association state without changing resources."""
        load_balancers = self._collect_pages(
            self.elbv2_client.describe_load_balancers,
            "LoadBalancers",
        )
        resources: list[Resource] = []
        for load_balancer in load_balancers:
            if load_balancer.get("Type") != "application":
                continue
            arn = load_balancer.get("LoadBalancerArn")
            if not isinstance(arn, str) or not arn:
                continue
            try:
                association = self.wafv2_client.get_web_acl_for_resource(ResourceArn=arn)
            except ClientError as error:
                code = error.response.get("Error", {}).get("Code", "")
                if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
                    web_acl = None
                    web_acl_id = None
                    association_state = "unknown"
                else:
                    raise
            else:
                web_acl = association.get("WebACL") if isinstance(association, dict) else None
                web_acl_id = web_acl.get("Id") if isinstance(web_acl, dict) else None
                association_state = "associated" if web_acl_id else "not_associated"
            listeners = self._collect_pages(self.elbv2_client.describe_listeners, "Listeners", LoadBalancerArn=arn)
            listener_data = [{"protocol": x.get("Protocol"), "port": x.get("Port"), "ssl_policy": x.get("SslPolicy")} for x in listeners if isinstance(x, dict)]
            lb_attrs = self.elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=arn).get("Attributes", [])
            access_logs = next((x.get("Value") for x in lb_attrs if isinstance(x, dict) and x.get("Key") == "access_logs.s3.enabled"), None)
            resources.append(Resource(
                resource_type="aws_lb",
                resource_id=arn,
                attributes={
                    "name": load_balancer.get("LoadBalancerName"),
                    "arn": arn,
                    "scheme": load_balancer.get("Scheme"),
                    "state": load_balancer.get("State", {}).get("Code"),
                    "vpc_id": load_balancer.get("VpcId"),
                    "security_group_ids": load_balancer.get("SecurityGroups", []),
                    "web_acl_id": web_acl_id,
                    "waf_association_state": association_state,
                    "listeners": listener_data,
                    "access_logs_enabled": access_logs == "true" if access_logs is not None else None,
                },
                source="aws",
                region=self.region,
            ))
        return resources


    def discover_aws_config(self) -> list[Resource]:
        """Discover regional AWS Config recorder, recording and delivery-channel status."""
        recorders = self.config_client.describe_configuration_recorders().get(
            "ConfigurationRecorders", []
        )
        channels = self.config_client.describe_delivery_channels().get(
            "DeliveryChannels", []
        )

        recording = None
        if recorders:
            recorder_names = [
                recorder.get("name")
                for recorder in recorders
                if isinstance(recorder, dict) and isinstance(recorder.get("name"), str)
            ]
            if recorder_names:
                statuses = self.config_client.describe_configuration_recorder_status(
                    ConfigurationRecorderNames=recorder_names
                ).get("ConfigurationRecordersStatus", [])
                status_by_name = {
                    item.get("name"): item.get("recording")
                    for item in statuses
                    if isinstance(item, dict) and isinstance(item.get("name"), str)
                }
                if all(name in status_by_name for name in recorder_names):
                    values = [status_by_name[name] for name in recorder_names]
                    # A missing/non-boolean status is unknown. If all statuses are
                    # explicit booleans, any stopped recorder means recording is incomplete.
                    if all(isinstance(value, bool) for value in values):
                        recording = all(value is True for value in values)

        return [
            Resource(
                resource_type="aws_config_service",
                resource_id=f"aws-config:{self.region or 'default'}",
                attributes={
                    "recorder_configured": bool(recorders),
                    "recording": recording,
                    "delivery_channel_configured": bool(channels),
                },
                source="aws",
                region=self.region,
            )
        ]

    def discover_macie_session(self) -> list[Resource]:
        """Discover regional Amazon Macie session status using a read-only API."""
        try:
            response = self.macie_client.get_macie_session()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ResourceNotFoundException":
                # Permission and unexpected API errors must not be reported as
                # a disabled service.
                raise
            return [
                Resource(
                    resource_type="aws_macie_session",
                    resource_id="macie-session",
                    attributes={
                        "enabled": False,
                        "status": "NOT_ENABLED",
                    },
                    source="aws",
                    region=self.region,
                )
            ]

        status = response.get("status")
        enabled = True if status == "ENABLED" else (
            False if status == "PAUSED" else None
        )
        return [
            Resource(
                resource_type="aws_macie_session",
                resource_id="macie-session",
                attributes={
                    "enabled": enabled,
                    "status": status if isinstance(status, str) else None,
                    "finding_publishing_frequency": response.get(
                        "findingPublishingFrequency"
                    ),
                    "created_at": response.get("createdAt"),
                    "updated_at": response.get("updatedAt"),
                },
                source="aws",
                region=self.region,
            )
        ]

    def discover_security_hub(self) -> list[Resource]:
        """Discover regional Security Hub enablement without importing findings.

        ResourceNotFoundException from DescribeHub means Security Hub is not
        enabled in this region. Permission and unexpected API errors propagate
        rather than being interpreted as a disabled service.
        """
        try:
            response = self.securityhub_client.describe_hub()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ResourceNotFoundException":
                raise
            return [
                Resource(
                    resource_type="aws_securityhub_hub",
                    resource_id="securityhub",
                    attributes={
                        "enabled": False,
                        "status": "NOT_ENABLED",
                    },
                    source="aws",
                    region=self.region,
                )
            ]

        return [
            Resource(
                resource_type="aws_securityhub_hub",
                resource_id=response.get("HubArn", "securityhub"),
                attributes={
                    "enabled": True,
                    "status": "ENABLED",
                    "hub_arn": response.get("HubArn"),
                    "subscribed_at": response.get("SubscribedAt"),
                    "auto_enable_controls": response.get("AutoEnableControls"),
                },
                source="aws",
                region=self.region,
            )
        ]

    def get_securityhub_findings(
        self,
        limit: int = 100,
        *,
        workflow_statuses: list[str] | None = None,
        record_state: str | None = "ACTIVE",
        compliance_status: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return bounded regional Security Hub findings with optional control filters.

        The API is read-only. Access and service errors deliberately propagate;
        an incomplete or denied query must not be represented as zero findings.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("Security Hub finding limit must be between 1 and 1000.")

        valid_workflow_statuses = {"NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"}
        if workflow_statuses is not None and (
            not workflow_statuses
            or any(not isinstance(value, str) or value not in valid_workflow_statuses for value in workflow_statuses)
        ):
            raise ValueError("Security Hub workflow statuses must be NEW, NOTIFIED, RESOLVED or SUPPRESSED.")
        if record_state not in {None, "ACTIVE", "ARCHIVED"}:
            raise ValueError("Security Hub record state must be ACTIVE, ARCHIVED or None.")
        if compliance_status not in {None, "PASSED", "WARNING", "FAILED", "NOT_AVAILABLE", "NOT_SUPPORTED"}:
            raise ValueError("Unsupported Security Hub compliance status.")

        findings: list[dict[str, Any]] = []
        token: str | None = None
        seen_tokens: set[str] = set()
        seen_findings: set[tuple[str, str]] = set()
        filters: dict[str, list[dict[str, str]]] = {}
        if record_state is not None:
            filters["RecordState"] = [{"Comparison": "EQUALS", "Value": record_state}]
        if workflow_statuses is not None:
            filters["WorkflowStatus"] = [
                {"Comparison": "EQUALS", "Value": value}
                for value in workflow_statuses
            ]
        if compliance_status is not None:
            filters["ComplianceStatus"] = [
                {"Comparison": "EQUALS", "Value": compliance_status}
            ]

        while len(findings) < limit:
            request: dict[str, Any] = {"MaxResults": min(100, limit - len(findings))}
            if filters:
                request["Filters"] = filters
            if token:
                request["NextToken"] = token
            response = self.securityhub_client.get_findings(**request)

            for item in response.get("Findings", []):
                if not isinstance(item, dict):
                    continue
                finding_id = item.get("Id")
                product_arn = item.get("ProductArn")
                if not isinstance(finding_id, str) or not finding_id:
                    continue
                key = (product_arn if isinstance(product_arn, str) else "", finding_id)
                if key in seen_findings:
                    continue
                seen_findings.add(key)
                findings.append(item)
                if len(findings) >= limit:
                    break

            next_token = response.get("NextToken")
            if not next_token or len(findings) >= limit:
                break
            if not isinstance(next_token, str) or next_token in seen_tokens:
                raise RuntimeError("Security Hub returned an invalid or repeated NextToken.")
            seen_tokens.add(next_token)
            token = next_token

        return findings

    def get_guardduty_findings(
        self,
        limit: int = 100,
        *,
        archived: bool | None = None,
        updated_after: str | None = None,
        require_detector: bool = False,
    ) -> list[dict[str, Any]]:
        """Return bounded native GuardDuty findings with optional time/status filters.

        ListFindings is paginated per detector; GetFindings is then called in
        batches of at most 50 IDs. Permission and service errors propagate.
        When require_detector is true, absent or disabled detectors are explicit
        failures rather than being reported as a clean empty result.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("GuardDuty finding limit must be between 1 and 1000.")

        if archived is not None and not isinstance(archived, bool):
            raise ValueError("archived must be True, False or None.")
        if updated_after is not None:
            if not isinstance(updated_after, str) or not updated_after.strip():
                raise ValueError("updated_after must be an ISO-8601 date-time string.")
            try:
                parsed_updated_after = datetime.fromisoformat(
                    updated_after.replace("Z", "+00:00")
                )
            except ValueError:
                raise ValueError("updated_after must be an ISO-8601 date-time string.") from None
            if parsed_updated_after.tzinfo is None:
                raise ValueError("updated_after must include a timezone, such as Z or +00:00.")

        detector_ids = self._collect_pages(
            self.guardduty_client.list_detectors,
            "DetectorIds",
            request_token="NextToken",
            response_token="NextToken",
        )
        if not detector_ids and require_detector:
            raise RuntimeError("GuardDuty is not enabled in this region (no detector found).")
        findings: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for detector_id in detector_ids:
            if require_detector:
                detector = self.guardduty_client.get_detector(DetectorId=detector_id)
                if detector.get("Status") != "ENABLED":
                    raise RuntimeError("GuardDuty detector is not enabled in this region.")
            finding_ids: list[str] = []
            token: str | None = None
            seen_tokens: set[str] = set()
            while len(findings) + len(finding_ids) < limit:
                remaining = limit - len(findings) - len(finding_ids)
                request: dict[str, Any] = {
                    "DetectorId": detector_id,
                    "MaxResults": min(50, remaining),
                }
                criteria: dict[str, dict[str, list[str]]] = {}
                if archived is not None:
                    criteria["service.archived"] = {"Eq": ["true" if archived else "false"]}
                if updated_after is not None:
                    criteria["updatedAt"] = {"Gte": [updated_after]}
                if criteria:
                    request["FindingCriteria"] = {"Criterion": criteria}
                if token:
                    request["NextToken"] = token
                response = self.guardduty_client.list_findings(**request)
                for finding_id in response.get("FindingIds", []):
                    if isinstance(finding_id, str) and finding_id and finding_id not in seen_ids:
                        seen_ids.add(finding_id)
                        finding_ids.append(finding_id)
                        if len(findings) + len(finding_ids) >= limit:
                            break
                next_token = response.get("NextToken")
                if not next_token or len(findings) + len(finding_ids) >= limit:
                    break
                if not isinstance(next_token, str) or next_token in seen_tokens:
                    raise RuntimeError("GuardDuty returned an invalid or repeated NextToken.")
                seen_tokens.add(next_token)
                token = next_token

            for offset in range(0, len(finding_ids), 50):
                batch = finding_ids[offset:offset + 50]
                response = self.guardduty_client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=batch,
                )
                for item in response.get("Findings", []):
                    if isinstance(item, dict):
                        findings.append(item)
                        if len(findings) >= limit:
                            return findings
            if len(findings) >= limit:
                break

        return findings

    def get_inspector_findings(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return a bounded, paginated set of active Amazon Inspector findings.

        Only selected finding metadata is normalised by the integration layer.
        The API is regional and read-only; service and permission errors propagate.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("Amazon Inspector finding limit must be between 1 and 1000.")

        findings: list[dict[str, Any]] = []
        seen_arns: set[str] = set()
        token: str | None = None
        seen_tokens: set[str] = set()
        while len(findings) < limit:
            request: dict[str, Any] = {
                "maxResults": min(100, limit - len(findings)),
                "filterCriteria": {
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
                },
            }
            if token:
                request["nextToken"] = token
            response = self.inspector2_client.list_findings(**request)
            for item in response.get("findings", []):
                if not isinstance(item, dict):
                    continue
                arn = item.get("findingArn")
                if not isinstance(arn, str) or not arn or arn in seen_arns:
                    continue
                seen_arns.add(arn)
                findings.append(item)
                if len(findings) >= limit:
                    break
            next_token = response.get("nextToken")
            if not next_token or len(findings) >= limit:
                break
            if not isinstance(next_token, str) or next_token in seen_tokens:
                raise RuntimeError("Amazon Inspector returned an invalid or repeated nextToken.")
            seen_tokens.add(next_token)
            token = next_token
        return findings

    def get_access_analyzer_findings(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return a bounded, paginated set of active IAM Access Analyzer findings.

        All analyzer types returned by ListAnalyzers are considered. Only finding
        metadata is returned; API errors and permission failures propagate.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("IAM Access Analyzer finding limit must be between 1 and 1000.")

        analyzers = self._collect_pages(
            self.accessanalyzer_client.list_analyzers,
            "analyzers",
            request_token="nextToken",
            response_token="nextToken",
        )
        findings: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for analyzer in analyzers:
            if not isinstance(analyzer, dict):
                continue
            analyzer_arn = analyzer.get("arn")
            if not isinstance(analyzer_arn, str) or not analyzer_arn:
                continue

            token: str | None = None
            seen_tokens: set[str] = set()
            while len(findings) < limit:
                request: dict[str, Any] = {
                    "analyzerArn": analyzer_arn,
                    "filter": {"status": [{"eq": ["ACTIVE"]}]},
                    "maxResults": min(1000, limit - len(findings)),
                }
                if token:
                    request["nextToken"] = token
                response = self.accessanalyzer_client.list_findings_v2(**request)
                for item in response.get("findings", []):
                    if not isinstance(item, dict):
                        continue
                    finding_id = item.get("id")
                    if not isinstance(finding_id, str) or not finding_id or finding_id in seen_ids:
                        continue
                    status = item.get("status")
                    if isinstance(status, str) and status.upper() != "ACTIVE":
                        continue
                    seen_ids.add(finding_id)
                    findings.append(item)
                    if len(findings) >= limit:
                        break

                next_token = response.get("nextToken")
                if not next_token or len(findings) >= limit:
                    break
                if not isinstance(next_token, str) or next_token in seen_tokens:
                    raise RuntimeError(
                        "IAM Access Analyzer returned an invalid or repeated nextToken."
                    )
                seen_tokens.add(next_token)
                token = next_token

            if len(findings) >= limit:
                break
        return findings

    def discover_guardduty(self) -> list[Resource]:
        """Discover regional GuardDuty detector state without fetching findings."""
        detector_ids = self._collect_pages(
            self.guardduty_client.list_detectors,
            "DetectorIds",
            request_token="NextToken",
            response_token="NextToken",
        )
        if not detector_ids:
            return [
                Resource(
                    resource_type="aws_guardduty_detector",
                    resource_id="guardduty",
                    attributes={
                        "enabled": False,
                        "status": "NOT_ENABLED",
                    },
                    source="aws",
                    region=self.region,
                )
            ]

        resources: list[Resource] = []
        for detector_id in detector_ids:
            response = self.guardduty_client.get_detector(DetectorId=detector_id)
            status = response.get("Status")
            resources.append(
                Resource(
                    resource_type="aws_guardduty_detector",
                    resource_id=detector_id,
                    attributes={
                        "enabled": status == "ENABLED" if status is not None else None,
                        "status": status,
                        "finding_publishing_frequency": response.get(
                            "FindingPublishingFrequency"
                        ),
                        "service_role_arn": response.get("ServiceRole"),
                    },
                    source="aws",
                    region=self.region,
                )
            )
        return resources

    def get_macie_findings(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return a bounded, paginated set of active Macie findings.

        Only finding metadata is returned; sensitive-data samples and object
        contents are never requested. API and permission errors propagate.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("Amazon Macie finding limit must be between 1 and 1000.")

        findings: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        token: str | None = None
        seen_tokens: set[str] = set()
        while len(findings) < limit:
            request: dict[str, Any] = {
                "maxResults": min(50, limit - len(findings)),
                "findingCriteria": {"criterion": {"archived": {"eq": ["false"]}}},
            }
            if token:
                request["nextToken"] = token
            response = self.macie_client.list_findings(**request)
            ids = response.get("findingIds", [])
            unique_ids = [
                finding_id for finding_id in ids
                if isinstance(finding_id, str) and finding_id and finding_id not in seen_ids
            ]
            for finding_id in unique_ids:
                seen_ids.add(finding_id)
            for offset in range(0, len(unique_ids), 50):
                batch = unique_ids[offset:offset + 50]
                detail_response = self.macie_client.get_findings(findingIds=batch)
                for item in detail_response.get("findings", []):
                    if not isinstance(item, dict):
                        continue
                    finding_id = item.get("id")
                    if not isinstance(finding_id, str) or not finding_id:
                        continue
                    if item.get("archived") is True:
                        continue
                    findings.append(item)
                    if len(findings) >= limit:
                        break
                if len(findings) >= limit:
                    break
            next_token = response.get("nextToken")
            if not next_token or len(findings) >= limit:
                break
            if not isinstance(next_token, str) or next_token in seen_tokens:
                raise RuntimeError("Amazon Macie returned an invalid or repeated nextToken.")
            seen_tokens.add(next_token)
            token = next_token
        return findings
