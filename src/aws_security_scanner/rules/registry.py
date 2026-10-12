from aws_security_scanner.rules.s3_rules import (
    check_public_bucket,
    check_encryption,
    check_versioning,
    check_block_public_access,
    check_logging,
    check_wildcard_bucket_policy,
    check_tls_enforcement,
    check_excessive_s3_actions,
    check_wildcard_bucket_resource,
    check_public_write_access,
)

from aws_security_scanner.rules.iam_rules import (
    check_overly_permissive_policy,
    check_wildcard_permissions,
    check_excessive_administrative_permissions,
    check_insecure_trust_policy,
    check_privilege_escalation_permissions,
    check_sensitive_iam_action,
    check_broad_trust_relationship,
    check_user_without_mfa,
    check_active_access_key,
    check_old_access_key,
    check_stale_password_user,
    check_inline_wildcard_permissions,
    check_root_account_without_mfa,
    check_root_account_access_keys,
    check_unused_access_key,
    check_never_used_console_password,
    check_unused_iam_role,
)

from aws_security_scanner.rules.ec2_rules import (
    check_ssh_exposed,
    check_rdp_exposed,
    check_sensitive_port_exposed,
    check_unrestricted_ingress,
    check_unrestricted_egress,
    check_public_ipv4,
    check_imdsv1_enabled,
    check_unrestricted_ipv6_ingress,
    check_broad_port_range,
    check_unrestricted_ipv6_egress,
    check_instance_detailed_monitoring_disabled,
    check_instance_without_profile,
)

from aws_security_scanner.rules.cloudtrail_rules import (
    check_cloudtrail_logging,
    check_cloudtrail_multi_region,
    check_cloudtrail_log_file_validation,
    check_cloudtrail_cloudwatch_logs_integration,
    check_cloudtrail_delivery_error,
)

from aws_security_scanner.rules.kms_rules import (
    check_kms_key_rotation,
    check_kms_key_pending_deletion,
    check_kms_key_policy_wildcard_access,
    check_kms_cross_account_access,
)

from aws_security_scanner.rules.rds_rules import (
    check_rds_storage_encryption,
    check_rds_public_accessibility,
    check_rds_backup_retention,
    check_rds_deletion_protection,
)

from aws_security_scanner.rules.lambda_rules import (
    check_lambda_public_function_url,
    check_lambda_wildcard_invoke_policy,
    check_lambda_deprecated_runtime,
)

from aws_security_scanner.rules.secretsmanager_rules import (
    check_secret_rotation_disabled,
    check_secret_wildcard_resource_policy,
)

from aws_security_scanner.rules.ecr_rules import (
    check_ecr_mutable_image_tags,
    check_ecr_scan_on_push_disabled,
)

from aws_security_scanner.rules.dynamodb_rules import (
    check_dynamodb_pitr_disabled,
    check_dynamodb_sse_disabled,
    check_dynamodb_deletion_protection_disabled,
)

from aws_security_scanner.rules.messaging_rules import (
    check_sqs_public_access_policy,
    check_sqs_encryption_disabled,
    check_sns_public_access_policy,
    check_sns_encryption_disabled,
)

from aws_security_scanner.rules.api_gateway_rules import (
    check_api_gateway_unauthenticated_methods,
    check_api_gateway_access_logging_disabled,
)

from aws_security_scanner.rules.ecs_rules import (
    check_ecs_privileged_container,
    check_ecs_host_network_mode,
    check_ecs_root_user,
    check_ecs_root_filesystem_writable,
    check_ecs_service_public_ip,
    check_ecs_task_and_execution_roles_shared,
)

from aws_security_scanner.rules.cloudfront_rules import (
    check_cloudfront_http_viewer_access,
    check_cloudfront_weak_tls_policy,
    check_cloudfront_logging_disabled,
    check_cloudfront_missing_waf,
)

from aws_security_scanner.rules.vpc_rules import (
    check_public_subnet,
    check_unrestricted_ipv4_route,
    check_unrestricted_ipv6_route,
    check_unrestricted_nacl_ingress,
    check_unrestricted_nacl_egress,
    check_unrestricted_nacl_ipv6_ingress,
    check_unrestricted_nacl_ipv6_egress,
    check_default_nacl_ingress,
    check_default_nacl_egress,
    check_associated_public_route,
)


from aws_security_scanner.rules.ebs_rules import (
    check_ebs_volume_encryption,
    check_ebs_snapshot_encryption,
    check_public_ebs_snapshot,
)

def get_all_rules():
    """Return all registered security rules."""

    return [
        check_public_bucket,
        check_encryption,
        check_versioning,
        check_block_public_access,
        check_logging,
        check_wildcard_bucket_policy,
        check_tls_enforcement,
        check_excessive_s3_actions,
        check_wildcard_bucket_resource,
        check_public_write_access,
        check_overly_permissive_policy,
        check_wildcard_permissions,
        check_excessive_administrative_permissions,
        check_insecure_trust_policy,
        check_privilege_escalation_permissions,
        check_sensitive_iam_action,
        check_broad_trust_relationship,
        check_user_without_mfa,
        check_active_access_key,
        check_old_access_key,
        check_stale_password_user,
        check_inline_wildcard_permissions,
        check_root_account_without_mfa,
        check_root_account_access_keys,
        check_unused_access_key,
        check_never_used_console_password,
        check_unused_iam_role,
        check_ssh_exposed,
        check_rdp_exposed,
        check_sensitive_port_exposed,
        check_unrestricted_ingress,
        check_unrestricted_egress,
        check_public_ipv4,
        check_imdsv1_enabled,
        check_unrestricted_ipv6_ingress,
        check_broad_port_range,
        check_unrestricted_ipv6_egress,
        check_instance_detailed_monitoring_disabled,
        check_instance_without_profile,
        check_ebs_volume_encryption,
        check_ebs_snapshot_encryption,
        check_public_ebs_snapshot,
        check_cloudtrail_logging,
        check_cloudtrail_multi_region,
        check_cloudtrail_log_file_validation,
        check_cloudtrail_cloudwatch_logs_integration,
        check_cloudtrail_delivery_error,
        check_kms_key_rotation,
        check_kms_key_pending_deletion,
        check_kms_key_policy_wildcard_access,
        check_kms_cross_account_access,
        check_rds_storage_encryption,
        check_rds_public_accessibility,
        check_rds_backup_retention,
        check_rds_deletion_protection,
        check_lambda_public_function_url,
        check_lambda_wildcard_invoke_policy,
        check_lambda_deprecated_runtime,
        check_secret_rotation_disabled,
        check_secret_wildcard_resource_policy,
        check_ecr_mutable_image_tags,
        check_ecr_scan_on_push_disabled,
        check_dynamodb_pitr_disabled,
        check_dynamodb_sse_disabled,
        check_dynamodb_deletion_protection_disabled,
        check_sqs_public_access_policy,
        check_sqs_encryption_disabled,
        check_sns_public_access_policy,
        check_sns_encryption_disabled,
        check_api_gateway_unauthenticated_methods,
        check_api_gateway_access_logging_disabled,
        check_ecs_privileged_container,
        check_ecs_host_network_mode,
        check_ecs_root_user,
        check_ecs_root_filesystem_writable,
        check_ecs_service_public_ip,
        check_ecs_task_and_execution_roles_shared,
        check_public_subnet,
        check_unrestricted_ipv4_route,
        check_unrestricted_ipv6_route,
        check_unrestricted_nacl_ingress,
        check_unrestricted_nacl_egress,
        check_unrestricted_nacl_ipv6_ingress,
        check_unrestricted_nacl_ipv6_egress,
        check_default_nacl_ingress,
        check_default_nacl_egress,
        check_associated_public_route,
    ]
