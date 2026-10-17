from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from aws_security_scanner.providers.aws import AWSProvider


def _provider_with_s3_client(client):
    provider = AWSProvider.__new__(AWSProvider)
    provider.s3_client = client
    return provider


@pytest.mark.parametrize(
    ("method_name", "api_name", "response"),
    [
        ("_get_bucket_versioning", "get_bucket_versioning", {}),
        ("_get_bucket_logging", "get_bucket_logging", {}),
    ],
)
def test_s3_successful_empty_response_means_setting_is_absent(
    method_name, api_name, response
):
    client = Mock()
    getattr(client, api_name).return_value = response
    provider = _provider_with_s3_client(client)

    assert getattr(provider, method_name)("fixture-bucket") is False


@pytest.mark.parametrize(
    ("method_name", "api_name", "operation"),
    [
        ("_get_bucket_versioning", "get_bucket_versioning", "GetBucketVersioning"),
        ("_get_bucket_logging", "get_bucket_logging", "GetBucketLogging"),
    ],
)
@pytest.mark.parametrize(
    "error_code",
    ["AccessDenied", "AccessDeniedException", "SlowDown", "InternalError"],
)
def test_s3_api_failure_is_unknown_not_disabled(
    method_name, api_name, operation, error_code
):
    client = Mock()
    getattr(client, api_name).side_effect = ClientError(
        {"Error": {"Code": error_code, "Message": "fixture error"}},
        operation,
    )
    provider = _provider_with_s3_client(client)

    assert getattr(provider, method_name)("fixture-bucket") is None
