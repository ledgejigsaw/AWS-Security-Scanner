from unittest.mock import Mock

import pytest

from aws_security_scanner.providers.aws import AWSProvider


def _provider():
    # _collect_pages does not need constructed SDK clients.
    return object.__new__(AWSProvider)


def test_collect_pages_follows_continuation_tokens():
    method = Mock(
        side_effect=[
            {"Items": [{"id": 1}], "NextToken": "page-2"},
            {"Items": [{"id": 2}]},
        ]
    )

    result = _provider()._collect_pages(method, "Items")

    assert result == [{"id": 1}, {"id": 2}]
    assert method.call_args_list[1].kwargs == {"NextToken": "page-2"}


def test_collect_pages_fails_when_page_limit_is_reached():
    method = Mock(
        side_effect=[
            {"Items": [{"id": 1}], "NextToken": "page-2"},
            {"Items": [{"id": 2}], "NextToken": "page-3"},
        ]
    )

    with pytest.raises(RuntimeError, match="pagination limit of 1 pages.*incomplete"):
        _provider()._collect_pages(method, "Items", max_pages=1)

    assert method.call_count == 1


@pytest.mark.parametrize("max_pages", [0, -1, True, 1.5, "2"])
def test_collect_pages_rejects_invalid_page_limits(max_pages):
    with pytest.raises(ValueError, match="max_pages must be a positive integer"):
        _provider()._collect_pages(Mock(), "Items", max_pages=max_pages)


def test_collect_pages_rejects_truncated_response_without_token():
    method = Mock(return_value={"Items": [{"id": 1}], "IsTruncated": True})

    with pytest.raises(RuntimeError, match="truncated results without a continuation token"):
        _provider()._collect_pages(method, "Items")


def test_aws_provider_applies_bounded_standard_retry_and_timeout_config():
    from unittest.mock import Mock
    from botocore.config import Config
    from aws_security_scanner.providers.aws import AWSProvider

    session = Mock()
    provider = AWSProvider(session=session)
    assert session.client.call_count > 1
    config = session.client.call_args.kwargs["config"]
    assert isinstance(config, Config)
    assert config.retries["mode"] == "standard"
    assert config.retries["total_max_attempts"] == 4
    assert config.connect_timeout == 5
    assert config.read_timeout == 30


def test_aws_provider_uses_configured_default_pagination_page_limit():
    from unittest.mock import Mock
    from aws_security_scanner.providers.aws import AWSProvider

    provider = AWSProvider(ec2_client=Mock(), max_pages=1)
    provider.ec2_client.describe_vpcs.return_value = {
        "Vpcs": [{"VpcId": "vpc-first"}],
        "NextToken": "page-2",
    }
    with pytest.raises(RuntimeError, match="pagination limit of 1 pages"):
        provider._collect_pages(provider.ec2_client.describe_vpcs, "Vpcs")


def test_aws_provider_rejects_invalid_default_page_limit():
    from aws_security_scanner.providers.aws import AWSProvider

    with pytest.raises(ValueError, match="max_pages"):
        AWSProvider(max_pages=0)
