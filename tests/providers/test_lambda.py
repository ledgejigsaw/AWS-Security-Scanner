from unittest.mock import Mock, call

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider


def test_lambda_discovery_normalises_url_auth_and_resource_policy():
    lambda_client = Mock()
    lambda_client.list_functions.return_value = {
        "Functions": [{
            "FunctionName": "customer-handler",
            "Runtime": "python3.12",
            "Handler": "app.handler",
            "Role": "arn:aws:iam::123456789012:role/lambda-role",
            "State": "Active",
        }]
    }
    lambda_client.list_function_url_configs.return_value = {
        "FunctionUrlConfigs": [{
            "FunctionUrl": "https://example.lambda-url.eu-west-2.on.aws/",
            "AuthType": "NONE",
        }]
    }
    lambda_client.get_policy.return_value = {
        "Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction","Resource":"*"}]}'
    }

    provider = AWSProvider(lambda_client=lambda_client, region="eu-west-2")
    resources = provider.discover_lambda_functions()

    assert len(resources) == 1
    resource = resources[0]
    assert isinstance(resource, Resource)
    assert resource.resource_type == "aws_lambda_function"
    assert resource.resource_id == "customer-handler"
    assert resource.source == "aws"
    assert resource.region == "eu-west-2"
    assert resource.attributes["runtime"] == "python3.12"
    assert resource.attributes["function_url_auth_type"] == "NONE"
    assert resource.attributes["resource_policy"]["Statement"][0]["Principal"] == "*"


def test_lambda_discovery_follows_function_pagination():
    lambda_client = Mock()
    lambda_client.list_functions.side_effect = [
        {"Functions": [{"FunctionName": "function-one"}], "NextMarker": "next"},
        {"Functions": [{"FunctionName": "function-two"}]},
    ]
    lambda_client.list_function_url_configs.return_value = {"FunctionUrlConfigs": []}
    lambda_client.get_policy.side_effect = Exception("no policy expected in this test")

    provider = AWSProvider(lambda_client=lambda_client, region="eu-west-2")
    # A missing policy is represented by the Lambda API as ClientError; avoid
    # needing an AWS account while checking the list-functions pagination path.
    from botocore.exceptions import ClientError
    lambda_client.get_policy.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "No policy"}},
        "GetPolicy",
    )

    resources = provider.discover_lambda_functions()

    assert [resource.resource_id for resource in resources] == ["function-one", "function-two"]
    assert lambda_client.list_functions.call_args_list == [
        call(),
        call(Marker="next"),
    ]
    assert lambda_client.list_function_url_configs.call_count == 2
