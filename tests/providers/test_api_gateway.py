from unittest.mock import Mock, call

from aws_security_scanner.providers.aws import AWSProvider


def test_rest_api_discovery_normalises_method_auth_and_stage_logging():
    client = Mock()
    client.get_rest_apis.return_value = {
        "items": [{
            "id": "abc123",
            "name": "payments",
            "policy": None,
            "endpointConfiguration": {"types": ["REGIONAL"]},
        }]
    }
    client.get_resources.return_value = {
        "items": [{
            "id": "root",
            "path": "/",
            "resourceMethods": {"GET": {}, "POST": {}},
        }]
    }
    client.get_method.side_effect = [
        {"httpMethod": "GET", "authorizationType": "NONE", "apiKeyRequired": False},
        {"httpMethod": "POST", "authorizationType": "AWS_IAM", "apiKeyRequired": True},
    ]
    client.get_stages.return_value = {"item": [{
        "stageName": "prod",
        "accessLogSettings": {
            "destinationArn": "arn:aws:logs:eu-west-2:123456789012:log-group:api-access",
            "format": '{"requestId":"$context.requestId"}',
        },
        "methodSettings": {"*/*": {"loggingLevel": "INFO"}},
    }]}

    resources = AWSProvider(apigateway_client=client, region="eu-west-2").discover_api_gateway_rest_apis()
    assert len(resources) == 1
    stage = resources[0]
    assert stage.resource_type == "aws_api_gateway_stage"
    assert stage.resource_id == "abc123:prod"
    assert stage.attributes["api_name"] == "payments"
    assert stage.attributes["endpoint_configuration"] == {"types": ["REGIONAL"]}
    assert stage.attributes["access_logging_enabled"] is True
    assert stage.attributes["stage_logging_level"] == "INFO"
    assert [method["authorization_type"] for method in stage.attributes["methods"]] == ["NONE", "AWS_IAM"]
    client.get_resources.assert_called_once_with(restApiId="abc123")
    assert client.get_method.call_args_list == [
        call(restApiId="abc123", resourceId="root", httpMethod="GET"),
        call(restApiId="abc123", resourceId="root", httpMethod="POST"),
    ]


def test_rest_api_discovery_paginates_api_and_resource_lists():
    client = Mock()
    client.get_rest_apis.side_effect = [
        {"items": [{"id": "one", "name": "first"}], "position": "api-page-2"},
        {"items": [{"id": "two", "name": "second"}]},
    ]
    client.get_resources.side_effect = [
        {"items": [{"id": "r1", "path": "/", "resourceMethods": {}}], "position": "res-page-2"},
        {"items": [{"id": "r2", "path": "/status", "resourceMethods": {}}]},
        {"items": []},
    ]
    client.get_stages.side_effect = [{"item": [{"stageName": "prod"}]}, {"item": []}]

    resources = AWSProvider(apigateway_client=client).discover_api_gateway_rest_apis()
    assert [resource.resource_id for resource in resources] == ["one:prod"]
    assert client.get_rest_apis.call_args_list == [call(), call(position="api-page-2")]
    assert client.get_resources.call_args_list == [
        call(restApiId="one"),
        call(restApiId="one", position="res-page-2"),
        call(restApiId="two"),
    ]
    assert resources[0].attributes["access_logging_enabled"] is False
    assert resources[0].attributes["methods"] == []


def test_rest_api_discovery_preserves_incomplete_metadata():
    client = Mock()
    client.get_rest_apis.return_value = {"items": [{"id": "abc", "name": "partial"}]}
    client.get_resources.return_value = {"items": [{"id": "r", "path": "/", "resourceMethods": {"GET": {}}}]}
    client.get_method.return_value = {}
    client.get_stages.return_value = {"item": [{"stageName": "dev", "accessLogSettings": {}}]}

    resource = AWSProvider(apigateway_client=client).discover_api_gateway_rest_apis()[0]
    assert resource.attributes["methods"][0]["authorization_type"] is None
    assert resource.attributes["access_logging_enabled"] is False


def test_http_api_discovery_normalises_routes_and_stage_logging():
    client = Mock()
    client.get_apis.return_value = {"Items": [{
        "ApiId": "http123", "Name": "payments-http", "ProtocolType": "HTTP",
        "ApiEndpoint": "https://http123.execute-api.eu-west-2.amazonaws.com",
        "DisableExecuteApiEndpoint": False,
    }]}
    client.get_routes.return_value = {"Items": [
        {"RouteKey": "POST /payments", "AuthorizationType": "NONE"},
        {"RouteKey": "GET /health", "AuthorizationType": "JWT", "AuthorizerId": "auth1"},
    ]}
    client.get_stages.return_value = {"Items": [{
        "StageName": "$default",
        "AccessLogSettings": {"DestinationArn": "arn:aws:logs:eu-west-2:123456789012:log-group:http-api", "Format": "$context.requestId"},
    }]}
    resources = AWSProvider(apigatewayv2_client=client, region="eu-west-2").discover_api_gateway_http_apis()
    assert len(resources) == 1
    resource = resources[0]
    assert resource.resource_type == "aws_api_gateway_http_api_stage"
    assert resource.resource_id == "http123:$default"
    assert resource.attributes["routes"][0]["authorization_type"] == "NONE"
    assert resource.attributes["access_logging_enabled"] is True
    client.get_routes.assert_called_once_with(ApiId="http123")
    client.get_stages.assert_called_once_with(ApiId="http123")
