from unittest.mock import Mock, call

from aws_security_scanner.providers.aws import AWSProvider


def test_sqs_discovery_normalises_policy_encryption_and_redrive_metadata():
    client = Mock()
    client.list_queues.return_value = {
        "QueueUrls": ["https://sqs.eu-west-2.amazonaws.com/123456789012/orders"]
    }
    client.get_queue_attributes.return_value = {"Attributes": {
        "QueueArn": "arn:aws:sqs:eu-west-2:123456789012:orders",
        "Policy": '{"Statement": []}',
        "KmsMasterKeyId": "alias/queue-key",
        "RedrivePolicy": '{"deadLetterTargetArn":"arn:aws:sqs:eu-west-2:123456789012:orders-dlq","maxReceiveCount":"5"}',
    }}

    resources = AWSProvider(sqs_client=client, region="eu-west-2").discover_sqs_queues()
    assert len(resources) == 1
    resource = resources[0]
    assert resource.resource_type == "aws_sqs_queue"
    assert resource.resource_id == "orders"
    assert resource.attributes["arn"].endswith(":orders")
    assert resource.attributes["encryption_enabled"] is True
    assert resource.attributes["dead_letter_target_arn"].endswith(":orders-dlq")
    client.get_queue_attributes.assert_called_once_with(
        QueueUrl="https://sqs.eu-west-2.amazonaws.com/123456789012/orders",
        AttributeNames=["All"],
    )


def test_sqs_discovery_paginates_and_preserves_unknown_encryption_state():
    client = Mock()
    client.list_queues.side_effect = [
        {"QueueUrls": ["https://sqs.eu-west-2.amazonaws.com/123/first"], "NextToken": "page-2"},
        {"QueueUrls": ["https://sqs.eu-west-2.amazonaws.com/123/second"]},
    ]
    client.get_queue_attributes.return_value = {"Attributes": {}}
    resources = AWSProvider(sqs_client=client).discover_sqs_queues()
    assert [resource.resource_id for resource in resources] == ["first", "second"]
    assert resources[0].attributes["encryption_enabled"] is None
    assert client.list_queues.call_args_list == [call(), call(NextToken="page-2")]


def test_sns_discovery_normalises_topic_policy_and_encryption():
    client = Mock()
    client.list_topics.return_value = {
        "Topics": [{"TopicArn": "arn:aws:sns:eu-west-2:123456789012:alerts"}]
    }
    client.get_topic_attributes.return_value = {"Attributes": {
        "TopicArn": "arn:aws:sns:eu-west-2:123456789012:alerts",
        "Policy": '{"Statement": []}',
        "KmsMasterKeyId": "alias/topic-key",
    }}

    resources = AWSProvider(sns_client=client, region="eu-west-2").discover_sns_topics()
    assert len(resources) == 1
    resource = resources[0]
    assert resource.resource_type == "aws_sns_topic"
    assert resource.resource_id == "alerts"
    assert resource.attributes["encryption_enabled"] is True
    assert resource.attributes["policy"] == '{"Statement": []}'
    client.get_topic_attributes.assert_called_once_with(
        TopicArn="arn:aws:sns:eu-west-2:123456789012:alerts"
    )


def test_sns_discovery_paginates_topics_and_preserves_unknown_metadata():
    client = Mock()
    client.list_topics.side_effect = [
        {"Topics": [{"TopicArn": "arn:aws:sns:eu-west-2:123:one"}], "NextToken": "next"},
        {"Topics": [{"TopicArn": "arn:aws:sns:eu-west-2:123:two"}]},
    ]
    client.get_topic_attributes.return_value = {"Attributes": {}}
    resources = AWSProvider(sns_client=client).discover_sns_topics()
    assert [resource.resource_id for resource in resources] == ["one", "two"]
    assert all(resource.attributes["encryption_enabled"] is None for resource in resources)
    assert client.list_topics.call_args_list == [call(), call(NextToken="next")]


def test_messaging_discovery_handles_empty_services():
    sqs = Mock()
    sqs.list_queues.return_value = {"QueueUrls": []}
    sns = Mock()
    sns.list_topics.return_value = {"Topics": []}
    provider = AWSProvider(sqs_client=sqs, sns_client=sns)
    assert provider.discover_sqs_queues() == []
    assert provider.discover_sns_topics() == []
