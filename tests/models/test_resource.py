from aws_security_scanner.models.resource import Resource


def test_resource_supports_relationships():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company_data",
        attributes={
            "bucket": "company-sensitive-data"
        },
        source="terraform",
        region="eu-west-2",
        relationships={
            "versioning": "aws_s3_bucket_versioning.company_data"
        },
    )

    assert resource.relationships == {
        "versioning": "aws_s3_bucket_versioning.company_data"
    }