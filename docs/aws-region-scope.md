# Implementation notes

The region_scope module provides deterministic region selection and bounded enabled-region enumeration. Explicit include/exclude lists are supported; all-enabled-region mode selects the enumerated enabled set; the default region is retained when no broader scope is requested. Unknown requested regions are diagnosed and not silently added. Failed or denied enumeration returns an incomplete scope instead of falling back to one region and claiming account-wide coverage.

enumerate_enabled_regions calls EC2 DescribeRegions(AllRegions=False) and propagates API failures. Required permission: ec2:DescribeRegions. Global service scope is passed separately because CloudFront and CloudFront-scope WAF do not follow the same regional model. These helpers are not yet wired into CLI orchestration.
