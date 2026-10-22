# Implementation notes

The data_services module adds read-only metadata collectors for OpenSearch domains, Redshift clusters, ElastiCache clusters, MSK clusters, and AWS Backup vaults/plans/protected-resource inventory. Collectors return normalized Resource objects and use bounded pagination where supported. OpenSearch DescribeDomains calls are batched to five names per request. No documents, SQL rows, cached values, messages or backup payloads are read.

API errors propagate so orchestration can report denied/failed discovery instead of a clean inventory. discovery_complete indicates whether pagination completed within the configured bound. These functions are additive provider helpers and still need registration in AWSProvider orchestration and service-specific rules before this service family can be described as fully scanned.

Permissions vary by collector and include read/list/describe operations for OpenSearch, Redshift, ElastiCache, MSK and AWS Backup.
