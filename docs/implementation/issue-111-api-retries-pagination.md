# Issue #111 — AWS retries and pagination

All AWS clients created by AWSProvider now receive explicit botocore standard-mode retry configuration with at most four total attempts, a five-second connection timeout, and a thirty-second read timeout. This makes transient retry behavior consistent for ordinary and assumed-role sessions without retrying indefinitely.

The provider's default pagination ceiling is configurable when constructing AWSProvider (default 1,000 pages). Existing strict handling of missing or repeated continuation tokens remains in place. KMS grant pagination remains separately bounded to ten pages and marks the grant inventory unknown if the bound is exhausted. Partial pages are not reported as a complete grant inventory.

These bounds limit worst-case discovery duration but are not a guarantee that every AWS service has identical retry semantics. Botocore performs the actual retry attempts; offline tests verify configuration and pagination failure behavior without requiring AWS credentials.
