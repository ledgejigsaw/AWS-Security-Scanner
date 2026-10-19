# Native AWS GuardDuty findings

`fetch_guardduty_region_findings` queries one configured region, selects a stable detector ID, follows `ListFindings` pagination, retrieves finding details in batches of at most 50, deduplicates native IDs, and optionally excludes archived or older findings. `fetch_guardduty_findings` runs this process for a caller-selected region list in sorted order using `client_factory(region)`.

A disabled detector is represented as an empty result with no detector ID. Access-denied, throttling, and other API errors propagate; orchestration should record a regional coverage gap rather than treating the region as clean. Each regional result includes its page count and `truncated` flag, so bounded queries are not presented as complete. The optional age filter uses `CreatedAt`; malformed or missing timestamps are excluded when age filtering is enabled.

Required actions: `guardduty:ListDetectors`, `guardduty:ListFindings`, and `guardduty:GetFindings`. This is read-only ingestion and does not enable detectors or modify findings. Native IDs and observation timestamps are preserved by the normalisation layer.
