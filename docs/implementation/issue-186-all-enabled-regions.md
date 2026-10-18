# Issue #186 — All enabled AWS regions

Status: implementation plan / draft PR. This document does not claim the multi-region feature is implemented.

## Implementation sequence
1. Add a region-discovery adapter using STS/EC2 read-only APIs and explicitly classify opt-in-disabled regions.
2. Preserve the existing explicit single-region path; introduce a separate opt-in flag for all enabled regions to avoid silently changing scan cost or behaviour.
3. Classify provider methods as regional or global. Run global discovery once per account, not once per region.
4. Aggregate regional resources and coverage independently; a failure in one region must not discard successful results from others.
5. Include region and account in stable resource/finding identity where applicable.

## Required tests
- Enabled, opt-in-required, and disabled regions.
- Denied region enumeration and regional partial failure.
- Global service deduplication.
- Backward compatibility for explicit --region.
- Report lists attempted, skipped, failed regions.

## Safety
All tests must use mocks; no credentials or live AWS calls in default CI. Document required read-only permissions and API throttling.