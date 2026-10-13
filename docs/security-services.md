# AWS-native security-service posture

The AWS provider includes initial read-only posture discovery for AWS Security Hub and Amazon GuardDuty in the selected AWS region.

## Current checks

- `SECURITYHUB-001`: reports Security Hub as not enabled only when `DescribeHub` returns `ResourceNotFoundException`.
- `GUARDDUTY-001`: reports GuardDuty as not enabled only when `ListDetectors` returns no detector IDs.

The checks do not import Security Hub or GuardDuty findings in this increment. Native finding ingestion is a separate design step so source IDs, timestamps, pagination, deduplication and source attribution can be handled deliberately.

## Scope and permissions

The checks are regional and use read-only APIs:

- Security Hub: `securityhub:DescribeHub`
- GuardDuty: `guardduty:ListDetectors`, `guardduty:GetDetector`

The scanner does not enable or configure either service. It does not retrieve finding details, threat-intelligence data, or protected content.

## Error semantics and limitations

An explicit Security Hub `ResourceNotFoundException` or an empty GuardDuty detector list is treated as not enabled. Access-denied and unexpected API errors propagate; they are not converted into a clean result. If a GuardDuty response does not include a detector status, the status remains unknown and the disabled check does not fire.

The checks only describe the selected region. They do not establish organization-wide coverage, delegated-administrator configuration, standards enablement, control effectiveness, or the quality of detections. Run with a least-privilege identity and review regional coverage requirements before drawing conclusions.
