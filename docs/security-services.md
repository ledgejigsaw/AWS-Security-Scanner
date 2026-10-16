# AWS-native security-service posture and findings

The AWS provider includes read-only regional posture discovery for AWS Security Hub, Amazon GuardDuty, AWS Config and Amazon Macie, and optional bounded native finding import from Amazon Inspector. Native finding import is opt-in and is enabled with `--include-native-findings`.

## Current posture checks

- `SECURITYHUB-001`: reports Security Hub as not enabled only when `DescribeHub` returns `ResourceNotFoundException`.
- `GUARDDUTY-001`: reports GuardDuty as not enabled only when `ListDetectors` returns no detector IDs.
- `CONFIG-001`: reports no configuration recorder only when the recorder list is explicitly empty.
- `CONFIG-002`: reports recording stopped only when status explicitly reports `recording=false`.
- `CONFIG-003`: reports no delivery channel only when the delivery-channel list is explicitly empty.
- `MACIE-001`: reports Macie as not enabled only when `GetMacieSession` returns `ResourceNotFoundException` or an explicit `PAUSED` status.

These are regional posture signals. Macie discovery does not assess whether discovery jobs, sensitive-data discovery coverage or delegated-administrator settings are sufficient. They do not prove that the services' detection coverage or controls are effective.

## Native finding sources

When `--include-native-findings` is enabled for an AWS-source scan, the scanner imports a bounded set of findings from:

| Source | APIs | Report identity |
| --- | --- | --- |
| AWS Security Hub | `GetFindings` | `AWS-SHUB-NATIVE`, source type `security_hub` |
| Amazon GuardDuty | `ListDetectors`, `ListFindings`, `GetFindings` | `AWS-GD-NATIVE`, source type `guardduty` |
| IAM Access Analyzer | `ListAnalyzers`, `ListFindingsV2` | `AWS-AA-NATIVE`, source type `access_analyzer` |\n| Amazon Inspector | `ListFindings` (active findings only) | `AWS-INSPECTOR-NATIVE`, source type `inspector` |

The configured `--native-findings-limit` applies separately to each source (default 100; maximum 1,000). Pagination is bounded and duplicate source IDs are removed. Access Analyzer imports active findings from analyzers returned in the selected region. Amazon Inspector imports active findings in the selected region, preserving the finding ARN and observation timestamps while excluding raw resource payloads. The same per-source cap applies. If no analyzer is configured, the import contributes no findings; API and permission errors propagate rather than being interpreted as a clean result.

Native findings preserve source IDs, source product/analyzer ARN, account identity and observation timestamps where provided. Only selected metadata is retained; full source payloads, principal details, conditions and policy documents are not copied into the scanner's evidence. Access Analyzer severity is a conservative triage mapping: public external access maps to HIGH, other external access to MEDIUM, unused access to LOW, and unrecognised types to INFO. These values are not a claim that the reported access is necessarily unintended.

## Read-only permissions

The following read-only actions are needed for the relevant optional integrations:

- Security Hub posture/findings: `securityhub:DescribeHub`, `securityhub:GetFindings`
- GuardDuty posture/findings: `guardduty:ListDetectors`, `guardduty:GetDetector`, `guardduty:ListFindings`, `guardduty:GetFindings`
- AWS Config posture: `config:DescribeConfigurationRecorders`, `config:DescribeConfigurationRecorderStatus`, `config:DescribeDeliveryChannels`
- Amazon Macie posture: `macie2:GetMacieSession`
- IAM Access Analyzer findings: `access-analyzer:ListAnalyzers`, `access-analyzer:ListFindingsV2`\n- Amazon Inspector findings: `inspector2:ListFindings`

The scanner does not enable or configure these services. Access-denied and unexpected API errors propagate; they are not converted into a clean result. The checks do not establish organization-wide coverage, delegated-administrator configuration, standards enablement or control effectiveness. Live AWS end-to-end validation remains outstanding.
