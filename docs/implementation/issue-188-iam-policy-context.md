# Issue #188 — IAM policy-context analysis

## Implemented in this PR

The new collect_iam_policy_context API inventories IAM users, groups, and roles;
records attached and inline policies; reads managed policies at their default
version; captures permissions-boundary presence and role trust-policy context;
and applies the existing conservative statement analyzer to policy documents.
Pagination is checked, and access denied or malformed/missing documents remain
unknown/partial rather than being interpreted as no policy.

Raw API responses are not copied into the report. Policy documents are reduced
to statement-level observations by the existing analyzer.

## Limits

This does not calculate effective permissions and does not yet inventory AWS
Organizations SCP attachments or arbitrary resource policies. Those contexts
must be collected and evaluated before an effective-access conclusion could
be justified. The API reports these limits explicitly.

## Validation

Offline mock tests cover attached policies, default policy versions, boundaries,
trust principals, and AccessDenied handling. Tests were added but not executed
in this editing session; CI is the merge gate.

## Permissions

The caller needs read-only IAM inventory permissions, including ListUsers,
ListGroups, ListRoles, ListAttachedUserPolicies, ListAttachedGroupPolicies,
ListAttachedRolePolicies, ListUserPolicies, ListGroupPolicies, ListRolePolicies,
GetUserPolicy, GetGroupPolicy, GetRolePolicy, GetPolicy, and GetPolicyVersion.
Grant only the calls required by the inventory scope.
