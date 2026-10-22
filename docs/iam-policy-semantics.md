# Implementation notes

The iam_policy_analysis module provides a conservative structural representation of IAM policy statements. It normalises scalar/list forms of Action, NotAction, Resource, NotResource, Principal and NotPrincipal; records condition operators and keys; and flags malformed or incomplete structures. It identifies unconditional Allow statements and the exact Action * plus Resource * combination without attempting to determine effective access.

Conditions are recorded, not evaluated. This is not an AWS policy simulator: effective permissions can depend on identity/resource policies, SCPs, permissions boundaries, session policies, trust relationships and service-specific controls. This helper is additive; existing rule evaluation is not silently changed.
