# Conservative IAM policy context analysis

`aws_security_scanner.iam_analysis.analyze_iam_policy` normalizes one policy document and reports statement-level observations: wildcard actions/resources/principals, high-risk IAM or STS actions, explicit Deny statements, NotAction/NotResource usage, and conditions requiring evaluation. Pass `policy_source` to preserve whether the document came from an identity policy, resource policy, permissions boundary, session policy, or SCP.

This deliberately does **not** simulate effective permissions. An Allow in one document does not establish access; explicit denies and interactions among identity/resource policies, permissions boundaries, session policies, SCPs, principal context, resource context, and condition keys matter. Conditions and policy variables are retained as uncertainty signals rather than treated as satisfied. Callers should combine independently collected documents and label missing context explicitly.

The analysis is pure Python and performs no AWS calls or policy changes.