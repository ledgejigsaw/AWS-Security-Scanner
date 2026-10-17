# AWS CodeBuild build-security checks

The scanner uses read-only CodeBuild APIs to enumerate project configuration. It records environment-variable names and types only; it never retains or reports environment-variable values, build logs or build artifacts.

## Checks

- **CB-001 (MEDIUM):** privileged build mode is explicitly enabled. Some container builds require this mode, so the finding asks for review and does not assert that the configuration is exploitable.
- **CB-002 (MEDIUM):** a sensitive-looking environment variable name (for example, one containing `TOKEN`, `PASSWORD`, `SECRET` or `API_KEY`) is explicitly configured as `PLAINTEXT`. The evidence lists names only. Values are not copied from API responses.

The provider also records the project service role, build image/type, source type/location, VPC/subnet/security-group identifiers and CloudWatch Logs configuration where returned. It does not download source, execute builds, inspect build logs or fully evaluate the permissions of the CodeBuild service role.

## Permissions

The discovery path uses `codebuild:ListProjects` and `codebuild:BatchGetProjects`. Use a read-only audit role and treat denied or incomplete discovery as an assessment gap.

Run a scoped scan with:

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 --service codebuild --format json --output reports/codebuild.json
```

All automated tests use mocked responses; live AWS validation has not been performed.
