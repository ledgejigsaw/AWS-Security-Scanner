# Testing and validation

## Local setup

Use Python 3.11 or newer. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

If the project is already installed in an active virtual environment, run `pytest -q` after pulling the latest changes.

## Test layers

- **Rule tests** exercise secure, insecure and incomplete resource metadata.
- **Provider tests** mock AWS API responses and check discovery, pagination and normalisation behaviour.
- **CLI and integration tests** exercise scan orchestration and output behaviour.
- **Terraform tests** cover Terraform JSON conversion and resource relationships.
- **Reporting tests** check JSON, HTML, SARIF and summary output.

## CI

GitHub Actions runs the test suite against Python 3.11 and 3.13. Review the checks for a pull request before merging. After merge, update local `main` and run the suite again:

```bash
git switch main
git pull --ff-only origin main
pytest -q
```

## What passing tests mean

The automated suite uses mocks and fixtures. It demonstrates expected behaviour for the covered scenarios; it does not prove that every AWS API edge case has been encountered or that the scanner has been validated end-to-end in a real AWS account.

## Safe test-data practices

Do not commit AWS credentials, secret values, production exports containing sensitive data, or generated scan reports. Keep test fixtures synthetic and purpose-built. Live-account validation should use an isolated non-production account and a least-privilege read-only identity.
