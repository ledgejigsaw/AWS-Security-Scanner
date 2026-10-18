# Issue #110 — AWS permissions preflight

The optional --aws-permissions-preflight flag runs one low-impact read-only probe for each selected service before scanning. If no --service filters are supplied, it checks the supported service probe matrix. STS identity is validated; service results distinguish success, access denied, throttling, disabled services, unsupported probes, and other safe failure categories.

The preflight is advisory and does not block the scan. One successful API call does not prove all service-specific actions are granted. Discovery coverage from the actual scan remains authoritative. The JSON assessment includes preflight results alongside discovery coverage; HTML and SARIF reports receive the same assessment metadata. The flag is restricted to single-account AWS scans so it cannot silently imply that every account in a multi-account file was checked.

No credentials are accepted on the command line, no resources are changed, and raw AWS error messages are not included in the result. Tests use mocks only.
