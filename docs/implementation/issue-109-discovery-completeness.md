# Issue #109 — Discovery completeness reporting

AWS service coverage entries now carry schema version 1.0.0, configured scope, per-discovery-function outcomes, safe error categories, and an operation summary. Existing service-level status and fields remain available for compatibility. A successful empty result is distinct from a denied or failed discovery call.

The JSON assessment includes an overall completeness status and operation counts. CLI output continues to print service-level results and warns when discovery is incomplete. Raw AWS error messages and request payloads are not serialized; diagnostic categories include authorization, throttling, service-disabled, unsupported-operation, and generic failure.

The operation name is the scanner's discovery function, not a claim that each nested AWS API call has been instrumented. Detailed API-operation telemetry remains separate work. This report therefore improves service-level transparency without overstating visibility into every internal API call.

Offline tests cover successful empty results, partial failures, access denial, and safe diagnostic output. No AWS credentials are required.
