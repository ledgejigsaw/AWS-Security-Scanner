# Compliance mapping foundation

The scanner can associate individual check IDs with versioned control objectives using a validated JSON mapping document. Mapping metadata is kept separate from rule detection.

## Mapping format

Mapping documents use `schema_version: 1`, a framework name and version, and a list of control mappings. Each mapping contains:

- `control_id` and `title`
- `check_ids`, which must refer to registered scanner checks when validated against the registry
- `confidence`: `direct`, `partial`, or `contextual`
- `rationale`, explaining why the check is related to the control

The initial sample at `mappings/nist-sp-800-53-rev5.json` is deliberately narrow. It is an illustrative crosswalk, not a compliance assessment.

## Validation

The `aws_security_scanner.compliance` module provides `load_mapping_file` and `validate_mapping_document`. Call validation with the IDs returned by the current rule registry to detect stale or misspelled check references.

Validation rejects unsupported schema versions, malformed required fields, invalid confidence values, duplicate control/check pairs, and unregistered check IDs when a registry is supplied.

## Important limitation

A mapping means that a check may provide evidence relevant to a control objective. It does **not** mean the scanner evaluates the entire control, that absence of findings proves compliance, or that an organisation is certified. Mapping rationale and confidence must be reviewed whenever rules or framework versions change.
