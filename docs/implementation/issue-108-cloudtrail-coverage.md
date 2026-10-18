# Issue #108 — CloudTrail organisation and selector coverage

The provider now preserves missing organisation-trail, multi-region, and log-file-validation metadata as unknown instead of coercing absent fields to false. It also records an explicit organisation/account/unknown scope label.

Basic data-resource entries and advanced selectors explicitly matching eventCategory=Data contribute to the data-event coverage summary. Advanced selectors that only cover management events do not inflate the data-event count. If selector access is denied, coverage remains unknown rather than being reported as absent.

The existing CT-001 through CT-006 IDs remain unchanged. This PR does not claim complete data-event coverage: selector metadata is only a configuration signal and must be interpreted against the resources and events the organisation actually needs to audit.

Offline tests cover account-scoped trails, explicit Data selectors, management-only advanced selectors, and denied selector access. No CloudTrail configuration is modified.
