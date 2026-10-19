# Native AWS Security Hub findings

The Security Hub integration normalises ASFF records into native scanner findings. `fetch_securityhub_findings` accepts a configured boto3 Security Hub client, optional `GetFindings` filters, and explicit result/page bounds. It follows `NextToken`, deduplicates native finding IDs, and returns `truncated=True` if a configured bound prevents complete retrieval. Repeated pagination tokens and malformed response collections fail explicitly.

API exceptions intentionally propagate. In particular, access denied or disabled Security Hub must be recorded as a coverage gap by the caller, not converted into an empty finding list. Results are the findings returned by the requested filter and bounded query; they do not prove that a Security Hub standard has been fully evaluated.

Required action: `securityhub:GetFindings`. Use a read-only identity and narrow filters where possible. The helper does not enable Security Hub, change standards, or remediate findings. Native source identity is retained by the normalisation layer.
