from unittest.mock import Mock

import pytest

from aws_security_scanner.providers.aws import AWSProvider


def _provider():
    provider = AWSProvider.__new__(AWSProvider)
    provider.guardduty_client = Mock()
    provider.guardduty_client.list_detectors.return_value = {"DetectorIds": ["detector-1"]}
    provider.guardduty_client.list_findings.return_value = {"FindingIds": ["finding-1"]}
    provider.guardduty_client.get_findings.return_value = {"Findings": [{"Id": "finding-1"}]}
    return provider


def test_guardduty_applies_archive_and_updated_after_filters():
    provider = _provider()

    assert provider.get_guardduty_findings(
        archived=False,
        updated_after="2026-10-01T00:00:00Z",
        require_detector=True,
    ) == [{"Id": "finding-1"}]

    request = provider.guardduty_client.list_findings.call_args.kwargs
    assert request["FindingCriteria"]["Criterion"] == {
        "service.archived": {"Eq": ["false"]},
        "updatedAt": {"Gte": ["2026-10-01T00:00:00Z"]},
    }
    provider.guardduty_client.get_detector.assert_called_once_with(DetectorId="detector-1")


@pytest.mark.parametrize("value", ["2026-10-01", "not-a-date", "2026-10-01T00:00:00"])
def test_guardduty_rejects_invalid_or_timezone_naive_updated_after(value):
    provider = _provider()
    with pytest.raises(ValueError, match="ISO-8601"):
        provider.get_guardduty_findings(updated_after=value)
    provider.guardduty_client.list_detectors.assert_not_called()


def test_guardduty_can_require_a_detector_to_avoid_false_clean_results():
    provider = _provider()
    provider.guardduty_client.list_detectors.return_value = {"DetectorIds": []}

    with pytest.raises(RuntimeError, match="no detector"):
        provider.get_guardduty_findings(require_detector=True)
