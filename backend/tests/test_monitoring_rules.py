"""Changes assistants may make to monitoring and alerts: every allowed and refused transition."""

import pytest

from depradar.domain.monitoring import alert_refusal, effective_threshold, monitoring_refusal


@pytest.mark.parametrize(
    ("enabled_now", "interval_now", "enabled", "interval"),
    [
        (False, 24, True, 24),  # turned on
        (False, 6, True, 168),  # turned on: any interval is more than none
        (False, 24, True, 1),
        (True, 24, True, 24),  # unchanged
        (True, 24, True, 6),  # more often
        (True, 2, True, 1),
    ],
)
def test_monitoring_may_be_turned_on_or_checked_more_often(
    enabled_now: bool, interval_now: int, enabled: bool, interval: int
) -> None:
    assert monitoring_refusal(enabled_now, interval_now, enabled, interval) is None


@pytest.mark.parametrize(
    ("enabled_now", "interval_now", "enabled", "interval", "reason"),
    [
        (True, 24, False, 24, "cannot turn monitoring off"),
        (True, 24, True, 25, "cannot check less often"),
        (True, 1, True, 168, "cannot check less often"),
        (False, 24, False, 24, "already off"),
        (False, 24, True, 0, "1 to 168 hours"),
        (True, 24, True, 169, "1 to 168 hours"),
    ],
)
def test_monitoring_is_never_relaxed(
    enabled_now: bool, interval_now: int, enabled: bool, interval: int, reason: str
) -> None:
    refusal = monitoring_refusal(enabled_now, interval_now, enabled, interval)
    assert refusal is not None and reason in refusal


def test_inherit_resolves_against_the_installation_threshold() -> None:
    assert effective_threshold(None, "high") == "high"
    assert effective_threshold("medium", "high") == "medium"


@pytest.mark.parametrize(
    ("enabled_now", "threshold_now", "enabled", "threshold"),
    [
        (True, "high", True, "high"),  # unchanged
        (True, "high", True, "medium"),  # lower
        (True, "critical", True, "low"),
        (False, "low", True, "critical"),  # turned on: alerts off send nothing at all
        (False, "high", True, "high"),
    ],
)
def test_alerts_may_be_turned_on_or_lowered(
    enabled_now: bool, threshold_now: str, enabled: bool, threshold: str
) -> None:
    assert alert_refusal(enabled_now, threshold_now, enabled, threshold) is None


@pytest.mark.parametrize(
    ("enabled_now", "threshold_now", "enabled", "threshold", "reason"),
    [
        (True, "high", False, "high", "cannot turn alerts off"),
        (True, "high", False, "low", "cannot turn alerts off"),
        (True, "medium", True, "high", "cannot raise"),
        (True, "low", True, "critical", "cannot raise"),
        (False, "high", False, "high", "already off"),
        (True, "high", True, "unknown", "low, medium, high, or critical"),
        (True, "high", True, "inherit", "low, medium, high, or critical"),
    ],
)
def test_alerts_are_never_relaxed(
    enabled_now: bool, threshold_now: str, enabled: bool, threshold: str, reason: str
) -> None:
    refusal = alert_refusal(enabled_now, threshold_now, enabled, threshold)
    assert refusal is not None and reason in refusal
