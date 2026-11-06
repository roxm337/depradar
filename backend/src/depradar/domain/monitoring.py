"""Changes an AI assistant may make to a project's monitoring and alerts: tighten, never relax.

Each rule returns the reason a change is refused, or None when it keeps or increases what
DepRadar watches and reports. Relaxing a setting stays with the owner, in the dashboard.
"""

from depradar.domain.gate import LEVELS

MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 168
ALERT_LEVELS = ("low", "medium", "high", "critical")


def effective_threshold(project_threshold: str | None, installation_threshold: str) -> str:
    """The lowest severity that alerts immediately; a project without its own inherits."""
    return project_threshold or installation_threshold


def monitoring_refusal(
    enabled_now: bool, interval_now: int, enabled: bool, interval_hours: int
) -> str | None:
    """Turning monitoring on, or checking at least as often, is allowed; nothing else is."""
    if not MIN_INTERVAL_HOURS <= interval_hours <= MAX_INTERVAL_HOURS:
        return f"The interval must be {MIN_INTERVAL_HOURS} to {MAX_INTERVAL_HOURS} hours"
    if not enabled:
        if enabled_now:
            return "Assistants cannot turn monitoring off"
        return "Monitoring is already off; pass enabled=true to turn it on"
    if enabled_now and interval_hours > interval_now:
        return (
            f"Assistants cannot check less often: the project is checked every {interval_now} "
            f"hours, and {interval_hours} would lengthen that"
        )
    return None


def alert_refusal(
    enabled_now: bool, threshold_now: str, enabled: bool, threshold: str
) -> str | None:
    """Thresholds are effective ones, after ``inherit`` is resolved.

    Turning alerts on is always an increase, since a project with alerts off sends none. With
    alerts on, the threshold may stay or get lower, so that more severities alert.
    """
    if threshold not in ALERT_LEVELS:
        return "The threshold must be low, medium, high, or critical"
    if not enabled:
        if enabled_now:
            return "Assistants cannot turn alerts off"
        return "Alerts are already off; pass enabled=true to turn them on"
    if enabled_now and LEVELS.index(threshold) > LEVELS.index(threshold_now):
        return (
            f"Assistants cannot raise the alert threshold: it is {threshold_now}, and "
            f"{threshold} would alert on fewer findings"
        )
    return None
