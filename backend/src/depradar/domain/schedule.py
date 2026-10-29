"""When notifications go out: daily digest times and quiet hours."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from depradar.domain.entities import NotificationPolicy


def next_digest(now: datetime, timezone: str, hour: int) -> datetime:
    local = now.astimezone(ZoneInfo(timezone))
    candidate = local.replace(hour=hour, minute=0, second=0, microsecond=0)
    if candidate <= local:
        candidate += timedelta(days=1)
    return candidate.astimezone(UTC)


def quiet_end_at(now: datetime, policy: NotificationPolicy) -> datetime:
    start, end = policy.quiet_hours_start, policy.quiet_hours_end
    if start is None or end is None:
        return now
    local = now.astimezone(ZoneInfo(policy.timezone))
    in_quiet_hours = (
        start <= local.hour < end if start < end else local.hour >= start or local.hour < end
    )
    if not in_quiet_hours:
        return now
    end_at = local.replace(hour=end, minute=0, second=0, microsecond=0)
    if start > end and local.hour >= start:
        end_at += timedelta(days=1)
    return end_at.astimezone(UTC)
