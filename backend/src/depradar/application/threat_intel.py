"""Advisory prioritization signals: CISA KEV membership and FIRST EPSS scores."""

import logging
import re
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from depradar.application.ports import FeedUnavailable, IntelligenceFeed
from depradar.config import Settings
from depradar.domain.entities import Finding, Scan, SystemState, ThreatIntel, utcnow

logger = logging.getLogger(__name__)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CHECK_LOOKBACK = timedelta(days=7)


def refresh_if_due(
    factory: sessionmaker[Session], settings: Settings, feed: IntelligenceFeed
) -> bool:
    """Refresh CVE intel once per configured interval; failures leave last-good data intact."""
    now = utcnow()
    with factory.begin() as db:
        state = db.get(SystemState, 1)
        if state is None:
            return False
        if state.next_intelligence_refresh_at and state.next_intelligence_refresh_at > now:
            return False
        # Claim the refresh window before network I/O so repeated worker cycles do not fan out.
        state.next_intelligence_refresh_at = now + timedelta(minutes=15)
        ids = {
            alias.upper()
            for finding in db.scalars(select(Finding).where(Finding.status == "open"))
            for alias in finding.advisory_ids
            if CVE_PATTERN.fullmatch(alias)
        }
        # Recent CI checks can introduce CVEs that no monitored finding has yet.
        for results in db.scalars(
            select(Scan.results).where(
                Scan.mode == "check", Scan.created_at >= now - CHECK_LOOKBACK
            )
        ):
            for result in results or []:
                ids.update(
                    alias.upper()
                    for alias in result.get("advisory_ids", [])
                    if isinstance(alias, str) and CVE_PATTERN.fullmatch(alias)
                )

    try:
        kev_ids, epss_scores = feed(sorted(ids))
    except FeedUnavailable:
        logger.warning("threat_intelligence_refresh_failed; cached scores remain in use")
        with factory.begin() as db:
            state = db.get(SystemState, 1)
            if state is not None:
                state.next_intelligence_refresh_at = utcnow() + timedelta(hours=1)
        return False

    refreshed_at = utcnow()
    with factory.begin() as db:
        # Cache the whole KEV catalog so CI checks can flag exploited CVEs on first sight.
        for row in db.scalars(select(ThreatIntel).where(ThreatIntel.kev_known.is_(True))):
            if row.cve_id not in kev_ids:
                row.kev_known = False
                row.updated_at = refreshed_at
        for cve_id in ids | kev_ids:
            row = db.get(ThreatIntel, cve_id) or ThreatIntel(cve_id=cve_id)
            if cve_id in ids:
                score = epss_scores.get(cve_id)
                row.epss_score = score[0] if score else None
                row.epss_percentile = score[1] if score else None
            row.kev_known = cve_id in kev_ids
            row.updated_at = refreshed_at
            db.add(row)
        for finding in db.scalars(select(Finding).where(Finding.status == "open")):
            _apply_rows(finding, _intel_rows(db, finding.advisory_ids), refreshed_at)
        state = db.get(SystemState, 1)
        if state is not None:
            state.last_intelligence_refresh_at = refreshed_at
            state.next_intelligence_refresh_at = refreshed_at + timedelta(
                hours=settings.intelligence_refresh_hours
            )
    return True


def apply_cached_intelligence(db: Session, finding: Finding) -> None:
    _apply_rows(finding, _intel_rows(db, finding.advisory_ids))


def cached_signals(db: Session, advisory_ids: list[str]) -> tuple[bool, float | None]:
    """KEV membership and highest EPSS score cached for any CVE alias."""
    rows = _intel_rows(db, advisory_ids)
    scores = [row.epss_score for row in rows if row.epss_score is not None]
    return any(row.kev_known for row in rows), max(scores, default=None)


def _intel_rows(db: Session, advisory_ids: list[str]) -> list[ThreatIntel]:
    rows: list[ThreatIntel] = []
    for alias in advisory_ids:
        if CVE_PATTERN.fullmatch(alias):
            row = db.get(ThreatIntel, alias.upper())
            if row is not None:
                rows.append(row)
    return rows


def _apply_rows(
    finding: Finding, rows: list[ThreatIntel], updated_at: datetime | None = None
) -> None:
    finding.kev_known = any(row.kev_known for row in rows)
    scores = [row.epss_score for row in rows if row.epss_score is not None]
    finding.epss_score = max(scores, default=None)
    finding.epss_percentile = max(
        (row.epss_percentile for row in rows if row.epss_percentile is not None), default=None
    )
    finding.intel_updated_at = (
        updated_at or max((row.updated_at for row in rows), default=None) if rows else None
    )
