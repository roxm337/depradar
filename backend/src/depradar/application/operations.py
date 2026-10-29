"""Service health: readiness, queue depth, and worker and scanner heartbeats."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from depradar.application.errors import Unavailable
from depradar.application.ports import ScannerProbe
from depradar.domain.entities import Delivery, Job, Project, SystemState, utcnow


@dataclass(frozen=True)
class Health:
    database: str
    worker: str
    worker_heartbeat_at: datetime | None
    scanner: str
    scanner_checked_at: datetime | None
    queued_jobs: int
    running_jobs: int
    failed_jobs: int
    oldest_queued_job_at: datetime | None
    due_projects: int
    queued_deliveries: int
    failed_deliveries: int
    intelligence_updated_at: datetime | None


def check_ready(db: Session) -> None:
    try:
        db.execute(text("SELECT id FROM system_state WHERE id = 1")).scalar_one()
    except SQLAlchemyError as exc:
        raise Unavailable("Database unavailable or migrations pending") from exc


def health(db: Session) -> Health:
    state = db.get(SystemState, 1)
    assert state is not None
    now = utcnow()
    jobs_by_status = {
        status: count
        for status, count in db.execute(select(Job.status, func.count()).group_by(Job.status)).all()
    }
    deliveries_by_status = {
        status: count
        for status, count in db.execute(
            select(Delivery.status, func.count()).group_by(Delivery.status)
        ).all()
    }
    oldest_queued = db.scalar(select(func.min(Job.available_at)).where(Job.status == "queued"))
    due_projects = (
        db.scalar(
            select(func.count())
            .select_from(Project)
            .where(
                Project.monitoring_enabled.is_(True),
                Project.next_check_at.is_not(None),
                Project.next_check_at <= now,
            )
        )
        or 0
    )
    worker_fresh = bool(
        state.last_worker_heartbeat_at
        and state.last_worker_heartbeat_at >= now - timedelta(seconds=45)
    )
    scanner_fresh = bool(
        state.last_scanner_check_at and state.last_scanner_check_at >= now - timedelta(seconds=90)
    )
    return Health(
        database="ready",
        worker="healthy" if worker_fresh else "stale",
        worker_heartbeat_at=state.last_worker_heartbeat_at,
        scanner=("healthy" if state.scanner_available else "unavailable")
        if scanner_fresh
        else "stale",
        scanner_checked_at=state.last_scanner_check_at,
        queued_jobs=jobs_by_status.get("queued", 0),
        running_jobs=jobs_by_status.get("running", 0),
        failed_jobs=jobs_by_status.get("failed", 0),
        oldest_queued_job_at=oldest_queued,
        due_projects=due_projects,
        queued_deliveries=deliveries_by_status.get("queued", 0)
        + deliveries_by_status.get("sending", 0),
        failed_deliveries=deliveries_by_status.get("failed", 0),
        intelligence_updated_at=state.last_intelligence_refresh_at,
    )


def update_worker_health(factory: sessionmaker[Session], probe: ScannerProbe) -> None:
    now = utcnow()
    should_probe = False
    with factory.begin() as db:
        state = db.get(SystemState, 1)
        if state is None:
            return
        if not state.last_worker_heartbeat_at or state.last_worker_heartbeat_at < now - timedelta(
            seconds=15
        ):
            state.last_worker_heartbeat_at = now
        should_probe = (
            state.last_scanner_check_at is None
            or state.last_scanner_check_at < now - timedelta(seconds=30)
        )
    if not should_probe:
        return
    available = probe()
    with factory.begin() as db:
        state = db.get(SystemState, 1)
        if state is not None:
            state.scanner_available = available
            state.last_scanner_check_at = utcnow()
