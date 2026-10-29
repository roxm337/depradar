"""The worker's periodic pass: scheduled rechecks, risk expiry, alert routing, and cleanup."""

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from depradar.application.findings import expire_risks
from depradar.application.housekeeping import collect_files, retention
from depradar.application.locking import lock_writes
from depradar.application.notifications import prepare_digest, route_outbox
from depradar.application.ports import InventoryStore
from depradar.config import Settings
from depradar.domain.entities import Inventory, Job, Project, Scan, utcnow


def schedule_projects(db: Session) -> int:
    count = 0
    for project in db.scalars(select(Project).where(Project.monitoring_enabled.is_(True))):
        if project.next_check_at and project.next_check_at > utcnow():
            continue
        target_paths: set[str] = set()
        for inventory in db.scalars(
            select(Inventory)
            .where(Inventory.project_id == project.id, Inventory.kind == "monitor")
            .order_by(Inventory.created_at.desc(), Inventory.id.desc())
        ):
            if inventory.target_path in target_paths:
                continue
            target_paths.add(inventory.target_path)
            active = db.scalar(
                select(Scan.id)
                .join(Inventory)
                .join(Job, Job.scan_id == Scan.id)
                .where(
                    Scan.project_id == project.id,
                    Scan.mode == "monitor",
                    Inventory.target_path == inventory.target_path,
                    Job.status.in_(["queued", "running"]),
                )
                .limit(1)
            )
            if active:
                continue
            scan = Scan(project_id=project.id, inventory_id=inventory.id)
            db.add(scan)
            db.flush()
            db.add(Job(scan_id=scan.id))
            count += 1
        # One catch-up check after downtime, never a replay of every missed interval.
        project.next_check_at = utcnow() + timedelta(hours=project.check_interval_hours)
    return count


def tick(
    factory: sessionmaker[Session], settings: Settings, store: InventoryStore
) -> dict[str, int]:
    with factory.begin() as db:
        state = lock_writes(db)
        scheduled = schedule_projects(db)
        expired = expire_risks(db)
        routed = route_outbox(db, settings)
        db.flush()
        prepare_digest(db, settings)
        files = collect_files(db, store)
        if not state.last_housekeeping_at or state.last_housekeeping_at < utcnow() - timedelta(
            days=1
        ):
            retention(db, store, state)
        return {
            "scheduled": scheduled,
            "expired": expired,
            "routed": routed,
            "files_removed": files,
        }
