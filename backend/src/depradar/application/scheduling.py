"""The worker's periodic pass (scheduled rechecks, risk expiry, alert routing, and cleanup),
and rescans on request that queue the same monitor scans."""

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from depradar.application.components import current_snapshots
from depradar.application.errors import Conflict, Invalid, NotFound
from depradar.application.findings import expire_risks
from depradar.application.housekeeping import collect_files, retention
from depradar.application.locking import lock_writes
from depradar.application.notifications import prepare_digest, route_outbox
from depradar.application.ports import InventoryStore
from depradar.application.projects import get_project
from depradar.application.uploads import queue_scan
from depradar.config import Settings
from depradar.domain.entities import Inventory, Job, Project, Scan, utcnow
from depradar.domain.security import Principal


@dataclass
class Rescan:
    """A manifest's monitor scan: newly queued, or the one already queued or running."""

    inventory: Inventory
    scan: Scan
    queued: bool


def active_scan(db: Session, project_id: str, target_path: str) -> Scan | None:
    """A monitor scan of any snapshot at this path that is still queued or running."""
    return db.scalar(
        select(Scan)
        .join(Inventory, Inventory.id == Scan.inventory_id)
        .join(Job, Job.scan_id == Scan.id)
        .where(
            Scan.project_id == project_id,
            Scan.mode == "monitor",
            Inventory.target_path == target_path,
            Job.status.in_(["queued", "running"]),
        )
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    )


def queue_rescans(db: Session, inventories: list[Inventory]) -> list[Rescan]:
    """Queue a monitor scan of each current snapshot, unless its path already has one active.

    The scheduler and assistant rescans both go through here, so repeated requests never pile
    up jobs for the same manifest. Callers hold the write barrier.
    """
    rescans = []
    for inventory in inventories:
        scan = active_scan(db, inventory.project_id, inventory.target_path)
        queued = scan is None
        rescans.append(Rescan(inventory, scan or queue_scan(db, inventory), queued))
    return rescans


def schedule_projects(db: Session) -> int:
    count = 0
    for project in db.scalars(select(Project).where(Project.monitoring_enabled.is_(True))):
        if project.next_check_at and project.next_check_at > utcnow():
            continue
        # Retired manifests are skipped: the owner retired them, and a new upload resumes them.
        rescans = queue_rescans(db, current_snapshots(db, project.id))
        count += sum(rescan.queued for rescan in rescans)
        # One catch-up check after downtime, never a replay of every missed interval.
        project.next_check_at = utcnow() + timedelta(hours=project.check_interval_hours)
    return count


def rescan(
    db: Session, principal: Principal, project_id: str, inventory_ids: list[str] | None = None
) -> list[Rescan]:
    """Rescan a project's stored monitored manifests now, as the scheduler would.

    Without ``inventory_ids`` every current manifest is rescanned. Only a path's newest snapshot
    that is not retired qualifies; older snapshots, retired manifests, and check inventories are
    refused. Nothing is uploaded, so the content is the snapshot already stored.
    """
    lock_writes(db)
    project = get_project(db, project_id, principal)
    current = {inventory.id: inventory for inventory in current_snapshots(db, project.id)}
    if inventory_ids is None:
        chosen = sorted(current.values(), key=lambda inventory: inventory.target_path)
    else:
        chosen = []
        for inventory_id in dict.fromkeys(inventory_ids):
            inventory = db.get(Inventory, inventory_id)
            if inventory is None or inventory.project_id != project.id:
                raise NotFound("Inventory not found in this project")
            if inventory.kind != "monitor":
                raise Invalid("Check inventories are never rescanned; only monitored manifests")
            if inventory.retired_at is not None:
                raise Conflict("This manifest is retired; upload it again to resume monitoring")
            if inventory.id not in current:
                raise Conflict(
                    "This is an older snapshot; rescan the manifest's current one instead"
                )
            chosen.append(inventory)
    rescans = queue_rescans(db, chosen)
    db.commit()
    return rescans


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
