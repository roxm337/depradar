"""Project deletion, retention of old history, and cleanup of stored manifests."""

from datetime import timedelta
from uuid import UUID

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session, aliased

from depradar.application.errors import Conflict
from depradar.application.ports import InventoryStore
from depradar.domain.entities import (
    ApiToken,
    ChangeEvent,
    Delivery,
    FileDeletion,
    Finding,
    FindingDecision,
    Inventory,
    Job,
    Observation,
    OutboxEvent,
    Project,
    Scan,
    SystemState,
    utcnow,
)


def purge_project(db: Session, project: Project) -> None:
    """Delete a project and everything recorded about it; its files are collected later."""
    scans = select(Scan.id).where(Scan.project_id == project.id)
    active_scan = db.scalar(
        select(Job.id)
        .where(Job.scan_id.in_(scans), Job.status == "running", Job.lease_until > utcnow())
        .limit(1)
    )
    active_delivery = db.scalar(
        select(Delivery.id)
        .where(
            Delivery.project_id == project.id,
            Delivery.status == "sending",
            Delivery.lease_until > utcnow(),
        )
        .limit(1)
    )
    batches = list(
        db.scalars(
            select(Delivery.batch_id).where(
                Delivery.project_id == project.id, Delivery.batch_id.is_not(None)
            )
        )
    )
    if batches:
        active_delivery = active_delivery or db.scalar(
            select(Delivery.id)
            .where(
                Delivery.id.in_(batches),
                Delivery.status == "sending",
                Delivery.lease_until > utcnow(),
            )
            .limit(1)
        )
    if active_scan or active_delivery:
        raise Conflict("Wait for in-flight scans or deliveries before deleting this project")
    # Remove aggregate digests that could otherwise retain deleted project details.
    if batches:
        db.execute(delete(Delivery).where(Delivery.id.in_(batches)))
    finding_ids = select(Finding.id).where(Finding.project_id == project.id)
    changes = select(ChangeEvent.id).where(ChangeEvent.finding_id.in_(finding_ids))
    outbox = select(OutboxEvent.id).where(OutboxEvent.change_id.in_(changes))
    db.execute(delete(Delivery).where(Delivery.outbox_id.in_(outbox)))
    db.execute(delete(OutboxEvent).where(OutboxEvent.id.in_(outbox)))
    db.execute(delete(ChangeEvent).where(ChangeEvent.id.in_(changes)))
    db.execute(delete(FindingDecision).where(FindingDecision.finding_id.in_(finding_ids)))
    db.execute(delete(Observation).where(Observation.finding_id.in_(finding_ids)))
    db.execute(delete(Finding).where(Finding.id.in_(finding_ids)))
    db.execute(delete(Job).where(Job.scan_id.in_(scans)))
    db.execute(delete(Scan).where(Scan.id.in_(scans)))
    # Never detach restricted tokens: a token without its project would become unrestricted.
    db.execute(delete(ApiToken).where(ApiToken.project_id == project.id))
    for inventory in db.scalars(select(Inventory).where(Inventory.project_id == project.id)):
        if db.get(FileDeletion, inventory.id) is None:
            db.add(FileDeletion(inventory_id=inventory.id))
        db.delete(inventory)
    db.flush()
    db.delete(project)


def collect_files(db: Session, store: InventoryStore, *, orphans: bool = False) -> int:
    removed = 0
    for record in db.scalars(select(FileDeletion).limit(1000)):
        # Server-generated identifiers only, never a stored relative path.
        if str(UUID(record.inventory_id)) != record.inventory_id:
            continue
        if db.get(Inventory, record.inventory_id) is None:
            store.remove(record.inventory_id)
            db.delete(record)
            removed += 1
    # Recover files left by a process crash between writing the upload and committing its row.
    if orphans:
        for identifier in store.stale(utcnow() - timedelta(days=1)):
            if db.get(Inventory, identifier) is None:
                store.remove(identifier)
                removed += 1
    return removed


def retention(db: Session, store: InventoryStore, state: SystemState) -> dict[str, int]:
    scan_cutoff = utcnow() - timedelta(days=state.scan_retention_days)
    delivery_cutoff = utcnow() - timedelta(days=state.delivery_retention_days)
    parent = aliased(Delivery)
    active_batches = select(parent.id).where(parent.status.in_(["queued", "sending"]))
    db.execute(
        delete(Delivery).where(
            Delivery.created_at < delivery_cutoff,
            Delivery.status.in_(["accepted", "cancelled", "bundled", "failed"]),
            or_(Delivery.batch_id.is_(None), Delivery.batch_id.not_in(active_batches)),
        )
    )
    # Keep event-bearing scans as audit evidence and every inventory's newest scan.
    latest: set[str] = set()
    for scan in db.scalars(select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc())):
        if scan.inventory_id not in latest:
            latest.add(scan.inventory_id)
            continue
        if scan.created_at >= scan_cutoff or scan.status in {"queued", "running"}:
            continue
        if db.scalar(select(ChangeEvent.id).where(ChangeEvent.scan_id == scan.id).limit(1)):
            continue
        db.execute(delete(Observation).where(Observation.scan_id == scan.id))
        db.execute(delete(Job).where(Job.scan_id == scan.id))
        db.delete(scan)
    db.flush()
    newest: set[tuple[str, str]] = set()
    for inventory in db.scalars(
        select(Inventory).order_by(Inventory.created_at.desc(), Inventory.id.desc())
    ):
        # Every monitored manifest keeps its latest snapshot; check uploads are never project state.
        key = (inventory.project_id, inventory.target_path)
        if inventory.kind == "monitor" and key not in newest:
            newest.add(key)
            continue
        if inventory.created_at >= scan_cutoff:
            continue
        scans = list(db.scalars(select(Scan).where(Scan.inventory_id == inventory.id)))
        if any(
            s.status in {"queued", "running"}
            or db.scalar(select(ChangeEvent.id).where(ChangeEvent.scan_id == s.id).limit(1))
            for s in scans
        ):
            continue
        for scan in scans:
            db.execute(delete(Observation).where(Observation.scan_id == scan.id))
            db.execute(delete(Job).where(Job.scan_id == scan.id))
            db.delete(scan)
        db.flush()
        db.add(FileDeletion(inventory_id=inventory.id))
        db.delete(inventory)
    state.last_housekeeping_at = utcnow()
    db.flush()
    return {"files_removed": collect_files(db, store, orphans=True)}


def retention_settings(db: Session) -> SystemState:
    state = db.get(SystemState, 1)
    assert state is not None
    return state


def set_retention(db: Session, scan_days: int, delivery_days: int) -> None:
    state = retention_settings(db)
    state.scan_retention_days = scan_days
    state.delivery_retention_days = delivery_days
    db.commit()


def run_retention(db: Session, store: InventoryStore) -> dict[str, int]:
    result = retention(db, store, retention_settings(db))
    db.commit()
    return result
