"""Project deletion, retention of old history, and cleanup of stored manifests."""

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, distinct, func, or_, select, update
from sqlalchemy.orm import Session, aliased

from depradar.application.components import current_snapshots
from depradar.application.errors import Conflict
from depradar.application.notifications import rebuild_digest
from depradar.application.ports import InventoryStore
from depradar.domain.entities import (
    ApiToken,
    AuditEvent,
    ChangeEvent,
    ComponentOccurrence,
    Delivery,
    FileDeletion,
    Finding,
    FindingDecision,
    GateDecision,
    Inventory,
    Job,
    Observation,
    OutboxEvent,
    Project,
    Scan,
    SecurityPolicy,
    SystemState,
    TrustedIdentity,
    utcnow,
)


def purge_project(db: Session, project: Project, dashboard_url: str = "") -> None:
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
    # A digest bundles alerts from several projects. An unsent digest keeps the other
    # projects' alerts and is re-rendered without this one. A sent or terminal digest is
    # removed so its text cannot retain deleted details; its other children are not replayed.
    unsent: list[Delivery] = []
    for digest in db.scalars(select(Delivery).where(Delivery.id.in_(set(batches)))):
        survivor = db.scalar(
            select(Delivery.id)
            .where(Delivery.batch_id == digest.id, Delivery.project_id != project.id)
            .limit(1)
        )
        if survivor and digest.status in {"queued", "sending"}:
            unsent.append(digest)
            continue
        db.execute(update(Delivery).where(Delivery.batch_id == digest.id).values(batch_id=None))
        db.execute(delete(Delivery).where(Delivery.id == digest.id))
    finding_ids = select(Finding.id).where(Finding.project_id == project.id)
    changes = select(ChangeEvent.id).where(ChangeEvent.finding_id.in_(finding_ids))
    outbox = select(OutboxEvent.id).where(OutboxEvent.change_id.in_(changes))
    db.execute(delete(Delivery).where(Delivery.outbox_id.in_(outbox)))
    db.execute(delete(OutboxEvent).where(OutboxEvent.id.in_(outbox)))
    db.execute(delete(ChangeEvent).where(ChangeEvent.id.in_(changes)))
    db.execute(delete(FindingDecision).where(FindingDecision.finding_id.in_(finding_ids)))
    db.execute(delete(Observation).where(Observation.finding_id.in_(finding_ids)))
    db.execute(delete(Finding).where(Finding.id.in_(finding_ids)))
    db.execute(delete(ComponentOccurrence).where(ComponentOccurrence.project_id == project.id))
    db.execute(delete(Job).where(Job.scan_id.in_(scans)))
    db.execute(delete(Scan).where(Scan.id.in_(scans)))
    # Never detach restricted tokens: a token without its project would become unrestricted.
    db.execute(delete(ApiToken).where(ApiToken.project_id == project.id))
    db.execute(delete(TrustedIdentity).where(TrustedIdentity.project_id == project.id))
    db.execute(delete(SecurityPolicy).where(SecurityPolicy.project_id == project.id))
    db.execute(delete(GateDecision).where(GateDecision.project_id == project.id))
    for inventory in db.scalars(select(Inventory).where(Inventory.project_id == project.id)):
        if db.get(FileDeletion, inventory.id) is None:
            db.add(FileDeletion(inventory_id=inventory.id))
        db.delete(inventory)
    db.flush()
    for digest in unsent:
        rebuild_digest(db, digest, dashboard_url)
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
    # Search reads only each manifest's current snapshot, so older and retired snapshots drop
    # their package lists now, even when their scans and inventory stay as audit evidence.
    current = {inventory.id for inventory in current_snapshots(db)}
    indexed = set(db.scalars(select(distinct(ComponentOccurrence.inventory_id))))
    for inventory_id in indexed - current:
        db.execute(
            delete(ComponentOccurrence).where(ComponentOccurrence.inventory_id == inventory_id)
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
        # A failed rescan can be newer than the scan that indexed the snapshot's packages.
        if db.scalar(
            select(ComponentOccurrence.id).where(ComponentOccurrence.scan_id == scan.id).limit(1)
        ):
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
            # A retired manifest's last snapshot ages out like any other history.
            if inventory.retired_at is None:
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
        db.execute(
            delete(ComponentOccurrence).where(ComponentOccurrence.inventory_id == inventory.id)
        )
        for scan in scans:
            db.execute(delete(Observation).where(Observation.scan_id == scan.id))
            db.execute(delete(Job).where(Job.scan_id == scan.id))
            db.delete(scan)
        db.flush()
        db.add(FileDeletion(inventory_id=inventory.id))
        db.delete(inventory)
    prune_decisions(db, scan_cutoff)
    db.execute(
        delete(AuditEvent).where(
            AuditEvent.created_at < utcnow() - timedelta(days=state.audit_retention_days)
        )
    )
    # Exchanged identity tokens live 30 minutes; keep a day for troubleshooting, then drop them.
    db.execute(
        delete(ApiToken).where(
            ApiToken.kind == "identity", ApiToken.expires_at < utcnow() - timedelta(days=1)
        )
    )
    state.last_housekeeping_at = utcnow()
    db.flush()
    return {"files_removed": collect_files(db, store, orphans=True)}


def prune_decisions(db: Session, cutoff: datetime) -> None:
    """Gate decisions follow scan retention; each project keeps its most recent decision."""
    newest = (
        select(GateDecision.project_id, func.max(GateDecision.created_at).label("latest"))
        .group_by(GateDecision.project_id)
        .subquery()
    )
    kept = select(GateDecision.id).join(
        newest,
        (GateDecision.project_id == newest.c.project_id)
        & (GateDecision.created_at == newest.c.latest),
    )
    db.execute(
        delete(GateDecision).where(GateDecision.created_at < cutoff, GateDecision.id.not_in(kept))
    )


def retention_settings(db: Session) -> SystemState:
    state = db.get(SystemState, 1)
    assert state is not None
    return state


def set_retention(
    db: Session, scan_days: int, delivery_days: int, audit_days: int | None = None
) -> None:
    state = retention_settings(db)
    state.scan_retention_days = scan_days
    state.delivery_retention_days = delivery_days
    if audit_days is not None:
        state.audit_retention_days = audit_days
    db.commit()


def run_retention(db: Session, store: InventoryStore) -> dict[str, int]:
    result = retention(db, store, retention_settings(db))
    db.commit()
    return result
