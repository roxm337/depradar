"""Accept manifests from the dashboard and pipelines, store them, and queue their scans."""

import hashlib
from datetime import timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from depradar.application.errors import Forbidden, Invalid, NotFound
from depradar.application.locking import lock_writes
from depradar.application.ports import InventoryStore
from depradar.application.projects import get_project
from depradar.domain.entities import Inventory, Job, Project, Scan, new_id, utcnow
from depradar.domain.inventory import (
    InventoryError,
    canonical_filename,
    canonical_revision,
    canonical_target_path,
    default_target,
    validate_inventory,
)
from depradar.domain.security import Principal


def manifest_target(
    filename: str, target_path: str | None, revision: str | None
) -> tuple[str, str, str | None]:
    """Canonical filename, repository path, and revision of an uploaded manifest."""
    try:
        canonical = canonical_filename(filename)
        target = canonical_target_path(target_path, default_target(filename, canonical))
        return canonical, target, canonical_revision(revision)
    except InventoryError as exc:
        raise Invalid(str(exc)) from exc


def queue_scan(db: Session, inventory: Inventory, notes: list[str] | None = None) -> Scan:
    scan = Scan(
        id=new_id(),
        project_id=inventory.project_id,
        inventory_id=inventory.id,
        mode=inventory.kind,
        coverage_notes=notes or [],
    )
    db.add(scan)
    db.flush()
    db.add(Job(scan_id=scan.id))
    return scan


def reusable_inventory(
    db: Session, project_id: str, target_path: str, kind: str, sha256: str
) -> Inventory | None:
    """Unchanged CI uploads recheck the stored snapshot instead of storing another copy.

    Monitored manifests compare with the latest snapshot only, so restoring older content still
    becomes the new project state. Check uploads may reuse any stored snapshot of the manifest.
    """
    query = select(Inventory).where(
        Inventory.project_id == project_id,
        Inventory.target_path == target_path,
        Inventory.kind == kind,
    )
    if kind == "check":
        query = query.where(Inventory.sha256 == sha256)
    latest = db.scalar(query.order_by(Inventory.created_at.desc(), Inventory.id.desc()).limit(1))
    return latest if latest is not None and latest.sha256 == sha256 else None


def store_inventory(
    db: Session,
    store: InventoryStore,
    project: Project,
    filename: str,
    target_path: str,
    revision: str | None,
    content: bytes,
    *,
    kind: str = "monitor",
    reuse: bool = False,
) -> tuple[Inventory, Scan, bool]:
    """Callers hold the write barrier; this commits and returns (inventory, scan, reused)."""
    try:
        notes = validate_inventory(filename, content)
    except InventoryError as exc:
        raise Invalid(str(exc)) from exc
    sha256 = hashlib.sha256(content).hexdigest()
    existing = reusable_inventory(db, project.id, target_path, kind, sha256) if reuse else None
    if existing is not None and existing.filename == filename:
        active = db.scalar(
            select(Scan)
            .join(Job, Job.scan_id == Scan.id)
            .where(Scan.inventory_id == existing.id, Job.status.in_(["queued", "running"]))
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        scan = active or queue_scan(db, existing, notes)
        db.commit()
        return existing, scan, True
    inventory = Inventory(
        id=new_id(),
        project_id=project.id,
        filename=filename,
        target_path=target_path,
        revision=revision,
        sha256=sha256,
        size_bytes=len(content),
        kind=kind,
    )
    # Stored under the server-generated ID only: the supplied filename is never a storage path.
    try:
        store.save(inventory.id, content)
        db.add(inventory)
        db.flush()
        scan = queue_scan(db, inventory, notes)
        db.commit()
    except Exception:
        db.rollback()
        store.remove(inventory.id)
        raise
    return inventory, scan, False


def upload_inventory(
    db: Session,
    store: InventoryStore,
    principal: Principal,
    project_id: str,
    filename: str,
    target_path: str,
    revision: str | None,
    content: bytes,
) -> tuple[Inventory, Scan]:
    lock_writes(db)
    # Re-read under the barrier: the project may have been deleted during the upload.
    project = get_project(db, project_id, principal)
    inventory, scan, _ = store_inventory(
        db, store, project, filename, target_path, revision, content
    )
    return inventory, scan


def recheck(db: Session, principal: Principal, inventory_id: str) -> Scan:
    inventory = db.get(Inventory, inventory_id)
    if inventory is None or not principal.allows(inventory.project_id):
        raise NotFound("Inventory not found")
    scan = queue_scan(db, inventory)
    db.commit()
    return scan


def require_project_creation(principal: Principal) -> None:
    if "projects:write" not in principal.scopes or principal.project_id:
        raise Forbidden("Creating projects requires an unrestricted token with projects:write")


def resolve_project(
    db: Session, principal: Principal, reference: str, create: bool
) -> tuple[Project, bool]:
    """Find a project by ID or exact name; callers hold the write barrier for creation."""
    reference = reference.strip()
    if not reference:
        raise Invalid("Project name or ID is required")
    record = None
    try:
        record = db.get(Project, str(UUID(reference)))
    except ValueError:
        pass
    record = record or db.scalar(select(Project).where(Project.name == reference))
    if record is not None and principal.allows(record.id):
        return record, False
    if record is not None or not create:
        raise NotFound("Project not found. Create it in DepRadar or pass create_project=true")
    # Pipelines exist to keep inventories current, so new CI projects are monitored daily.
    record = Project(
        name=reference,
        description="Created by a CI/CD pipeline",
        monitoring_enabled=True,
        check_interval_hours=24,
        next_check_at=utcnow() + timedelta(hours=24),
    )
    db.add(record)
    db.flush()
    return record, True


def pipeline_upload(
    db: Session,
    store: InventoryStore,
    principal: Principal,
    reference: str,
    create: bool,
    filename: str,
    target_path: str,
    revision: str | None,
    content: bytes,
    mode: str,
) -> tuple[Project, bool, Inventory, Scan, bool]:
    """Returns (project, project created, inventory, scan, inventory reused)."""
    lock_writes(db)
    project, created = resolve_project(db, principal, reference, create)
    inventory, scan, reused = store_inventory(
        db, store, project, filename, target_path, revision, content, kind=mode, reuse=True
    )
    return project, created, inventory, scan, reused
