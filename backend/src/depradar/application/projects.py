"""Projects, their monitoring and alert settings, and the records listed for them."""

from typing import Literal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from depradar.application.errors import Conflict, Forbidden, NotFound
from depradar.application.housekeeping import purge_project
from depradar.domain.entities import Finding, Inventory, Job, Project, Scan, utcnow
from depradar.domain.security import Principal


def get_project(db: Session, project_id: str, principal: Principal | None = None) -> Project:
    project = db.get(Project, project_id)
    # Restricted tokens get the same answer for other projects as for missing ones.
    if project is None or (principal is not None and not principal.allows(project.id)):
        raise NotFound("Project not found")
    return project


def create_project(db: Session, principal: Principal, name: str, description: str) -> Project:
    if principal.project_id:
        raise Forbidden("Project-restricted tokens cannot create projects")
    project = Project(name=name, description=description)
    db.add(project)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise Conflict("Project name already exists") from exc
    return project


def list_projects(
    db: Session, principal: Principal, limit: int, offset: int, name: str | None = None
) -> list[Project]:
    query = select(Project)
    if principal.project_id:
        query = query.where(Project.id == principal.project_id)
    if name is not None:
        query = query.where(Project.name == name.strip())
    return list(
        db.scalars(query.order_by(Project.created_at, Project.id).limit(limit).offset(offset))
    )


def delete_project(db: Session, project_id: str) -> None:
    purge_project(db, get_project(db, project_id))
    db.commit()


def set_monitoring(db: Session, project_id: str, enabled: bool, interval_hours: int) -> Project:
    project = get_project(db, project_id)
    project.monitoring_enabled = enabled
    project.check_interval_hours = interval_hours
    project.next_check_at = utcnow() if enabled else None
    db.commit()
    return project


def set_alerts(db: Session, project_id: str, enabled: bool, min_severity: str) -> Project:
    """Per-project alerts; ``inherit`` follows the global immediate-alert threshold."""
    project = get_project(db, project_id)
    project.notifications_enabled = enabled
    project.alert_min_severity = None if min_severity == "inherit" else min_severity
    db.commit()
    return project


def list_inventories(
    db: Session,
    project_id: str,
    principal: Principal,
    kind: Literal["monitor", "check", "all"],
    limit: int,
    offset: int,
) -> list[Inventory]:
    get_project(db, project_id, principal)
    query = select(Inventory).where(Inventory.project_id == project_id)
    if kind != "all":
        query = query.where(Inventory.kind == kind)
    return list(
        db.scalars(
            query.order_by(Inventory.target_path, Inventory.created_at.desc(), Inventory.id)
            .limit(limit)
            .offset(offset)
        )
    )


def list_scans(
    db: Session, project_id: str, principal: Principal, limit: int, offset: int
) -> list[Scan]:
    get_project(db, project_id, principal)
    return list(
        db.scalars(
            select(Scan)
            .where(Scan.project_id == project_id)
            .order_by(Scan.created_at.desc(), Scan.id)
            .limit(limit)
            .offset(offset)
        )
    )


def get_scan(db: Session, scan_id: str, principal: Principal) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or not principal.allows(scan.project_id):
        raise NotFound("Scan not found")
    return scan


def list_findings(
    db: Session,
    project_id: str,
    principal: Principal,
    status: str | None,
    limit: int,
    offset: int,
) -> list[Finding]:
    get_project(db, project_id, principal)
    query = select(Finding).where(Finding.project_id == project_id)
    if status:
        query = query.where(Finding.status == status)
    return list(
        db.scalars(
            query.order_by(Finding.first_seen_at.desc(), Finding.id).limit(limit).offset(offset)
        )
    )


def list_jobs(db: Session, limit: int, offset: int) -> list[Job]:
    return list(
        db.scalars(
            select(Job).order_by(Job.available_at.desc(), Job.id).limit(limit).offset(offset)
        )
    )
