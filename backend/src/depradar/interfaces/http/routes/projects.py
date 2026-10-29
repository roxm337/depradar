"""Projects, their manifests, scans, and findings, for the dashboard and automation clients."""

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from depradar.application import projects, uploads
from depradar.domain.entities import Finding, Inventory, Project, Scan
from depradar.interfaces.http.dependencies import (
    Config,
    Db,
    ReadFindings,
    ReadProjects,
    ReadScans,
    Store,
    UploadInventories,
    WriteInventories,
    WriteProjects,
    read_limited,
    require_session,
)
from depradar.interfaces.http.schemas import (
    FindingOutput,
    InventoryOutput,
    MonitoringInput,
    ProjectInput,
    ProjectNotificationInput,
    ProjectNotificationOutput,
    ProjectOutput,
    ScanOutput,
    UploadOutput,
)

# Owner session or a scoped API token; each endpoint declares the scope it needs.
router = APIRouter(prefix="/api")
owner = APIRouter(prefix="/api", dependencies=[Depends(require_session)])
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]


@router.post("/projects", response_model=ProjectOutput, status_code=201)
def create_project(body: ProjectInput, db: Db, principal: WriteProjects) -> Project:
    return projects.create_project(db, principal, body.name, body.description)


@router.get("/projects", response_model=list[ProjectOutput])
def list_projects(
    db: Db,
    principal: ReadProjects,
    limit: Limit = 50,
    offset: Offset = 0,
    name: Annotated[str | None, Query(min_length=1, max_length=120)] = None,
) -> list[Project]:
    return projects.list_projects(db, principal, limit, offset, name)


@router.get("/projects/{project_id}", response_model=ProjectOutput)
def project_detail(project_id: UUID, db: Db, principal: ReadProjects) -> Project:
    return projects.get_project(db, str(project_id), principal)


@router.get("/projects/{project_id}/inventories", response_model=list[InventoryOutput])
def inventories(
    project_id: UUID,
    db: Db,
    principal: ReadProjects,
    limit: Limit = 50,
    offset: Offset = 0,
    kind: Literal["monitor", "check", "all"] = "monitor",
) -> list[Inventory]:
    return projects.list_inventories(db, str(project_id), principal, kind, limit, offset)


@router.post("/projects/{project_id}/inventories", response_model=UploadOutput, status_code=202)
async def upload(
    project_id: UUID,
    filename: str,
    request: Request,
    db: Db,
    settings: Config,
    store: Store,
    principal: UploadInventories,
    target_path: Annotated[str | None, Query(max_length=512)] = None,
    revision: Annotated[str | None, Query(max_length=200)] = None,
) -> UploadOutput:
    projects.get_project(db, str(project_id), principal)
    filename, target, revision = uploads.manifest_target(filename, target_path, revision)
    content = await read_limited(request, settings.upload_limit_bytes)
    inventory, scan = uploads.upload_inventory(
        db, store, principal, str(project_id), filename, target, revision, content
    )
    return UploadOutput(
        inventory=InventoryOutput.model_validate(inventory), scan=ScanOutput.model_validate(scan)
    )


@router.post("/inventories/{inventory_id}/scans", response_model=ScanOutput, status_code=202)
def recheck(inventory_id: UUID, db: Db, principal: WriteInventories) -> Scan:
    return uploads.recheck(db, principal, str(inventory_id))


@router.get("/projects/{project_id}/scans", response_model=list[ScanOutput])
def scans(
    project_id: UUID, db: Db, principal: ReadScans, limit: Limit = 50, offset: Offset = 0
) -> list[Scan]:
    return projects.list_scans(db, str(project_id), principal, limit, offset)


@router.get("/scans/{scan_id}", response_model=ScanOutput)
def scan_detail(scan_id: UUID, db: Db, principal: ReadScans) -> Scan:
    return projects.get_scan(db, str(scan_id), principal)


@router.get("/projects/{project_id}/findings", response_model=list[FindingOutput])
def findings(
    project_id: UUID,
    db: Db,
    principal: ReadFindings,
    status: Annotated[str | None, Query(pattern="^(open|resolved)$")] = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> list[Finding]:
    return projects.list_findings(db, str(project_id), principal, status, limit, offset)


@owner.delete("/projects/{project_id}", status_code=204)
def remove_project(project_id: UUID, db: Db) -> None:
    projects.delete_project(db, str(project_id))


@owner.put("/projects/{project_id}/monitoring")
def monitoring(project_id: UUID, body: MonitoringInput, db: Db) -> dict[str, Any]:
    project = projects.set_monitoring(db, str(project_id), body.enabled, body.interval_hours)
    return {
        "enabled": project.monitoring_enabled,
        "interval_hours": project.check_interval_hours,
        "next_check_at": project.next_check_at,
    }


def alert_settings(project: Project) -> dict[str, Any]:
    return {
        "enabled": project.notifications_enabled,
        "immediate_min_severity": project.alert_min_severity,
    }


@owner.get("/projects/{project_id}/notifications", response_model=ProjectNotificationOutput)
def get_project_notifications(project_id: UUID, db: Db) -> dict[str, Any]:
    return alert_settings(projects.get_project(db, str(project_id)))


@owner.put("/projects/{project_id}/notifications", response_model=ProjectNotificationOutput)
def set_project_notifications(
    project_id: UUID, body: ProjectNotificationInput, db: Db
) -> dict[str, Any]:
    project = projects.set_alerts(db, str(project_id), body.enabled, body.immediate_min_severity)
    return alert_settings(project)
