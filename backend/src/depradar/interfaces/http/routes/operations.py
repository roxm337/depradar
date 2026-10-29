"""Health checks, the job queue, service health, and history retention."""

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from depradar.application import housekeeping, operations, projects
from depradar.domain.entities import Job
from depradar.interfaces.http.dependencies import Db, Store, require_session
from depradar.interfaces.http.schemas import JobOutput, OperationsHealth, RetentionInput

probes = APIRouter(prefix="/health")
router = APIRouter(prefix="/api", dependencies=[Depends(require_session)])


@probes.get("/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@probes.get("/ready")
def ready(db: Db) -> dict[str, str]:
    operations.check_ready(db)
    return {"status": "ready"}


@router.get("/jobs", response_model=list[JobOutput])
def jobs(
    db: Db,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Job]:
    return projects.list_jobs(db, limit, offset)


@router.get("/operations/health", response_model=OperationsHealth)
def operations_health(db: Db) -> OperationsHealth:
    return OperationsHealth(**asdict(operations.health(db)))


@router.put("/maintenance/retention", response_model=RetentionInput)
def set_retention(body: RetentionInput, db: Db) -> RetentionInput:
    housekeeping.set_retention(db, body.scan_days, body.delivery_days)
    return body


@router.get("/maintenance/retention", response_model=RetentionInput)
def get_retention(db: Db) -> RetentionInput:
    state = housekeeping.retention_settings(db)
    return RetentionInput(
        scan_days=state.scan_retention_days, delivery_days=state.delivery_retention_days
    )


@router.post("/maintenance/retention/run")
def run_retention(db: Db, store: Store) -> dict[str, int]:
    return housekeeping.run_retention(db, store)
