"""Search which projects use a package, across every current monitored manifest."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from depradar.application import components
from depradar.domain.entities import Scan
from depradar.interfaces.http.dependencies import Db, require_session
from depradar.interfaces.http.schemas import (
    ComponentCoverageOutput,
    ComponentIndexOutput,
    ComponentMatchOutput,
    ComponentSearchOutput,
    ComponentSnapshotOutput,
    PartialSnapshotOutput,
)

router = APIRouter(prefix="/api/components", dependencies=[Depends(require_session)])


def snapshot_output(snapshot: components.Snapshot) -> ComponentSnapshotOutput:
    inventory = snapshot.inventory
    return ComponentSnapshotOutput(
        project_id=snapshot.project.id,
        project_name=snapshot.project.name,
        inventory_id=inventory.id,
        filename=inventory.filename,
        target_path=inventory.target_path,
        revision=inventory.revision,
        uploaded_at=inventory.created_at,
    )


def index_output(scan: Scan) -> ComponentIndexOutput:
    return ComponentIndexOutput(
        scan_id=scan.id,
        status=scan.status,
        complete=scan.complete,
        completed_at=scan.completed_at,
        coverage_notes=scan.coverage_notes,
    )


def coverage_output(coverage: components.Coverage) -> ComponentCoverageOutput:
    partial = []
    for snapshot in coverage.partial:
        assert snapshot.scan is not None
        partial.append(
            PartialSnapshotOutput(
                **snapshot_output(snapshot).model_dump(), indexed_by=index_output(snapshot.scan)
            )
        )
    return ComponentCoverageOutput(
        snapshots=len(coverage.snapshots),
        indexed=len(coverage.snapshots) - len(coverage.not_indexed),
        ecosystems=coverage.ecosystems,
        not_indexed=[snapshot_output(snapshot) for snapshot in coverage.not_indexed],
        partial=partial,
    )


@router.get("/coverage", response_model=ComponentCoverageOutput)
def index_coverage(db: Db) -> ComponentCoverageOutput:
    return coverage_output(components.coverage(db))


@router.get("", response_model=ComponentSearchOutput)
def search(
    db: Db,
    name: Annotated[str, Query(min_length=1, max_length=512)],
    ecosystem: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    version: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
) -> ComponentSearchOutput:
    name = name.strip()
    result = components.search(db, name, ecosystem, version)
    matches = []
    for match in result.matches:
        assert match.snapshot.scan is not None
        row = match.occurrence
        matches.append(
            ComponentMatchOutput(
                ecosystem=row.ecosystem,
                name=row.name,
                version=row.version,
                purl=row.purl,
                snapshot=snapshot_output(match.snapshot),
                indexed_by=index_output(match.snapshot.scan),
                open_findings=match.open_findings,
            )
        )
    return ComponentSearchOutput(
        name=name,
        ecosystem=ecosystem,
        version=version,
        matches=matches,
        truncated=result.truncated,
        coverage=coverage_output(result.coverage),
    )
