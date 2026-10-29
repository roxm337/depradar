"""CI/CD automation API: pipeline uploads, policy gate evaluation, and the CI client."""

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from depradar import ci_client
from depradar.application import gates, uploads
from depradar.application.ports import InventoryStore
from depradar.domain.gate import GatePolicy, GateResult, ScanGate
from depradar.interfaces.http.dependencies import (
    Config,
    Db,
    ReadScans,
    Store,
    UploadInventories,
    read_limited,
)
from depradar.interfaces.http.reports import (
    LineFinder,
    LineIndex,
    render_junit,
    render_markdown,
    render_sarif,
)
from depradar.interfaces.http.schemas import (
    CiUploadOutput,
    EvaluationQuery,
    InventoryOutput,
    ProjectOutput,
    ScanOutput,
)

router = APIRouter(prefix="/api/ci")
CLIENT = Path(ci_client.__file__)


@router.post("/uploads", response_model=CiUploadOutput, status_code=202)
async def ci_upload(
    request: Request,
    db: Db,
    settings: Config,
    store: Store,
    principal: UploadInventories,
    project: Annotated[str, Query(min_length=1, max_length=120)],
    filename: Annotated[str, Query(min_length=1, max_length=120)],
    target_path: Annotated[str | None, Query(max_length=512)] = None,
    revision: Annotated[str | None, Query(max_length=200)] = None,
    mode: Literal["monitor", "check"] = "monitor",
    create_project: bool = False,
) -> CiUploadOutput:
    """Upload one manifest from a pipeline. Unchanged content rechecks the stored snapshot.

    `monitor` uploads become the project's monitored state and drive alerts. `check` uploads
    (pull/merge requests) are evaluated for the gate only and never change findings.
    """
    filename, target, revision = uploads.manifest_target(filename, target_path, revision)
    if create_project:
        uploads.require_project_creation(principal)
    content = await read_limited(request, settings.upload_limit_bytes)
    record, created, inventory, scan, reused = uploads.pipeline_upload(
        db, store, principal, project, create_project, filename, target, revision, content, mode
    )
    return CiUploadOutput(
        project=ProjectOutput.model_validate(record),
        inventory=InventoryOutput.model_validate(inventory),
        scan=ScanOutput.model_validate(scan),
        project_created=created,
        reused_inventory=reused,
    )


def line_finder(db: Session, store: InventoryStore) -> Callable[[ScanGate], LineFinder]:
    def for_gate(gate: ScanGate) -> LineFinder:
        content = gates.scanned_manifest(db, store, gate.scan_id)
        return LineIndex(content).line_for if content is not None else (lambda item: 1)

    return for_gate


@router.get(
    "/evaluation",
    response_model=GateResult,
    responses={
        200: {
            "content": {
                "application/sarif+json": {},
                "application/xml": {},
                "text/markdown": {},
            }
        },
        409: {"description": "A scan has not finished yet"},
    },
)
def evaluation(
    query: Annotated[EvaluationQuery, Query()],
    db: Db,
    store: Store,
    principal: ReadScans,
) -> Response:
    """Evaluate finished scans against a gate policy, as JSON, SARIF, JUnit, or Markdown."""
    scans = gates.scans_for(db, principal, [str(value) for value in query.scan_id])
    policy = GatePolicy.model_validate(query.model_dump(exclude={"scan_id", "format"}))
    result = gates.evaluate(db, scans, policy)
    if query.format == "sarif":
        sarif = render_sarif(result, line_finder(db, store))
        return Response(sarif, media_type="application/sarif+json")
    if query.format == "junit":
        return Response(render_junit(result), media_type="application/xml")
    if query.format == "markdown":
        return Response(render_markdown(result), media_type="text/markdown; charset=utf-8")
    return JSONResponse(result.model_dump(mode="json"))


@router.get("/client.py")
def client_script() -> Response:
    """Standard-library CI client matching this server's API. Compare its SHA-256 to pin it."""
    content = CLIENT.read_bytes()
    return Response(
        content,
        media_type="text/x-python; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="depradar_ci.py"',
            "X-Content-SHA256": hashlib.sha256(content).hexdigest(),
        },
    )
