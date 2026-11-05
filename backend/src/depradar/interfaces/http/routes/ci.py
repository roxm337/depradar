"""CI/CD automation API: pipeline uploads, recorded gate decisions, OIDC, and the CI client."""

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from depradar import ci_client
from depradar.application import decisions, gates, identities, uploads
from depradar.application.ports import InventoryStore
from depradar.domain.entities import GateDecision
from depradar.domain.gate import GatePolicy, GateResult, ScanGate
from depradar.interfaces.http.dependencies import (
    Config,
    Db,
    PipelineUpload,
    ReadScans,
    Store,
    Verifier,
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
    DecisionDetail,
    DecisionRequest,
    DecisionSummary,
    EvaluationQuery,
    ExchangeInput,
    ExchangeOutput,
    InventoryOutput,
    OidcConfigOutput,
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
    principal: PipelineUpload,
    project: Annotated[str, Query(min_length=1, max_length=120)],
    filename: Annotated[str, Query(min_length=1, max_length=120)],
    target_path: Annotated[str | None, Query(max_length=512)] = None,
    revision: Annotated[str | None, Query(max_length=200)] = None,
    mode: Literal["monitor", "check"] = "monitor",
    create_project: bool = False,
) -> CiUploadOutput:
    """Upload one manifest from a pipeline. Unchanged content rechecks the stored snapshot.

    `monitor` uploads become the project's monitored state and drive alerts and need
    `inventories:write`. `check` uploads (pull/merge requests) are evaluated for the gate only,
    never change findings, and also accept `inventories:check`. Runs authenticated through a
    trusted OIDC identity are labelled with their verified branch and commit.
    """
    uploads.require_upload(principal, mode)
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
    """Preview a gate without recording it, as JSON, SARIF, JUnit, or Markdown.

    Central policies apply exactly as they do to recorded decisions. Pipelines should record
    their decision with POST /api/ci/decisions instead, so it is auditable.
    """
    scans = gates.scans_for(db, principal, [str(value) for value in query.scan_id])
    policy = GatePolicy.model_validate(query.model_dump(exclude={"scan_id", "format"}))
    return rendered(gates.evaluate(db, scans, policy), query.format, db, store)


Format = Literal["json", "sarif", "junit", "markdown"]


def rendered(result: GateResult, fmt: Format, db: Session, store: InventoryStore) -> Response:
    if fmt == "sarif":
        sarif = render_sarif(result, line_finder(db, store))
        return Response(sarif, media_type="application/sarif+json")
    if fmt == "junit":
        return Response(render_junit(result), media_type="application/xml")
    if fmt == "markdown":
        return Response(render_markdown(result), media_type="text/markdown; charset=utf-8")
    return JSONResponse(result.model_dump(mode="json"))


@router.post(
    "/decisions",
    response_model=GateResult,
    status_code=201,
    responses={409: {"description": "A scan has not finished yet"}},
)
def record_decision(body: DecisionRequest, db: Db, principal: ReadScans) -> GateResult:
    """Decide the gate for one project's finished scans under central policy, and record it.

    The response carries `decision_id`; fetch reports with GET /api/ci/decisions/{id}.
    """
    return decisions.record(db, principal, [str(value) for value in body.scan_ids], body.policy)


def summary_fields(decision: GateDecision, project_name: str) -> dict[str, object]:
    result = decision.result
    return {
        "id": decision.id,
        "created_at": decision.created_at,
        "status": decision.status,
        "project_id": decision.project_id,
        "project_name": project_name,
        "revision": decision.revision,
        "commit": decision.commit,
        "mode": decision.mode,
        "violations": decision.violations,
        "ignored": decision.ignored,
        "below_threshold": decision.below_threshold,
        "missing_manifests": len(result.get("missing_manifests", [])),
        "actor": decision.actor,
        "policy_sources": result.get("policy_sources", []),
        "adjustments": len(result.get("adjustments", [])),
    }


@router.get("/decisions", response_model=list[DecisionSummary])
def list_decisions(
    db: Db,
    principal: ReadScans,
    project_id: UUID | None = None,
    status: Literal["pass", "fail", "error"] | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[DecisionSummary]:
    """Recorded gate decisions, newest first."""
    rows = decisions.list_decisions(
        db, principal, str(project_id) if project_id else None, status, limit, offset
    )
    names = decisions.project_names(db, rows)
    return [
        DecisionSummary.model_validate(summary_fields(row, names.get(row.project_id, "")))
        for row in rows
    ]


@router.get(
    "/decisions/{decision_id}",
    response_model=DecisionDetail,
    responses={
        200: {
            "content": {
                "application/sarif+json": {},
                "application/xml": {},
                "text/markdown": {},
            }
        }
    },
)
def get_decision(
    decision_id: UUID,
    db: Db,
    store: Store,
    principal: ReadScans,
    format: Format = "json",
) -> Response:
    """One recorded decision with its evidence, or its report rendered from the stored result."""
    decision = decisions.get_decision(db, principal, str(decision_id))
    if format != "json":
        return rendered(decisions.stored_result(decision), format, db, store)
    names = decisions.project_names(db, [decision])
    detail = DecisionDetail.model_validate(
        {
            **summary_fields(decision, names.get(decision.project_id, "")),
            "inputs": decision.inputs,
            "exceptions": decision.exceptions,
            "intelligence_updated_at": decision.intelligence_updated_at,
            "result": decision.result,
        }
    )
    return JSONResponse(detail.model_dump(mode="json"))


@router.get("/oidc", response_model=OidcConfigOutput)
def oidc_config(settings: Config) -> OidcConfigOutput:
    """The audience pipelines request for their OIDC identity token. Public; not a secret."""
    return OidcConfigOutput(audience=identities.audience(settings))


@router.post("/identity/exchange", response_model=ExchangeOutput, status_code=201)
def exchange_identity(
    body: ExchangeInput, db: Db, settings: Config, verifier: Verifier
) -> ExchangeOutput:
    """Exchange a GitHub Actions or GitLab CI OIDC job token for a 30-minute DepRadar token.

    No DepRadar secret is needed. The token must come from a repository the owner trusts under
    Settings → Trusted identities. Pull and merge request runs receive check-only access.
    """
    token, secret, access, project, _ = identities.exchange(
        db, verifier, settings, body.id_token, body.project
    )
    assert token.identity_id is not None
    return ExchangeOutput(
        token=secret,
        expires_at=token.expires_at,
        project_id=project.id,
        project_name=project.name,
        access=access,
        scopes=token.scopes,
        identity_id=token.identity_id,
    )


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
