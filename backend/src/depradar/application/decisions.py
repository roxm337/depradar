"""Record CI gate decisions with the evidence behind them, and read them back.

A decision is immutable. It keeps the enforced policy and its versions, the scanned inputs and
their hashes, scanner versions, intelligence freshness, the owner decisions that applied, and who
asked. Reports are rendered from the stored result, so they always match the decision.
"""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from depradar.application import gates
from depradar.application.errors import Forbidden, Invalid, NotFound
from depradar.application.locking import lock_writes
from depradar.domain.entities import (
    Finding,
    GateDecision,
    Inventory,
    Project,
    Scan,
    SystemState,
)
from depradar.domain.gate import GatePolicy, GateResult
from depradar.domain.security import Principal

OWNER_DECISIONS = {"risk_accepted", "acknowledged"}


def actor_for(principal: Principal) -> dict[str, Any]:
    run = principal.run
    if run is not None:
        return {
            "kind": "identity",
            "name": f"{run.provider} · {run.repository}",
            "token_id": principal.token_id,
            "verified": True,
            "provider": run.provider,
            "repository": run.repository,
            "workflow": run.workflow or None,
            "ref": run.ref,
            "event": run.event,
            "run_id": run.run_id,
            "run_url": run.run_url,
        }
    return {
        "kind": "token" if principal.token_id else "owner",
        "name": principal.name,
        "token_id": principal.token_id,
        "verified": False,
        "provider": None,
        "repository": None,
        "workflow": None,
        "ref": None,
        "event": None,
        "run_id": None,
        "run_url": None,
    }


def _inputs(db: Session, scans: list[Scan]) -> list[dict[str, Any]]:
    inputs = []
    for scan in scans:
        inventory = db.get(Inventory, scan.inventory_id)
        assert inventory is not None
        inputs.append(
            {
                "scan_id": scan.id,
                "target_path": inventory.target_path,
                "filename": inventory.filename,
                "mode": scan.mode,
                "sha256": inventory.sha256,
                "revision": inventory.revision,
                "scan_status": scan.status,
                "complete": scan.complete,
                "engine_version": scan.engine_version,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "coverage_notes": list(scan.coverage_notes),
            }
        )
    return inputs


def _exceptions(db: Session, result: GateResult) -> list[dict[str, Any]]:
    """Findings the gate ignored because the owner acknowledged them or accepted the risk."""
    exceptions = []
    for gate in result.scans:
        for item in gate.items:
            if item.outcome != "ignored" or item.workflow_status not in OWNER_DECISIONS:
                continue
            finding = db.get(Finding, item.finding_id) if item.finding_id else None
            until = finding.risk_until if finding and finding.risk_until else None
            exceptions.append(
                {
                    "finding_id": item.finding_id,
                    "target_path": item.target_path,
                    "package_name": item.package_name,
                    "package_version": item.package_version,
                    "advisory_ids": item.advisory_ids,
                    "workflow_status": item.workflow_status,
                    "reason": "; ".join(item.reasons),
                    "risk_until": until.isoformat() if until else None,
                }
            )
    return exceptions


def record(
    db: Session, principal: Principal, scan_ids: list[str], requested: GatePolicy
) -> GateResult:
    """Evaluate one project's finished scans under central policy and store the decision."""
    # Recording writes audit history, so read-only tokens may only preview the gate.
    if not ({"inventories:write", "inventories:check"} & principal.scopes):
        raise Forbidden("Recording decisions needs inventories:write or inventories:check")
    lock_writes(db)
    scans = gates.scans_for(db, principal, scan_ids)
    projects = {scan.project_id for scan in scans}
    if len(projects) != 1:
        raise Invalid("A decision covers one project; record each project's scans separately")
    project = db.get(Project, projects.pop())
    assert project is not None
    result = gates.evaluate(db, scans, requested)
    inputs = _inputs(db, scans)
    revisions = {entry["revision"] for entry in inputs}
    revision = next((value for value in sorted(revisions, key=str) if value), None)
    run = principal.run
    # A verified commit describes the decision only if every input came from that run's commit;
    # older scans cited by a verified run keep their own revision and no verified commit.
    commit = run.sha if run is not None and revisions == {run.revision()} else None
    modes = {scan.mode for scan in scans}
    state = db.get(SystemState, 1)
    decision = GateDecision(
        project_id=project.id,
        created_at=result.evaluated_at,
        status=result.status,
        mode=modes.pop() if len(modes) == 1 else "mixed",
        revision=revision,
        commit=commit,
        violations=result.violations,
        ignored=result.ignored,
        below_threshold=result.below_threshold,
        actor=actor_for(principal),
        inputs=inputs,
        exceptions=_exceptions(db, result),
        intelligence_updated_at=state.last_intelligence_refresh_at if state else None,
        result={},
    )
    db.add(decision)
    db.flush()
    result.decision_id = decision.id
    decision.result = result.model_dump(mode="json")
    db.commit()
    return result


def get_decision(db: Session, principal: Principal, decision_id: str) -> GateDecision:
    decision = db.get(GateDecision, decision_id)
    if decision is None or not principal.allows(decision.project_id):
        raise NotFound("Decision not found")
    return decision


def stored_result(decision: GateDecision) -> GateResult:
    return GateResult.model_validate(decision.result)


def list_decisions(
    db: Session,
    principal: Principal,
    project_id: str | None,
    status: str | None,
    limit: int,
    offset: int,
) -> list[GateDecision]:
    query = select(GateDecision)
    if principal.project_id:
        query = query.where(GateDecision.project_id == principal.project_id)
    if project_id:
        query = query.where(GateDecision.project_id == project_id)
    if status:
        query = query.where(GateDecision.status == status)
    return list(
        db.scalars(
            query.order_by(GateDecision.created_at.desc(), GateDecision.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )


def project_names(db: Session, decisions: list[GateDecision]) -> dict[str, str]:
    ids = {decision.project_id for decision in decisions}
    if not ids:
        return {}
    rows = db.execute(select(Project.id, Project.name).where(Project.id.in_(ids)))
    return {project_id: name for project_id, name in rows.tuples()}
