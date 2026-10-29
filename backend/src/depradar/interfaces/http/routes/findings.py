"""The owner's triage decisions on findings."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends

from depradar.application import findings
from depradar.interfaces.http.dependencies import Db, require_session
from depradar.interfaces.http.schemas import AcknowledgeInput, RiskInput

router = APIRouter(prefix="/api/findings", dependencies=[Depends(require_session)])


@router.post("/{finding_id}/acknowledge")
def acknowledge(finding_id: UUID, body: AcknowledgeInput, db: Db) -> dict[str, str]:
    finding = findings.acknowledge(db, str(finding_id), body.note)
    return {"workflow_status": finding.workflow_status}


@router.post("/{finding_id}/risk-acceptance")
def accept_risk(finding_id: UUID, body: RiskInput, db: Db) -> dict[str, str]:
    finding = findings.accept_risk(db, str(finding_id), body.reason, body.expires_at)
    return {"workflow_status": finding.workflow_status}


@router.delete("/{finding_id}/acknowledge")
def revoke_acknowledgement(finding_id: UUID, db: Db) -> dict[str, str]:
    return {"workflow_status": findings.revoke_acknowledgement(db, str(finding_id)).workflow_status}


@router.delete("/{finding_id}/risk-acceptance")
def revoke_risk(finding_id: UUID, db: Db) -> dict[str, str]:
    return {"workflow_status": findings.revoke_risk(db, str(finding_id)).workflow_status}


@router.get("/{finding_id}/decisions")
def decisions(finding_id: UUID, db: Db) -> list[dict[str, Any]]:
    return findings.decisions(db, str(finding_id))
