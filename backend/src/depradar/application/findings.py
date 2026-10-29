"""Finding workflow: change events for alerts, and the owner's triage decisions."""

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from depradar.application.errors import Conflict, Invalid, NotFound
from depradar.domain.entities import (
    ChangeEvent,
    Finding,
    FindingDecision,
    Observation,
    OutboxEvent,
    Scan,
    utcnow,
)


def record_change(db: Session, finding: Finding, scan: Scan, kind: str) -> None:
    event = ChangeEvent(finding_id=finding.id, scan_id=scan.id, kind=kind)
    db.add(event)
    db.flush()
    db.add(
        OutboxEvent(
            change_id=event.id,
            payload={
                "finding_id": finding.id,
                "project_id": finding.project_id,
                "scan_id": scan.id,
                "kind": kind,
            },
        )
    )


def latest_scan(db: Session, finding: Finding) -> Scan | None:
    """The most recent scan that observed the finding."""
    observation = db.scalar(
        select(Observation)
        .join(Scan)
        .where(Observation.finding_id == finding.id)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    if observation is None:
        return None
    scan = db.get(Scan, observation.scan_id)
    assert scan is not None
    return scan


def get_finding(db: Session, finding_id: str) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFound("Finding not found")
    return finding


def decide(
    db: Session, finding: Finding, action: str, note: str, expires_at: datetime | None = None
) -> None:
    db.add(FindingDecision(finding_id=finding.id, action=action, note=note, expires_at=expires_at))
    scan = latest_scan(db, finding)
    if scan:
        record_change(db, finding, scan, action)


def acknowledge(db: Session, finding_id: str, note: str) -> Finding:
    finding = get_finding(db, finding_id)
    if finding.status != "open":
        raise Conflict("Only active findings can be acknowledged")
    finding.workflow_status = "acknowledged"
    finding.acknowledged_at = utcnow()
    finding.risk_until = None
    finding.decision_note = note
    decide(db, finding, "acknowledged", note)
    db.commit()
    return finding


def accept_risk(db: Session, finding_id: str, reason: str, expires_at: datetime) -> Finding:
    finding = get_finding(db, finding_id)
    if (
        expires_at.tzinfo is None
        or not utcnow() < expires_at <= utcnow() + timedelta(days=365)
        or not reason.strip()
    ):
        raise Invalid("Provide a reason and timezone-aware expiry within the next 365 days")
    if finding.status != "open":
        raise Conflict("Only active findings can have risk accepted")
    finding.workflow_status = "risk_accepted"
    finding.risk_until = expires_at
    finding.acknowledged_at = None
    finding.decision_note = reason
    decide(db, finding, "risk_accepted", reason, expires_at)
    db.commit()
    return finding


def revoke_acknowledgement(db: Session, finding_id: str) -> Finding:
    finding = get_finding(db, finding_id)
    if finding.workflow_status != "acknowledged":
        raise Conflict("Finding is not acknowledged")
    finding.workflow_status = "open"
    finding.acknowledged_at = None
    decide(db, finding, "ack_revoked", "Acknowledgement revoked by owner")
    db.commit()
    return finding


def revoke_risk(db: Session, finding_id: str) -> Finding:
    finding = get_finding(db, finding_id)
    if finding.workflow_status != "risk_accepted":
        raise Conflict("Finding has no accepted risk")
    finding.workflow_status = "open"
    finding.risk_until = None
    decide(db, finding, "risk_revoked", "Risk acceptance revoked by owner")
    db.commit()
    return finding


def decisions(db: Session, finding_id: str) -> list[dict[str, Any]]:
    get_finding(db, finding_id)
    return [
        {"action": d.action, "note": d.note, "expires_at": d.expires_at, "created_at": d.created_at}
        for d in db.scalars(
            select(FindingDecision)
            .where(FindingDecision.finding_id == finding_id)
            .order_by(FindingDecision.created_at.desc())
            .limit(100)
        )
    ]


def expire_risks(db: Session) -> int:
    count = 0
    for finding in db.scalars(
        select(Finding).where(
            Finding.workflow_status == "risk_accepted", Finding.risk_until <= utcnow()
        )
    ):
        finding.workflow_status = "open"
        finding.risk_until = None
        db.add(
            FindingDecision(
                finding_id=finding.id,
                action="risk_expired",
                note="Risk acceptance expired automatically",
            )
        )
        if finding.status == "open":
            scan = latest_scan(db, finding)
            if scan:
                record_change(db, finding, scan, "risk_expired")
        count += 1
    return count
