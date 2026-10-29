"""Evaluate finished scans against a CI/CD gate policy. Evaluation never changes findings."""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from depradar.application.errors import Conflict, NotFound
from depradar.application.ports import InventoryStore
from depradar.application.threat_intel import cached_signals
from depradar.domain.entities import (
    ChangeEvent,
    Finding,
    Inventory,
    Observation,
    Project,
    Scan,
    utcnow,
)
from depradar.domain.gate import (
    FINISHED,
    Candidate,
    GatePolicy,
    GateResult,
    ScanGate,
    gate_result,
    scan_gate,
)
from depradar.domain.security import Principal


def scans_for(db: Session, principal: Principal, scan_ids: list[str]) -> list[Scan]:
    scans = []
    for scan_id in dict.fromkeys(scan_ids):
        scan = db.get(Scan, scan_id)
        if scan is None or not principal.allows(scan.project_id):
            raise NotFound("Scan not found")
        scans.append(scan)
    return scans


def evaluate(db: Session, scans: list[Scan], policy: GatePolicy) -> GateResult:
    if any(scan.status not in FINISHED for scan in scans):
        raise Conflict(
            "A scan is still queued or running; poll GET /api/scans/{id} until it finishes"
        )
    now = utcnow()
    return gate_result([evaluate_scan(db, scan, policy, now) for scan in scans], policy, now)


def evaluate_scan(db: Session, scan: Scan, policy: GatePolicy, now: datetime) -> ScanGate:
    inventory = db.get(Inventory, scan.inventory_id)
    project = db.get(Project, scan.project_id)
    assert inventory is not None and project is not None
    candidates: list[Candidate] = []
    if scan.status not in {"failed", "superseded"}:
        candidates = (
            check_candidates(db, scan, inventory)
            if scan.mode == "check"
            else monitor_candidates(db, scan)
        )
    return scan_gate(scan, project, inventory, policy, now, candidates)


def monitor_candidates(db: Session, scan: Scan) -> list[Candidate]:
    opened = set(
        db.scalars(
            select(ChangeEvent.finding_id).where(
                ChangeEvent.scan_id == scan.id, ChangeEvent.kind.in_(["opened", "reopened"])
            )
        )
    )
    findings = db.scalars(
        select(Finding)
        .join(Observation, Observation.finding_id == Finding.id)
        .where(Observation.scan_id == scan.id)
        .order_by(Finding.package_name, Finding.id)
    )
    return [
        Candidate(
            finding=finding,
            detected={
                "ecosystem": finding.ecosystem,
                "package_name": finding.package_name,
                "package_version": finding.package_version,
                "purl": finding.purl,
                "advisory_ids": finding.advisory_ids,
                "summary": finding.summary,
                "severity": finding.severity,
                "fixed_versions": finding.fixed_versions,
                "cvss_vectors": finding.cvss_vectors,
            },
            kev_known=finding.kev_known,
            epss_score=finding.epss_score,
            new=finding.id in opened,
        )
        for finding in findings
    ]


def check_candidates(db: Session, scan: Scan, inventory: Inventory) -> list[Candidate]:
    """Decisions recorded on the monitored manifest also apply to check uploads of it."""
    monitored = list(
        db.scalars(
            select(Finding).where(
                Finding.project_id == scan.project_id,
                Finding.target_path == inventory.target_path,
                Finding.status == "open",
            )
        )
    )
    candidates = []
    for detected in scan.results or []:
        ids = set(detected["advisory_ids"])
        match = next(
            (
                finding
                for finding in monitored
                if finding.ecosystem == detected["ecosystem"]
                and finding.package_name == detected["package_name"]
                and finding.package_version == detected["package_version"]
                and ids.intersection(finding.advisory_ids)
            ),
            None,
        )
        kev_known, epss_score = cached_signals(db, detected["advisory_ids"])
        candidates.append(
            Candidate(
                finding=match,
                detected=detected,
                kev_known=kev_known,
                epss_score=epss_score,
                new=match is None,
            )
        )
    return candidates


def scanned_manifest(db: Session, store: InventoryStore, scan_id: str) -> bytes | None:
    """The manifest a scan read, for locating findings in reports; None when it is gone."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        return None
    try:
        return store.load(scan.inventory_id)
    except OSError:
        return None
