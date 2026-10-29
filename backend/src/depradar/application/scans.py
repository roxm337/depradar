"""Scan jobs: lease a queued scan, run the scanner, and record what it found."""

import hashlib
import logging
from datetime import timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, sessionmaker

from depradar.application.findings import record_change
from depradar.application.locking import lock_writes
from depradar.application.ports import InventoryStore, Scanner, ScannerFailure
from depradar.application.threat_intel import apply_cached_intelligence
from depradar.config import Settings
from depradar.domain.entities import (
    Finding,
    Inventory,
    Job,
    Observation,
    Project,
    Scan,
    new_id,
    utcnow,
)
from depradar.domain.inventory import validate_inventory
from depradar.domain.scanning import ScanResponse, normalize

logger = logging.getLogger(__name__)


def claim_job(factory: sessionmaker[Session], settings: Settings) -> tuple[str, str] | None:
    with factory.begin() as db:
        lock_writes(db)
        query = (
            select(Job)
            .where(
                or_(
                    and_(Job.status == "queued", Job.available_at <= utcnow()),
                    and_(Job.status == "running", Job.lease_until <= utcnow()),
                )
            )
            .order_by(Job.available_at, Job.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        job = db.scalar(query)
        if job is None:
            return None
        scan = db.get(Scan, job.scan_id)
        assert scan is not None
        if job.attempts >= settings.max_job_attempts:
            job.status = "failed"
            job.lease_token = None
            job.lease_until = None
            scan.status = "failed"
            scan.complete = False
            scan.error = "Job exhausted its attempts after worker interruption"
            scan.completed_at = utcnow()
            return None
        job.status = "running"
        job.attempts += 1
        job.lease_token = new_id()
        job.lease_until = utcnow() + timedelta(seconds=settings.job_lease_seconds)
        scan.status = "running"
        scan.error = None
        return job.id, job.lease_token


def run_once(
    factory: sessionmaker[Session], settings: Settings, store: InventoryStore, scanner: Scanner
) -> bool:
    claim = claim_job(factory, settings)
    if claim is None:
        return False
    job_id, token = claim
    try:
        with factory() as db:
            job = db.get(Job, job_id)
            assert job is not None
            scan = db.get(Scan, job.scan_id)
            assert scan is not None
            inventory = db.get(Inventory, scan.inventory_id)
            assert inventory is not None
            filename = inventory.filename
            content = store.load(inventory.id)
            if len(content) > settings.upload_limit_bytes:
                raise ValueError("Stored inventory exceeds limit")
            if hashlib.sha256(content).hexdigest() != inventory.sha256:
                raise ValueError("Inventory checksum mismatch")
            notes = validate_inventory(filename, content)
        result = scanner(content, filename)
        if not any(source.packages for source in result.report.results):
            raise ValueError("Scanner returned no packages; coverage is unknown")
        with factory.begin() as db:
            lock_writes(db)
            job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
            if job is None:
                return True
            if job.lease_token != token or job.status != "running":
                return True
            scan = db.get(Scan, job.scan_id)
            assert scan is not None
            inventory = db.get(Inventory, scan.inventory_id)
            assert inventory is not None
            scan.coverage_notes = notes
            if scan.mode == "check":
                record_check(scan, result)
            else:
                apply_report(db, scan, inventory, result)
            job.status = "succeeded"
            job.lease_token = None
            job.lease_until = None
            job.last_error = None
    except Exception as exc:
        # Do not persist exception strings containing HTTP bodies, inventory data, or credentials.
        if isinstance(exc, ScannerFailure):
            error = str(exc)
        elif isinstance(exc, FileNotFoundError):
            error = "Stored inventory is missing"
        else:
            error = "Scan failed validation or processing; existing findings were retained"
        logger.warning("scan_job_failed job_id=%s error=%s", job_id, error)
        with factory.begin() as db:
            lock_writes(db)
            job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
            if job is None:
                return True
            if job.lease_token != token or job.status != "running":
                return True
            scan = db.get(Scan, job.scan_id)
            assert scan is not None
            terminal = job.attempts >= settings.max_job_attempts
            job.status = "failed" if terminal else "queued"
            job.last_error = error
            job.available_at = utcnow() + timedelta(seconds=10 * 2 ** (job.attempts - 1))
            job.lease_token = None
            job.lease_until = None
            scan.status = "failed" if terminal else "queued"
            scan.complete = False
            scan.error = error
            scan.completed_at = utcnow() if terminal else None
    return True


def record_scan_metadata(scan: Scan, response: ScanResponse) -> None:
    scan.engine_version = response.engine_version
    scan.completed_at = utcnow()
    scan.complete = response.complete
    scan.package_count = sum(len(source.packages) for source in response.report.results)
    scan.coverage_notes = sorted(set(scan.coverage_notes + response.notes))
    scan.complete = scan.complete and not scan.coverage_notes


def record_check(scan: Scan, response: ScanResponse) -> None:
    """Check-mode scans answer CI gates without changing findings or queueing alerts."""
    record_scan_metadata(scan, response)
    scan.results = [
        detected.model_dump(exclude={"evidence"}) for detected in normalize(response.report)
    ]
    scan.status = "succeeded" if scan.complete else "partial"


def apply_report(db: Session, scan: Scan, inventory: Inventory, response: ScanResponse) -> None:
    # Serialize result application per project, including stale inventory/recheck races.
    db.scalar(select(Project).where(Project.id == scan.project_id).with_for_update())
    latest = db.scalar(
        select(Inventory)
        .where(
            Inventory.project_id == inventory.project_id,
            Inventory.target_path == inventory.target_path,
            Inventory.kind == "monitor",
        )
        .order_by(Inventory.created_at.desc(), Inventory.id.desc())
        .limit(1)
    )
    newer_scan = db.scalar(
        select(Scan.id)
        .join(Inventory)
        .where(
            Scan.project_id == scan.project_id,
            Inventory.target_path == inventory.target_path,
            Scan.mode == "monitor",
            Scan.created_at > scan.created_at,
            Scan.status.in_(["succeeded", "partial"]),
        )
        .limit(1)
    )
    record_scan_metadata(scan, response)
    if latest is None or latest.id != inventory.id or newer_scan:
        scan.status = "superseded"
        return
    existing = list(
        db.scalars(
            select(Finding).where(
                Finding.project_id == scan.project_id,
                Finding.target_path == inventory.target_path,
            )
        )
    )
    seen: set[str] = set()
    for detected in normalize(response.report):
        ids = set(detected.advisory_ids)
        matches = [
            f
            for f in existing
            if (
                f.ecosystem == detected.ecosystem
                and f.package_name == detected.package_name
                and f.package_version == detected.package_version
                and ids.intersection(f.advisory_ids)
            )
        ]
        if matches:
            finding = matches[0]
            changed = finding.severity != detected.severity or set(finding.fixed_versions) != set(
                detected.fixed_versions
            )
            for duplicate in matches[1:]:
                # Retain historical IDs/events; mark old duplicates as resolved after alias merge.
                ids.update(duplicate.advisory_ids)
                if scan.complete and duplicate.status != "resolved":
                    duplicate.status = "resolved"
                    duplicate.resolved_at = utcnow()
                    record_change(db, duplicate, scan, "alias_merged")
            kind = "reopened" if finding.status == "resolved" else ("updated" if changed else None)
            ids.update(finding.advisory_ids)
        else:
            finding = Finding(
                project_id=scan.project_id,
                target_filename=inventory.filename,
                target_path=inventory.target_path,
                revision=inventory.revision,
                ecosystem=detected.ecosystem,
                package_name=detected.package_name,
                package_version=detected.package_version,
                purl=detected.purl,
                advisory_ids=detected.advisory_ids,
                summary=detected.summary,
            )
            db.add(finding)
            db.flush()
            existing.append(finding)
            kind = "opened"
        if kind == "reopened":
            finding.workflow_status = "open"
            finding.risk_until = None
            finding.acknowledged_at = None
        finding.advisory_ids = sorted(ids)
        finding.summary = detected.summary
        finding.severity = detected.severity
        finding.purl = detected.purl
        finding.revision = inventory.revision
        finding.cvss_vectors = detected.cvss_vectors
        finding.fixed_versions = detected.fixed_versions
        finding.evidence = detected.evidence
        apply_cached_intelligence(db, finding)
        finding.status = "open"
        finding.last_seen_at = utcnow()
        finding.resolved_at = None
        seen.add(finding.id)
        db.add(Observation(scan_id=scan.id, finding_id=finding.id, evidence=detected.evidence))
        if kind:
            record_change(db, finding, scan, kind)
    if scan.complete:
        for finding in existing:
            if finding.id not in seen and finding.status == "open":
                finding.status = "resolved"
                finding.resolved_at = utcnow()
                record_change(db, finding, scan, "resolved")
    scan.status = "succeeded" if scan.complete else "partial"
