from datetime import timedelta

from sqlalchemy import func, select

from depradar.application.scans import claim_job, run_once
from depradar.domain.entities import Finding, Job, OutboxEvent, Scan, utcnow
from depradar.domain.scanning import ScanResponse

from .conftest import Harness
from .test_uploads import upload


def report(vulnerable: bool = True, complete: bool = True) -> ScanResponse:
    vulnerabilities = (
        [
            {
                "id": "GHSA-example",
                "aliases": ["CVE-2021-44906"],
                "summary": "Prototype pollution",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": "minimist", "ecosystem": "npm"},
                        "ranges": [{"type": "SEMVER", "events": [{"fixed": "1.2.6"}]}],
                    }
                ],
            },
            {"id": "CVE-2021-44906", "aliases": ["GHSA-example"]},
        ]
        if vulnerable
        else []
    )
    return ScanResponse.model_validate(
        {
            "engine_version": "fixture",
            "complete": complete,
            "report": {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {
                                    "name": "minimist",
                                    "version": "1.2.5",
                                    "ecosystem": "npm",
                                },
                                "vulnerabilities": vulnerabilities,
                            }
                        ]
                    }
                ]
            },
        }
    )


def enqueue_recheck(harness: Harness, inventory_id: str) -> str:
    response = harness.client.post(
        f"/api/inventories/{inventory_id}/scans", headers=harness.headers
    )
    assert response.status_code == 202
    return str(response.json()["id"])


def count_events(harness: Harness) -> int:
    with harness.factory() as db:
        return db.scalar(select(func.count()).select_from(OutboxEvent)) or 0


def test_aliases_deduplicate_and_rescans_do_not_repeat_events(
    harness: Harness, project_id: str
) -> None:
    response = upload(harness, project_id).json()
    assert run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    findings = harness.client.get(f"/api/projects/{project_id}/findings").json()
    assert len(findings) == 1
    assert findings[0]["advisory_ids"] == ["CVE-2021-44906", "GHSA-example"]
    assert findings[0]["fixed_versions"] == ["1.2.6"]
    assert findings[0]["severity"] == "high"
    assert count_events(harness) == 1
    enqueue_recheck(harness, response["inventory"]["id"])
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    assert count_events(harness) == 1


def test_partial_scan_retains_findings_then_complete_scan_resolves_and_reopens(
    harness: Harness,
    project_id: str,
) -> None:
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False, False))
    with harness.factory() as db:
        assert db.scalars(select(Finding)).one().status == "open"
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    with harness.factory() as db:
        assert db.scalars(select(Finding)).one().status == "resolved"
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    with harness.factory() as db:
        assert db.scalars(select(Finding)).one().status == "open"
    assert count_events(harness) == 3


def test_failed_scan_retries_without_resolving_findings(harness: Harness, project_id: str) -> None:
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    scan_id = enqueue_recheck(harness, inventory_id)

    def failing_scanner(*args):
        raise RuntimeError("do-not-store-private-data")

    for attempt in range(3):
        assert run_once(harness.factory, harness.settings, harness.store, failing_scanner)
        with harness.factory.begin() as db:
            job = db.scalars(select(Job).where(Job.scan_id == scan_id)).one()
            assert job.attempts == attempt + 1
            assert "do-not-store" not in (job.last_error or "")
            job.available_at = utcnow() - timedelta(seconds=1)
    with harness.factory() as db:
        assert db.get(Scan, scan_id).status == "failed"
        assert db.scalars(select(Finding)).one().status == "open"


def test_lease_recovery_and_stale_claim_cannot_write(harness: Harness, project_id: str) -> None:
    upload(harness, project_id)
    first = claim_job(harness.factory, harness.settings)
    assert first is not None
    assert claim_job(harness.factory, harness.settings) is None
    with harness.factory.begin() as db:
        job = db.get(Job, first[0])
        assert job is not None
        job.lease_until = utcnow() - timedelta(seconds=1)
    assert run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    with harness.factory() as db:
        job = db.get(Job, first[0])
        assert job is not None and job.status == "succeeded" and job.attempts == 2


def test_older_inventory_results_are_superseded(harness: Harness, project_id: str) -> None:
    first = upload(harness, project_id).json()
    second = upload(harness, project_id).json()
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    with harness.factory() as db:
        assert db.get(Scan, first["scan"]["id"]).status == "superseded"
        assert db.scalar(select(Finding)) is None
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    assert harness.client.get(f"/api/scans/{second['scan']['id']}").json()["complete"]


def test_replaced_lease_fences_out_stale_worker(harness: Harness, project_id: str) -> None:
    upload(harness, project_id)

    def replaced_while_scanning(*args):
        with harness.factory.begin() as db:
            job = db.scalars(select(Job)).one()
            job.lease_token = "a-new-worker-owns-this-lease"
        return report()

    run_once(harness.factory, harness.settings, harness.store, replaced_while_scanning)
    with harness.factory() as db:
        assert db.scalar(select(Finding)) is None
        assert db.scalars(select(Job)).one().status == "running"


def test_empty_scanner_result_never_resolves(harness: Harness, project_id: str) -> None:
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    enqueue_recheck(harness, inventory_id)
    empty = ScanResponse.model_validate(
        {
            "report": {"results": []},
            "engine_version": "fixture",
            "complete": True,
        }
    )
    run_once(harness.factory, harness.settings, harness.store, lambda *_: empty)
    with harness.factory() as db:
        assert db.scalars(select(Finding)).one().status == "open"
