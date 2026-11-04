"""Owners retire renamed or removed manifests; uploads alone never retire anything."""

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from depradar.application.housekeeping import retention
from depradar.application.scans import run_once
from depradar.application.scheduling import tick
from depradar.domain.entities import (
    ChangeEvent,
    Delivery,
    Finding,
    Inventory,
    Job,
    Project,
    Scan,
    SystemState,
    utcnow,
)

from .conftest import Harness
from .test_ci_tokens import bearer, create_token
from .test_notifications import connect
from .test_scans import report
from .test_uploads import upload

TARGET = "package-lock.json"


def retire(harness: Harness, project_id: str, target: str = TARGET):
    return harness.client.post(
        f"/api/projects/{project_id}/targets/retire",
        json={"target_path": target},
        headers=harness.headers,
    )


def scanned_project(harness: Harness, project_id: str, vulnerable: bool = True) -> str:
    response = upload(harness, project_id)
    assert response.status_code == 202
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(vulnerable))
    return str(response.json()["inventory"]["id"])


def test_retiring_resolves_findings_without_alerts_and_stops_rechecks(
    harness: Harness, project_id: str
) -> None:
    connect(harness)
    inventory_id = scanned_project(harness, project_id)
    tick(harness.factory, harness.settings, harness.store)  # route the opened alert
    with harness.factory() as db:
        before = len(list(db.scalars(select(Delivery))))

    response = retire(harness, project_id)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "target_path": TARGET,
        "retired_inventories": 1,
        "resolved_findings": 1,
    }
    with harness.factory.begin() as db:
        finding = db.scalars(select(Finding)).one()
        assert finding.status == "resolved" and finding.resolved_at is not None
        kinds = [event.kind for event in db.scalars(select(ChangeEvent))]
        assert kinds == ["opened", "retired"]
        project = db.get(Project, project_id)
        project.monitoring_enabled = True
        project.next_check_at = utcnow() - timedelta(seconds=1)
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        assert len(list(db.scalars(select(Delivery)))) == before  # retirement sends nothing
        assert db.scalar(select(Job).where(Job.status == "queued")) is None
    listed = harness.client.get(f"/api/projects/{project_id}/inventories").json()
    assert listed[0]["retired_at"] is not None
    rescan = harness.client.post(
        f"/api/inventories/{inventory_id}/scans", json={}, headers=harness.headers
    )
    assert rescan.status_code == 409
    assert retire(harness, project_id).status_code == 404


def test_uploading_a_retired_manifest_again_resumes_monitoring(
    harness: Harness, project_id: str
) -> None:
    first = scanned_project(harness, project_id)
    assert retire(harness, project_id).status_code == 200
    again = upload(harness, project_id)
    assert again.status_code == 202
    assert again.json()["inventory"]["id"] != first
    assert again.json()["inventory"]["retired_at"] is None
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    with harness.factory() as db:
        finding = db.scalars(select(Finding)).one()
        assert finding.status == "open"
        assert [e.kind for e in db.scalars(select(ChangeEvent))] == [
            "opened",
            "retired",
            "reopened",
        ]


def test_a_scan_queued_before_retirement_cannot_reopen_findings(
    harness: Harness, project_id: str
) -> None:
    inventory_id = scanned_project(harness, project_id)
    queued = harness.client.post(
        f"/api/inventories/{inventory_id}/scans", json={}, headers=harness.headers
    ).json()["id"]
    assert retire(harness, project_id).status_code == 200
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    with harness.factory() as db:
        assert db.get(Scan, queued).status == "superseded"
        assert db.scalars(select(Finding)).one().status == "resolved"


def test_retirement_is_owner_only_and_needs_an_active_manifest(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    scanned_project(harness, project_id)
    assert retire(harness, project_id, "missing/package-lock.json").status_code == 404
    token = create_token(harness)
    denied = anonymous.post(
        f"/api/projects/{project_id}/targets/retire",
        json={"target_path": TARGET},
        headers=bearer(token),
    )
    assert denied.status_code in {401, 403}
    with harness.factory() as db:
        assert db.scalars(select(Inventory)).one().retired_at is None


def test_retired_manifest_history_ages_out_with_retention(
    harness: Harness, project_id: str
) -> None:
    scanned_project(harness, project_id, vulnerable=False)
    assert retire(harness, project_id).status_code == 200
    with harness.factory.begin() as db:
        old = utcnow() - timedelta(days=400)
        for inventory in db.scalars(select(Inventory)):
            inventory.created_at = old
        for scan in db.scalars(select(Scan)):
            scan.created_at = old
        state = db.get(SystemState, 1)
        retention(db, harness.store, state)
    with harness.factory() as db:
        assert db.scalar(select(Inventory)) is None
