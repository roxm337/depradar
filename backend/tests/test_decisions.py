import json
from datetime import timedelta
from typing import Any
from xml.etree import ElementTree

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from depradar.application.scans import run_once
from depradar.domain.entities import (
    Finding,
    GateDecision,
    Inventory,
    Job,
    Project,
    SystemState,
    utcnow,
)

from .conftest import Harness
from .test_ci_gate import advisory, ci_upload, scanned
from .test_ci_tokens import CI_SCOPES, bearer, create_token

CHECK_SCOPES = ["projects:read", "inventories:check", "scans:read", "findings:read"]


def decide(client: TestClient, token: str, *scan_ids: str, **policy: Any) -> Any:
    return client.post(
        "/api/ci/decisions",
        json={"scan_ids": list(scan_ids), "policy": policy},
        headers=bearer(token),
    )


def scan_all(harness: Harness, *vulnerabilities: dict[str, Any]) -> None:
    while run_once(
        harness.factory, harness.settings, harness.store, lambda *_: scanned(*vulnerabilities)
    ):
        pass


def test_decisions_record_evidence_and_render_reports_from_the_record(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    first = ci_upload(anonymous, token).json()["scan"]["id"]
    scan_all(harness, advisory("GHSA-high", "HIGH"), advisory("GHSA-low", "LOW"))
    with harness.factory.begin() as db:
        accepted = db.scalars(select(Finding).where(Finding.advisory_ids == ["GHSA-low"])).one()
        accepted_id = accepted.id
        db.get(SystemState, 1).last_intelligence_refresh_at = utcnow() - timedelta(hours=3)
    until = (utcnow() + timedelta(days=7)).isoformat()
    harness.client.post(
        f"/api/findings/{accepted_id}/risk-acceptance",
        json={"reason": "Dev dependency", "expires_at": until},
        headers=harness.headers,
    )
    response = decide(anonymous, token, first, fail_on="low")
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["status"] == "fail" and result["decision_id"]
    assert result["violations"] == 1 and result["ignored"] == 1
    decision_id = result["decision_id"]
    listed = harness.client.get("/api/ci/decisions").json()
    assert [row["id"] for row in listed] == [decision_id]
    summary = listed[0]
    assert summary["project_name"] == "Example" and summary["mode"] == "monitor"
    assert summary["revision"] == "main@abc123" and summary["commit"] is None
    assert summary["actor"]["kind"] == "token" and summary["actor"]["name"] == "CI"
    assert not summary["actor"]["verified"]
    assert summary["policy_sources"][0]["version"] == 0
    detail = anonymous.get(f"/api/ci/decisions/{decision_id}", headers=bearer(token)).json()
    [entry] = detail["inputs"]
    with harness.factory() as db:
        inventory = db.scalars(select(Inventory)).one()
    assert entry["sha256"] == inventory.sha256 and entry["engine_version"] == "fixture"
    assert entry["complete"] and entry["target_path"] == "web/package-lock.json"
    assert detail["intelligence_updated_at"] is not None
    [exception] = detail["exceptions"]
    assert exception["finding_id"] == accepted_id
    assert exception["workflow_status"] == "risk_accepted" and exception["risk_until"]
    assert detail["result"]["decision_id"] == decision_id
    # Reports come from the stored decision: a later decision change cannot rewrite them.
    harness.client.delete(f"/api/findings/{accepted_id}/risk-acceptance", headers=harness.headers)
    markdown = anonymous.get(
        f"/api/ci/decisions/{decision_id}?format=markdown", headers=bearer(token)
    ).text
    assert "1 ignored" in markdown and decision_id in markdown
    junit = ElementTree.fromstring(
        anonymous.get(f"/api/ci/decisions/{decision_id}?format=junit", headers=bearer(token)).text
    )
    assert junit.get("failures") == "1" and junit.get("skipped") == "1"
    sarif = anonymous.get(f"/api/ci/decisions/{decision_id}?format=sarif", headers=bearer(token))
    assert sarif.headers["content-type"].startswith("application/sarif+json")
    assert json.loads(sarif.text)["version"] == "2.1.0"
    assert decide(anonymous, token, first).json()["ignored"] == 0
    filtered = harness.client.get("/api/ci/decisions?status=pass").json()
    assert filtered == []


def test_decisions_cover_one_project_and_respect_token_restrictions(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    other = harness.client.post("/api/projects", json={"name": "Other"}, headers=harness.headers)
    other_id = other.json()["id"]
    token = create_token(harness)
    mine = ci_upload(anonymous, token).json()["scan"]["id"]
    theirs = ci_upload(anonymous, token, project="Other").json()["scan"]["id"]
    assert decide(anonymous, token, mine).status_code == 409  # still queued
    scan_all(harness)
    assert decide(anonymous, token, mine, theirs).status_code == 422
    recorded = decide(anonymous, token, theirs).json()
    restricted = create_token(harness, CI_SCOPES, project_id)
    assert decide(anonymous, restricted, theirs).status_code == 404
    path = f"/api/ci/decisions/{recorded['decision_id']}"
    assert anonymous.get(path, headers=bearer(restricted)).status_code == 404
    assert anonymous.get("/api/ci/decisions", headers=bearer(restricted)).json() == []
    assert decide(anonymous, restricted, mine).status_code == 201
    own = anonymous.get("/api/ci/decisions", headers=bearer(restricted)).json()
    assert [row["project_id"] for row in own] == [project_id]
    by_project = harness.client.get(f"/api/ci/decisions?project_id={other_id}").json()
    assert [row["project_name"] for row in by_project] == ["Other"]
    unknown = anonymous.get(
        "/api/ci/decisions/00000000-0000-4000-8000-000000000000", headers=bearer(token)
    )
    assert unknown.status_code == 404


def test_read_only_tokens_preview_but_never_record(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    scan_id = ci_upload(anonymous, create_token(harness)).json()["scan"]["id"]
    scan_all(harness)
    reader = create_token(harness, ["projects:read", "scans:read", "findings:read"])
    denied = decide(anonymous, reader, scan_id)
    assert denied.status_code == 403 and "inventories" in denied.json()["detail"]
    preview = anonymous.get(
        "/api/ci/evaluation", params={"scan_id": scan_id}, headers=bearer(reader)
    )
    assert preview.status_code == 200 and preview.json()["decision_id"] is None
    assert harness.client.get("/api/ci/decisions").json() == []


def test_failed_scans_are_recorded_as_errors(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    failed = ci_upload(anonymous, token).json()["scan"]["id"]
    with harness.factory.begin() as db:
        job = db.scalars(select(Job)).one()
        job.attempts, job.status = harness.settings.max_job_attempts, "running"
        job.lease_until = utcnow() - timedelta(seconds=1)
    scan_all(harness)
    result = decide(anonymous, token, failed).json()
    assert result["status"] == "error"
    assert harness.client.get("/api/ci/decisions").json()[0]["status"] == "error"


def test_check_only_tokens_never_change_monitored_state(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    checks = create_token(harness, CHECK_SCOPES)
    denied = ci_upload(anonymous, checks)
    assert denied.status_code == 403 and "monitor uploads" in denied.json()["detail"]
    check = ci_upload(anonymous, checks, mode="check")
    assert check.status_code == 202, check.text
    scan_all(harness, advisory("GHSA-high", "HIGH"))
    result = decide(anonymous, checks, check.json()["scan"]["id"]).json()
    assert result["status"] == "fail" and result["scans"][0]["mode"] == "check"
    with harness.factory() as db:
        assert db.scalar(select(func.count()).select_from(Finding)) == 0
        assert db.scalars(select(Inventory)).one().kind == "check"
    # Rechecking monitored inventories still needs inventories:write.
    writer = create_token(harness)
    monitored = ci_upload(anonymous, writer).json()["inventory"]["id"]
    recheck = anonymous.post(f"/api/inventories/{monitored}/scans", headers=bearer(checks))
    assert recheck.status_code == 403
    listed = harness.client.get("/api/tokens").json()
    assert any(row["scopes"] == sorted(CHECK_SCOPES) for row in listed)


def test_retention_keeps_each_projects_latest_decision(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    scan_id = ci_upload(anonymous, token).json()["scan"]["id"]
    scan_all(harness)
    old, latest = (decide(anonymous, token, scan_id).json()["decision_id"] for _ in range(2))
    with harness.factory.begin() as db:
        for decision in db.scalars(select(GateDecision)):
            decision.created_at -= timedelta(days=60 if decision.id == old else 50)
    response = harness.client.post("/api/maintenance/retention/run", headers=harness.headers)
    assert response.status_code == 200
    with harness.factory() as db:
        assert [row.id for row in db.scalars(select(GateDecision))] == [latest]
    harness.client.delete(f"/api/projects/{project_id}", headers=harness.headers)
    with harness.factory() as db:
        assert db.scalar(select(func.count()).select_from(GateDecision)) == 0
        assert db.get(Project, project_id) is None
