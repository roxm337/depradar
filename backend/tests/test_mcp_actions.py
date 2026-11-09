"""MCP changes that only increase coverage: projects, rescans, monitoring, and alerts."""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from depradar.application.scans import run_once
from depradar.application.scheduling import schedule_projects
from depradar.domain.entities import AuditEvent, Finding, Job, OutboxEvent, Project, Scan

from .conftest import Harness
from .test_mcp import (
    ALL,
    READ,
    assistant_token,
    enable_mcp,
    ok,
    rpc,
    scanned_project,
    tool,
    tool_names,
)
from .test_scans import report
from .test_uploads import LOCKFILE, upload

ACT = ["projects:write", "scans:write", "monitoring:tighten"]


@pytest.fixture
def mcp(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return enable_mcp(harness, monkeypatch)


def refused(client: TestClient, token: str, name: str, /, **arguments: object) -> str:
    result = tool(client, token, name, **arguments)
    assert result["isError"], result
    return str(result["content"][0]["text"])


def project_row(harness: Harness, project_id: str) -> Project:
    with harness.factory() as db:
        project = db.get(Project, project_id)
        assert project is not None
        return project


def active_jobs(harness: Harness) -> int:
    with harness.factory() as db:
        query = select(func.count()).select_from(Job).where(Job.status == "queued")
        return db.scalar(query) or 0


def test_actions_need_their_scopes_and_stay_assistant_only(
    mcp: Harness, anonymous: TestClient
) -> None:
    names = {"create_project", "rescan_manifests", "set_monitoring", "set_alerts"}
    assert not names & tool_names(anonymous, assistant_token(mcp, ALL))
    assert names <= tool_names(anonymous, assistant_token(mcp, [*READ, *ACT]))
    assert tool_names(anonymous, assistant_token(mcp, ["monitoring:tighten"])) == {
        "set_monitoring",
        "set_alerts",
    }

    def create(scopes: list[str], audience: str, project_id: str | None = None) -> int:
        body = {"name": "x", "scopes": scopes, "audience": audience, "project_id": project_id}
        return mcp.client.post("/api/tokens", json=body, headers=mcp.headers).status_code

    # REST tokens keep using inventories:write for rechecks; the new scopes are MCP-only.
    assert create(["scans:write"], "api") == 422
    assert create(["monitoring:tighten"], "api") == 422
    assert create(["inventories:write"], "mcp") == 422
    project = scanned_project(mcp, "Acme")
    assert create(["projects:write"], "mcp", project) == 422


def test_annotations_mark_changes_as_never_destructive(mcp: Harness, anonymous: TestClient) -> None:
    response = rpc(anonymous, assistant_token(mcp, [*READ, *ACT]), "tools/list")
    tools = {item["name"]: item["annotations"] for item in response.json()["result"]["tools"]}
    for name in ("create_project", "rescan_manifests", "set_monitoring", "set_alerts"):
        assert tools[name]["readOnlyHint"] is False and tools[name]["destructiveHint"] is False
    assert tools["create_project"]["idempotentHint"] is False
    assert tools["set_alerts"]["idempotentHint"] is True


def test_create_project_starts_unmonitored(mcp: Harness, anonymous: TestClient) -> None:
    token = assistant_token(mcp, [*READ, *ACT])
    created = ok(anonymous, token, "create_project", name="  Globex ", description="New client")
    assert created["name"] == "Globex" and created["monitoring_enabled"] is False
    assert "already exists" in refused(anonymous, token, "create_project", name="Globex")
    # Refused by the tool itself rather than the use case, and still audited as an error.
    assert "cannot be blank" in refused(anonymous, token, "create_project", name="   ")
    turned_on = ok(
        anonymous, token, "set_monitoring", project_id=created["id"], enabled=True, interval_hours=6
    )
    assert turned_on["enabled"] and turned_on["interval_hours"] == 6
    with mcp.factory() as db:
        events = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.name == "create_project")
            .order_by(AuditEvent.created_at)
        ).all()
    assert [(event.outcome, event.project_id, event.detail) for event in events] == [
        ("ok", created["id"], ""),
        ("error", None, "Project name already exists"),
        ("error", None, "The project name cannot be blank"),
    ]


def test_restricted_tokens_act_on_their_own_project_only(
    mcp: Harness, anonymous: TestClient
) -> None:
    own = scanned_project(mcp, "Acme")
    other = scanned_project(mcp, "Globex")
    token = assistant_token(mcp, [*READ, "scans:write", "monitoring:tighten"], project_id=own)
    for name, arguments in (
        ("rescan_manifests", {"project_id": other}),
        ("set_monitoring", {"project_id": other, "enabled": True}),
        ("set_alerts", {"project_id": other, "enabled": True}),
    ):
        assert "not found" in refused(anonymous, token, name, **arguments), name
    assert not project_row(mcp, other).monitoring_enabled
    assert ok(anonymous, token, "set_monitoring", project_id=own, enabled=True)["enabled"]
    assert ok(anonymous, token, "rescan_manifests", project_id=own)["scans"]
    assert "create_project" not in tool_names(anonymous, token)


def test_monitoring_only_tightens(mcp: Harness, anonymous: TestClient) -> None:
    project = scanned_project(mcp, "Acme")
    token = assistant_token(mcp, [*READ, "monitoring:tighten"])
    message = refused(anonymous, token, "set_monitoring", project_id=project, enabled=False)
    assert "already off" in message
    ok(anonymous, token, "set_monitoring", project_id=project, enabled=True, interval_hours=12)
    for arguments, reason in (
        ({"enabled": False, "interval_hours": 12}, "cannot turn monitoring off"),
        ({"enabled": True, "interval_hours": 24}, "cannot check less often"),
    ):
        message = refused(anonymous, token, "set_monitoring", project_id=project, **arguments)
        assert reason in message and "dashboard" in message
    shorter = ok(
        anonymous, token, "set_monitoring", project_id=project, enabled=True, interval_hours=4
    )
    assert shorter["interval_hours"] == 4
    row = project_row(mcp, project)
    assert row.monitoring_enabled and row.check_interval_hours == 4
    with mcp.factory() as db:
        outcomes = list(
            db.scalars(
                select(AuditEvent.outcome)
                .where(AuditEvent.name == "set_monitoring")
                .order_by(AuditEvent.created_at)
            )
        )
    assert outcomes == ["error", "ok", "error", "error", "ok"]
    # The owner can still relax it.
    relaxed = mcp.client.put(
        f"/api/projects/{project}/monitoring",
        json={"enabled": False, "interval_hours": 24},
        headers=mcp.headers,
    )
    assert relaxed.status_code == 200, relaxed.text


def test_alerts_only_tighten_after_inherit_is_resolved(mcp: Harness, anonymous: TestClient) -> None:
    project = scanned_project(mcp, "Acme")
    token = assistant_token(mcp, [*READ, "monitoring:tighten"])
    policy = mcp.client.put(
        "/api/notifications/policy", json={"immediate_min_severity": "medium"}, headers=mcp.headers
    )
    assert policy.status_code == 200, policy.text
    current = ok(anonymous, token, "set_alerts", project_id=project, enabled=True)
    assert current["threshold"] == "inherit" and current["effective_threshold"] == "medium"
    assert "cannot raise" in refused(
        anonymous,
        token,
        "set_alerts",
        project_id=project,
        enabled=True,
        immediate_min_severity="high",
    )
    lowered = ok(
        anonymous,
        token,
        "set_alerts",
        project_id=project,
        enabled=True,
        immediate_min_severity="low",
    )
    assert lowered["threshold"] == "low" and lowered["effective_threshold"] == "low"
    # Back to inherit would raise the effective threshold from low to medium.
    assert "cannot raise" in refused(
        anonymous,
        token,
        "set_alerts",
        project_id=project,
        enabled=True,
        immediate_min_severity="inherit",
    )
    assert "cannot turn alerts off" in refused(
        anonymous,
        token,
        "set_alerts",
        project_id=project,
        enabled=False,
        immediate_min_severity="low",
    )
    row = project_row(mcp, project)
    assert row.notifications_enabled and row.alert_min_severity == "low"
    # Alerts the owner turned off may be turned back on, at any threshold.
    off = mcp.client.put(
        f"/api/projects/{project}/notifications",
        json={"enabled": False, "immediate_min_severity": "low"},
        headers=mcp.headers,
    )
    assert off.status_code == 200, off.text
    on = ok(
        anonymous,
        token,
        "set_alerts",
        project_id=project,
        enabled=True,
        immediate_min_severity="critical",
    )
    assert on["enabled"] and on["effective_threshold"] == "critical"


def test_rescan_queues_monitor_scans_without_piling_up(mcp: Harness, anonymous: TestClient) -> None:
    project = scanned_project(mcp, "Acme")
    second = mcp.client.post(
        f"/api/projects/{project}/inventories",
        params={"filename": "package-lock.json", "target_path": "web/package-lock.json"},
        headers=mcp.headers,
        content=json.dumps(LOCKFILE).encode(),
    )
    assert second.status_code == 202, second.text
    run_once(mcp.factory, mcp.settings, mcp.store, lambda *_: report())
    token = assistant_token(mcp, [*READ, "scans:write"])
    before = active_jobs(mcp)
    first = ok(anonymous, token, "rescan_manifests", project_id=project)
    paths = [item["untrusted"]["path"] for item in first["scans"]]
    assert paths == ["package-lock.json", "web/package-lock.json"]
    assert all(item["queued"] for item in first["scans"])
    assert active_jobs(mcp) == before + len(first["scans"])
    again = ok(anonymous, token, "rescan_manifests", project_id=project)
    assert [item["scan_id"] for item in again["scans"]] == [
        item["scan_id"] for item in first["scans"]
    ]
    assert not any(item["queued"] for item in again["scans"])
    assert active_jobs(mcp) == before + len(first["scans"])
    with mcp.factory() as db:
        scan = db.get(Scan, first["scans"][0]["scan_id"])
        assert scan is not None and scan.mode == "monitor"
    # The scheduler sees the active scan too and queues nothing more for the same path.
    with mcp.factory.begin() as db:
        row = db.get(Project, project)
        assert row is not None
        row.monitoring_enabled = True
        row.next_check_at = None
        assert schedule_projects(db) == 0


def test_rescan_refuses_retired_old_and_check_inventories(
    mcp: Harness, anonymous: TestClient
) -> None:
    project = scanned_project(mcp, "Acme")
    token = assistant_token(mcp, [*READ, "scans:write", "inventories:check"])
    with mcp.factory() as db:
        old = db.scalars(select(Scan.inventory_id).where(Scan.project_id == project)).one()
    changed = json.dumps({**LOCKFILE, "version": "2.0.0"}).encode()
    assert upload(mcp, project, changed).status_code == 202
    message = refused(anonymous, token, "rescan_manifests", project_id=project, inventory_ids=[old])
    assert "older snapshot" in message

    check = ok(
        anonymous,
        token,
        "check_manifest",
        project_id=project,
        filename="package-lock.json",
        content=json.dumps({**LOCKFILE, "version": "3.0.0"}),
    )
    message = refused(
        anonymous,
        token,
        "rescan_manifests",
        project_id=project,
        inventory_ids=[check["inventory_id"]],
    )
    assert "Check inventories" in message

    retired = mcp.client.post(
        f"/api/projects/{project}/targets/retire",
        json={"target_path": "package-lock.json"},
        headers=mcp.headers,
    )
    assert retired.status_code == 200, retired.text
    with mcp.factory() as db:
        latest = db.scalars(
            select(Scan.inventory_id)
            .where(Scan.project_id == project, Scan.mode == "monitor")
            .order_by(Scan.created_at.desc())
        ).first()
    message = refused(
        anonymous, token, "rescan_manifests", project_id=project, inventory_ids=[latest]
    )
    assert "retired" in message
    # Every manifest retired: nothing to rescan, and nothing is queued.
    assert ok(anonymous, token, "rescan_manifests", project_id=project)["scans"] == []


def test_rescan_opens_findings_and_queues_alerts_like_a_scheduled_scan(
    mcp: Harness, anonymous: TestClient
) -> None:
    project = scanned_project(mcp, "Acme", report(vulnerable=False))
    with mcp.factory() as db:
        assert db.scalar(select(func.count()).select_from(Finding)) == 0
    token = assistant_token(mcp, [*READ, "scans:write"])
    started = ok(anonymous, token, "rescan_manifests", project_id=project)
    assert run_once(mcp.factory, mcp.settings, mcp.store, lambda *_: report())
    scan = ok(anonymous, token, "get_scan", scan_id=started["scans"][0]["scan_id"])
    assert scan["finished"] and scan["status"] == "succeeded"
    with mcp.factory() as db:
        assert db.scalars(select(Finding.status)).all() == ["open"]
        assert (db.scalar(select(func.count()).select_from(OutboxEvent)) or 0) >= 1

    # A failed rescan never resolves the open finding.
    again = ok(anonymous, token, "rescan_manifests", project_id=project)

    def broken(*_: object) -> object:
        raise RuntimeError("scanner unavailable")

    run_once(mcp.factory, mcp.settings, mcp.store, broken)
    with mcp.factory() as db:
        scan_row = db.get(Scan, again["scans"][0]["scan_id"])
        assert scan_row is not None and scan_row.status != "succeeded"
        assert db.scalars(select(Finding.status)).all() == ["open"]
