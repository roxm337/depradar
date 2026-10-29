import json
from datetime import timedelta
from typing import Any
from xml.etree import ElementTree

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from depradar.application.scans import run_once
from depradar.domain.entities import Finding, Inventory, Job, OutboxEvent, Project, Scan, utcnow
from depradar.domain.scanning import ScanResponse

from .conftest import Harness
from .test_ci_tokens import CI_SCOPES, bearer, create_token
from .test_scans import report
from .test_uploads import LOCKFILE

LOCK_BYTES = json.dumps(LOCKFILE, indent=2).encode()


def ci_upload(
    client: TestClient,
    token: str,
    *,
    project: str = "Example",
    mode: str = "monitor",
    content: bytes = LOCK_BYTES,
    target_path: str = "web/package-lock.json",
    create: bool = False,
) -> Any:
    return client.post(
        "/api/ci/uploads",
        params={
            "project": project,
            "filename": "package-lock.json",
            "target_path": target_path,
            "revision": "main@abc123",
            "mode": mode,
            "create_project": str(create).lower(),
        },
        content=content,
        headers=bearer(token),
    )


def evaluate(client: TestClient, token: str, *scan_ids: str, **policy: Any) -> Any:
    params: list[tuple[str, str]] = [("scan_id", scan_id) for scan_id in scan_ids]
    params += [(key, str(value).lower()) for key, value in policy.items()]
    return client.get("/api/ci/evaluation", params=params, headers=bearer(token))


def advisory(identifier: str, severity: str, summary: str = "Example issue") -> dict[str, Any]:
    return {
        "id": identifier,
        "summary": summary,
        "database_specific": {"severity": severity},
        "affected": [
            {
                "package": {"name": "minimist", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"fixed": "1.2.6"}]}],
            }
        ],
    }


def scanned(*vulnerabilities: dict[str, Any], complete: bool = True) -> ScanResponse:
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
                                "vulnerabilities": list(vulnerabilities),
                            }
                        ]
                    }
                ]
            },
        }
    )


def events(harness: Harness) -> int:
    with harness.factory() as db:
        return db.scalar(select(func.count()).select_from(OutboxEvent)) or 0


def test_ci_upload_resolves_projects_and_reuses_unchanged_content(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    first = ci_upload(anonymous, token)
    assert first.status_code == 202, first.text
    body = first.json()
    assert body["project"]["id"] == project_id and not body["reused_inventory"]
    assert body["inventory"]["target_path"] == "web/package-lock.json"
    assert body["scan"]["mode"] == "monitor"
    again = ci_upload(anonymous, token).json()
    # An identical upload while the scan is queued returns the same scan, not a duplicate file.
    assert again["reused_inventory"] and again["scan"]["id"] == body["scan"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    rechecked = ci_upload(anonymous, token).json()
    assert rechecked["inventory"]["id"] == body["inventory"]["id"]
    assert rechecked["scan"]["id"] != body["scan"]["id"]
    with harness.factory() as db:
        assert db.scalar(select(func.count()).select_from(Inventory)) == 1
    assert ci_upload(anonymous, token, project="acme/site").status_code == 404
    assert ci_upload(anonymous, token, project="acme/site", create=True).status_code == 403
    writer = create_token(harness, [*CI_SCOPES, "projects:write"])
    created = ci_upload(anonymous, writer, project="acme/site", create=True)
    assert created.status_code == 202 and created.json()["project_created"]
    assert created.json()["project"]["monitoring_enabled"]
    assert ci_upload(anonymous, writer, project="  ", create=True).status_code == 422


def test_check_mode_never_changes_monitored_state(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    monitored = ci_upload(anonymous, token).json()
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    assert events(harness) == 1
    # A newer check upload must neither supersede monitor scans nor become project state.
    rechecked = anonymous.post(
        f"/api/inventories/{monitored['inventory']['id']}/scans", headers=bearer(token)
    ).json()
    check = ci_upload(anonymous, token, mode="check", content=LOCK_BYTES + b"\n").json()
    assert check["inventory"]["kind"] == "check" and check["scan"]["mode"] == "check"
    assert run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    assert run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    with harness.factory() as db:
        assert db.get(Scan, rechecked["id"]).status == "succeeded"
        check_scan = db.get(Scan, check["scan"]["id"])
        assert check_scan.status == "succeeded" and check_scan.results == []
        # The clean monitor recheck resolved the finding; the check scan changed nothing.
        assert db.scalars(select(Finding)).one().status == "resolved"
    assert events(harness) == 2
    inventories = anonymous.get(
        f"/api/projects/{project_id}/inventories", headers=bearer(token)
    ).json()
    assert [row["kind"] for row in inventories] == ["monitor"]
    everything = anonymous.get(
        f"/api/projects/{project_id}/inventories?kind=all", headers=bearer(token)
    ).json()
    assert sorted(row["kind"] for row in everything) == ["check", "monitor"]


def test_gate_policy_outcomes_for_monitor_scans(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    scan_id = ci_upload(anonymous, token).json()["scan"]["id"]
    assert evaluate(anonymous, token, scan_id).status_code == 409
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    failed = evaluate(anonymous, token, scan_id).json()
    assert failed["status"] == "fail" and failed["violations"] == 1
    item = failed["scans"][0]["items"][0]
    assert item["reasons"] == ["high severity"] and item["new"]
    assert item["advisory_ids"] == ["CVE-2021-44906", "GHSA-example"]
    assert evaluate(anonymous, token, scan_id, fail_on="critical").json()["status"] == "pass"
    with harness.factory.begin() as db:
        db.scalars(select(Finding)).one().kev_known = True
    kev = evaluate(anonymous, token, scan_id, fail_on="critical").json()
    assert kev["status"] == "fail"
    assert kev["scans"][0]["items"][0]["reasons"] == ["listed in CISA KEV"]
    assert evaluate(anonymous, token, scan_id, fail_on="none", fail_on_kev=False).json()[
        "status"
    ] == ("pass")
    # A later unchanged scan detects the same finding, which is no longer new.
    recheck = ci_upload(anonymous, token).json()["scan"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    old = evaluate(anonymous, token, recheck, new_only=True).json()
    assert old["status"] == "pass" and old["scans"][0]["items"][0]["outcome"] == "ignored"
    finding_id = item["finding_id"]
    accepted = harness.client.post(
        f"/api/findings/{finding_id}/risk-acceptance",
        json={"reason": "Not reachable", "expires_at": (utcnow() + timedelta(days=7)).isoformat()},
        headers=harness.headers,
    )
    assert accepted.status_code == 200
    ignored = evaluate(anonymous, token, scan_id).json()
    assert ignored["status"] == "pass" and ignored["ignored"] == 1
    assert ignored["scans"][0]["items"][0]["reasons"][0].startswith("risk accepted until")
    assert evaluate(anonymous, token, scan_id, fail_on="sometimes").status_code == 422
    assert evaluate(anonymous, token, scan_id, unknown_option="x").status_code == 422


def test_failed_superseded_and_incomplete_scans_never_pass(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    failed = ci_upload(anonymous, token).json()["scan"]["id"]
    with harness.factory.begin() as db:
        db.scalars(select(Job)).one().attempts = harness.settings.max_job_attempts
        db.scalars(select(Job)).one().status = "running"
        db.scalars(select(Job)).one().lease_until = utcnow() - timedelta(seconds=1)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    result = evaluate(anonymous, token, failed).json()
    assert result["status"] == "error" and result["scans"][0]["error"]
    older = ci_upload(anonymous, token, content=LOCK_BYTES + b" ").json()["scan"]["id"]
    ci_upload(anonymous, token, content=LOCK_BYTES + b"  ")
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    superseded = evaluate(anonymous, token, older).json()
    assert superseded["status"] == "error" and superseded["scans"][0]["scan_status"] == (
        "superseded"
    )
    partial = ci_upload(anonymous, token, target_path="api/package-lock.json").json()
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False, False))
    scan_id = partial["scan"]["id"]
    assert evaluate(anonymous, token, scan_id).json()["status"] == "pass"
    strict = evaluate(anonymous, token, scan_id, fail_on_incomplete=True).json()
    assert strict["status"] == "fail" and not strict["scans"][0]["complete"]
    # A pass and an error together report an error.
    assert evaluate(anonymous, token, scan_id, failed).json()["status"] == "error"


def test_check_scans_apply_monitored_decisions_and_flag_new_advisories(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    ci_upload(anonymous, token)
    known = advisory("GHSA-known", "HIGH")
    run_once(harness.factory, harness.settings, harness.store, lambda *_: scanned(known))
    with harness.factory() as db:
        finding_id = db.scalars(select(Finding)).one().id
    harness.client.post(
        f"/api/findings/{finding_id}/risk-acceptance",
        json={"reason": "Mitigated", "expires_at": (utcnow() + timedelta(days=7)).isoformat()},
        headers=harness.headers,
    )
    check = ci_upload(anonymous, token, mode="check").json()["scan"]["id"]
    introduced = advisory("GHSA-introduced", "CRITICAL")
    run_once(
        harness.factory, harness.settings, harness.store, lambda *_: scanned(known, introduced)
    )
    result = evaluate(anonymous, token, check).json()
    items = {item["advisory_ids"][0]: item for item in result["scans"][0]["items"]}
    assert items["GHSA-known"]["outcome"] == "ignored" and not items["GHSA-known"]["new"]
    assert items["GHSA-introduced"]["outcome"] == "violation" and items["GHSA-introduced"]["new"]
    assert result["status"] == "fail"
    with harness.factory() as db:
        assert db.scalars(select(Finding)).one().advisory_ids == ["GHSA-known"]
        assert db.get(Project, project_id) is not None


def test_sarif_junit_and_markdown_reports(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    scan_id = ci_upload(anonymous, token).json()["scan"]["id"]
    # Advisory IDs and text come from external feeds; every format must neutralize them.
    hostile_id = "GHSA-<img src=x>|![p](https://evil.example/p.png)"
    run_once(
        harness.factory,
        harness.settings,
        harness.store,
        lambda *_: scanned(advisory(hostile_id, "HIGH", "Pollution `code`\x07 | <b>")),
    )
    sarif_response = evaluate(anonymous, token, scan_id, format="sarif")
    assert sarif_response.headers["content-type"].startswith("application/sarif+json")
    sarif = sarif_response.json()
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["automationDetails"]["id"] == "depradar/web/package-lock.json/"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == hostile_id
    assert rule["helpUri"].startswith("https://osv.dev/vulnerability/GHSA-%3Cimg")
    assert rule["properties"]["security-severity"] == "8.0"
    result = run["results"][0]
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "web/package-lock.json"
    line = LOCK_BYTES.decode().splitlines()[location["region"]["startLine"] - 1]
    assert '"node_modules/minimist"' in line
    assert result["partialFingerprints"]["primaryLocationLineHash"].endswith(":1")
    assert "\\u0007" not in json.dumps(sarif)
    junit = ElementTree.fromstring(evaluate(anonymous, token, scan_id, format="junit").content)
    assert junit.get("failures") == "1" and junit.get("tests") == "1"
    assert junit.find("testsuite/testcase/failure").get("message") == "high severity"
    markdown = evaluate(anonymous, token, scan_id, format="markdown").text
    assert markdown.startswith("## DepRadar dependency gate: FAILED")
    assert "<img" not in markdown and "](" not in markdown and "\\|" in markdown
    table_rows = [line for line in markdown.splitlines() if line.startswith("| violation")]
    assert len(table_rows) == 1 and table_rows[0].count(" | ") == 6
