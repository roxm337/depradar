"""Scan history stays truthful: per-scan gate snapshots, revisions, and advisory alias splits."""

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from depradar.application.scans import run_once
from depradar.domain.entities import ChangeEvent, Finding, Scan
from depradar.domain.scanning import ScanResponse

from .conftest import Harness
from .test_ci_gate import LOCK_BYTES, advisory, evaluate, scanned
from .test_ci_tokens import bearer, create_token


def upload(client: TestClient, token: str, revision: str = "main@abc123") -> dict[str, Any]:
    response = client.post(
        "/api/ci/uploads",
        params={
            "project": "Example",
            "filename": "package-lock.json",
            "target_path": "web/package-lock.json",
            "revision": revision,
            "mode": "monitor",
        },
        content=LOCK_BYTES,
        headers=bearer(token),
    )
    assert response.status_code == 202, response.text
    return dict(response.json())


def scan_with(harness: Harness, response: ScanResponse) -> None:
    assert run_once(harness.factory, harness.settings, harness.store, lambda *_: response)


def test_old_monitor_gate_keeps_the_severity_that_scan_saw(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    first = upload(anonymous, token)["scan"]["id"]
    scan_with(harness, scanned(advisory("GHSA-aaaa", "HIGH")))
    second = upload(anonymous, token)["scan"]["id"]
    scan_with(harness, scanned(advisory("GHSA-aaaa", "LOW")))

    earlier = evaluate(anonymous, token, first).json()
    assert earlier["status"] == "fail"
    assert earlier["scans"][0]["items"][0]["severity"] == "high"
    later = evaluate(anonymous, token, second).json()
    assert later["status"] == "pass"
    assert later["scans"][0]["items"][0]["severity"] == "low"


def test_old_monitor_gate_still_follows_live_owner_decisions(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    first = upload(anonymous, token)["scan"]["id"]
    scan_with(harness, scanned(advisory("GHSA-aaaa", "HIGH")))
    finding_id = evaluate(anonymous, token, first).json()["scans"][0]["items"][0]["finding_id"]
    harness.client.post(
        f"/api/findings/{finding_id}/acknowledge",
        json={"note": "Tracked"},
        headers=harness.headers,
    )
    ignored = evaluate(anonymous, token, first, ignore_acknowledged=True).json()
    assert ignored["status"] == "pass" and ignored["ignored"] == 1


def test_same_bytes_at_a_new_commit_keep_their_own_revision(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    first = upload(anonymous, token, "main@aaaaaaa")
    scan_with(harness, scanned(advisory("GHSA-aaaa", "HIGH")))
    retried = upload(anonymous, token, "main@aaaaaaa")
    assert retried["reused_inventory"]
    second = upload(anonymous, token, "main@bbbbbbb")
    assert not second["reused_inventory"]
    while run_once(
        harness.factory,
        harness.settings,
        harness.store,
        lambda *_: scanned(advisory("GHSA-aaaa", "HIGH")),
    ):
        pass

    for body, revision in ((first, "main@aaaaaaa"), (second, "main@bbbbbbb")):
        result = evaluate(anonymous, token, body["scan"]["id"]).json()
        assert result["scans"][0]["inventory_revision"] == revision
    with harness.factory() as db:
        assert db.scalars(select(Finding)).one().revision == "main@bbbbbbb"


def merged() -> ScanResponse:
    return scanned({**advisory("GHSA-aaaa", "HIGH"), "aliases": ["CVE-2099-0001"]})


def split(complete: bool = True) -> ScanResponse:
    return scanned(
        advisory("GHSA-aaaa", "HIGH"), advisory("CVE-2099-0001", "MEDIUM"), complete=complete
    )


def findings(harness: Harness) -> list[tuple[list[str], str]]:
    with harness.factory() as db:
        rows = db.scalars(select(Finding).order_by(Finding.first_seen_at, Finding.id))
        return [(row.advisory_ids, row.status) for row in rows]


def test_advisories_reported_apart_after_a_merge_get_their_own_findings(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    upload(anonymous, token)
    scan_with(harness, merged())
    assert findings(harness) == [(["CVE-2099-0001", "GHSA-aaaa"], "open")]

    split_scan = upload(anonymous, token)["scan"]["id"]
    scan_with(harness, split())
    with harness.factory() as db:
        assert db.get(Scan, split_scan).status == "succeeded"
    assert sorted(findings(harness)) == [(["CVE-2099-0001"], "open"), (["GHSA-aaaa"], "open")]

    # The split is stable: another identical report opens and resolves nothing.
    with harness.factory() as db:
        before = len(list(db.scalars(select(ChangeEvent))))
    upload(anonymous, token)
    scan_with(harness, split())
    with harness.factory() as db:
        assert len(list(db.scalars(select(ChangeEvent)))) == before
    assert sorted(findings(harness)) == [(["CVE-2099-0001"], "open"), (["GHSA-aaaa"], "open")]


def test_partial_split_report_is_recorded_without_resolving_anything(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    upload(anonymous, token)
    scan_with(harness, merged())
    partial = upload(anonymous, token)["scan"]["id"]
    scan_with(harness, split(complete=False))
    with harness.factory() as db:
        assert db.get(Scan, partial).status == "partial"
    assert all(status == "open" for _, status in findings(harness))
    upload(anonymous, token)
    scan_with(harness, split())
    assert sorted(findings(harness)) == [(["CVE-2099-0001"], "open"), (["GHSA-aaaa"], "open")]
