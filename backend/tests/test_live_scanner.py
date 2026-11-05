import os
from pathlib import Path

import pytest

from depradar.application.scans import run_once
from depradar.infrastructure.scanner_client import RemoteScanner

from .conftest import Harness
from .test_ci_tokens import bearer, create_token
from .test_uploads import upload

FIXTURES = Path(__file__).parent / "fixtures" / "manifests"
# One long-published advisory per fixture, observed through the pinned scanner on 2026-11-04.
KNOWN_ADVISORY = {
    "Cargo.lock": "CVE-2021-25900",
    "Gemfile.lock": "CVE-2022-30122",
    "Pipfile.lock": "CVE-2024-24680",
    "bun.lock": "CVE-2021-44906",
    "composer.lock": "CVE-2022-24775",
    "go.mod": "CVE-2021-38561",
    "pnpm-lock.yaml": "CVE-2021-44906",
    "poetry.lock": "CVE-2024-35195",
    "pubspec.lock": "CVE-2020-35669",
    "pylock.toml": "CVE-2024-35195",
    "requirements.txt": "CVE-2024-24680",
    "sbom-1.7.cdx.json": "CVE-2021-44906",
    "uv.lock": "CVE-2024-35195",
    "yarn.lock": "CVE-2021-44906",
}


def test_every_fixture_names_its_known_advisory() -> None:
    # A new manifest format is accepted only with a fixture and its expected advisory.
    assert {path.name for path in FIXTURES.iterdir()} == set(KNOWN_ADVISORY)


@pytest.mark.skipif(
    not os.getenv("DEPRADAR_LIVE_SCANNER_URL"),
    reason="Real isolated scanner service is not configured",
)
def test_real_osv_scan_through_upload_worker_and_findings(
    harness: Harness, project_id: str
) -> None:
    harness.settings.scanner_url = os.environ["DEPRADAR_LIVE_SCANNER_URL"]
    response = upload(harness, project_id)
    assert response.status_code == 202
    assert run_once(
        harness.factory, harness.settings, harness.store, RemoteScanner(harness.settings)
    )
    scan_id = response.json()["scan"]["id"]
    result = harness.client.get(f"/api/scans/{scan_id}").json()
    assert result["status"] in {"succeeded", "partial"}, result
    findings = harness.client.get(f"/api/projects/{project_id}/findings").json()
    assert any("CVE-2021-44906" in f["advisory_ids"] for f in findings), findings


@pytest.mark.skipif(
    not os.getenv("DEPRADAR_LIVE_SCANNER_URL"),
    reason="Real isolated scanner service is not configured",
)
def test_real_osv_check_scan_gates_pipeline_without_changing_findings(
    harness: Harness, project_id: str
) -> None:
    harness.settings.scanner_url = os.environ["DEPRADAR_LIVE_SCANNER_URL"]
    token = create_token(harness)
    content = (Path(__file__).parents[1] / "examples" / "package-lock.json").read_bytes()
    response = harness.client.post(
        "/api/ci/uploads",
        params={"project": "Example", "filename": "package-lock.json", "mode": "check"},
        content=content,
        headers=bearer(token),
    )
    assert response.status_code == 202, response.text
    assert run_once(
        harness.factory, harness.settings, harness.store, RemoteScanner(harness.settings)
    )
    scan_id = response.json()["scan"]["id"]
    gate = harness.client.get(
        "/api/ci/evaluation", params={"scan_id": scan_id, "fail_on": "medium"}
    ).json()
    assert gate["status"] == "fail", gate
    assert any("CVE-2021-44906" in item["advisory_ids"] for item in gate["scans"][0]["items"])
    sarif = harness.client.get(
        "/api/ci/evaluation", params={"scan_id": scan_id, "format": "sarif"}
    ).json()
    assert sarif["runs"][0]["results"], sarif
    assert harness.client.get(f"/api/projects/{project_id}/findings").json() == []


@pytest.mark.skipif(
    not os.getenv("DEPRADAR_LIVE_SCANNER_URL"),
    reason="Real isolated scanner service is not configured",
)
@pytest.mark.parametrize("fixture", sorted(FIXTURES.iterdir()), ids=lambda path: path.name)
def test_every_manifest_format_detects_its_known_advisory(
    harness: Harness, project_id: str, fixture: Path
) -> None:
    """Each accepted format must reach the pinned scanner and surface a known advisory."""
    harness.settings.scanner_url = os.environ["DEPRADAR_LIVE_SCANNER_URL"]
    response = upload(harness, project_id, fixture.read_bytes(), fixture.name)
    assert response.status_code == 202, response.text
    assert run_once(
        harness.factory, harness.settings, harness.store, RemoteScanner(harness.settings)
    )
    scan = harness.client.get(f"/api/scans/{response.json()['scan']['id']}").json()
    assert scan["status"] in {"succeeded", "partial"}, scan
    assert scan["package_count"] > 0, scan
    findings = harness.client.get(f"/api/projects/{project_id}/findings").json()
    advisories = {advisory for finding in findings for advisory in finding["advisory_ids"]}
    assert KNOWN_ADVISORY[fixture.name] in advisories, sorted(advisories)
    # Package search finds the affected package under the ecosystem the scanner reported.
    known = next(f for f in findings if KNOWN_ADVISORY[fixture.name] in f["advisory_ids"])
    found = harness.client.get(
        "/api/components",
        params={"name": known["package_name"], "ecosystem": known["ecosystem"]},
    ).json()
    assert any(
        m["version"] == known["package_version"] and m["open_findings"] >= 1
        for m in found["matches"]
    ), found
    assert found["coverage"]["not_indexed"] == []


@pytest.mark.skipif(
    not os.getenv("DEPRADAR_LIVE_SCANNER_URL"),
    reason="Real isolated scanner service is not configured",
)
def test_real_osv_check_scan_through_mcp(
    harness: Harness, project_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An assistant's check scan reaches the pinned scanner and gates on the known advisory."""
    from fastapi.testclient import TestClient

    from depradar.interfaces.http.app import app
    from depradar.interfaces.mcp.context import RUNTIME

    from .test_mcp import assistant_token, ok

    harness.settings.scanner_url = os.environ["DEPRADAR_LIVE_SCANNER_URL"]
    harness.settings.mcp_enabled = True
    monkeypatch.setattr(RUNTIME, "settings", lambda: harness.settings)
    monkeypatch.setattr(RUNTIME, "factory", lambda: harness.factory)
    token = assistant_token(harness, project_id=project_id)
    assistant = TestClient(app)
    fixture = FIXTURES / "pnpm-lock.yaml"
    started = ok(
        assistant,
        token,
        "check_manifest",
        project_id=project_id,
        filename=fixture.name,
        content=fixture.read_text(),
    )
    assert run_once(
        harness.factory, harness.settings, harness.store, RemoteScanner(harness.settings)
    )
    scan = ok(assistant, token, "get_scan", scan_id=started["scan_id"])
    assert scan["finished"] and scan["status"] in {"succeeded", "partial"}, scan
    gate = ok(assistant, token, "preview_gate", scan_ids=[started["scan_id"]])
    advisories = {
        advisory
        for item in gate["scans"][0]["items"]
        for advisory in item["untrusted"]["advisory_ids"]
    }
    assert KNOWN_ADVISORY[fixture.name] in advisories, gate
    assert harness.client.get(f"/api/projects/{project_id}/findings").json() == []
