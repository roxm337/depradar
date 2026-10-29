import os
from pathlib import Path

import pytest

from depradar.application.scans import run_once
from depradar.infrastructure.scanner_client import RemoteScanner

from .conftest import Harness
from .test_ci_tokens import bearer, create_token
from .test_uploads import upload


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
