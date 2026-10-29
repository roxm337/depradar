import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from depradar.config import Settings
from depradar.interfaces import scanner_service

from .test_uploads import LOCKFILE


def scanner_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    exit_code: int = 1,
    diagnostics: str = "",
    valid: bool = True,
) -> TestClient:
    # Contract double, not an OSV execution: verify process isolation and error handling.
    executable = tmp_path / "scanner-double"
    report = {
        "results": [
            {
                "packages": [
                    {
                        "package": {
                            "name": "minimist",
                            "version": "1.2.5",
                            "ecosystem": "npm",
                        },
                        "vulnerabilities": [],
                    }
                ]
            }
        ]
    }
    output = json.dumps(report) if valid else "invalid-json"
    executable.write_text(
        f"#!{sys.executable}\nimport os,sys\n"
        "assert '--no-resolve' in sys.argv\n"
        "assert '--no-call-analysis=go' in sys.argv\n"
        "assert 'DEPRADAR_TEST_SENTINEL' not in os.environ\n"
        f"print({output!r})\nprint({diagnostics!r},file=sys.stderr)\nsys.exit({exit_code})\n"
    )
    executable.chmod(0o700)
    settings = Settings(osv_binary=str(executable))
    monkeypatch.setattr(scanner_service, "get_settings", lambda: settings)
    monkeypatch.setenv("DEPRADAR_TEST_SENTINEL", "private-do-not-pass")
    return TestClient(scanner_service.app)


def test_exit_one_is_findings_not_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = scanner_client(tmp_path, monkeypatch)
    response = client.post("/scan?filename=package-lock.json", content=json.dumps(LOCKFILE))
    assert response.status_code == 200
    assert response.json()["complete"]


@pytest.mark.parametrize("exit_code,valid", [(127, True), (128, True), (0, False)])
def test_bad_results_do_not_report_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int, valid: bool
) -> None:
    client = scanner_client(tmp_path, monkeypatch, exit_code=exit_code, valid=valid)
    response = client.post("/scan?filename=package-lock.json", content=json.dumps(LOCKFILE))
    assert response.status_code == 502


def test_scanner_warning_makes_coverage_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = scanner_client(tmp_path, monkeypatch, diagnostics="WARN: incomplete extraction")
    response = client.post("/scan?filename=package-lock.json", content=json.dumps(LOCKFILE))
    assert response.status_code == 200
    assert not response.json()["complete"]
