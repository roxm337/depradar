import ast
import hashlib
import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from depradar import ci_client
from depradar.application.scans import run_once
from depradar.ci_client import Api, ClientError, api_base, ci_context, escape_command, run
from depradar.domain import inventory
from depradar.domain.entities import Finding, Inventory, Project, Scan
from depradar.domain.inventory import InventoryError, canonical_filename
from depradar.domain.scanning import ScanResponse
from depradar.interfaces.http.app import app

from .conftest import Harness
from .test_ci_gate import LOCK_BYTES
from .test_ci_tokens import CI_SCOPES, create_token
from .test_scans import report


class AppApi(Api):
    """Route the client's HTTP calls into the FastAPI app; polling advances the worker."""

    def __init__(self, token: str, advance: Callable[[], None]) -> None:
        super().__init__("http://localhost:8000/api", token)
        self.client = TestClient(app)
        self.advance = advance

    def send(
        self,
        method: str,
        path: str,
        query: list[tuple[str, str]] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, bytes]:
        if method == "GET" and path.startswith("/scans/"):
            self.advance()
        response = self.client.request(
            method,
            "/api" + path,
            params=query,
            content=body,
            headers={"Authorization": "Bearer " + self.token},
        )
        return response.status_code, response.content


def worker(harness: Harness, result: Callable[[], ScanResponse]) -> Callable[[], None]:
    def advance() -> None:
        while run_once(harness.factory, harness.settings, harness.store, lambda *_: result()):
            pass

    return advance


def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for relative in ("package-lock.json", "node_modules/dep/package-lock.json"):
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_bytes(LOCK_BYTES)
    (root / "examples").mkdir()
    (root / "examples" / "package-lock.json").write_bytes(LOCK_BYTES)
    return root


def github_env(token: str, tmp_path: Path, event: str) -> dict[str, str]:
    return {
        "DEPRADAR_TOKEN": token,
        "DEPRADAR_URL": "http://localhost:8000",
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": event,
        "GITHUB_REPOSITORY": "acme/web",
        "GITHUB_SHA": "0123456789abcdef0123",
        "GITHUB_HEAD_REF": "feature/login" if event == "pull_request" else "",
        "GITHUB_REF_NAME": "main",
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }


def invoke(
    harness: Harness, env: dict[str, str], argv: list[str], result: Callable[[], ScanResponse]
) -> tuple[int, str]:
    out = io.StringIO()
    code = run(
        argv,
        env=env,
        api_factory=lambda base, token, args: AppApi(token, worker(harness, result)),
        sleep=lambda seconds: None,
        out=out,
    )
    return code, out.getvalue()


def test_pull_request_pipeline_gates_in_check_mode(harness: Harness, tmp_path: Path) -> None:
    token = create_token(harness, [*CI_SCOPES, "projects:write"])
    root = repository(tmp_path)
    reports = {name: tmp_path / name for name in ("gate.sarif", "gate.xml", "gate.json")}
    code, output = invoke(
        harness,
        github_env(token, tmp_path, "pull_request"),
        [
            "scan",
            "--root",
            str(root),
            "--create-project",
            "--exclude",
            "examples/*",
            "--sarif",
            str(reports["gate.sarif"]),
            "--junit",
            str(reports["gate.xml"]),
            "--json",
            str(reports["gate.json"]),
        ],
        report,
    )
    assert code == 1, output
    assert "package-lock.json: uploaded (check scan" in output
    assert "::error file=package-lock.json,title=DepRadar high vulnerability::minimist@1.2.5" in (
        output
    )
    assert json.loads(reports["gate.sarif"].read_text())["version"] == "2.1.0"
    assert ElementTree.parse(reports["gate.xml"]).getroot().get("failures") == "1"
    assert json.loads(reports["gate.json"].read_text())["status"] == "fail"
    assert (tmp_path / "summary.md").read_text().startswith("## DepRadar dependency gate: FAILED")
    with harness.factory() as db:
        project = db.scalars(select(Project).where(Project.name == "acme/web")).one()
        inventory = db.scalars(select(Inventory).where(Inventory.project_id == project.id)).one()
        assert (inventory.kind, inventory.target_path) == ("check", "package-lock.json")
        assert inventory.revision == "feature/login@0123456789ab"
        # Check mode never creates monitored findings or alerts.
        assert db.scalar(select(Finding)) is None


def test_default_branch_pipeline_monitors_and_passes_when_clean(
    harness: Harness, tmp_path: Path, project_id: str
) -> None:
    token = create_token(harness)
    root = repository(tmp_path)
    env = github_env(token, tmp_path, "push")
    argv = ["scan", "package-lock.json", "--root", str(root), "--project", "Example"]
    code, output = invoke(harness, env, argv, lambda: report(False))
    assert code == 0, output
    assert "DepRadar gate PASS" in output and "monitor scan of package-lock.json: pass" in output
    with harness.factory() as db:
        assert db.scalars(select(Inventory)).one().kind == "monitor"
    # Re-running an unchanged pipeline rechecks the stored snapshot.
    code, output = invoke(harness, env, argv, lambda: report(False))
    assert code == 0 and "unchanged, rechecking" in output


def test_evaluate_command_applies_a_different_policy(
    harness: Harness, tmp_path: Path, project_id: str
) -> None:
    token = create_token(harness)
    env = github_env(token, tmp_path, "push")
    root = repository(tmp_path)
    argv = ["scan", "--root", str(root), "--project", "Example", "--exclude", "examples/*"]
    code, output = invoke(harness, env, argv, report)
    assert code == 1
    with harness.factory() as db:
        scan_id = db.scalars(select(Scan)).one().id
    code, output = invoke(harness, env, ["evaluate", scan_id, "--fail-on", "critical"], report)
    assert code == 0, output


def test_configuration_and_timeout_errors_exit_2(
    harness: Harness, tmp_path: Path, project_id: str
) -> None:
    token = create_token(harness)
    root = repository(tmp_path)
    env = github_env(token, tmp_path, "push")
    cases: list[tuple[dict[str, str], list[str], str]] = [
        ({**env, "DEPRADAR_TOKEN": ""}, ["scan"], "Set the DEPRADAR_TOKEN"),
        (
            {**env, "DEPRADAR_URL": "http://depradar.internal"},
            ["scan"],
            "plain HTTP",
        ),
        (env, ["scan", "--root", str(root), "missing.lock"], "Path not found"),
        (env, ["scan", "--root", str(root / "examples"), "--exclude", "*"], "No supported"),
        (env, ["scan", "--root", str(root), "--project", "Missing"], "HTTP 404"),
        (env, ["evaluate", "00000000-0000-4000-8000-000000000000"], "Scan not found"),
    ]
    for case_env, argv, message in cases:
        code, output = invoke(harness, case_env, argv, report)
        assert code == 2 and message in output, output
    out = io.StringIO()
    stalled = run(
        ["scan", "--root", str(root), "--project", "Example", "--timeout", "0"],
        env=env,
        api_factory=lambda base, secret, args: AppApi(secret, lambda: None),
        sleep=lambda seconds: None,
        out=out,
    )
    assert stalled == 2 and "Timed out" in out.getvalue()


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        (
            {
                "GITLAB_CI": "true",
                "CI_PROJECT_PATH": "agency/client",
                "CI_COMMIT_SHA": "a" * 40,
                "CI_MERGE_REQUEST_IID": "7",
                "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "fix",
            },
            ("gitlab", "agency/client", "fix@aaaaaaaaaaaa", True),
        ),
        (
            {
                "BITBUCKET_BUILD_NUMBER": "3",
                "BITBUCKET_REPO_FULL_NAME": "a/b",
                "BITBUCKET_COMMIT": "b" * 40,
                "BITBUCKET_BRANCH": "main",
            },
            ("bitbucket", "a/b", "main@bbbbbbbbbbbb", False),
        ),
        (
            {
                "TF_BUILD": "True",
                "BUILD_REPOSITORY_NAME": "site",
                "BUILD_SOURCEVERSION": "c" * 40,
                "BUILD_REASON": "PullRequest",
                "SYSTEM_PULLREQUEST_SOURCEBRANCH": "topic",
            },
            ("azure", "site", "topic@cccccccccccc", True),
        ),
        (
            {
                "JENKINS_URL": "https://ci",
                "JOB_NAME": "shop",
                "GIT_COMMIT": "d" * 40,
                "BRANCH_NAME": "main",
            },
            ("jenkins", "shop", "main@dddddddddddd", False),
        ),
        (
            {
                "CIRCLECI": "true",
                "CIRCLE_PROJECT_USERNAME": "acme",
                "CIRCLE_PROJECT_REPONAME": "app",
                "CIRCLE_SHA1": "e" * 40,
                "CIRCLE_PULL_REQUEST": "https://github.com/acme/app/pull/1",
            },
            ("circleci", "acme/app", "eeeeeeeeeeee", True),
        ),
        ({}, ("local", "", "", False)),
    ],
)
def test_ci_context_detects_providers(env: dict[str, str], expected: tuple[Any, ...]) -> None:
    context = ci_context(env)
    assert (
        context["provider"],
        context["repository"],
        context["revision"],
        context["change_request"],
    ) == expected


def test_url_and_workflow_command_handling() -> None:
    assert api_base("https://radar.example", False) == "https://radar.example/api"
    assert api_base("https://radar.example/api/backend/", False) == (
        "https://radar.example/api/backend"
    )
    assert api_base("http://localhost:8000", False) == "http://localhost:8000/api"
    assert api_base("http://radar.lan", True) == "http://radar.lan/api"
    with pytest.raises(ClientError):
        api_base("ftp://radar.example", False)
    assert escape_command("a\r\nb%c:d,e") == "a%0D%0Ab%25c:d,e"
    assert escape_command("x:y,z", True) == "x%3Ay%2Cz"
    assert ci_client.NoRedirect().redirect_request() is None


def test_client_matches_server_formats_and_runs_on_python_39(harness: Harness) -> None:
    assert ci_client.LOCKFILES == inventory.LOCKFILES
    names = (*ci_client.LOCKFILES, *ci_client.SBOM_NAMES, "service.cdx.json", "requirements-ci.txt")
    for name in names:
        assert ci_client.supported(name) and canonical_filename(name)
    for name in ("setup.py", "package.json", "requirements.in"):
        assert not ci_client.supported(name)
        with pytest.raises(InventoryError):
            canonical_filename(name)
    source = Path(ci_client.__file__).read_bytes()
    # CI images often lag behind; the downloadable client must parse on Python 3.9.
    ast.parse(source, feature_version=(3, 9))
    response = harness.client.get("/api/ci/client.py")
    assert response.status_code == 200 and response.content == source
    assert response.headers["x-content-sha256"] == hashlib.sha256(source).hexdigest()
