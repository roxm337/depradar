import io
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from depradar.application.ports import IdentityRejected
from depradar.application.scans import run_once
from depradar.ci_client import run
from depradar.domain.entities import ApiToken, Inventory, TrustedIdentity
from depradar.domain.identity import IdentityMismatch, access_for, same_repository, verified_run
from depradar.infrastructure.oidc import JwksVerifier
from depradar.interfaces.http.app import app
from depradar.interfaces.http.dependencies import identity_verifier

from .conftest import Harness
from .oidc_fixture import GITHUB, GITLAB, SHA, Issuer, github_claims, gitlab_claims
from .test_ci_client import AppApi, github_env, repository, worker
from .test_ci_gate import LOCK_BYTES, ci_upload
from .test_ci_tokens import bearer
from .test_scans import report

AUDIENCE = "http://localhost:8000"


@pytest.fixture(scope="module")
def issuer() -> Issuer:
    return Issuer()


@pytest.fixture
def verifier(harness: Harness, issuer: Issuer) -> Iterator[JwksVerifier]:
    instance = JwksVerifier(fetch=issuer.fetch)
    app.dependency_overrides[identity_verifier] = lambda: instance
    yield instance


def binding(**values: Any) -> TrustedIdentity:
    defaults: dict[str, Any] = {
        "project_id": "p",
        "name": "web",
        "provider": "github",
        "issuer": GITHUB,
        "repository": "acme/web",
        "repository_id": "4242",
        "workflow": ".github/workflows/depradar.yml",
        "monitor_ref": "refs/heads/main",
    }
    return TrustedIdentity(**{**defaults, **values})


def github_run(**claims: Any) -> Any:
    return verified_run("github", GITHUB, github_claims(AUDIENCE, **claims))


@pytest.mark.parametrize(
    ("claims", "access"),
    [
        ({}, "monitor"),
        ({"event": "schedule"}, "monitor"),
        ({"event": "workflow_dispatch"}, "monitor"),
        ({"event": "pull_request", "ref": "refs/pull/7/merge"}, "check"),
        # pull_request_target runs on the base branch with secrets but may run PR code.
        ({"event": "pull_request_target"}, "check"),
        ({"event": "merge_group"}, "check"),
        ({"ref": "refs/heads/feature"}, "check"),
        ({"ref": "refs/tags/v1.0.0"}, "check"),
    ],
)
def test_only_reviewed_runs_of_the_monitor_branch_may_monitor(
    claims: dict[str, Any], access: str
) -> None:
    run_ = github_run(**claims)
    assert same_repository(binding(), run_)
    assert access_for(binding(), run_) == access
    assert access_for(binding(monitor_ref=None), run_) == "check"


def test_runs_are_bound_to_repository_identity_and_workflow() -> None:
    run_ = github_run()
    assert run_.workflow == ".github/workflows/depradar.yml"
    assert run_.run_url == "https://github.com/acme/web/actions/runs/777"
    assert run_.revision() == "main@0123456789ab"
    assert github_run(event="pull_request", head_ref="feat/x").revision() == "feat/x@0123456789ab"
    # A deleted and re-created namesake has a new repository ID.
    assert not same_repository(binding(), github_run(repository_id="9999"))
    assert not same_repository(binding(), github_run(repository="acme/other"))
    assert not same_repository(binding(issuer="https://ghe.example.com/_services/token"), run_)
    assert same_repository(binding(repository_id=None, repository="ACME/Web"), run_)
    with pytest.raises(IdentityMismatch, match="not the trusted workflow"):
        access_for(binding(), github_run(workflow=".github/workflows/release.yml"))
    assert access_for(binding(workflow=None), github_run(workflow=".github/workflows/x.yml"))
    with pytest.raises(IdentityMismatch, match="sha"):
        verified_run("github", GITHUB, {**github_claims(AUDIENCE), "sha": "not-a-commit"})


def test_gitlab_runs_need_a_protected_branch_to_monitor() -> None:
    gitlab = binding(
        provider="gitlab",
        issuer=GITLAB,
        repository="acme/api",
        repository_id="99",
        workflow=".gitlab-ci.yml",
    )
    pushed = verified_run("gitlab", GITLAB, gitlab_claims(AUDIENCE))
    assert pushed.ref == "refs/heads/main" and pushed.workflow == ".gitlab-ci.yml"
    assert pushed.run_url == f"{GITLAB}/acme/api/-/jobs/556"
    assert access_for(gitlab, pushed) == "monitor"
    unprotected = verified_run("gitlab", GITLAB, gitlab_claims(AUDIENCE, protected=False))
    assert access_for(gitlab, unprotected) == "check"
    merge_request = gitlab_claims(AUDIENCE, source="merge_request_event")
    assert access_for(gitlab, verified_run("gitlab", GITLAB, merge_request)) == "check"


def test_verifier_checks_signature_issuer_algorithm_audience_and_lifetime(issuer: Issuer) -> None:
    verifier = JwksVerifier(fetch=issuer.fetch)
    trusted = {GITHUB}
    token = issuer.sign(github_claims(AUDIENCE))
    assert verifier(token, trusted, AUDIENCE)["repository"] == "acme/web"
    listed = issuer.sign({**github_claims(AUDIENCE), "aud": ["other", AUDIENCE]})
    assert verifier(listed, trusted, AUDIENCE)["sha"] == SHA

    def rejected(value: str, message: str, issuers: set[str] = trusted) -> None:
        with pytest.raises(IdentityRejected, match=message):
            verifier(value, issuers, AUDIENCE)

    header, payload, signature = token.split(".")
    tampered = issuer.sign({**github_claims(AUDIENCE), "repository": "evil/repo"}).split(".")[1]
    rejected(f"{header}.{tampered}.{signature}", "signature is invalid")
    rejected(issuer.sign(github_claims(AUDIENCE), key=Issuer().key), "signature is invalid")
    rejected(issuer.sign(github_claims(AUDIENCE), alg="HS256"), "RS256")
    rejected(f"{header.replace(header, 'eyJhbGciOiJub25lIn0')}.{payload}.", "RS256")
    rejected(issuer.sign(github_claims("https://other.example")), "audience must be")
    rejected(issuer.sign(github_claims(AUDIENCE, lifetime=-120)), "expired")
    rejected(issuer.sign({**github_claims(AUDIENCE), "nbf": 2**40}), "not valid yet")
    rejected("not-a-token", "malformed")
    rejected(f"{header}.{payload}.%%%", "malformed")
    # Keys are never fetched for an issuer the owner does not trust.
    before = len(issuer.fetches)
    rejected(token, "untrusted issuer", {"https://gitlab.com"})
    assert len(issuer.fetches) == before


def test_verifier_caches_keys_and_limits_refetching(issuer: Issuer) -> None:
    clock = [1000.0]
    verifier = JwksVerifier(fetch=issuer.fetch, clock=lambda: clock[0])
    trusted = {GITHUB}
    claims_clock = github_claims(AUDIENCE)
    claims_clock.update(iat=900, nbf=900, exp=2000)
    token = issuer.sign(claims_clock)
    issuer.fetches.clear()
    verifier(token, trusted, AUDIENCE)
    verifier(token, trusted, AUDIENCE)
    assert len(issuer.fetches) == 2  # discovery and key set, once
    rotated = issuer.sign(claims_clock, kid="key-2")
    with pytest.raises(IdentityRejected, match="unknown key"):
        verifier(rotated, trusted, AUDIENCE)
    assert len(issuer.fetches) == 2  # fetched under a minute ago
    clock[0] += 61
    with pytest.raises(IdentityRejected, match="unknown key"):
        verifier(rotated, trusted, AUDIENCE)
    assert len(issuer.fetches) == 4
    small = Issuer(bits=1024)
    with pytest.raises(IdentityRejected, match="unknown key"):
        JwksVerifier(fetch=small.fetch)(small.sign(github_claims(AUDIENCE)), trusted, AUDIENCE)
    elsewhere = Issuer()
    elsewhere.jwks_uri = "https://keys.example.net/jwks"
    with pytest.raises(IdentityRejected, match="unexpected URL"):
        JwksVerifier(fetch=elsewhere.fetch)(
            elsewhere.sign(github_claims(AUDIENCE)), trusted, AUDIENCE
        )


def add_identity(harness: Harness, project_id: str, **values: Any) -> Any:
    body = {
        "project_id": project_id,
        "provider": "github",
        "repository": "acme/web",
        "repository_id": "4242",
        "workflow": "./.github/workflows/depradar.yml",
        "monitor_ref": "main",
        **values,
    }
    return harness.client.post("/api/identities", json=body, headers=harness.headers)


def exchange(client: TestClient, token: str, project: str | None = None) -> Any:
    body: dict[str, Any] = {"id_token": token}
    if project:
        body["project"] = project
    return client.post("/api/ci/identity/exchange", json=body)


def test_owner_manages_trusted_identities(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    created = add_identity(harness, project_id)
    assert created.status_code == 201, created.text
    identity = created.json()
    assert identity["workflow"] == ".github/workflows/depradar.yml"
    assert identity["monitor_ref"] == "refs/heads/main" and identity["issuer"] == GITHUB
    assert add_identity(harness, project_id).status_code == 409
    assert add_identity(harness, project_id, repository="not a repo").status_code == 422
    insecure = add_identity(harness, project_id, issuer="http://gitlab.internal")
    assert insecure.status_code == 422
    listed = harness.client.get("/api/identities").json()
    assert listed["audience"] == AUDIENCE and len(listed["identities"]) == 1
    assert anonymous.get("/api/ci/oidc").json() == {"audience": AUDIENCE}
    assert anonymous.get("/api/identities").status_code == 401
    removed = harness.client.delete(f"/api/identities/{identity['id']}", headers=harness.headers)
    assert removed.status_code == 204
    assert harness.client.get("/api/identities").json()["identities"][0]["disabled_at"]
    assert add_identity(harness, project_id).status_code == 201


def test_exchanged_tokens_follow_the_verified_run(
    harness: Harness,
    anonymous: TestClient,
    project_id: str,
    issuer: Issuer,
    verifier: JwksVerifier,
) -> None:
    assert exchange(anonymous, issuer.sign(github_claims(AUDIENCE))).status_code == 401
    identity_id = add_identity(harness, project_id).json()["id"]
    pull = github_claims(AUDIENCE, event="pull_request", ref="refs/pull/7/merge", head_ref="feat")
    checked = exchange(anonymous, issuer.sign(pull))
    assert checked.status_code == 201, checked.text
    grant = checked.json()
    assert grant["access"] == "check" and "inventories:write" not in grant["scopes"]
    assert grant["project_id"] == project_id and grant["identity_id"] == identity_id
    denied = ci_upload(anonymous, grant["token"])
    assert denied.status_code == 403 and "check manifests" in denied.json()["detail"]
    check = ci_upload(anonymous, grant["token"], mode="check")
    assert check.status_code == 202, check.text
    # The verified branch and commit replace whatever the request claimed.
    assert check.json()["inventory"]["revision"] == "feat@0123456789ab"
    while run_once(harness.factory, harness.settings, harness.store, lambda *_: report()):
        pass
    decision = anonymous.post(
        "/api/ci/decisions",
        json={"scan_ids": [check.json()["scan"]["id"]]},
        headers=bearer(grant["token"]),
    ).json()
    summary = harness.client.get("/api/ci/decisions").json()[0]
    assert summary["id"] == decision["decision_id"] and summary["commit"] == SHA
    actor = summary["actor"]
    assert actor["kind"] == "identity" and actor["verified"]
    assert (
        actor["event"] == "pull_request" and actor["workflow"] == ".github/workflows/depradar.yml"
    )
    assert actor["run_url"] == "https://github.com/acme/web/actions/runs/777"
    monitor = exchange(anonymous, issuer.sign(github_claims(AUDIENCE))).json()
    assert monitor["access"] == "monitor" and "inventories:write" in monitor["scopes"]
    uploaded = ci_upload(anonymous, monitor["token"])
    assert uploaded.status_code == 202 and uploaded.json()["inventory"]["kind"] == "monitor"
    # Projects cannot be created through an identity, and other projects are invisible.
    assert ci_upload(anonymous, monitor["token"], project="other", create=True).status_code == 403
    wrong_repo = exchange(anonymous, issuer.sign(github_claims(AUDIENCE, repository="acme/x")))
    assert wrong_repo.status_code == 403 and "acme/x" in wrong_repo.json()["detail"]
    release = github_claims(AUDIENCE, workflow=".github/workflows/release.yml")
    assert exchange(anonymous, issuer.sign(release)).status_code == 403
    # The project hint only breaks ties, so a repository-named default never blocks the exchange.
    hinted = exchange(anonymous, issuer.sign(github_claims(AUDIENCE)), "acme/web")
    assert hinted.status_code == 201 and hinted.json()["project_id"] == project_id
    dashboard = anonymous.post(
        f"/api/projects/{project_id}/inventories",
        params={"filename": "package-lock.json", "revision": "release@forged"},
        content=LOCK_BYTES + b"\n",
        headers=bearer(monitor["token"]),
    )
    assert dashboard.status_code == 202, dashboard.text
    assert dashboard.json()["inventory"]["revision"] == "main@0123456789ab"
    assert exchange(anonymous, issuer.sign(github_claims("https://x.example"))).status_code == 401
    # Exchanged tokens never appear among the owner's tokens and cannot be revoked there.
    assert harness.client.get("/api/tokens").json() == []
    with harness.factory() as db:
        exchanged = db.scalars(select(ApiToken).where(ApiToken.kind == "identity")).all()
        assert len(exchanged) == 3 and all(row.claims for row in exchanged)
        monitored = db.scalars(select(Inventory).where(Inventory.kind == "monitor")).all()
        assert {row.revision for row in monitored} == {"main@0123456789ab"}
    assert (
        harness.client.delete(f"/api/tokens/{exchanged[0].id}", headers=harness.headers).status_code
        == 404
    )
    harness.client.delete(f"/api/identities/{identity_id}", headers=harness.headers)
    assert anonymous.get("/api/projects", headers=bearer(monitor["token"])).status_code == 401
    assert exchange(anonymous, issuer.sign(github_claims(AUDIENCE))).status_code == 401


def test_a_repository_trusted_by_several_projects_needs_a_project(
    harness: Harness,
    anonymous: TestClient,
    project_id: str,
    issuer: Issuer,
    verifier: JwksVerifier,
) -> None:
    other = harness.client.post("/api/projects", json={"name": "Other"}, headers=harness.headers)
    add_identity(harness, project_id)
    add_identity(harness, other.json()["id"], monitor_ref=None)
    token = issuer.sign(github_claims(AUDIENCE))
    assert exchange(anonymous, token).status_code == 409
    chosen = exchange(anonymous, token, "Other").json()
    assert chosen["project_name"] == "Other" and chosen["access"] == "check"
    assert exchange(anonymous, token, project_id).json()["access"] == "monitor"
    assert exchange(anonymous, token, "Unrelated").status_code == 403


def test_ci_client_authenticates_with_the_job_identity(
    harness: Harness, tmp_path: Any, project_id: str, issuer: Issuer, verifier: JwksVerifier
) -> None:
    add_identity(harness, project_id)
    root = repository(tmp_path)
    env = github_env("", tmp_path, "pull_request")
    env.update(
        ACTIONS_ID_TOKEN_REQUEST_URL="https://pipelines.example/token?api-version=2.0",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN="runner-secret",
    )
    requested: list[str] = []

    def id_token(environment: Any, audience: str) -> str:
        requested.append(audience)
        claims = github_claims(
            audience, event="pull_request", ref="refs/pull/7/merge", head_ref="feature/login"
        )
        return issuer.sign(claims)

    out = io.StringIO()
    code = run(
        ["scan", "--root", str(root), "--exclude", "examples/*"],
        env=env,
        api_factory=lambda base, token, args: AppApi(token, worker(harness, report)),
        sleep=lambda seconds: None,
        out=out,
        id_token=id_token,
    )
    output = out.getvalue()
    assert code == 1, output
    assert requested == [AUDIENCE]
    assert "Verified CI identity: check access to Example" in output
    assert "::add-mask::depradar_" in output and "Decision " in output
    summary = harness.client.get("/api/ci/decisions").json()[0]
    assert summary["actor"]["verified"] and summary["mode"] == "check"
    explicit = io.StringIO()
    refused = run(
        ["scan", "--root", str(root), "--mode", "monitor"],
        env=env,
        api_factory=lambda base, token, args: AppApi(token, worker(harness, report)),
        sleep=lambda seconds: None,
        out=explicit,
        id_token=id_token,
    )
    assert refused == 2 and "trusted for check uploads only" in explicit.getvalue()
    bare = io.StringIO()
    missing = run(
        ["scan", "--root", str(root)],
        env={key: value for key, value in env.items() if not key.startswith("ACTIONS_ID")},
        out=bare,
    )
    assert missing == 2 and "OIDC identity" in bare.getvalue()
