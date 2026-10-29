import hashlib
import json
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from depradar.domain.entities import ApiToken, utcnow
from depradar.domain.tokens import generate_token, well_formed

from .conftest import Harness
from .test_uploads import LOCKFILE

CI_SCOPES = ["projects:read", "inventories:write", "scans:read", "findings:read"]


def create_token(
    harness: Harness, scopes: list[str] | None = None, project_id: str | None = None
) -> str:
    response = harness.client.post(
        "/api/tokens",
        json={"name": "CI", "scopes": scopes or CI_SCOPES, "project_id": project_id},
        headers=harness.headers,
    )
    assert response.status_code == 201, response.text
    return str(response.json()["token"])


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_token_format_has_prefix_and_offline_checksum() -> None:
    token = generate_token()
    assert token.startswith("depradar_") and len(token) == 47 and well_formed(token)
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert not well_formed(tampered)
    assert not well_formed("ghp_" + token[4:])


def test_token_lifecycle_scopes_and_revocation(harness: Harness, anonymous: TestClient) -> None:
    token = create_token(harness, ["projects:read", "scans:read"])
    listed = harness.client.get("/api/tokens").json()
    assert len(listed) == 1 and "token" not in listed[0] and "token_hash" not in listed[0]
    assert listed[0]["display_prefix"] == token[:15]
    with harness.factory() as db:
        row = db.scalars(select(ApiToken)).one()
        assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert token not in json.dumps([str(value) for value in row.__dict__.values()])
        assert row.last_used_at is None
    assert anonymous.get("/api/projects", headers=bearer(token)).status_code == 200
    with harness.factory() as db:
        assert db.scalars(select(ApiToken)).one().last_used_at is not None
    # Missing scope, session-only operations, and token management are all refused.
    denied = anonymous.post("/api/projects", json={"name": "x"}, headers=bearer(token))
    assert denied.status_code == 403 and "projects:write" in denied.json()["detail"]
    assert anonymous.get("/api/connectors", headers=bearer(token)).status_code == 401
    assert anonymous.get("/api/jobs", headers=bearer(token)).status_code == 401
    assert anonymous.get("/api/tokens", headers=bearer(token)).status_code == 401
    revoke = harness.client.delete(f"/api/tokens/{listed[0]['id']}", headers=harness.headers)
    assert revoke.status_code == 204
    assert anonymous.get("/api/projects", headers=bearer(token)).status_code == 401
    assert harness.client.get("/api/tokens").json()[0]["revoked_at"] is not None


def test_malformed_expired_and_foreign_credentials_are_rejected(
    harness: Harness, anonymous: TestClient
) -> None:
    token = create_token(harness)
    for header in (
        "Bearer " + token[:-1] + ("A" if token[-1] != "A" else "B"),
        "Bearer " + generate_token(),
        "Basic " + token,
        "",
    ):
        response = anonymous.get("/api/projects", headers={"Authorization": header})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
    with harness.factory.begin() as db:
        db.scalars(select(ApiToken)).one().expires_at = utcnow() - timedelta(seconds=1)
    assert anonymous.get("/api/projects", headers=bearer(token)).status_code == 401


def test_token_requests_skip_csrf_while_session_mutations_still_require_it(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    token = create_token(harness)
    url = f"/api/projects/{project_id}/inventories"
    params = {"filename": "package-lock.json"}
    content = json.dumps(LOCKFILE).encode()
    assert harness.client.post(url, params=params, content=content).status_code == 403
    response = anonymous.post(url, params=params, content=content, headers=bearer(token))
    assert response.status_code == 202


def test_project_restricted_token_cannot_see_or_create_other_projects(
    harness: Harness, anonymous: TestClient, project_id: str
) -> None:
    other = harness.client.post("/api/projects", json={"name": "Other"}, headers=harness.headers)
    other_id = other.json()["id"]
    token = create_token(harness, project_id=project_id)
    projects = anonymous.get("/api/projects", headers=bearer(token)).json()
    assert [project["id"] for project in projects] == [project_id]
    for path in (f"/api/projects/{other_id}", f"/api/projects/{other_id}/findings"):
        assert anonymous.get(path, headers=bearer(token)).status_code == 404
    upload = anonymous.post(
        f"/api/projects/{other_id}/inventories",
        params={"filename": "package-lock.json"},
        content=json.dumps(LOCKFILE).encode(),
        headers=bearer(token),
    )
    assert upload.status_code == 404
    refused = harness.client.post(
        "/api/tokens",
        json={"name": "bad", "scopes": ["projects:write"], "project_id": project_id},
        headers=harness.headers,
    )
    assert refused.status_code == 422
    # Deleting the project removes its restricted tokens instead of widening them.
    assert harness.client.delete(f"/api/projects/{project_id}", headers=harness.headers).is_success
    with harness.factory() as db:
        assert db.scalar(select(ApiToken)) is None
