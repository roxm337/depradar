from datetime import timedelta

from sqlalchemy import select

from depradar.domain.entities import AuthGuard, OwnerSession, utcnow

from .conftest import Harness


def test_owner_bootstrap_is_single_use(harness: Harness) -> None:
    result = harness.client.post(
        "/api/auth/bootstrap",
        json={"password": "another-password"},
        headers={"X-Bootstrap-Token": "test-token-" * 4},
    )
    assert result.status_code == 409


def test_session_csrf_origin_and_logout(harness: Harness) -> None:
    client = harness.client
    assert client.post("/api/projects", json={"name": "blocked"}).status_code == 403
    assert (
        client.post(
            "/api/projects",
            json={"name": "blocked"},
            headers={
                **harness.headers,
                "Origin": "https://untrusted.example",
            },
        ).status_code
        == 403
    )
    assert client.get("/api/auth/me").json()["csrf_token"] == harness.headers["X-CSRF-Token"]
    assert client.post("/api/auth/logout", headers=harness.headers).status_code == 204
    assert client.get("/api/projects").status_code == 401
    result = client.post("/api/auth/login", json={"password": "developer-password"})
    assert result.status_code == 200
    cookie = result.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_expired_session_is_rejected(harness: Harness) -> None:
    with harness.factory.begin() as db:
        session = db.scalars(select(OwnerSession)).one()
        session.expires_at = utcnow() - timedelta(seconds=1)
    assert harness.client.get("/api/projects").status_code == 401


def test_login_failures_persist_and_rate_limit(harness: Harness) -> None:
    for _ in range(10):
        assert (
            harness.client.post(
                "/api/auth/login",
                json={
                    "password": "wrong-password-value",
                },
            ).status_code
            == 401
        )
    assert (
        harness.client.post(
            "/api/auth/login",
            json={
                "password": "developer-password",
            },
        ).status_code
        == 429
    )
    with harness.factory.begin() as db:
        guard = db.get(AuthGuard, 1)
        assert guard is not None and guard.failures == 10
        guard.window_start = utcnow() - timedelta(minutes=16)
    assert (
        harness.client.post(
            "/api/auth/login",
            json={
                "password": "developer-password",
            },
        ).status_code
        == 200
    )
