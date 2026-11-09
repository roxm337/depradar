from typing import Any

from fastapi.testclient import TestClient
from httpx import Response

from .conftest import Harness
from .test_ci_tokens import bearer, create_token


def rename(harness: Harness, project_id: str, body: dict[str, Any]) -> Response:
    return harness.client.patch(f"/api/projects/{project_id}", json=body, headers=harness.headers)


def test_owner_renames_a_project_and_keeps_its_id(harness: Harness, project_id: str) -> None:
    response = rename(harness, project_id, {"name": "  acme/storefront  "})
    assert response.status_code == 200, response.text
    assert response.json()["id"] == project_id
    assert response.json()["name"] == "acme/storefront"
    detail = harness.client.get(f"/api/projects/{project_id}", headers=harness.headers)
    assert detail.json()["name"] == "acme/storefront"

    def by_name(name: str) -> list[str]:
        found = harness.client.get("/api/projects", params={"name": name}, headers=harness.headers)
        return [row["id"] for row in found.json()]

    assert by_name("acme/storefront") == [project_id]
    assert by_name("Example") == []


def test_rename_refuses_a_name_another_project_uses(harness: Harness, project_id: str) -> None:
    other = harness.client.post("/api/projects", json={"name": "Other"}, headers=harness.headers)
    assert other.status_code == 201
    response = rename(harness, project_id, {"name": "Other"})
    assert response.status_code == 409
    assert response.json()["detail"] == "Project name already exists"
    detail = harness.client.get(f"/api/projects/{project_id}", headers=harness.headers)
    assert detail.json()["name"] == "Example"


def test_rename_to_the_same_name_succeeds(harness: Harness, project_id: str) -> None:
    response = rename(harness, project_id, {"name": "Example"})
    assert response.status_code == 200
    assert response.json()["name"] == "Example"


def test_rename_validates_the_name(harness: Harness, project_id: str) -> None:
    for body in ({"name": "   "}, {"name": "x" * 121}, {}, {"name": "New", "description": "x"}):
        response = rename(harness, project_id, body)
        assert response.status_code == 422, body
    missing = harness.client.patch(
        "/api/projects/00000000-0000-0000-0000-000000000000",
        json={"name": "New"},
        headers=harness.headers,
    )
    assert missing.status_code == 404


def test_only_the_owner_renames_and_bound_tokens_follow_the_project(
    harness: Harness, project_id: str, anonymous: TestClient
) -> None:
    # Even a token that may create projects cannot rename one.
    writer = create_token(harness, ["projects:read", "projects:write"])
    refused = anonymous.patch(
        f"/api/projects/{project_id}", json={"name": "Renamed"}, headers=bearer(writer)
    )
    assert refused.status_code == 401
    bound = create_token(harness, ["projects:read"], project_id)
    assert rename(harness, project_id, {"name": "Renamed"}).is_success
    # Tokens are bound to the project ID, so they keep working under the new name.
    detail = anonymous.get(f"/api/projects/{project_id}", headers=bearer(bound))
    assert detail.status_code == 200
    assert detail.json()["name"] == "Renamed"
