import json

from sqlalchemy import select

from depradar.domain.entities import Inventory, Job, Scan

from .conftest import Harness

LOCKFILE = {
    "name": "example",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "example", "version": "1.0.0"},
        "node_modules/minimist": {
            "version": "1.2.5",
            "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz",
        },
    },
}


def upload(
    harness: Harness,
    project_id: str,
    data: bytes | None = None,
    filename: str = "package-lock.json",
):
    return harness.client.post(
        f"/api/projects/{project_id}/inventories",
        params={"filename": filename},
        headers=harness.headers,
        content=data if data is not None else json.dumps(LOCKFILE).encode(),
    )


def test_upload_persists_inventory_and_job_together(harness: Harness, project_id: str) -> None:
    response = upload(harness, project_id)
    assert response.status_code == 202
    body = response.json()
    assert body["scan"]["status"] == "queued"
    assert not body["scan"]["complete"]
    with harness.factory() as db:
        inventory = db.scalars(select(Inventory)).one()
        assert (harness.settings.storage_dir / inventory.id).is_file()
        assert db.scalars(select(Job)).one().scan_id == body["scan"]["id"]
        assert db.scalars(select(Scan)).one().inventory_id == inventory.id


def test_invalid_paths_formats_and_oversized_inputs(harness: Harness, project_id: str) -> None:
    assert upload(harness, project_id, filename="../../package-lock.json").status_code == 422
    assert upload(harness, project_id, filename="setup.py").status_code == 422
    assert upload(harness, project_id, data=b"not json").status_code == 422
    assert upload(harness, project_id, data=b'{"lockfileVersion":{}}').status_code == 422
    assert upload(harness, project_id, data=b"[]").status_code == 422
    harness.settings.upload_limit_bytes = 1024
    assert upload(harness, project_id, data=b"x" * 1025).status_code == 413
    with harness.factory() as db:
        assert db.scalar(select(Inventory)) is None
        assert db.scalar(select(Job)) is None


def test_duplicate_project_name_and_pagination(harness: Harness, project_id: str) -> None:
    assert (
        harness.client.post(
            "/api/projects", json={"name": "Example"}, headers=harness.headers
        ).status_code
        == 409
    )
    assert harness.client.get("/api/projects?limit=1&offset=1").json() == []
