"""Package search: which current monitored manifests use a package, and how sure that answer is."""

from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from depradar.application.ports import ScannerFailure
from depradar.application.scans import run_once
from depradar.domain.components import components, normalize_name
from depradar.domain.entities import ComponentOccurrence, Inventory, Project, Scan
from depradar.domain.scanning import ScannerReport, ScanResponse

from .conftest import Harness
from .test_ci_gate import ci_upload
from .test_ci_tokens import bearer, create_token
from .test_scans import report
from .test_uploads import upload

Package = tuple[str, str, str]
DEFAULT: list[Package] = [
    ("npm", "minimist", "1.2.5"),
    ("npm", "left-pad", "1.3.0"),
    ("PyPI", "Flask_SQLAlchemy", "3.1.1"),
    ("npm", "unpinned-tool", ""),
]


def packages(*items: Package, complete: bool = True, vulnerable: bool = True) -> ScanResponse:
    """A report listing the given packages; minimist 1.2.5 carries an advisory when vulnerable."""
    advisory = report(vulnerable).report.results[0].packages[0].vulnerabilities
    listed: list[dict[str, Any]] = [
        {
            "package": {"ecosystem": ecosystem, "name": name, "version": version},
            "vulnerabilities": (
                [v.model_dump() for v in advisory]
                if (ecosystem, name, version) == ("npm", "minimist", "1.2.5")
                else []
            ),
        }
        for ecosystem, name, version in items
    ]
    return ScanResponse.model_validate(
        {
            "engine_version": "fixture",
            "complete": complete,
            "report": {"results": [{"packages": listed}]},
        }
    )


def scanned(harness: Harness, project_id: str, response: ScanResponse | None = None, **kw) -> str:
    created = upload(harness, project_id, **kw)
    assert created.status_code == 202, created.text
    result = response or packages(*DEFAULT)
    assert run_once(harness.factory, harness.settings, harness.store, lambda *_: result)
    return str(created.json()["inventory"]["id"])


def search(client: TestClient, name: str, **params: str) -> dict[str, Any]:
    response = client.get("/api/components", params={"name": name, **params})
    assert response.status_code == 200, response.text
    return dict(response.json())


def recheck(harness: Harness, inventory_id: str, response: ScanResponse | Exception) -> None:
    queued = harness.client.post(
        f"/api/inventories/{inventory_id}/scans", json={}, headers=harness.headers
    )
    assert queued.status_code == 202, queued.text

    def scanner(*_: Any) -> ScanResponse:
        if isinstance(response, Exception):
            raise response
        return response

    assert run_once(harness.factory, harness.settings, harness.store, scanner)


def rows(harness: Harness, inventory_id: str | None = None) -> list[ComponentOccurrence]:
    with harness.factory() as db:
        query = select(ComponentOccurrence).order_by(ComponentOccurrence.normalized_name)
        if inventory_id:
            query = query.where(ComponentOccurrence.inventory_id == inventory_id)
        return list(db.scalars(query))


def test_names_fold_only_where_the_registry_defines_equivalence() -> None:
    assert normalize_name("PyPI", "Flask_SQLAlchemy") == "flask-sqlalchemy"
    assert normalize_name("PyPI", "zope.interface") == normalize_name("PyPI", "Zope--Interface")
    assert normalize_name("crates.io", "Serde-JSON") == "serde_json"
    assert normalize_name("Packagist", "Symfony/Console") == "symfony/console"
    # npm, Go, RubyGems, and unknown ecosystems keep distinct spellings distinct.
    assert normalize_name("npm", "JSONStream") == "JSONStream"
    assert normalize_name("Go", "github.com/BurntSushi/toml") == "github.com/BurntSushi/toml"
    assert normalize_name("Maven", "org.Example:Lib") == "org.Example:Lib"


def test_components_deduplicate_and_keep_unpinned_packages() -> None:
    found = components(
        ScannerReport.model_validate(
            {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {
                                    "ecosystem": "PyPI",
                                    "name": "Flask_SQLAlchemy",
                                    "version": "3.1.1",
                                }
                            },
                            {
                                "package": {
                                    "ecosystem": "PyPI",
                                    "name": "flask-sqlalchemy",
                                    "version": "3.1.1",
                                }
                            },
                            {"package": {"ecosystem": "npm", "name": "tool", "version": ""}},
                        ]
                    }
                ]
            }
        )
    )
    assert [(c.name, c.normalized_name, c.version) for c in found] == [
        ("Flask_SQLAlchemy", "flask-sqlalchemy", "3.1.1"),
        ("tool", "tool", ""),
    ]


def test_monitor_scan_indexes_every_package_and_search_reports_evidence(
    harness: Harness, project_id: str
) -> None:
    inventory_id = scanned(harness, project_id)
    indexed = rows(harness, inventory_id)
    assert {(r.ecosystem, r.name, r.version) for r in indexed} == set(DEFAULT)
    scan_id = harness.client.get(f"/api/projects/{project_id}/scans").json()[0]["id"]
    assert {r.scan_id for r in indexed} == {scan_id}

    # A package without advisories is found, with where it lives and how fresh that is.
    clean = search(harness.client, "left-pad")
    assert clean["coverage"] == {
        "snapshots": 1,
        "indexed": 1,
        "ecosystems": ["PyPI", "npm"],
        "not_indexed": [],
        "partial": [],
    }
    [match] = clean["matches"]
    assert match["name"] == "left-pad" and match["version"] == "1.3.0"
    assert match["open_findings"] == 0 and match["indexed_by"]["complete"] is True
    assert match["snapshot"]["project_name"] == "Example"
    assert match["snapshot"]["target_path"] == "package-lock.json"
    assert match["indexed_by"]["scan_id"] == scan_id

    vulnerable = search(harness.client, "minimist")["matches"]
    assert [m["open_findings"] for m in vulnerable] == [1]

    # PEP 503: any spelling finds the package; the manifest's spelling is shown.
    for spelling in ("flask-sqlalchemy", "FLASK.SQLALCHEMY", "Flask_SQLAlchemy"):
        [found] = search(harness.client, spelling)["matches"]
        assert found["name"] == "Flask_SQLAlchemy" and found["ecosystem"] == "PyPI"

    # Unpinned packages answer "who uses it" with an empty version.
    [unpinned] = search(harness.client, "unpinned-tool")["matches"]
    assert unpinned["version"] == ""

    assert search(harness.client, "minimist", ecosystem="PyPI")["matches"] == []
    assert search(harness.client, "minimist", version="1.2.6")["matches"] == []
    assert len(search(harness.client, "minimist", ecosystem="npm", version="1.2.5")["matches"]) == 1
    assert search(harness.client, "absent")["matches"] == []


def test_failed_rescan_keeps_rows_and_unchanged_rescan_reattributes_them(
    harness: Harness, project_id: str
) -> None:
    inventory_id = scanned(harness, project_id)
    before = {r.id: r.scan_id for r in rows(harness, inventory_id)}

    harness.settings.max_job_attempts = 1  # fail for good on the first error
    recheck(harness, inventory_id, ScannerFailure("Scanner unavailable"))
    statuses = [s["status"] for s in harness.client.get(f"/api/projects/{project_id}/scans").json()]
    assert "failed" in statuses
    assert {r.id: r.scan_id for r in rows(harness, inventory_id)} == before
    [match] = search(harness.client, "left-pad")["matches"]
    assert match["indexed_by"]["scan_id"] in set(before.values())
    assert match["indexed_by"]["status"] == "succeeded"

    recheck(harness, inventory_id, packages(*DEFAULT))
    after = rows(harness, inventory_id)
    assert {r.id for r in after} == set(before)  # same list: rows kept, not rewritten
    assert len({r.scan_id for r in after}) == 1 and after[0].scan_id not in set(before.values())

    recheck(harness, inventory_id, packages(("npm", "left-pad", "1.3.1")))
    assert [(r.name, r.version) for r in rows(harness, inventory_id)] == [("left-pad", "1.3.1")]


def test_retention_keeps_the_indexing_scan_after_newer_failed_scans(
    harness: Harness, project_id: str
) -> None:
    # No advisories, so no change event pins the indexing scan; only its package rows do.
    inventory_id = scanned(harness, project_id, packages(*DEFAULT, vulnerable=False))
    harness.settings.max_job_attempts = 1
    recheck(harness, inventory_id, ScannerFailure("Scanner unavailable"))
    with harness.factory.begin() as db:
        scans = list(db.scalars(select(Scan).order_by(Scan.created_at)))
        assert [scan.status for scan in scans] == ["succeeded", "failed"]
        writer = scans[0].id
        for scan in scans:
            scan.created_at -= timedelta(days=400)
    response = harness.client.post("/api/maintenance/retention/run", headers=harness.headers)
    assert response.status_code == 200, response.text
    with harness.factory() as db:
        assert db.get(Scan, writer) is not None
    assert {r.scan_id for r in rows(harness, inventory_id)} == {writer}


def test_only_current_monitored_snapshots_are_searched(
    harness: Harness, project_id: str, anonymous: TestClient
) -> None:
    old = scanned(harness, project_id)
    # A pull request check of the same manifest never enters the index.
    token = create_token(harness, ["inventories:check", "scans:read"])
    check = ci_upload(anonymous, token, mode="check", target_path="package-lock.json")
    assert check.status_code == 202, check.text
    assert run_once(
        harness.factory,
        harness.settings,
        harness.store,
        lambda *_: packages(("npm", "pr-only", "1.0.0")),
    )
    assert search(harness.client, "pr-only")["matches"] == []
    assert all(r.inventory_id == old for r in rows(harness))

    # A newer snapshot that is not scanned yet makes the manifest "not indexed", never "not used".
    newer = upload(harness, project_id).json()["inventory"]["id"]
    result = search(harness.client, "left-pad")
    assert result["matches"] == []
    assert result["coverage"]["indexed"] == 0
    [pending] = result["coverage"]["not_indexed"]
    assert pending["inventory_id"] == newer and pending["project_name"] == "Example"
    assert rows(harness, old)  # history stays until retention removes the old snapshot

    # Once scanned, the new snapshot answers; the old one's rows are history only.
    assert run_once(
        harness.factory,
        harness.settings,
        harness.store,
        lambda *_: packages(("npm", "left-pad", "2.0.0")),
    )
    [match] = search(harness.client, "left-pad")["matches"]
    assert match["version"] == "2.0.0" and match["snapshot"]["inventory_id"] == newer

    retired = harness.client.post(
        f"/api/projects/{project_id}/targets/retire",
        json={"target_path": "package-lock.json"},
        headers=harness.headers,
    )
    assert retired.status_code == 200, retired.text
    result = search(harness.client, "left-pad")
    assert result["matches"] == [] and result["coverage"]["snapshots"] == 0


def test_partial_scans_label_matches_and_coverage(harness: Harness, project_id: str) -> None:
    scanned(harness, project_id, packages(*DEFAULT, complete=False))
    result = search(harness.client, "left-pad")
    [match] = result["matches"]
    assert match["indexed_by"]["complete"] is False
    assert match["indexed_by"]["status"] == "partial"
    [partial] = result["coverage"]["partial"]
    assert partial["indexed_by"]["scan_id"] == match["indexed_by"]["scan_id"]
    # A partial list qualifies a miss too: the package may be among the ones not listed.
    missing = search(harness.client, "absent")
    assert missing["matches"] == [] and len(missing["coverage"]["partial"]) == 1


def test_coverage_lists_every_project_and_superseded_scans_do_not_index(
    harness: Harness, project_id: str
) -> None:
    scanned(harness, project_id)
    other = harness.client.post("/api/projects", json={"name": "Second"}, headers=harness.headers)
    other_id = other.json()["id"]
    upload(harness, other_id)  # queued, not scanned
    coverage = harness.client.get("/api/components/coverage").json()
    assert coverage["snapshots"] == 2 and coverage["indexed"] == 1
    assert [s["project_name"] for s in coverage["not_indexed"]] == ["Second"]

    # A scan of a snapshot that a newer upload replaced does not index the old snapshot again.
    latest = upload(harness, other_id).json()["inventory"]["id"]
    assert run_once(harness.factory, harness.settings, harness.store, lambda *_: packages(*DEFAULT))
    with harness.factory() as db:
        superseded = db.scalars(select(Scan).where(Scan.status == "superseded")).all()
        assert len(superseded) == 1
        assert db.get(Inventory, superseded[0].inventory_id).project_id == other_id
    assert all(r.project_id == project_id or r.inventory_id == latest for r in rows(harness))


def test_retention_and_project_deletion_remove_rows(harness: Harness, project_id: str) -> None:
    clean = packages(*DEFAULT, vulnerable=False)
    stale = scanned(harness, project_id, clean)
    current = scanned(harness, project_id, clean)
    with harness.factory.begin() as db:
        db.get(Inventory, stale).created_at -= timedelta(days=400)
        for scan in db.scalars(select(Scan).where(Scan.inventory_id == stale)):
            scan.created_at -= timedelta(days=400)
    response = harness.client.post("/api/maintenance/retention/run", headers=harness.headers)
    assert response.status_code == 200, response.text
    with harness.factory() as db:
        assert db.get(Inventory, stale) is None
    assert rows(harness, stale) == []
    assert rows(harness, current)

    other = harness.client.post("/api/projects", json={"name": "Kept"}, headers=harness.headers)
    kept = other.json()["id"]
    scanned(harness, kept)
    deleted = harness.client.delete(f"/api/projects/{project_id}", headers=harness.headers)
    assert deleted.status_code == 204, deleted.text
    with harness.factory() as db:
        assert db.get(Project, project_id) is None
    remaining = rows(harness)
    assert remaining and all(r.project_id == kept for r in remaining)


def test_old_and_retired_snapshots_drop_their_rows_but_stay_as_evidence(
    harness: Harness, project_id: str
) -> None:
    # The first snapshot opens the minimist finding, so retention keeps it as audit evidence.
    old = scanned(harness, project_id)
    current = scanned(harness, project_id)
    assert rows(harness, old) and rows(harness, current)
    response = harness.client.post("/api/maintenance/retention/run", headers=harness.headers)
    assert response.status_code == 200, response.text
    with harness.factory() as db:
        assert db.get(Inventory, old) is not None
    assert rows(harness, old) == []
    assert {r.inventory_id for r in rows(harness)} == {current}
    assert search(harness.client, "minimist")["matches"]

    retired = harness.client.post(
        f"/api/projects/{project_id}/targets/retire",
        json={"target_path": "package-lock.json"},
        headers=harness.headers,
    )
    assert retired.status_code == 200, retired.text
    response = harness.client.post("/api/maintenance/retention/run", headers=harness.headers)
    assert response.status_code == 200, response.text
    assert rows(harness) == []


def test_package_search_needs_the_owner_session(
    harness: Harness, project_id: str, anonymous: TestClient
) -> None:
    token = create_token(harness, ["projects:read", "scans:read", "findings:read"])
    for path in ("/api/components?name=minimist", "/api/components/coverage"):
        assert anonymous.get(path).status_code == 401
        assert anonymous.get(path, headers=bearer(token)).status_code == 401
    assert harness.client.get("/api/components").status_code == 422
    assert harness.client.get("/api/components", params={"name": ""}).status_code == 422
