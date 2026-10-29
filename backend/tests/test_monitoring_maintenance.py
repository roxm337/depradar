import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from depradar.application.housekeeping import collect_files
from depradar.application.scans import claim_job, run_once
from depradar.application.scheduling import tick
from depradar.domain.entities import (
    ApiToken,
    AuthGuard,
    Base,
    Connector,
    Delivery,
    FileDeletion,
    Finding,
    Inventory,
    Job,
    NotificationPolicy,
    Owner,
    OwnerSession,
    Project,
    Scan,
    SystemState,
    utcnow,
)
from depradar.infrastructure.backups import create_backup, restore_backup

from .conftest import Harness
from .test_notifications import connect
from .test_scans import enqueue_recheck, report
from .test_uploads import LOCKFILE, upload


def test_scheduler_catches_up_once_uses_latest_inventory_and_skips_active_job(
    harness: Harness,
    project_id: str,
) -> None:
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    response = harness.client.put(
        f"/api/projects/{project_id}/monitoring",
        headers=harness.headers,
        json={"enabled": True, "interval_hours": 1},
    )
    assert response.status_code == 200
    assert tick(harness.factory, harness.settings, harness.store)["scheduled"] == 0
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    with harness.factory.begin() as db:
        project = db.get(Project, project_id)
        project.next_check_at = utcnow() - timedelta(days=7)
    assert tick(harness.factory, harness.settings, harness.store)["scheduled"] == 1
    assert tick(harness.factory, harness.settings, harness.store)["scheduled"] == 0
    with harness.factory() as db:
        assert len(list(db.scalars(select(Job)))) == 2
        assert all(s.inventory_id == inventory_id for s in db.scalars(select(Scan)))


def test_risk_acceptance_expires_and_queues_a_new_alert(harness: Harness, project_id: str) -> None:
    connect(harness)
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    with harness.factory() as db:
        finding_id = db.scalars(select(Finding)).one().id
    response = harness.client.post(
        f"/api/findings/{finding_id}/risk-acceptance",
        headers=harness.headers,
        json={
            "reason": "Temporary mitigation",
            "expires_at": (utcnow() + timedelta(days=1)).isoformat(),
        },
    )
    assert response.status_code == 200
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        assert db.scalar(select(Delivery)) is None
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    with harness.factory.begin() as db:
        finding = db.get(Finding, finding_id)
        assert finding.workflow_status == "risk_accepted"
        finding.risk_until = utcnow() - timedelta(seconds=1)
    assert tick(harness.factory, harness.settings, harness.store)["expired"] == 1
    with harness.factory() as db:
        assert db.get(Finding, finding_id).workflow_status == "open"
        assert db.scalars(select(Delivery)).one().status == "queued"
    decisions = harness.client.get(f"/api/findings/{finding_id}/decisions").json()
    assert {d["action"] for d in decisions} == {"risk_accepted", "risk_expired"}


def test_risk_requires_reason_future_and_timezone(harness: Harness, project_id: str) -> None:
    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    with harness.factory() as db:
        finding_id = db.scalars(select(Finding)).one().id
    for value in ["2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "2026-10-24T00:00:00"]:
        assert (
            harness.client.post(
                f"/api/findings/{finding_id}/risk-acceptance",
                headers=harness.headers,
                json={"reason": "Temporary", "expires_at": value},
            ).status_code
            == 422
        )


def test_project_deletion_cleans_records_and_files_and_rejects_active_scan(
    harness: Harness,
    project_id: str,
) -> None:
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    claim = claim_job(harness.factory, harness.settings)
    assert claim
    assert (
        harness.client.delete(f"/api/projects/{project_id}", headers=harness.headers).status_code
        == 409
    )
    with harness.factory.begin() as db:
        job = db.get(Job, claim[0])
        job.lease_until = utcnow() - timedelta(seconds=1)
    assert (
        harness.client.delete(f"/api/projects/{project_id}", headers=harness.headers).status_code
        == 204
    )
    with harness.factory.begin() as db:
        assert db.scalar(select(Project)) is None
        assert db.scalar(select(Inventory)) is None
        assert db.scalar(select(Scan)) is None
        assert db.scalar(select(Job)) is None
        assert db.get(FileDeletion, inventory_id)
        assert collect_files(db, harness.store) == 1
    assert not (harness.settings.storage_dir / inventory_id).exists()


def test_project_deletion_removes_findings_and_delivery_history(
    harness: Harness, project_id: str
) -> None:
    connect(harness)
    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    response = harness.client.delete(f"/api/projects/{project_id}", headers=harness.headers)
    assert response.status_code == 204, response.text
    with harness.factory() as db:
        assert db.scalar(select(Finding)) is None
        assert db.scalar(select(Delivery)) is None
        assert db.scalar(select(Connector)) is not None


def test_retention_keeps_current_inventory_and_audit_evidence(
    harness: Harness, project_id: str
) -> None:
    first = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    second = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    with harness.factory.begin() as db:
        for inventory in db.scalars(select(Inventory)):
            inventory.created_at -= timedelta(days=40)
        for scan in db.scalars(select(Scan)):
            scan.created_at -= timedelta(days=40)
    response = harness.client.post("/api/maintenance/retention/run", headers=harness.headers)
    assert response.status_code == 200, response.text
    with harness.factory() as db:
        assert db.get(Inventory, first) is None
        assert db.get(Inventory, second) is not None
    assert not (harness.settings.storage_dir / first).exists()


def test_retention_keeps_each_monorepo_manifest_and_prunes_old_checks(
    harness: Harness, project_id: str
) -> None:
    # Two clean manifests with the same filename have no change events to protect them.
    targets = ["apps/web/package-lock.json", "apps/api/package-lock.json"]
    kept = []
    for target in targets:
        response = harness.client.post(
            f"/api/projects/{project_id}/inventories",
            params={"filename": "package-lock.json", "target_path": target},
            headers=harness.headers,
            content=json.dumps(LOCKFILE).encode(),
        )
        kept.append(response.json()["inventory"]["id"])
        run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    with harness.factory.begin() as db:
        check = Inventory(
            project_id=project_id,
            filename="package-lock.json",
            target_path=targets[0],
            sha256="0" * 64,
            size_bytes=1,
            kind="check",
        )
        db.add(check)
        db.flush()
        check_id = check.id
        db.add(Scan(project_id=project_id, inventory_id=check_id, mode="check", status="succeeded"))
        for inventory in db.scalars(select(Inventory)):
            inventory.created_at -= timedelta(days=40)
        for scan in db.scalars(select(Scan)):
            scan.created_at -= timedelta(days=40)
    response = harness.client.post("/api/maintenance/retention/run", headers=harness.headers)
    assert response.status_code == 200, response.text
    with harness.factory() as db:
        assert all(db.get(Inventory, inventory_id) for inventory_id in kept)
        assert db.get(Inventory, check_id) is None
        assert db.scalar(select(Scan).where(Scan.inventory_id == check_id)) is None


def test_backups_exclude_api_tokens_and_upgrade_revision_0003(
    harness: Harness, project_id: str, tmp_path: Path
) -> None:
    import io
    import tarfile

    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    created = harness.client.post(
        "/api/tokens", json={"name": "CI", "scopes": ["scans:read"]}, headers=harness.headers
    )
    assert created.status_code == 201
    current = tmp_path / "current.tar.gz"
    manifest = create_backup(harness.factory, harness.settings.storage_dir, current)
    assert manifest["revision"] == "0004" and manifest["row_counts"]["api_token"] == 0
    # Rewrite the archive as revision 0003 would have produced it.
    legacy = tmp_path / "legacy.tar.gz"
    with tarfile.open(current, "r:gz") as source, tarfile.open(legacy, "w:gz") as target:
        files = {m.name: source.extractfile(m).read() for m in source.getmembers()}
        database = json.loads(files["database.json"])
        del database["api_token"]
        for row in database["inventory"]:
            del row["kind"]
        for row in database["scan"]:
            del row["mode"], row["results"]
        files["database.json"] = json.dumps(database).encode()
        old = json.loads(files["manifest.json"])
        old["revision"] = "0003"
        del old["row_counts"]["api_token"]
        old["files"]["database.json"] = hashlib.sha256(files["database.json"]).hexdigest()
        files["manifest.json"] = json.dumps(old).encode()
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            target.addfile(info, io.BytesIO(content))
    engine, factory = empty_database()
    restored = restore_backup(factory, tmp_path / "restored", legacy)
    assert restored["revision"] == "0004"
    with factory() as db:
        assert {scan.mode for scan in db.scalars(select(Scan))} == {"monitor"}
        assert db.scalars(select(Inventory)).one().kind == "monitor"
        assert db.scalar(select(ApiToken)) is None
    engine.dispose()


def empty_database():
    engine = create_engine("sqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory.begin() as db:
        db.add_all([AuthGuard(id=1), SystemState(id=1), NotificationPolicy(id=1)])
    return engine, factory


def test_backup_round_trip_preserves_data_hashes_and_revokes_sessions(
    harness: Harness,
    project_id: str,
    tmp_path: Path,
) -> None:
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    backup = tmp_path / "backup.tar.gz"
    manifest = create_backup(harness.factory, harness.settings.storage_dir, backup)
    assert backup.stat().st_mode & 0o777 == 0o600
    assert manifest["row_counts"]["owner_session"] == 0
    engine, factory = empty_database()
    storage = tmp_path / "restored"
    restored = restore_backup(factory, storage, backup)
    assert restored["row_counts"] == manifest["row_counts"]
    with factory() as db:
        assert db.get(Owner, 1)
        assert db.get(Project, project_id)
        assert db.scalars(select(Finding)).one().advisory_ids == ["CVE-2021-44906", "GHSA-example"]
        assert db.scalar(select(OwnerSession)) is None
    assert (storage / inventory_id).read_bytes() == (
        harness.settings.storage_dir / inventory_id
    ).read_bytes()
    with pytest.raises(ValueError, match="empty"):
        restore_backup(factory, tmp_path / "other", backup)
    engine.dispose()


def test_backup_rejects_corrupt_inventory_and_never_overwrites(
    harness: Harness,
    project_id: str,
    tmp_path: Path,
) -> None:
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    (harness.settings.storage_dir / inventory_id).write_bytes(b"changed")
    target = tmp_path / "broken.tar.gz"
    with pytest.raises(ValueError, match="checksum"):
        create_backup(harness.factory, harness.settings.storage_dir, target)
    assert not target.exists()
    target.write_text("existing-backup")
    with pytest.raises(FileExistsError):
        create_backup(harness.factory, harness.settings.storage_dir, target)
    assert target.read_text() == "existing-backup"


def test_restore_rejects_tampered_archive_before_writing(harness: Harness, tmp_path: Path) -> None:
    import io
    import tarfile

    source = tmp_path / "good.tar.gz"
    create_backup(harness.factory, harness.settings.storage_dir, source)
    tampered = tmp_path / "tampered.tar.gz"
    with tarfile.open(source, "r:gz") as original, tarfile.open(tampered, "w:gz") as changed:
        for member in original.getmembers():
            content = original.extractfile(member).read()
            if member.name == "database.json":
                content += b" "
            member.size = len(content)
            changed.addfile(member, io.BytesIO(content))
    engine, factory = empty_database()
    with pytest.raises(ValueError, match="checksum"):
        restore_backup(factory, tmp_path / "restored", tampered)
    with factory() as db:
        assert db.get(Owner, 1) is None
    engine.dispose()
