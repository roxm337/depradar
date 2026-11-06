import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, inspect, text

from depradar.application.scans import claim_job

from .conftest import Harness
from .test_uploads import upload

pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(
        not os.getenv("DEPRADAR_TEST_DATABASE_URL"),
        reason="PostgreSQL test URL is not configured",
    ),
]


def test_concurrent_workers_claim_distinct_jobs(harness: Harness, project_id: str) -> None:
    upload(harness, project_id)
    upload(harness, project_id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda _: claim_job(harness.factory, harness.settings), range(2)))
    assert all(claim is not None for claim in claims)
    assert claims[0][0] != claims[1][0]


def test_initial_migration_up_and_down(monkeypatch: pytest.MonkeyPatch) -> None:
    # Migrate only a random disposable schema; never drop the configured database.
    from alembic import command
    from alembic.config import Config

    from depradar.config import get_settings

    schema = "migration_test_" + uuid4().hex
    url = os.environ["DEPRADAR_TEST_DATABASE_URL"]
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    with engine.connect() as connection:
        connection.execute(text(f'SET search_path TO "{schema}"'))
        connection.commit()
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        assert "owner" in inspect(connection).get_table_names(schema=schema)
        assert connection.execute(text("SELECT count(*) FROM auth_guard")).scalar_one() == 1
        connection.commit()
        command.downgrade(config, "base")
        assert "owner" not in inspect(connection).get_table_names(schema=schema)
        connection.commit()
    with engine.begin() as connection:
        connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    engine.dispose()
    get_settings.cache_clear()


def test_populated_database_upgrades_from_0003_and_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing rows survive 0004 and 0005 and get the defaults the application relies on."""
    from alembic import command
    from alembic.config import Config

    from depradar.config import get_settings

    schema = "migration_data_" + uuid4().hex
    url = os.environ["DEPRADAR_TEST_DATABASE_URL"]
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    project, inventory, scan = (str(uuid4()) for _ in range(3))
    try:
        with engine.connect() as connection:
            connection.execute(text(f'SET search_path TO "{schema}"'))
            connection.commit()
            config.attributes["connection"] = connection
            command.upgrade(config, "0003")
            connection.execute(
                text(
                    "INSERT INTO project (id, name, description, created_at, monitoring_enabled,"
                    " check_interval_hours, notifications_enabled)"
                    " VALUES (:id, 'Legacy', '', now(), true, 24, true)"
                ),
                {"id": project},
            )
            connection.execute(
                text(
                    "INSERT INTO inventory (id, project_id, filename, target_path, sha256,"
                    " size_bytes, created_at) VALUES (:id, :project, 'package-lock.json',"
                    " 'web/package-lock.json', :sha, 10, now())"
                ),
                {"id": inventory, "project": project, "sha": "0" * 64},
            )
            connection.execute(
                text(
                    "INSERT INTO scan (id, inventory_id, project_id, status, complete,"
                    " package_count, coverage_notes, created_at)"
                    " VALUES (:id, :inventory, :project, 'succeeded', true, 3, '[]', now())"
                ),
                {"id": scan, "inventory": inventory, "project": project},
            )
            connection.commit()
            command.upgrade(config, "head")
            row = connection.execute(
                text("SELECT kind, retired_at FROM inventory WHERE id = :id"), {"id": inventory}
            ).one()
            assert tuple(row) == ("monitor", None)
            mode, results = connection.execute(
                text("SELECT mode, results FROM scan WHERE id = :id"), {"id": scan}
            ).one()
            assert (mode, results) == ("monitor", None)
            connection.commit()
            command.downgrade(config, "0003")
            assert connection.execute(text("SELECT count(*) FROM scan")).scalar_one() == 1
            assert "retired_at" not in {
                column["name"] for column in inspect(connection).get_columns("inventory", schema)
            }
            connection.commit()
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
        get_settings.cache_clear()


def test_populated_database_upgrades_from_0005_and_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """0006 keeps owner tokens, matches the ORM schema, and downgrades without identity tokens."""
    from alembic import command
    from alembic.autogenerate import compare_metadata
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext

    from depradar.config import get_settings
    from depradar.domain.entities import Base

    schema = "migration_0006_" + uuid4().hex
    url = os.environ["DEPRADAR_TEST_DATABASE_URL"]
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    project, identity = str(uuid4()), str(uuid4())
    added = {"trusted_identity", "security_policy", "gate_decision"}
    try:
        with engine.connect() as connection:
            connection.execute(text(f'SET search_path TO "{schema}"'))
            connection.commit()
            config.attributes["connection"] = connection
            command.upgrade(config, "0005")
            connection.execute(
                text(
                    "INSERT INTO project (id, name, description, created_at, monitoring_enabled,"
                    " check_interval_hours, notifications_enabled)"
                    " VALUES (:id, 'Legacy', '', now(), true, 24, true)"
                ),
                {"id": project},
            )
            connection.execute(
                text(
                    "INSERT INTO api_token (id, name, token_hash, display_prefix, scopes,"
                    " created_at, expires_at) VALUES (:id, 'CI', :hash, 'depradar_abc',"
                    " '[\"scans:read\"]', now(), now() + interval '1 day')"
                ),
                {"id": str(uuid4()), "hash": "1" * 64},
            )
            connection.commit()
            command.upgrade(config, "head")
            assert connection.execute(text("SELECT kind FROM api_token")).scalar_one() == "static"
            drift = [
                change
                for change in compare_metadata(
                    MigrationContext.configure(connection), Base.metadata
                )
                if any(name in str(change) for name in added | {"api_token"})
            ]
            assert drift == []
            connection.execute(
                text(
                    "INSERT INTO trusted_identity (id, project_id, name, provider, issuer,"
                    " repository, created_at) VALUES (:id, :project, 'web', 'github',"
                    " 'https://token.actions.githubusercontent.com', 'acme/web', now())"
                ),
                {"id": identity, "project": project},
            )
            connection.execute(
                text(
                    "INSERT INTO api_token (id, name, token_hash, display_prefix, scopes,"
                    " created_at, expires_at, kind, identity_id, project_id) VALUES (:id, 'run',"
                    " :hash, 'depradar_def', '[]', now(), now(), 'identity', :identity, :project)"
                ),
                {"id": str(uuid4()), "hash": "2" * 64, "identity": identity, "project": project},
            )
            connection.commit()
            command.downgrade(config, "0005")
            assert connection.execute(text("SELECT count(*) FROM api_token")).scalar_one() == 1
            assert not added & set(inspect(connection).get_table_names(schema=schema))
            connection.commit()
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
        get_settings.cache_clear()


def test_populated_database_upgrades_from_0006_and_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """0007 adds an empty package index that matches the ORM schema and drops cleanly."""
    from alembic import command
    from alembic.autogenerate import compare_metadata
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext

    from depradar.config import get_settings
    from depradar.domain.entities import Base

    schema = "migration_0007_" + uuid4().hex
    url = os.environ["DEPRADAR_TEST_DATABASE_URL"]
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    project, inventory, scan = (str(uuid4()) for _ in range(3))
    try:
        with engine.connect() as connection:
            connection.execute(text(f'SET search_path TO "{schema}"'))
            connection.commit()
            config.attributes["connection"] = connection
            command.upgrade(config, "0006")
            connection.execute(
                text(
                    "INSERT INTO project (id, name, description, created_at, monitoring_enabled,"
                    " check_interval_hours, notifications_enabled)"
                    " VALUES (:id, 'Legacy', '', now(), true, 24, true)"
                ),
                {"id": project},
            )
            connection.execute(
                text(
                    "INSERT INTO inventory (id, project_id, filename, target_path, sha256,"
                    " size_bytes, created_at, kind) VALUES (:id, :project, 'package-lock.json',"
                    " 'web/package-lock.json', :sha, 10, now(), 'monitor')"
                ),
                {"id": inventory, "project": project, "sha": "0" * 64},
            )
            connection.execute(
                text(
                    "INSERT INTO scan (id, inventory_id, project_id, status, complete,"
                    " package_count, coverage_notes, created_at, mode)"
                    " VALUES (:id, :inventory, :project, 'succeeded', true, 3, '[]', now(),"
                    " 'monitor')"
                ),
                {"id": scan, "inventory": inventory, "project": project},
            )
            connection.commit()
            command.upgrade(config, "head")
            drift = [
                change
                for change in compare_metadata(
                    MigrationContext.configure(connection), Base.metadata
                )
                if "component_occurrence" in str(change)
            ]
            assert drift == []
            # Existing snapshots start unindexed; rows fill on their next scan.
            count = "SELECT count(*) FROM component_occurrence"
            assert connection.execute(text(count)).scalar_one() == 0
            connection.execute(
                text(
                    "INSERT INTO component_occurrence (id, inventory_id, project_id, scan_id,"
                    " ecosystem, name, normalized_name, version)"
                    " VALUES (:id, :inventory, :project, :scan, 'npm', 'minimist', 'minimist',"
                    " '1.2.5')"
                ),
                {"id": str(uuid4()), "inventory": inventory, "project": project, "scan": scan},
            )
            connection.commit()
            command.downgrade(config, "0006")
            assert "component_occurrence" not in inspect(connection).get_table_names(schema)
            assert connection.execute(text("SELECT count(*) FROM scan")).scalar_one() == 1
            connection.commit()
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
        get_settings.cache_clear()


def test_tokens_keep_their_interface_across_0008(monkeypatch: pytest.MonkeyPatch) -> None:
    """0008 makes existing tokens REST tokens; downgrading removes assistant tokens."""
    from alembic import command
    from alembic.autogenerate import compare_metadata
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext

    from depradar.config import get_settings
    from depradar.domain.entities import Base

    schema = "migration_0008_" + uuid4().hex
    url = os.environ["DEPRADAR_TEST_DATABASE_URL"]
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    insert = text(
        "INSERT INTO api_token (id, name, token_hash, display_prefix, scopes, created_at,"
        " expires_at, kind) VALUES (:id, 'CI', :hash, 'depradar_abc', '[\"scans:read\"]',"
        " now(), now() + interval '1 day', 'static')"
    )
    try:
        with engine.connect() as connection:
            connection.execute(text(f'SET search_path TO "{schema}"'))
            connection.commit()
            config.attributes["connection"] = connection
            command.upgrade(config, "0007")
            pipeline = str(uuid4())
            connection.execute(insert, {"id": pipeline, "hash": "a" * 64})
            connection.commit()
            command.upgrade(config, "head")
            drift = [
                change
                for change in compare_metadata(
                    MigrationContext.configure(connection), Base.metadata
                )
                if any(name in str(change) for name in ("audit", "audience"))
            ]
            assert drift == []
            audiences = "SELECT audience FROM api_token"
            assert connection.execute(text(audiences)).scalars().all() == ["api"]
            retention = "SELECT audit_retention_days FROM system_state"
            assert connection.execute(text(retention)).scalars().all() == [90]
            assistant = str(uuid4())
            connection.execute(insert, {"id": assistant, "hash": "b" * 64})
            connection.execute(
                text("UPDATE api_token SET audience = 'mcp' WHERE id = :id"), {"id": assistant}
            )
            connection.commit()
            command.downgrade(config, "0007")
            # Without the audience column an assistant token would work on the REST API.
            remaining = connection.execute(text("SELECT id FROM api_token")).scalars().all()
            assert remaining == [pipeline]
            assert "audit_event" not in inspect(connection).get_table_names(schema)
            connection.commit()
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
        get_settings.cache_clear()


def test_backup_restore_drill_on_postgresql(
    harness: Harness, project_id: str, tmp_path: Path
) -> None:
    from depradar.application.scans import run_once
    from depradar.infrastructure.backups import create_backup, verify_backup

    from .test_scans import report

    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    path = tmp_path / "backup.tar.gz"
    create_backup(harness.factory, harness.settings.storage_dir, path)
    result = verify_backup(path, os.environ["DEPRADAR_TEST_DATABASE_URL"])
    assert result["verified"] and result["inventories"] == 1
