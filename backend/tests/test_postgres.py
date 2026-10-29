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
