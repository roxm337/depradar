import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from depradar.application.ports import InventoryStore
from depradar.config import Settings, get_settings
from depradar.domain.entities import AuthGuard, Base, NotificationPolicy, SystemState
from depradar.infrastructure.database import get_db
from depradar.infrastructure.storage import LocalInventoryStore
from depradar.interfaces.http.app import app


@dataclass
class Harness:
    client: TestClient
    factory: sessionmaker[Session]
    settings: Settings
    headers: dict[str, str]
    store: InventoryStore


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[Harness]:
    database_url = os.environ.get("DEPRADAR_TEST_DATABASE_URL")
    schema = "test_" + uuid4().hex
    if database_url:
        admin = create_engine(database_url)
        with admin.begin() as db:
            db.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_engine(database_url)

        @event.listens_for(engine, "connect")
        def set_schema(connection, record):  # type: ignore[no-untyped-def]
            with connection.cursor() as cursor:
                cursor.execute(f'SET search_path TO "{schema}"')
            connection.commit()
    else:
        engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )

        @event.listens_for(engine, "connect")
        def foreign_keys(connection, record):  # type: ignore[no-untyped-def]
            connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory.begin() as db:
        db.add(AuthGuard(id=1))
        db.add(SystemState(id=1))
        db.add(NotificationPolicy(id=1))
    settings = Settings(storage_dir=tmp_path / "inventories", bootstrap_token="test-token-" * 4)

    def override_db() -> Iterator[Session]:
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app) as client:
        response = client.post(
            "/api/auth/bootstrap",
            json={"password": "developer-password"},
            headers={"X-Bootstrap-Token": "test-token-" * 4},
        )
        assert response.status_code == 201
        headers = {"X-CSRF-Token": response.json()["csrf_token"]}
        yield Harness(client, factory, settings, headers, LocalInventoryStore(settings.storage_dir))
    app.dependency_overrides.clear()
    engine.dispose()
    if database_url:
        with admin.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture
def project_id(harness: Harness) -> str:
    response = harness.client.post(
        "/api/projects", json={"name": "Example"}, headers=harness.headers
    )
    assert response.status_code == 201
    return str(response.json()["id"])


@pytest.fixture
def anonymous(harness: Harness) -> TestClient:
    # A cookie-free client: pipelines authenticate with the bearer token alone.
    return TestClient(app)
