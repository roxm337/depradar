import json
import os
import time
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from depradar.application.notifications import deliver_once
from depradar.application.scans import run_once
from depradar.application.scheduling import tick
from depradar.domain.entities import Delivery, Finding, Project, utcnow
from depradar.infrastructure.backups import create_backup, verify_backup
from depradar.infrastructure.notifier import Notifier
from depradar.infrastructure.scanner_client import RemoteScanner

from .conftest import Harness
from .test_notifications import due
from .test_uploads import LOCKFILE, upload

pytestmark = pytest.mark.skipif(
    not os.getenv("DEPRADAR_E2E"), reason="Run the isolated compose.verify.yaml integration stack"
)


def drain(harness: Harness) -> None:
    for _ in range(20):
        due(harness)
        if not deliver_once(harness.factory, harness.settings, Notifier(harness.settings)):
            break
    with harness.factory() as db:
        assert not list(
            db.scalars(select(Delivery).where(Delivery.status.in_(["queued", "failed"])))
        )


def test_postgres_osv_smtp_telegram_scheduling_decisions_backup_and_delete(
    harness: Harness,
    project_id: str,
    tmp_path: Path,
) -> None:
    # Real PostgreSQL/OSV; SMTP and Telegram use local protocol capture services.
    assert harness.factory.kw["bind"].dialect.name == "postgresql"
    with httpx.Client(base_url="http://mailpit:8025", trust_env=False, timeout=2) as mail:
        deadline = time.monotonic() + 30
        while True:
            try:
                mail.get("/api/v1/messages").raise_for_status()
                break
            except httpx.HTTPError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.5)
    harness.settings.scanner_url = os.environ["DEPRADAR_LIVE_SCANNER_URL"]
    harness.settings.allow_insecure_smtp = True
    harness.settings.telegram_bot_token = SecretStr("integration-fixture-token")
    harness.settings.telegram_api_base_url = os.environ["DEPRADAR_TELEGRAM_FIXTURE_URL"]
    response = harness.client.put(
        "/api/connectors/email",
        headers=harness.headers,
        json={
            "host": "mailpit",
            "port": 1025,
            "tls_mode": "none",
            "sender": "radar@example.test",
            "recipient": "owner@example.test",
        },
    )
    assert response.status_code == 202, response.text
    drain(harness)
    with httpx.Client(base_url="http://mailpit:8025", trust_env=False) as client:
        inbox = client.get("/api/v1/messages").json()
        message = next(
            m for m in inbox["messages"] if m["Subject"] == "Your DepRadar verification code"
        )
        delivered = client.get(f"/api/v1/message/{message['ID']}").json()
    code = delivered["Text"].splitlines()[1].strip()
    assert code in delivered["HTML"] and delivered["From"]["Name"] == "DepRadar"
    assert (
        harness.client.post(
            "/api/connectors/email/verify", headers=harness.headers, json={"code": code}
        ).status_code
        == 200
    )
    response = harness.client.post("/api/connectors/telegram/pair", headers=harness.headers)
    assert response.status_code == 200, response.text
    with httpx.Client(trust_env=False) as client:
        client.post(
            harness.settings.telegram_api_base_url + "/fixture/pair",
            json={"command": response.json()["command"]},
        ).raise_for_status()
    assert (
        harness.client.post("/api/connectors/telegram/confirm", headers=harness.headers).json()[
            "status"
        ]
        == "verified"
    )
    drain(harness)
    response = upload(harness, project_id)
    assert response.status_code == 202
    scan_id = response.json()["scan"]["id"]
    assert run_once(
        harness.factory, harness.settings, harness.store, RemoteScanner(harness.settings)
    )
    result = harness.client.get(f"/api/scans/{scan_id}").json()
    assert result["status"] == "succeeded", result
    findings = harness.client.get(f"/api/projects/{project_id}/findings").json()
    finding = next(f for f in findings if "CVE-2021-44906" in f["advisory_ids"])
    tick(harness.factory, harness.settings, harness.store)
    drain(harness)
    with harness.factory() as db:
        assert {
            d.connector_id
            for d in db.scalars(
                select(Delivery).where(
                    Delivery.project_id == project_id, Delivery.status == "accepted"
                )
            )
        } == {"email", "telegram"}
    with httpx.Client(trust_env=False) as client:
        sent = client.get(harness.settings.telegram_api_base_url + "/fixture/messages").json()
        inbox = client.get("http://mailpit:8025/api/v1/messages").json()["messages"]
    # Details are off by default, so neither channel may name the package.
    assert sent and all(m["parse_mode"] == "HTML" for m in sent)
    assert not any("minimist" in m["text"] for m in sent)
    assert any(m["Subject"].endswith("vulnerability in a monitored project") for m in inbox)
    assert (
        harness.client.post(
            f"/api/findings/{finding['id']}/acknowledge",
            headers=harness.headers,
            json={"note": "Investigating"},
        ).status_code
        == 200
    )
    assert (
        harness.client.post(
            f"/api/findings/{finding['id']}/risk-acceptance",
            headers=harness.headers,
            json={
                "reason": "Temporary mitigation",
                "expires_at": (utcnow() + timedelta(days=1)).isoformat(),
            },
        ).status_code
        == 200
    )
    with harness.factory.begin() as db:
        row = db.get(Finding, finding["id"])
        row.risk_until = utcnow() - timedelta(seconds=1)
    assert tick(harness.factory, harness.settings, harness.store)["expired"] == 1
    drain(harness)
    assert (
        harness.client.put(
            f"/api/projects/{project_id}/monitoring",
            headers=harness.headers,
            json={"enabled": True, "interval_hours": 1},
        ).status_code
        == 200
    )
    assert tick(harness.factory, harness.settings, harness.store)["scheduled"] == 1
    assert run_once(
        harness.factory, harness.settings, harness.store, RemoteScanner(harness.settings)
    )
    fixed = json.loads(json.dumps(LOCKFILE))
    fixed["packages"]["node_modules/minimist"]["version"] = "1.2.8"
    fixed["packages"]["node_modules/minimist"]["resolved"] = (
        "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz"
    )
    response = upload(harness, project_id, json.dumps(fixed).encode())
    assert response.status_code == 202
    assert run_once(
        harness.factory, harness.settings, harness.store, RemoteScanner(harness.settings)
    )
    with harness.factory() as db:
        assert db.get(Finding, finding["id"]).status == "resolved"
    tick(harness.factory, harness.settings, harness.store)
    drain(harness)
    archive = tmp_path / "verified-backup.tar.gz"
    create_backup(harness.factory, harness.settings.storage_dir, archive)
    assert verify_backup(archive, os.environ["DEPRADAR_TEST_DATABASE_URL"])["verified"]
    assert (
        harness.client.delete(f"/api/projects/{project_id}", headers=harness.headers).status_code
        == 204
    )
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        assert db.get(Project, project_id) is None
    assert not list(harness.settings.storage_dir.iterdir())
