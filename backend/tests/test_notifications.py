import json
from copy import deepcopy
from datetime import timedelta

import pytest
from sqlalchemy import select

from depradar.application.notifications import deliver_once
from depradar.application.ports import DeliveryFailure
from depradar.application.scans import run_once
from depradar.application.scheduling import tick
from depradar.domain.entities import (
    Connector,
    Delivery,
    Finding,
    Inventory,
    NotificationPolicy,
    Project,
    Scan,
    utcnow,
)
from depradar.domain.scanning import ScanResponse
from depradar.domain.schedule import next_digest
from depradar.interfaces.http.dependencies import telegram_updates

from .conftest import Harness
from .test_scans import enqueue_recheck, report
from .test_uploads import LOCKFILE, upload


def connect(harness: Harness, channel: str = "email") -> None:
    with harness.factory.begin() as db:
        db.add(Connector(id=channel, config={}, verified_at=utcnow() - timedelta(days=1)))
        policy = db.get(NotificationPolicy, 1)
        assert policy is not None
        policy.next_digest_at = utcnow() + timedelta(days=1)


def due(harness: Harness) -> None:
    with harness.factory.begin() as db:
        for connector in db.scalars(select(Connector)):
            connector.next_send_at = utcnow() - timedelta(seconds=1)
        for delivery in db.scalars(select(Delivery)):
            delivery.available_at = utcnow() - timedelta(seconds=1)


def test_email_requires_actual_verification_and_keeps_secrets_out_of_api(harness: Harness) -> None:
    harness.settings.allow_insecure_smtp = True
    response = harness.client.put(
        "/api/connectors/email",
        headers=harness.headers,
        json={
            "host": "localhost",
            "port": 1025,
            "sender": "radar@example.test",
            "recipient": "owner@example.test",
            "tls_mode": "none",
        },
    )
    assert response.status_code == 202
    assert (
        harness.client.post("/api/connectors/email/test", headers=harness.headers).status_code
        == 409
    )
    captured = []

    def sender(*args):
        captured.append(args[2])
        return "smtp-message-id"

    assert deliver_once(harness.factory, harness.settings, sender)
    code = captured[0].code
    assert (
        harness.client.post(
            "/api/connectors/email/verify", headers=harness.headers, json={"code": "wrong-code"}
        ).status_code
        == 422
    )
    response = harness.client.post(
        "/api/connectors/email/verify", headers=harness.headers, json={"code": code}
    )
    assert response.status_code == 200
    assert code not in harness.client.get("/api/notifications/deliveries").text
    assert (
        harness.client.post(
            "/api/connectors/email/verify", headers=harness.headers, json={"code": code}
        ).status_code
        == 422
    )


def test_telegram_pairing_accepts_only_matching_private_chat(harness: Harness, monkeypatch) -> None:
    # Settings assignment doesn't validate by default; use the declared SecretStr type.
    from pydantic import SecretStr

    harness.settings.telegram_bot_token = SecretStr("bot-test-token")
    result = harness.client.post("/api/connectors/telegram/pair", headers=harness.headers)
    command = result.json()["command"]
    updates = [{"update_id": 1, "message": {"text": command, "chat": {"id": -1, "type": "group"}}}]
    harness.client.app.dependency_overrides[telegram_updates] = lambda: lambda offset: updates
    result = harness.client.post("/api/connectors/telegram/confirm", headers=harness.headers)
    assert result.json()["status"] == "waiting_for_private_chat_command"
    updates[:] = [
        {"update_id": 2, "message": {"text": command, "chat": {"id": 123, "type": "private"}}}
    ]
    result = harness.client.post("/api/connectors/telegram/confirm", headers=harness.headers)
    assert result.json()["status"] == "verified"
    assert "bot-test-token" not in harness.client.get("/api/connectors").text


def test_retries_honor_rate_limits_and_history(harness: Harness) -> None:
    connect(harness, "telegram")
    response = harness.client.post("/api/connectors/telegram/test", headers=harness.headers)
    assert response.status_code == 202

    def limited(*args):
        raise DeliveryFailure("telegram_rate_limited", retry_after=120)

    before = utcnow()
    assert deliver_once(harness.factory, harness.settings, limited)
    with harness.factory() as db:
        delivery = db.scalars(select(Delivery)).one()
        assert delivery.status == "queued" and delivery.attempts == 1
        assert delivery.available_at >= before + timedelta(seconds=120)
    due(harness)
    assert deliver_once(harness.factory, harness.settings, lambda *_: "1234")
    with harness.factory() as db:
        delivery = db.scalars(select(Delivery)).one()
        assert delivery.status == "accepted" and delivery.attempts == 2
        assert delivery.provider_id == "1234"


def test_permanent_failure_manual_retry_and_changed_destination_cancellation(
    harness: Harness,
) -> None:
    connect(harness)
    delivery_id = harness.client.post("/api/connectors/email/test", headers=harness.headers).json()[
        "delivery_id"
    ]

    def refused(*args):
        raise DeliveryFailure("smtp_rejected", permanent=True)

    deliver_once(harness.factory, harness.settings, refused)
    assert (
        harness.client.post(
            f"/api/notifications/deliveries/{delivery_id}/retry", headers=harness.headers
        ).status_code
        == 202
    )
    with harness.factory.begin() as db:
        connector = db.get(Connector, "email")
        assert connector is not None
        connector.generation += 1
    due(harness)
    deliver_once(harness.factory, harness.settings, lambda *_: "must-not-send")
    with harness.factory() as db:
        assert db.get(Delivery, delivery_id).status == "cancelled"


def test_event_routing_is_once_and_acknowledgement_mutes_queued_alert(
    harness: Harness,
    project_id: str,
) -> None:
    connect(harness)
    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        assert len(list(db.scalars(select(Delivery)))) == 2
        finding_id = db.scalars(select(Finding)).one().id
    assert (
        harness.client.post(
            f"/api/findings/{finding_id}/acknowledge",
            headers=harness.headers,
            json={"note": "Reviewing"},
        ).status_code
        == 200
    )
    deliver_once(harness.factory, harness.settings, lambda *_: "must-not-send")
    with harness.factory() as db:
        assert all(d.status == "cancelled" for d in db.scalars(select(Delivery)))
        assert db.get(Finding, finding_id).status == "open"


def test_digest_groups_lower_severity_and_uses_timezone(harness: Harness, project_id: str) -> None:
    connect(harness)
    with harness.factory.begin() as db:
        policy = db.get(NotificationPolicy, 1)
        assert policy is not None
        policy.immediate_min_severity = "critical"
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory.begin() as db:
        assert db.scalars(select(Delivery)).one().status == "digest_pending"
        policy = db.get(NotificationPolicy, 1)
        assert policy is not None
        policy.next_digest_at = utcnow() - timedelta(seconds=1)
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        rows = list(db.scalars(select(Delivery)))
        assert {d.status for d in rows} == {"bundled", "queued"}
        assert next(d for d in rows if d.status == "bundled").batch_id
    assert next_digest(utcnow(), "Africa/Casablanca", 8) > utcnow()


def test_acknowledgement_after_digest_preparation_cancels_unsent_digest(
    harness: Harness,
    project_id: str,
) -> None:
    connect(harness)
    with harness.factory.begin() as db:
        policy = db.get(NotificationPolicy, 1)
        policy.immediate_min_severity = "critical"
        policy.next_digest_at = utcnow() - timedelta(seconds=1)
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        finding_id = db.scalars(select(Finding)).one().id
        assert db.scalar(select(Delivery).where(Delivery.kind == "digest"))
    harness.client.post(
        f"/api/findings/{finding_id}/acknowledge",
        headers=harness.headers,
        json={"note": "Already reviewed"},
    )
    sent = []
    deliver_once(harness.factory, harness.settings, lambda *args: sent.append(args) or "id")
    assert not sent
    with harness.factory() as db:
        assert (
            db.scalars(select(Delivery).where(Delivery.kind == "digest")).one().status
            == "cancelled"
        )


def test_revoking_acknowledgement_resumes_alerts(harness: Harness, project_id: str) -> None:
    connect(harness)
    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    with harness.factory() as db:
        finding_id = db.scalars(select(Finding)).one().id
    harness.client.post(
        f"/api/findings/{finding_id}/acknowledge",
        headers=harness.headers,
        json={"note": "Reviewing"},
    )
    tick(harness.factory, harness.settings, harness.store)
    response = harness.client.delete(
        f"/api/findings/{finding_id}/acknowledge", headers=harness.headers
    )
    assert response.status_code == 200
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        assert db.get(Finding, finding_id).workflow_status == "open"
        assert db.scalars(select(Delivery)).one().status == "queued"


def test_alerts_follow_the_detail_setting_at_send_time(harness: Harness, project_id: str) -> None:
    connect(harness)
    with harness.factory.begin() as db:
        policy = db.get(NotificationPolicy, 1)
        assert policy is not None
        policy.include_details = True
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory.begin() as db:
        assert "minimist 1.2.5" in db.scalars(select(Delivery)).one().subject
        policy = db.get(NotificationPolicy, 1)
        assert policy is not None
        policy.include_details = False
    due(harness)
    sent = []
    deliver_once(harness.factory, harness.settings, lambda *args: sent.append(args[2]) or "id")
    assert sent[0].subject == "New high vulnerability in a monitored project"
    assert not sent[0].items and "minimist" not in sent[0].lead
    with harness.factory() as db:
        delivery = db.scalars(select(Delivery)).one()
        assert delivery.subject == sent[0].subject and "minimist" not in delivery.body


def findings_report(count: int, complete: bool = True) -> ScanResponse:
    data = report(complete=complete).model_dump()
    template = data["report"]["results"][0]["packages"][0]
    packages = []
    for index in range(count):
        package = deepcopy(template)
        package["package"]["name"] = f"package-{index}"
        package["vulnerabilities"] = [
            {
                "id": f"GHSA-test-{index}",
                "database_specific": {"severity": "CRITICAL" if index % 2 else "HIGH"},
            }
        ]
        packages.append(package)
    data["report"]["results"][0]["packages"] = packages
    return ScanResponse.model_validate(data)


@pytest.mark.parametrize("count,complete", [(6, True), (6, False), (501, True)])
def test_initial_report_groups_all_findings_once_per_channel(
    harness: Harness, project_id: str, count: int, complete: bool
) -> None:
    connect(harness)
    connect(harness, "telegram")
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(
        harness.factory,
        harness.settings,
        harness.store,
        lambda *_: findings_report(count, complete),
    )
    tick(harness.factory, harness.settings, harness.store)
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory.begin() as db:
        parents = list(db.scalars(select(Delivery).where(Delivery.kind == "initial_scan")))
        assert len(parents) == 2
        assert {d.connector_id for d in parents} == {"email", "telegram"}
        assert all(d.status == "queued" for d in parents)
        children = list(db.scalars(select(Delivery).where(Delivery.kind == "alert")))
        assert len(children) == count * 2
        assert all(d.status == "bundled" and d.batch_id for d in children)
        db.get(NotificationPolicy, 1).include_details = True
    sent = []
    for _ in range(2):
        due(harness)
        assert deliver_once(
            harness.factory, harness.settings, lambda *args: sent.append(args[2]) or "id"
        )
    assert len(sent) == 2
    for message in sent:
        assert sum(n for _, n in message.counts) == count
        assert len(message.items) == min(count, 20)
        assert ("incomplete" in message.note) == (not complete)
    enqueue_recheck(harness, inventory_id)
    run_once(
        harness.factory, harness.settings, harness.store, lambda *_: findings_report(count + 2)
    )
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        new_alerts = list(db.scalars(select(Delivery).where(Delivery.status == "queued")))
        assert len(new_alerts) == 4
        assert all(d.kind == "alert" and d.batch_id is None for d in new_alerts)


def test_clean_initial_scan_does_not_report_and_replacement_uses_individual_alerts(
    harness: Harness, project_id: str
) -> None:
    connect(harness)
    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        assert db.scalar(select(Delivery)) is None
    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        delivery = db.scalars(select(Delivery)).one()
        assert delivery.kind == "alert" and delivery.status == "queued"


@pytest.mark.parametrize("first_status", ["failed", "superseded", "check"])
def test_unsuccessful_or_check_scan_does_not_consume_initial_report(
    harness: Harness, project_id: str, first_status: str
) -> None:
    connect(harness)
    upload(harness, project_id)
    with harness.factory.begin() as db:
        scan = db.scalars(select(Scan)).one()
        scan.status = "succeeded" if first_status == "check" else first_status
        scan.mode = "check" if first_status == "check" else "monitor"
    # A fresh upload supersedes the original queued job as well.
    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        assert db.scalars(select(Delivery).where(Delivery.kind == "initial_scan")).one()


def test_clean_baseline_survives_retention_while_replacement_is_pending(
    harness: Harness, project_id: str
) -> None:
    connect(harness)
    first = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    with harness.factory.begin() as db:
        for inventory in db.scalars(select(Inventory)):
            inventory.created_at -= timedelta(days=40)
        for scan in db.scalars(select(Scan)):
            scan.created_at -= timedelta(days=40)
    upload(harness, project_id)
    response = harness.client.post("/api/maintenance/retention/run", headers=harness.headers)
    assert response.status_code == 200
    with harness.factory() as db:
        assert db.get(Inventory, first) is not None
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        assert db.scalars(select(Delivery)).one().kind == "alert"


def test_initial_report_retries_and_honors_privacy(harness: Harness, project_id: str) -> None:
    connect(harness)
    with harness.factory.begin() as db:
        db.get(NotificationPolicy, 1).include_details = True
    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory.begin() as db:
        parent = db.scalars(select(Delivery).where(Delivery.kind == "initial_scan")).one()
        assert "minimist" in parent.body
        db.get(NotificationPolicy, 1).include_details = False
    sent = []

    def fail(*args):
        sent.append(args[2])
        raise DeliveryFailure("provider_unavailable")

    assert deliver_once(harness.factory, harness.settings, fail)
    assert not sent[0].items and "minimist" not in sent[0].subject
    due(harness)
    assert deliver_once(
        harness.factory, harness.settings, lambda *args: sent.append(args[2]) or "id"
    )
    with harness.factory.begin() as db:
        parent = db.scalars(select(Delivery).where(Delivery.kind == "initial_scan")).one()
        assert parent.attempts == 2 and parent.status == "accepted"


@pytest.mark.parametrize("muting", ["project", "finding", "one_finding"])
def test_initial_report_rechecks_muting_at_send_time(
    harness: Harness, project_id: str, muting: str
) -> None:
    connect(harness)
    upload(harness, project_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: findings_report(2))
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory.begin() as db:
        if muting == "project":
            db.get(Project, project_id).notifications_enabled = False
        else:
            for finding in db.scalars(select(Finding)):
                finding.workflow_status = "acknowledged"
                if muting == "one_finding":
                    break
    sent = []
    assert deliver_once(harness.factory, harness.settings, lambda *args: sent.append(args) or "id")
    assert len(sent) == (1 if muting == "one_finding" else 0)
    if sent:
        assert sum(n for _, n in sent[0][2].counts) == 1
    with harness.factory() as db:
        assert db.scalars(select(Delivery).where(Delivery.kind == "initial_scan")).one().status == (
            "accepted" if sent else "cancelled"
        )


def test_initial_report_is_per_manifest_path_and_obeys_quiet_hours(
    harness: Harness, project_id: str
) -> None:
    connect(harness)
    with harness.factory.begin() as db:
        policy = db.get(NotificationPolicy, 1)
        policy.timezone = "UTC"
        policy.quiet_hours_start = utcnow().hour
        policy.quiet_hours_end = (utcnow().hour + 1) % 24
    for path in ["apps/web/package-lock.json", "apps/api/package-lock.json"]:
        response = harness.client.post(
            f"/api/projects/{project_id}/inventories",
            params={"filename": "package-lock.json", "target_path": path},
            headers=harness.headers,
            content=json.dumps(LOCKFILE).encode(),
        )
        assert response.status_code == 202
        run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        parents = list(db.scalars(select(Delivery).where(Delivery.kind == "initial_scan")))
        assert len(parents) == 2
        assert all(parent.available_at > utcnow() for parent in parents)
    due(harness)
    sent = []
    assert deliver_once(harness.factory, harness.settings, lambda *args: sent.append(args) or "id")
    assert not sent
