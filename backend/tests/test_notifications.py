from datetime import timedelta

from sqlalchemy import select

from depradar.application.notifications import deliver_once
from depradar.application.ports import DeliveryFailure
from depradar.application.scans import run_once
from depradar.application.scheduling import tick
from depradar.domain.entities import Connector, Delivery, Finding, NotificationPolicy, utcnow
from depradar.domain.schedule import next_digest
from depradar.interfaces.http.dependencies import telegram_updates

from .conftest import Harness
from .test_scans import report
from .test_uploads import upload


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
        assert len(list(db.scalars(select(Delivery)))) == 1
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
        assert db.scalars(select(Delivery)).one().status == "cancelled"
        assert db.get(Finding, finding_id).status == "open"


def test_digest_groups_lower_severity_and_uses_timezone(harness: Harness, project_id: str) -> None:
    connect(harness)
    with harness.factory.begin() as db:
        policy = db.get(NotificationPolicy, 1)
        assert policy is not None
        policy.immediate_min_severity = "critical"
    upload(harness, project_id)
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
    upload(harness, project_id)
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
    upload(harness, project_id)
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
