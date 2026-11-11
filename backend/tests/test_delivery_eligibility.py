"""Queued alert work follows current project settings, quiet hours, and project deletion."""

from datetime import timedelta

from sqlalchemy import select

from depradar.application.notifications import deliver_once
from depradar.application.scans import run_once
from depradar.application.scheduling import tick
from depradar.domain.entities import (
    Delivery,
    DeliveryAttempt,
    NotificationPolicy,
    new_id,
    utcnow,
)
from depradar.domain.messages import Message

from .conftest import Harness
from .test_notifications import connect, due
from .test_scans import enqueue_recheck, report
from .test_uploads import upload


def digest_policy(harness: Harness, *, details: bool = True) -> None:
    with harness.factory.begin() as db:
        policy = db.get(NotificationPolicy, 1)
        assert policy is not None
        policy.immediate_min_severity = "critical"
        policy.include_details = details
        policy.next_digest_at = utcnow() + timedelta(days=1)


def scan_project(harness: Harness, name: str) -> str:
    response = harness.client.post("/api/projects", json={"name": name}, headers=harness.headers)
    project_id = str(response.json()["id"])
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    return project_id


def prepare_digest_now(harness: Harness) -> str:
    with harness.factory.begin() as db:
        policy = db.get(NotificationPolicy, 1)
        assert policy is not None
        policy.next_digest_at = utcnow() - timedelta(seconds=1)
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        digest = db.scalars(select(Delivery).where(Delivery.kind == "digest")).one()
        return digest.id


def capture() -> tuple[list[Message], object]:
    sent: list[Message] = []

    def sender(connector_id: str, config: dict, message: Message, delivery_id: str) -> str:
        sent.append(message)
        return "provider-id"

    return sent, sender


def quiet_now(harness: Harness) -> None:
    hour = utcnow().hour
    with harness.factory.begin() as db:
        policy = db.get(NotificationPolicy, 1)
        assert policy is not None
        policy.timezone = "UTC"
        policy.quiet_hours_start = hour
        policy.quiet_hours_end = (hour + 1) % 24


def test_deleting_one_project_keeps_other_projects_digest_alerts(harness: Harness) -> None:
    connect(harness)
    digest_policy(harness)
    removed = scan_project(harness, "Removed client")
    scan_project(harness, "Kept client")
    tick(harness.factory, harness.settings, harness.store)
    digest_id = prepare_digest_now(harness)
    with harness.factory() as db:
        assert "Removed client" in db.get(Delivery, digest_id).body

    assert (
        harness.client.delete(f"/api/projects/{removed}", headers=harness.headers).status_code
        == 204
    )

    with harness.factory() as db:
        digest = db.get(Delivery, digest_id)
        assert digest is not None and digest.status == "queued"
        assert "Removed client" not in digest.body and "Kept client" in digest.body
        children = list(db.scalars(select(Delivery).where(Delivery.batch_id == digest_id)))
        assert len(children) == 1 and children[0].status == "bundled"
    sent, sender = capture()
    due(harness)
    assert deliver_once(harness.factory, harness.settings, sender)
    assert len(sent) == 1
    assert [item.project for item in sent[0].items] == ["Kept client"]


def test_deleting_a_project_does_not_replay_a_sent_digest(harness: Harness) -> None:
    connect(harness)
    digest_policy(harness)
    removed = scan_project(harness, "Removed client")
    scan_project(harness, "Kept client")
    tick(harness.factory, harness.settings, harness.store)
    digest_id = prepare_digest_now(harness)
    due(harness)
    assert deliver_once(harness.factory, harness.settings, lambda *_: "accepted")

    assert (
        harness.client.delete(f"/api/projects/{removed}", headers=harness.headers).status_code
        == 204
    )

    with harness.factory() as db:
        assert db.get(Delivery, digest_id) is None
        rows = list(db.scalars(select(Delivery)))
        assert [row.status for row in rows] == ["bundled"] and rows[0].batch_id is None
    sent, sender = capture()
    due(harness)
    assert not deliver_once(harness.factory, harness.settings, sender)
    assert not sent


def test_disabling_project_alerts_cancels_queued_immediate_alerts(
    harness: Harness, project_id: str
) -> None:
    connect(harness)
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        assert db.scalars(select(Delivery)).one().status == "queued"
    response = harness.client.put(
        f"/api/projects/{project_id}/notifications",
        json={"enabled": False},
        headers=harness.headers,
    )
    assert response.status_code == 200
    sent, sender = capture()
    due(harness)
    assert deliver_once(harness.factory, harness.settings, sender)
    assert not sent
    with harness.factory() as db:
        assert db.scalars(select(Delivery)).one().status == "cancelled"


def test_disabling_one_project_keeps_the_rest_of_a_digest(harness: Harness) -> None:
    connect(harness)
    digest_policy(harness)
    muted = scan_project(harness, "Muted client")
    scan_project(harness, "Kept client")
    tick(harness.factory, harness.settings, harness.store)
    prepare_digest_now(harness)
    harness.client.put(
        f"/api/projects/{muted}/notifications", json={"enabled": False}, headers=harness.headers
    )
    sent, sender = capture()
    due(harness)
    assert deliver_once(harness.factory, harness.settings, sender)
    assert [item.project for item in sent[0].items] == ["Kept client"]
    with harness.factory() as db:
        statuses = {row.project_id: row.status for row in db.scalars(select(Delivery))}
        assert statuses[muted] == "cancelled"


def test_disabled_project_alerts_are_dropped_when_the_digest_is_prepared(
    harness: Harness, project_id: str
) -> None:
    connect(harness)
    digest_policy(harness)
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    harness.client.put(
        f"/api/projects/{project_id}/notifications",
        json={"enabled": False},
        headers=harness.headers,
    )
    with harness.factory.begin() as db:
        policy = db.get(NotificationPolicy, 1)
        assert policy is not None
        policy.next_digest_at = utcnow() - timedelta(seconds=1)
    tick(harness.factory, harness.settings, harness.store)
    with harness.factory() as db:
        assert db.scalar(select(Delivery).where(Delivery.kind == "digest")) is None
        assert db.scalars(select(Delivery)).one().status == "cancelled"


def test_prepared_digest_waits_for_quiet_hours_to_end(harness: Harness, project_id: str) -> None:
    connect(harness)
    digest_policy(harness)
    inventory_id = upload(harness, project_id).json()["inventory"]["id"]
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report(False))
    enqueue_recheck(harness, inventory_id)
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)
    digest_id = prepare_digest_now(harness)
    quiet_now(harness)
    sent, sender = capture()
    due(harness)
    assert deliver_once(harness.factory, harness.settings, sender)
    assert not sent
    with harness.factory() as db:
        digest = db.get(Delivery, digest_id)
        assert digest.status == "queued" and digest.available_at > utcnow()


def interrupted_send(harness: Harness, attempts: int) -> tuple[str, str]:
    connect(harness)
    delivery_id, attempt_id = new_id(), new_id()
    with harness.factory.begin() as db:
        db.add(
            Delivery(
                id=delivery_id,
                connector_id="email",
                generation=1,
                kind="alert",
                body="Queued alert",
                status="sending",
                attempts=attempts,
                lease_token=new_id(),
                lease_until=utcnow() - timedelta(seconds=1),
            )
        )
        db.flush()
        db.add(
            DeliveryAttempt(
                id=attempt_id, delivery_id=delivery_id, attempt_number=attempts, status="sending"
            )
        )
    return delivery_id, attempt_id


def test_exhausted_interrupted_delivery_closes_its_attempt(harness: Harness) -> None:
    delivery_id, attempt_id = interrupted_send(harness, harness.settings.delivery_max_attempts)
    sent, sender = capture()
    assert deliver_once(harness.factory, harness.settings, sender)
    assert not sent
    with harness.factory() as db:
        assert db.get(Delivery, delivery_id).status == "failed"
        attempt = db.get(DeliveryAttempt, attempt_id)
        assert attempt.status == "uncertain" and attempt.completed_at is not None


def test_interrupted_delivery_deferred_by_quiet_hours_is_not_reclaimed(
    harness: Harness,
) -> None:
    delivery_id, attempt_id = interrupted_send(harness, 1)
    quiet_now(harness)
    sent, sender = capture()
    assert deliver_once(harness.factory, harness.settings, sender)
    # The deferred row is queued for later, so the next pass finds nothing to claim.
    assert not deliver_once(harness.factory, harness.settings, sender)
    assert not sent
    with harness.factory() as db:
        delivery = db.get(Delivery, delivery_id)
        assert delivery.status == "queued" and delivery.lease_until is None
        assert delivery.available_at > utcnow()
        assert db.get(DeliveryAttempt, attempt_id).status == "uncertain"
