"""Several Telegram chats receive alerts, and each destination can be limited to some projects."""

from datetime import timedelta
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import select

from depradar.application.housekeeping import retention, retention_settings
from depradar.application.notifications import deliver_once
from depradar.application.scans import run_once
from depradar.application.scheduling import tick
from depradar.domain.connectors import chat_label, clean_label
from depradar.domain.entities import Connector, ConnectorProject, Delivery, utcnow
from depradar.domain.messages import scope_label, scope_note
from depradar.interfaces.http.dependencies import telegram_updates

from .conftest import Harness
from .test_notifications import connect, due
from .test_scans import report
from .test_uploads import upload


@pytest.fixture
def updates(harness: Harness) -> list[dict[str, Any]]:
    """What the fake bot returns from getUpdates; tests append pairing commands to it."""
    harness.settings.telegram_bot_token = SecretStr("bot-test-token")
    pending: list[dict[str, Any]] = []
    harness.client.app.dependency_overrides[telegram_updates] = lambda: (
        lambda offset: [u for u in pending if u["update_id"] >= offset]
    )
    return pending


def pair(harness: Harness, label: str = "", connector_id: str | None = None) -> tuple[str, str]:
    body: dict[str, Any] = {"label": label}
    if connector_id:
        body["connector_id"] = connector_id
    response = harness.client.post(
        "/api/connectors/telegram/pair", headers=harness.headers, json=body
    )
    assert response.status_code == 200, response.text
    return response.json()["connector_id"], response.json()["command"]


def send(updates: list[dict[str, Any]], command: str, chat_id: int, **chat: Any) -> None:
    updates.append(
        {
            "update_id": len(updates) + 1,
            "message": {"text": command, "chat": {"id": chat_id, "type": "private", **chat}},
        }
    )


def confirm(harness: Harness, connector_id: str | None = None) -> Any:
    return harness.client.post(
        "/api/connectors/telegram/confirm",
        headers=harness.headers,
        json={"connector_id": connector_id} if connector_id else None,
    )


def paired(harness: Harness, updates: list[dict[str, Any]], label: str, chat_id: int) -> str:
    connector_id, command = pair(harness, label)
    send(updates, command, chat_id)
    assert confirm(harness, connector_id).json()["status"] == "verified"
    return connector_id


def new_project(harness: Harness, name: str) -> str:
    response = harness.client.post("/api/projects", json={"name": name}, headers=harness.headers)
    assert response.status_code == 201
    return str(response.json()["id"])


def scan(harness: Harness, project_id: str) -> None:
    assert upload(harness, project_id).status_code == 202
    run_once(harness.factory, harness.settings, harness.store, lambda *_: report())
    tick(harness.factory, harness.settings, harness.store)


def alerted(harness: Harness, project_id: str) -> set[str]:
    """The destinations that received work for the project's alerts."""
    with harness.factory() as db:
        return {
            d.connector_id
            for d in db.scalars(select(Delivery).where(Delivery.project_id == project_id))
        }


def listed(harness: Harness) -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in harness.client.get("/api/connectors").json()}


def test_two_chats_pair_at_once_and_both_receive_alerts(
    harness: Harness, updates: list[dict[str, Any]], project_id: str
) -> None:
    first, first_command = pair(harness, "Hamza")
    second, second_command = pair(harness)
    assert first != second and first.startswith("telegram-")
    send(updates, first_command, 111)
    send(updates, second_command, 222, first_name="Sara", last_name="B.")
    # One read of the bot's updates binds every pairing it contains.
    assert confirm(harness, first).json()["status"] == "verified"
    assert confirm(harness, second).json()["status"] == "verified"
    recipients = listed(harness)
    assert recipients[first]["label"] == "Hamza"
    assert recipients[second]["label"] == "Sara B."
    assert recipients[first]["config"] == {"chat_id": "111"}
    assert recipients[second]["channel"] == "telegram"
    connect(harness)
    scan(harness, project_id)
    assert alerted(harness, project_id) == {"email", first, second}
    due(harness)
    sent: list[tuple[str, str]] = []

    def sender(channel: str, config: dict[str, Any], message: Any, delivery_id: str) -> str:
        sent.append((channel, str(config.get("chat_id", ""))))
        return delivery_id

    while deliver_once(harness.factory, harness.settings, sender):
        due(harness)
    assert {chat for channel, chat in sent if channel == "telegram"} == {"111", "222"}


def test_a_chat_already_receiving_alerts_cannot_pair_twice(
    harness: Harness, updates: list[dict[str, Any]]
) -> None:
    paired(harness, updates, "Hamza", 111)
    again, command = pair(harness, "Hamza again")
    send(updates, command, 111)
    response = confirm(harness, again)
    assert response.status_code == 409
    assert "Hamza" in response.json()["detail"]
    assert listed(harness)[again]["verified_at"] is None


def test_pairing_accepts_the_command_addressed_to_the_bot(
    harness: Harness, updates: list[dict[str, Any]]
) -> None:
    connector_id, command = pair(harness)
    code = command.split()[1]
    send(updates, f"/start@depradar_bot {code}", 333, username="sara")
    assert confirm(harness, connector_id).json()["status"] == "verified"
    assert listed(harness)[connector_id]["label"] == "@sara"


def test_repairing_keeps_the_recipient_and_removal_stops_its_alerts(
    harness: Harness, updates: list[dict[str, Any]], project_id: str
) -> None:
    connector_id = paired(harness, updates, "Hamza", 111)
    again, command = pair(harness, connector_id=connector_id)
    assert again == connector_id
    send(updates, command, 444)
    assert confirm(harness, connector_id).json()["status"] == "verified"
    assert listed(harness)[connector_id]["config"] == {"chat_id": "444"}
    assert listed(harness)[connector_id]["label"] == "Hamza"
    scan(harness, project_id)
    assert connector_id in alerted(harness, project_id)
    assert (
        harness.client.delete(
            f"/api/connectors/{connector_id}", headers=harness.headers
        ).status_code
        == 204
    )
    due(harness)
    while deliver_once(harness.factory, harness.settings, lambda *_: pytest.fail("sent")):
        pass
    with harness.factory() as db:
        statuses = {
            d.status
            for d in db.scalars(select(Delivery).where(Delivery.connector_id == connector_id))
        }
    assert statuses <= {"cancelled", "accepted", "bundled"} and "cancelled" in statuses
    removed = listed(harness)[connector_id]
    assert removed["removed_at"] and removed["config"] == {} and removed["label"] == "Hamza"
    for action in ("enable", "test"):
        response = harness.client.post(
            f"/api/connectors/{connector_id}/{action}", headers=harness.headers
        )
        assert response.status_code == 404
    # Email has one destination that is reconfigured, never removed.
    connect(harness)
    response = harness.client.delete("/api/connectors/email", headers=harness.headers)
    assert response.status_code == 404


def test_expired_unfinished_pairings_are_cleared(
    harness: Harness, updates: list[dict[str, Any]]
) -> None:
    abandoned, _ = pair(harness, "Never sent")
    with harness.factory.begin() as db:
        connector = db.get(Connector, abandoned)
        assert connector is not None
        connector.challenge_expires_at = utcnow() - timedelta(minutes=1)
    assert confirm(harness, abandoned).status_code == 422
    pair(harness, "Fresh")
    assert abandoned not in listed(harness)


def test_a_destination_limited_to_one_project_skips_the_others(
    harness: Harness, updates: list[dict[str, Any]], project_id: str
) -> None:
    other = new_project(harness, "Other")
    hamza = paired(harness, updates, "Hamza", 111)
    sara = paired(harness, updates, "Sara", 222)
    response = harness.client.patch(
        f"/api/connectors/{sara}",
        headers=harness.headers,
        json={"all_projects": False, "project_ids": [other]},
    )
    assert response.status_code == 204, response.text
    assert listed(harness)[sara]["all_projects"] is False
    assert listed(harness)[sara]["project_ids"] == [other]
    scan(harness, project_id)
    scan(harness, other)
    assert alerted(harness, project_id) == {hamza}
    assert alerted(harness, other) == {hamza, sara}
    # Widening the scope again restores every project.
    harness.client.patch(
        f"/api/connectors/{sara}", headers=harness.headers, json={"all_projects": True}
    )
    assert listed(harness)[sara]["project_ids"] == []


def test_narrowing_a_scope_cancels_alerts_already_queued_for_dropped_projects(
    harness: Harness, project_id: str
) -> None:
    connect(harness)
    other = new_project(harness, "Other")
    scan(harness, project_id)
    harness.client.patch(
        "/api/connectors/email", headers=harness.headers, json={"project_ids": [other]}
    )
    due(harness)
    while deliver_once(harness.factory, harness.settings, lambda *_: pytest.fail("sent")):
        pass
    with harness.factory() as db:
        assert {d.status for d in db.scalars(select(Delivery))} <= {"cancelled"}


def test_scope_changes_are_validated(harness: Harness, project_id: str) -> None:
    connect(harness)
    empty = harness.client.patch(
        "/api/connectors/email", headers=harness.headers, json={"all_projects": False}
    )
    assert empty.status_code == 422
    unknown = harness.client.patch(
        "/api/connectors/email",
        headers=harness.headers,
        json={"project_ids": ["00000000-0000-0000-0000-000000000000"]},
    )
    assert unknown.status_code == 404
    label = harness.client.patch(
        "/api/connectors/email", headers=harness.headers, json={"label": " Team\ninbox "}
    )
    assert label.status_code == 204
    assert listed(harness)["email"]["label"] == "Team inbox"
    missing = harness.client.patch(
        "/api/connectors/telegram-00000000", headers=harness.headers, json={"label": "x"}
    )
    assert missing.status_code == 404


def test_the_welcome_summary_counts_only_the_projects_in_scope(
    harness: Harness, updates: list[dict[str, Any]], project_id: str
) -> None:
    other = new_project(harness, "Other")
    scan(harness, project_id)
    connector_id, command = pair(harness, "Sara")
    harness.client.patch(
        f"/api/connectors/{connector_id}", headers=harness.headers, json={"project_ids": [other]}
    )
    send(updates, command, 222)
    assert confirm(harness, connector_id).json()["status"] == "verified"
    messages: list[Any] = []

    def sender(channel: str, config: dict[str, Any], message: Any, delivery_id: str) -> str:
        messages.append(message)
        return delivery_id

    due(harness)
    while deliver_once(harness.factory, harness.settings, sender):
        due(harness)
    summary = next(m for m in messages if m.kind == "summary")
    assert summary.counts == ()
    assert "cover 1 selected project only" in summary.note


def test_deleting_a_project_never_widens_a_limited_scope(harness: Harness, project_id: str) -> None:
    connect(harness)
    harness.client.patch(
        "/api/connectors/email", headers=harness.headers, json={"project_ids": [project_id]}
    )
    assert (
        harness.client.delete(f"/api/projects/{project_id}", headers=harness.headers).status_code
        == 204
    )
    email = listed(harness)["email"]
    assert email["all_projects"] is False and email["project_ids"] == []


def test_retention_forgets_removed_recipients_once_their_history_is_gone(
    harness: Harness, updates: list[dict[str, Any]]
) -> None:
    connector_id = paired(harness, updates, "Hamza", 111)
    project = new_project(harness, "P")
    with harness.factory.begin() as db:
        db.add(ConnectorProject(connector_id=connector_id, project_id=project))
    harness.client.delete(f"/api/connectors/{connector_id}", headers=harness.headers)
    due(harness)
    while deliver_once(harness.factory, harness.settings, lambda *_: pytest.fail("sent")):
        pass
    with harness.factory.begin() as db:
        retention(db, harness.store, retention_settings(db))
        assert db.get(Connector, connector_id) is not None
        for delivery in db.scalars(select(Delivery)):
            delivery.created_at = utcnow() - timedelta(days=365)
    with harness.factory.begin() as db:
        retention(db, harness.store, retention_settings(db))
    with harness.factory() as db:
        assert db.get(Connector, connector_id) is None
        assert not list(db.scalars(select(ConnectorProject)))


def test_labels_are_one_short_line() -> None:
    assert clean_label("  Hamza\t‮\nO.  ") == "Hamza O."
    assert len(clean_label("x" * 200)) == 80
    assert chat_label({"first_name": "Sara", "last_name": None}) == "Sara"
    assert chat_label({"username": "sara"}) == "@sara"
    assert chat_label({}) == ""


def test_messages_name_the_scope_only_when_details_are_on() -> None:
    assert scope_label(None, True) == "All projects"
    assert scope_label([], True) == "No projects"
    assert scope_label(["API", "Web"], True) == "API, Web"
    assert scope_label(["API", "Web"], False) == "2 selected projects"
    assert scope_note(None, True, "telegram") == ""
    assert "receives no alerts" in scope_note([], False, "telegram")
    assert (
        scope_note(["Web"], False, "email")
        == "Alerts to this address cover 1 selected project only."
    )
