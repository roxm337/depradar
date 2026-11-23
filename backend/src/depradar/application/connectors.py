"""Notification destinations, their verification, delivery history, and the alert policy."""

import hmac
import secrets
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, exists, select
from sqlalchemy.orm import Session

from depradar.application.errors import Conflict, Invalid, NotFound, Unavailable, UpstreamFailed
from depradar.application.notifications import (
    channel_test_message,
    queue_initial_summary,
    queue_message,
)
from depradar.application.ports import DeliveryFailure, TelegramUpdates
from depradar.config import Settings
from depradar.domain.connectors import (
    MAX_TELEGRAM_RECIPIENTS,
    EmailConfig,
    chat_label,
    clean_label,
)
from depradar.domain.entities import (
    Connector,
    ConnectorProject,
    Delivery,
    DeliveryAttempt,
    NotificationPolicy,
    Project,
    SystemState,
    utcnow,
)
from depradar.domain.messages import verification_message
from depradar.domain.schedule import next_digest
from depradar.domain.security import digest


def get_connector(db: Session, connector_id: str) -> Connector:
    connector = db.get(Connector, connector_id)
    if connector is None or connector.removed_at is not None:
        raise NotFound("Connector not configured")
    return connector


def new_generation(db: Session, connector: Connector) -> None:
    """Start a new configuration generation; unsent deliveries of the old one are cancelled."""
    running = db.scalar(
        select(Delivery.id)
        .where(
            Delivery.connector_id == connector.id,
            Delivery.status == "sending",
            Delivery.lease_until > utcnow(),
        )
        .limit(1)
    )
    if running:
        raise Conflict("Wait for the in-flight delivery before reconfiguring")
    connector.generation += 1


def reset_connector(db: Session, channel: str) -> Connector:
    """The channel's single destination (email), ready to be configured and verified again."""
    connector = db.get(Connector, channel)
    if connector is None:
        connector = Connector(id=channel, channel=channel, config={}, generation=1)
        db.add(connector)
        db.flush()
    else:
        new_generation(db, connector)
        connector.removed_at = None
    connector.verified_at = None
    connector.enabled = True
    return connector


def scoped_projects(db: Session, connector_id: str) -> list[str]:
    return list(
        db.scalars(
            select(ConnectorProject.project_id)
            .where(ConnectorProject.connector_id == connector_id)
            .order_by(ConnectorProject.project_id)
        )
    )


def list_connectors(db: Session, settings: Settings) -> list[dict[str, Any]]:
    """Every destination, removed ones included so delivery history can still name them."""
    return [
        {
            "id": c.id,
            "channel": c.channel,
            "label": c.label,
            "enabled": c.enabled,
            "verified_at": c.verified_at,
            "removed_at": c.removed_at,
            "config": {} if c.removed_at else c.config,
            "all_projects": c.all_projects,
            "project_ids": [] if c.all_projects else scoped_projects(db, c.id),
            "credential_configured": bool(
                settings.smtp_password.get_secret_value()
                if c.channel == "email"
                else settings.telegram_bot_token.get_secret_value()
            ),
        }
        for c in db.scalars(select(Connector).order_by(Connector.channel, Connector.created_at))
    ]


def set_scope(
    db: Session,
    connector_id: str,
    *,
    label: str | None = None,
    all_projects: bool | None = None,
    project_ids: list[str] | None = None,
) -> None:
    """Rename a destination or choose which projects alert it."""
    connector = get_connector(db, connector_id)
    if label is not None:
        connector.label = clean_label(label)
    if all_projects is None and project_ids is not None:
        all_projects = False
    if all_projects is True:
        connector.all_projects = True
        db.execute(delete(ConnectorProject).where(ConnectorProject.connector_id == connector.id))
    elif all_projects is False:
        wanted = set(project_ids or [])
        if not wanted:
            raise Invalid("Choose at least one project, or send alerts for every project")
        known = set(db.scalars(select(Project.id).where(Project.id.in_(wanted))))
        if known != wanted:
            raise NotFound("Project not found")
        connector.all_projects = False
        db.execute(delete(ConnectorProject).where(ConnectorProject.connector_id == connector.id))
        db.add_all(
            ConnectorProject(connector_id=connector.id, project_id=p) for p in sorted(wanted)
        )
    db.commit()


def configure_email(db: Session, settings: Settings, config: EmailConfig) -> None:
    """Save the destination and queue a one-time verification code to it."""
    if config.tls_mode == "none" and not settings.allow_insecure_smtp:
        raise Invalid("SMTP TLS is required")
    if config.username and not settings.smtp_password.get_secret_value():
        raise Unavailable("Set DEPRADAR_SMTP_PASSWORD before configuring authenticated SMTP")
    connector = reset_connector(db, "email")
    connector.config = config.model_dump()
    connector.enabled = config.enabled
    code = secrets.token_urlsafe(18)
    connector.challenge_hash = digest(code)
    connector.challenge_expires_at = utcnow() + timedelta(minutes=15)
    # Verification must be deliverable even when normal alerts are disabled.
    connector.enabled = True
    queue_message(db, connector, verification_message(code, config.recipient), settings)
    db.commit()


def verify_email(db: Session, settings: Settings, code: str) -> None:
    connector = get_connector(db, "email")
    if (
        not connector.challenge_hash
        or not connector.challenge_expires_at
        or connector.challenge_expires_at <= utcnow()
        or not hmac.compare_digest(connector.challenge_hash, digest(code))
    ):
        raise Invalid("Invalid or expired verification code")
    connector.challenge_hash = None
    connector.challenge_expires_at = None
    connector.verified_at = utcnow()
    connector.enabled = bool(connector.config.get("enabled", True))
    queue_initial_summary(db, connector, settings)
    db.commit()


def telegram_recipient(db: Session, connector_id: str) -> Connector:
    connector = get_connector(db, connector_id)
    if connector.channel != "telegram":
        raise NotFound("Telegram recipient not found")
    return connector


def pair_telegram(
    db: Session, settings: Settings, connector_id: str | None = None, label: str = ""
) -> tuple[str, str]:
    """Start pairing a new chat, or re-pair an existing one.

    Returns the recipient's ID and the one-time command its owner sends to the bot.
    """
    if not settings.telegram_bot_token.get_secret_value():
        raise Unavailable("Set DEPRADAR_TELEGRAM_BOT_TOKEN before pairing")
    # New chats whose pairing expired before anyone sent the command never received anything.
    # A chat being paired again has a later generation and stays listed.
    db.execute(
        delete(Connector).where(
            Connector.channel == "telegram",
            Connector.generation == 1,
            Connector.verified_at.is_(None),
            Connector.challenge_expires_at <= utcnow(),
            ~exists().where(Delivery.connector_id == Connector.id),
            ~exists().where(ConnectorProject.connector_id == Connector.id),
        )
    )
    if connector_id:
        connector = telegram_recipient(db, connector_id)
        new_generation(db, connector)
    else:
        active = db.scalars(
            select(Connector.id).where(
                Connector.channel == "telegram", Connector.removed_at.is_(None)
            )
        ).all()
        if len(active) >= MAX_TELEGRAM_RECIPIENTS:
            raise Conflict(f"Up to {MAX_TELEGRAM_RECIPIENTS} Telegram chats can receive alerts")
        connector = Connector(
            id=f"telegram-{secrets.token_hex(4)}", channel="telegram", config={}, generation=1
        )
        db.add(connector)
    if label.strip():
        connector.label = clean_label(label)
    connector.config = {}
    connector.verified_at = None
    connector.enabled = True
    code = secrets.token_urlsafe(24)
    connector.challenge_hash = digest(code)
    connector.challenge_expires_at = utcnow() + timedelta(minutes=15)
    db.commit()
    return connector.id, f"/start {code}"


def pairing_code(update: dict[str, Any]) -> tuple[dict[str, Any], str] | None:
    """The chat and code of a ``/start <code>`` command sent in a private chat."""
    message = update.get("message") or {}
    parts = str(message.get("text", "")).split()
    chat = message.get("chat") or {}
    # Telegram may address the command to the bot by name: /start@depradar_bot <code>.
    if (
        chat.get("type") != "private"
        or len(parts) != 2
        or parts[0].split("@", 1)[0] != "/start"
        or "id" not in chat
    ):
        return None
    return chat, parts[1]


def confirm_telegram(
    db: Session, settings: Settings, updates: TelegramUpdates, connector_id: str | None = None
) -> bool:
    """Bind every pending pairing whose command arrived in a private chat.

    The bot's updates are read once for all pairings, because reading them confirms them for
    the whole bot. Returns whether the given recipient (or, without one, any) is now bound.
    """
    target = telegram_recipient(db, connector_id) if connector_id else None
    if target and target.verified_at and not target.challenge_hash:
        return True
    pending = list(
        db.scalars(
            select(Connector).where(
                Connector.channel == "telegram",
                Connector.removed_at.is_(None),
                Connector.challenge_hash.is_not(None),
                Connector.challenge_expires_at > utcnow(),
            )
        )
    )
    if (target and target not in pending) or not pending:
        raise Invalid("Pairing expired; start a new pairing")
    state = db.scalar(
        select(SystemState)
        .where(SystemState.id == 1)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    assert state is not None
    try:
        received = updates(state.telegram_update_offset)
    except DeliveryFailure as exc:
        raise UpstreamFailed(exc.code) from exc
    bound: list[Connector] = []
    duplicate = ""
    for update in received:
        state.telegram_update_offset = max(
            state.telegram_update_offset, int(update["update_id"]) + 1
        )
        command = pairing_code(update)
        if command is None:
            continue
        chat, code = command
        connector = next(
            (
                c
                for c in pending
                if c.challenge_hash and hmac.compare_digest(digest(code), c.challenge_hash)
            ),
            None,
        )
        if connector is None:
            continue
        connector.challenge_hash = None
        connector.challenge_expires_at = None
        chat_id = str(chat["id"])
        taken = next(
            (
                other
                for other in db.scalars(
                    select(Connector).where(
                        Connector.channel == "telegram",
                        Connector.removed_at.is_(None),
                        Connector.id != connector.id,
                        Connector.verified_at.is_not(None),
                    )
                )
                if other.config.get("chat_id") == chat_id
            ),
            None,
        )
        if taken:
            duplicate = taken.label or "another recipient"
            continue
        connector.config = {"chat_id": chat_id}
        connector.verified_at = utcnow()
        connector.label = connector.label or chat_label(chat)
        queue_initial_summary(db, connector, settings)
        bound.append(connector)
    db.commit()
    if duplicate and (target is None or target not in bound):
        raise Conflict(f"This Telegram chat already receives alerts as {duplicate}")
    return target in bound if target else bool(bound)


def remove(db: Session, connector_id: str) -> None:
    """Stop sending to a Telegram chat for good; its delivery history keeps its name."""
    connector = telegram_recipient(db, connector_id)
    new_generation(db, connector)
    connector.removed_at = utcnow()
    connector.enabled = False
    connector.config = {}
    connector.challenge_hash = None
    connector.challenge_expires_at = None
    db.commit()


def disable(db: Session, connector_id: str) -> None:
    get_connector(db, connector_id).enabled = False
    db.commit()


def enable(db: Session, connector_id: str) -> None:
    connector = get_connector(db, connector_id)
    if not connector.verified_at:
        raise Conflict("Verify this destination first")
    connector.enabled = True
    db.commit()


def send_test(db: Session, settings: Settings, connector_id: str) -> str:
    """Queue a test message; returns its delivery ID."""
    connector = get_connector(db, connector_id)
    if not connector.verified_at or not connector.enabled:
        raise Conflict("Enable and verify this destination first")
    message = channel_test_message(db, connector, db.get(NotificationPolicy, 1))
    delivery = queue_message(db, connector, message, settings)
    db.commit()
    return delivery.id


def list_deliveries(db: Session, limit: int, offset: int) -> list[Delivery]:
    return list(
        db.scalars(
            select(Delivery)
            .order_by(Delivery.created_at.desc(), Delivery.id)
            .limit(limit)
            .offset(offset)
        )
    )


def delivery_attempts(db: Session, delivery_id: str) -> list[DeliveryAttempt]:
    if db.get(Delivery, delivery_id) is None:
        raise NotFound("Delivery not found")
    return list(
        db.scalars(
            select(DeliveryAttempt)
            .where(DeliveryAttempt.delivery_id == delivery_id)
            .order_by(DeliveryAttempt.attempt_number.desc())
        )
    )


def retry_delivery(db: Session, delivery_id: str) -> None:
    delivery = db.get(Delivery, delivery_id)
    if delivery is None:
        raise NotFound("Delivery not found")
    if delivery.status != "failed":
        raise Conflict("Only failed deliveries can be retried")
    delivery.status = "queued"
    delivery.attempts = 0
    delivery.available_at = utcnow()
    delivery.lease_token = None
    delivery.last_error = None
    db.commit()


def get_policy(db: Session) -> NotificationPolicy:
    policy = db.get(NotificationPolicy, 1)
    assert policy is not None
    return policy


def set_policy(db: Session, values: dict[str, Any]) -> None:
    policy = get_policy(db)
    for key, value in values.items():
        setattr(policy, key, value)
    policy.next_digest_at = next_digest(utcnow(), policy.timezone, policy.digest_hour)
    db.commit()
