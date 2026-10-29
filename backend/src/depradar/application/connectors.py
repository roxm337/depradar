"""Notification destinations, their verification, delivery history, and the alert policy."""

import hmac
import secrets
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from depradar.application.errors import Conflict, Invalid, NotFound, Unavailable, UpstreamFailed
from depradar.application.notifications import queue_initial_summary, queue_message
from depradar.application.ports import DeliveryFailure, TelegramUpdates
from depradar.config import Settings
from depradar.domain.connectors import EmailConfig
from depradar.domain.entities import (
    Connector,
    Delivery,
    DeliveryAttempt,
    NotificationPolicy,
    utcnow,
)
from depradar.domain.messages import connector_test_message, verification_message
from depradar.domain.schedule import next_digest
from depradar.domain.security import digest


def get_connector(db: Session, channel: str) -> Connector:
    connector = db.get(Connector, channel)
    if connector is None:
        raise NotFound("Connector not configured")
    return connector


def reset_connector(db: Session, channel: str) -> Connector:
    """Start a new configuration generation; unsent deliveries of the old one are cancelled."""
    connector = db.get(Connector, channel)
    if connector is None:
        connector = Connector(id=channel, config={}, generation=1)
        db.add(connector)
        db.flush()
    else:
        running = db.scalar(
            select(Delivery.id)
            .where(
                Delivery.connector_id == channel,
                Delivery.status == "sending",
                Delivery.lease_until > utcnow(),
            )
            .limit(1)
        )
        if running:
            raise Conflict("Wait for the in-flight delivery before reconfiguring")
        connector.generation += 1
    connector.verified_at = None
    connector.enabled = True
    return connector


def list_connectors(db: Session, settings: Settings) -> list[dict[str, Any]]:
    return [
        {
            "id": c.id,
            "enabled": c.enabled,
            "verified_at": c.verified_at,
            "config": c.config,
            "credential_configured": bool(
                settings.smtp_password.get_secret_value()
                if c.id == "email"
                else settings.telegram_bot_token.get_secret_value()
            ),
        }
        for c in db.scalars(select(Connector).order_by(Connector.id))
    ]


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


def pair_telegram(db: Session, settings: Settings) -> str:
    """Start pairing; returns the one-time command the owner sends to the bot."""
    if not settings.telegram_bot_token.get_secret_value():
        raise Unavailable("Set DEPRADAR_TELEGRAM_BOT_TOKEN before pairing")
    connector = reset_connector(db, "telegram")
    connector.config = {}
    code = secrets.token_urlsafe(24)
    connector.challenge_hash = digest(code)
    connector.challenge_expires_at = utcnow() + timedelta(minutes=15)
    db.commit()
    return f"/start {code}"


def confirm_telegram(db: Session, settings: Settings, updates: TelegramUpdates) -> bool:
    """Look for the pairing command in a private chat; True once the chat is bound."""
    connector = get_connector(db, "telegram")
    if not connector.challenge_expires_at or connector.challenge_expires_at <= utcnow():
        raise Invalid("Pairing expired; start a new pairing")
    try:
        pending = updates(connector.update_offset)
    except DeliveryFailure as exc:
        raise UpstreamFailed(exc.code) from exc
    matched = False
    for update in pending:
        connector.update_offset = max(connector.update_offset, int(update["update_id"]) + 1)
        message = update.get("message", {})
        parts = message.get("text", "").split()
        chat = message.get("chat", {})
        if (
            chat.get("type") == "private"
            and len(parts) == 2
            and parts[0] == "/start"
            and connector.challenge_hash
            and hmac.compare_digest(digest(parts[1]), connector.challenge_hash)
        ):
            connector.config = {"chat_id": str(chat["id"])}
            connector.verified_at = utcnow()
            connector.challenge_hash = None
            connector.challenge_expires_at = None
            queue_initial_summary(db, connector, settings)
            matched = True
            break
    db.commit()
    return matched


def disable(db: Session, channel: str) -> None:
    get_connector(db, channel).enabled = False
    db.commit()


def enable(db: Session, channel: str) -> None:
    connector = get_connector(db, channel)
    if not connector.verified_at:
        raise Conflict("Verify this destination first")
    connector.enabled = True
    db.commit()


def send_test(db: Session, settings: Settings, channel: str) -> str:
    """Queue a test message; returns its delivery ID."""
    connector = get_connector(db, channel)
    if not connector.verified_at or not connector.enabled:
        raise Conflict("Enable and verify this destination first")
    message = connector_test_message(connector.id, db.get(NotificationPolicy, 1))
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
