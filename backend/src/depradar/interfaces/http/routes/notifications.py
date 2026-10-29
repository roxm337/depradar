"""Notification destinations, delivery history, and the alert policy."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from depradar.application import connectors
from depradar.domain.connectors import EmailConfig
from depradar.domain.entities import Delivery, DeliveryAttempt
from depradar.interfaces.http.dependencies import Config, Db, Updates, require_session
from depradar.interfaces.http.schemas import (
    DeliveryAttemptOutput,
    DeliveryOutput,
    PolicyInput,
    VerificationInput,
)

router = APIRouter(prefix="/api", dependencies=[Depends(require_session)])


@router.get("/connectors")
def list_connectors(db: Db, settings: Config) -> list[dict[str, Any]]:
    return connectors.list_connectors(db, settings)


@router.put("/connectors/email", status_code=202)
def configure_email(body: EmailConfig, db: Db, settings: Config) -> dict[str, str]:
    connectors.configure_email(db, settings, body)
    return {"status": "verification_queued"}


@router.post("/connectors/email/verify")
def verify_email(body: VerificationInput, db: Db, settings: Config) -> dict[str, str]:
    connectors.verify_email(db, settings, body.code)
    return {"status": "verified"}


@router.post("/connectors/telegram/pair")
def pair_telegram(db: Db, settings: Config) -> dict[str, str]:
    command = connectors.pair_telegram(db, settings)
    return {"command": command, "instruction": "Send this to your bot in a private chat"}


@router.post("/connectors/telegram/confirm")
def confirm_telegram(db: Db, settings: Config, updates: Updates) -> dict[str, str]:
    matched = connectors.confirm_telegram(db, settings, updates)
    return {"status": "verified" if matched else "waiting_for_private_chat_command"}


@router.post("/connectors/{channel}/disable", status_code=204)
def disable_connector(channel: str, db: Db) -> None:
    connectors.disable(db, channel)


@router.post("/connectors/{channel}/test", status_code=202)
def test_connector(channel: str, db: Db, settings: Config) -> dict[str, str]:
    return {"delivery_id": connectors.send_test(db, settings, channel)}


@router.post("/connectors/{channel}/enable", status_code=204)
def enable_connector(channel: str, db: Db) -> None:
    connectors.enable(db, channel)


@router.get("/notifications/deliveries", response_model=list[DeliveryOutput])
def deliveries(
    db: Db,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Delivery]:
    return connectors.list_deliveries(db, limit, offset)


@router.get(
    "/notifications/deliveries/{delivery_id}/attempts",
    response_model=list[DeliveryAttemptOutput],
)
def delivery_attempts(delivery_id: UUID, db: Db) -> list[DeliveryAttempt]:
    return connectors.delivery_attempts(db, str(delivery_id))


@router.post("/notifications/deliveries/{delivery_id}/retry", status_code=202)
def retry_delivery(delivery_id: UUID, db: Db) -> dict[str, str]:
    connectors.retry_delivery(db, str(delivery_id))
    return {"status": "queued"}


@router.get("/notifications/policy", response_model=PolicyInput)
def get_policy(db: Db) -> PolicyInput:
    policy = connectors.get_policy(db)
    return PolicyInput(**{key: getattr(policy, key) for key in PolicyInput.model_fields})


@router.put("/notifications/policy", response_model=PolicyInput)
def set_policy(body: PolicyInput, db: Db) -> PolicyInput:
    connectors.set_policy(db, body.model_dump())
    return body
