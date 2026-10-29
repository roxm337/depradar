from typing import Any

from depradar.application.ports import DeliveryFailure
from depradar.config import Settings
from depradar.domain.connectors import EmailConfig
from depradar.domain.messages import Message
from depradar.infrastructure.email import send_email
from depradar.infrastructure.telegram import send_telegram


class Notifier:
    """Implements the NotificationSender port by dispatching to the connector's channel."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def __call__(
        self, connector_id: str, config: dict[str, Any], message: Message, delivery_id: str
    ) -> str:
        if connector_id == "email":
            email = EmailConfig.model_validate(config)
            return send_email(self.settings, email, message, delivery_id)
        if connector_id == "telegram":
            return send_telegram(self.settings, config, message, delivery_id)
        raise DeliveryFailure("unknown_connector", permanent=True)
