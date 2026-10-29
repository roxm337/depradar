import httpx
import pytest
from pydantic import SecretStr

from depradar.application.ports import DeliveryFailure
from depradar.config import Settings
from depradar.domain.connectors import EmailConfig
from depradar.domain.messages import connector_test_message
from depradar.infrastructure import email, telegram
from depradar.infrastructure.email import send_email
from depradar.infrastructure.telegram import telegram_call


def test_smtp_tls_precedes_auth_and_message_id_is_stable(monkeypatch) -> None:
    calls = []

    class SMTPDouble:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ehlo(self):
            calls.append("ehlo")

        def starttls(self, **kwargs):
            calls.append("tls")

        def login(self, *args):
            calls.append("login")

        def send_message(self, message):
            assert message["Message-ID"] == "<delivery-id@example.test>"
            assert message["To"] == "owner@example.test"
            assert message["From"] == "DepRadar <radar@example.test>"
            assert message["Auto-Submitted"] == "auto-generated"
            assert message.get_body(("plain",)) and message.get_body(("html",))
            calls.append("send")
            return {}

    monkeypatch.setattr(email.smtplib, "SMTP", SMTPDouble)
    config = EmailConfig(
        host="smtp.example.test",
        username="owner",
        sender="radar@example.test",
        recipient="owner@example.test",
    )
    settings = Settings(smtp_password=SecretStr("private"))
    send_email(settings, config, connector_test_message("email", None), "delivery-id")
    assert calls.index("tls") < calls.index("login") < calls.index("send")


def test_smtp_refuses_plaintext_without_explicit_test_override() -> None:
    config = EmailConfig(
        host="localhost",
        tls_mode="none",
        sender="radar@example.test",
        recipient="owner@example.test",
    )
    with pytest.raises(DeliveryFailure, match="smtp_tls_required"):
        send_email(Settings(), config, connector_test_message("email", None), "id")


def test_telegram_429_retry_after_and_secret_safe_errors(monkeypatch) -> None:
    original = httpx.Client
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            429,
            json={
                "ok": False,
                "parameters": {"retry_after": 123},
            },
        )
    )
    monkeypatch.setattr(telegram.httpx, "Client", lambda **kwargs: original(transport=transport))
    with pytest.raises(DeliveryFailure) as caught:
        telegram_call(Settings(telegram_bot_token=SecretStr("private-token")), "sendMessage", {})
    assert caught.value.retry_after == 123
    assert "private-token" not in str(caught.value)
