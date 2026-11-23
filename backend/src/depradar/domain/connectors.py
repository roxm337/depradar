"""Settings of the notification destinations the owner configures."""

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EmailConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    host: str = Field(min_length=1, max_length=253, pattern=r"^[a-zA-Z0-9.-]+$")
    port: int = Field(default=587, ge=1, le=65535)
    username: str = Field(default="", max_length=200, pattern=r"^[^\r\n]*$")
    sender: str = Field(max_length=254)
    recipient: str = Field(max_length=254)
    tls_mode: Literal["starttls", "tls", "none"] = "starttls"
    enabled: bool = True

    @field_validator("sender", "recipient")
    @classmethod
    def email_address(cls, value: str) -> str:
        if not re.fullmatch(
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value
        ):
            raise ValueError("Use a bare email address without display names or newlines")
        return value


# A Telegram chat (one person) is one recipient; the cap keeps a mistaken loop from piling up rows.
MAX_TELEGRAM_RECIPIENTS = 20
LABEL_MAX = 80


def clean_label(value: str) -> str:
    """One line of printable text, short enough to show beside a destination."""
    printable = "".join(char if char.isprintable() else " " for char in value)
    return " ".join(printable.split())[:LABEL_MAX]


def chat_label(chat: dict[str, Any]) -> str:
    """A default name for a paired chat, from the names its owner set in Telegram."""
    name = " ".join(str(chat.get(key) or "") for key in ("first_name", "last_name"))
    username = str(chat.get("username") or "")
    return clean_label(name) or (clean_label(f"@{username}") if username else "")
