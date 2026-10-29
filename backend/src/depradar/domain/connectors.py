"""Settings of the notification destinations the owner configures."""

import re
from typing import Literal

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
