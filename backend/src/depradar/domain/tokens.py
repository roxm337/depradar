"""Scoped API tokens for CI/CD pipelines and other automation clients."""

import hmac
import secrets
import string
import zlib
from typing import Literal, get_args

# inventories:write uploads monitored and check manifests; inventories:check uploads check
# manifests only, so a pull request pipeline holding it can never change monitored state.
# components:read searches where a package is used; only AI assistant (MCP) tokens hold it.
Scope = Literal[
    "projects:read",
    "projects:write",
    "inventories:write",
    "inventories:check",
    "scans:read",
    "findings:read",
    "components:read",
]
SCOPES: tuple[str, ...] = get_args(Scope)
# A token works on one interface only: "api" for the REST API, "mcp" for AI assistants.
Audience = Literal["api", "mcp"]
AUDIENCES: tuple[str, ...] = get_args(Audience)
# Assistants read, and may run check scans, which never change findings, alerts, or inventories.
AUDIENCE_SCOPES: dict[str, frozenset[str]] = {
    "api": frozenset(SCOPES) - {"components:read"},
    "mcp": frozenset(
        {"projects:read", "scans:read", "findings:read", "components:read", "inventories:check"}
    ),
}
PREFIX = "depradar_"
ALPHABET = string.digits + string.ascii_letters
BODY_LENGTH = 32
CHECKSUM_LENGTH = 6
DISPLAY_LENGTH = len(PREFIX) + 6


def _base62(value: int, width: int) -> str:
    digits = []
    for _ in range(width):
        value, remainder = divmod(value, 62)
        digits.append(ALPHABET[remainder])
    return "".join(reversed(digits))


def _checksum(body: str) -> str:
    return _base62(zlib.crc32(body.encode()), CHECKSUM_LENGTH)


def generate_token() -> str:
    body = "".join(secrets.choice(ALPHABET) for _ in range(BODY_LENGTH))
    return PREFIX + body + _checksum(body)


def well_formed(token: str) -> bool:
    """Reject typos and foreign secrets without a lookup; the checksum also aids leak scanners."""
    body = token[len(PREFIX) : -CHECKSUM_LENGTH]
    return (
        token.startswith(PREFIX)
        and len(token) == len(PREFIX) + BODY_LENGTH + CHECKSUM_LENGTH
        and all(character in ALPHABET for character in token[len(PREFIX) :])
        and hmac.compare_digest(_checksum(body), token[-CHECKSUM_LENGTH:])
    )
