"""Scoped API tokens for CI/CD pipelines and other automation clients."""

import hmac
import secrets
import string
import zlib
from typing import Literal, get_args

Scope = Literal[
    "projects:read", "projects:write", "inventories:write", "scans:read", "findings:read"
]
SCOPES: tuple[str, ...] = get_args(Scope)
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
