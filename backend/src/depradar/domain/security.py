"""Owner credentials, digests, and the principal a request acts as."""

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from depradar.domain.tokens import SCOPES


@dataclass(frozen=True)
class Principal:
    """The owner session (every scope, every project) or a scoped API token."""

    token_id: str | None = None
    scopes: frozenset[str] = frozenset(SCOPES)
    project_id: str | None = None

    def allows(self, project_id: str) -> bool:
        return self.project_id is None or self.project_id == project_id


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=67108864)
    return f"scrypt${salt.hex()}${key.hex()}"


DUMMY_HASH = hash_password(secrets.token_urlsafe(32))


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, salt, expected = encoded.split("$")
        if scheme != "scrypt":
            return False
        key = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=1, maxmem=67108864
        )
        return hmac.compare_digest(key.hex(), expected)
    except (ValueError, TypeError):
        return False
