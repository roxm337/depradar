"""Owner credentials, digests, and the principal a request acts as."""

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from depradar.domain.identity import VerifiedRun
from depradar.domain.tokens import SCOPES


@dataclass(frozen=True)
class Principal:
    """The owner session (every scope, every project), a scoped API token, or a verified run."""

    token_id: str | None = None
    scopes: frozenset[str] = frozenset(SCOPES)
    project_id: str | None = None
    name: str = "Owner"
    # Set for short-lived tokens exchanged from a verified OIDC identity token.
    run: VerifiedRun | None = None

    def allows(self, project_id: str) -> bool:
        return self.project_id is None or self.project_id == project_id

    def can_upload(self, mode: str) -> bool:
        """Check uploads never change monitored state, so a narrower scope suffices."""
        if "inventories:write" in self.scopes:
            return True
        return mode == "check" and "inventories:check" in self.scopes


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
