"""Owner sign-in and sessions, local password recovery, and scoped API tokens."""

import hmac
import secrets
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from depradar.application.errors import (
    Conflict,
    Forbidden,
    Invalid,
    NotFound,
    RateLimited,
    Unauthorized,
    Unavailable,
)
from depradar.application.locking import lock_writes
from depradar.config import Settings
from depradar.domain.entities import ApiToken, AuthGuard, Owner, OwnerSession, Project, utcnow
from depradar.domain.security import DUMMY_HASH, Principal, digest, hash_password, verify_password
from depradar.domain.tokens import DISPLAY_LENGTH, SCOPES, generate_token


def initialized(db: Session) -> bool:
    return db.get(Owner, 1) is not None


def session_for(db: Session, token: str) -> OwnerSession:
    session = db.get(OwnerSession, digest(token)) if len(token) <= 100 else None
    if session is None or session.expires_at <= utcnow():
        raise Unauthorized("Sign in required")
    return session


def lock_auth(db: Session) -> AuthGuard:
    lock_writes(db)
    guard = db.scalars(select(AuthGuard).where(AuthGuard.id == 1).with_for_update()).one()
    if guard.window_start <= utcnow() - timedelta(minutes=15):
        guard.window_start = utcnow()
        guard.failures = 0
    if guard.failures >= 10:
        raise RateLimited("Too many attempts; retry after 15 minutes", retry_after=900)
    return guard


def start_session(db: Session, settings: Settings) -> tuple[str, str]:
    """Open an owner session; returns the cookie token and its CSRF token."""
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_hex(32)
    db.execute(delete(OwnerSession).where(OwnerSession.expires_at <= utcnow()))
    db.add(
        OwnerSession(
            token_hash=digest(token),
            csrf_token=csrf,
            expires_at=utcnow() + timedelta(hours=settings.session_hours),
        )
    )
    db.commit()
    return token, csrf


def bootstrap(
    db: Session, settings: Settings, password: str, bootstrap_token: str
) -> tuple[str, str]:
    guard = lock_auth(db)
    if db.get(Owner, 1):
        raise Conflict("Owner is already initialized")
    expected = settings.bootstrap_token.get_secret_value()
    if len(expected) < 32 or not hmac.compare_digest(expected, bootstrap_token):
        guard.failures += 1
        db.commit()
        raise Forbidden("Valid bootstrap token required")
    db.add(Owner(id=1, password_hash=hash_password(password)))
    guard.failures = 0
    return start_session(db, settings)


def login(db: Session, settings: Settings, password: str) -> tuple[str, str]:
    guard = lock_auth(db)
    owner = db.get(Owner, 1)
    valid = verify_password(password, owner.password_hash if owner else DUMMY_HASH)
    if not valid or owner is None:
        guard.failures += 1
        db.commit()
        raise Unauthorized("Invalid credentials")
    guard.failures = 0
    return start_session(db, settings)


def logout(db: Session, session: OwnerSession) -> None:
    db.delete(session)
    db.commit()


def set_owner_password(factory: sessionmaker[Session], password: str, *, initialize: bool) -> None:
    """Local recovery: create the owner or replace its password, revoking every session."""
    with factory.begin() as db:
        lock_writes(db)
        guard = db.scalar(select(AuthGuard).where(AuthGuard.id == 1).with_for_update())
        owner = db.get(Owner, 1)
        if guard is None:
            raise Unavailable("Apply database migrations before owner setup")
        if initialize:
            if owner is not None:
                raise Conflict("Owner already initialized; use reset-password for recovery")
            db.add(Owner(id=1, password_hash=hash_password(password)))
        else:
            if owner is None:
                raise Conflict("Initialize the owner before resetting the password")
            owner.password_hash = hash_password(password)
        guard.failures = 0
        guard.window_start = utcnow()
        db.execute(delete(OwnerSession))


def principal_for(db: Session, secret: str) -> Principal:
    """The principal a well-formed bearer token acts as."""
    token = db.scalar(select(ApiToken).where(ApiToken.token_hash == digest(secret)))
    now = utcnow()
    if token is None or token.revoked_at is not None or token.expires_at <= now:
        raise Unauthorized("API token is invalid, expired, or revoked")
    if token.last_used_at is None or token.last_used_at < now - timedelta(minutes=1):
        token.last_used_at = now
        # Tokens are excluded from backups, so this bookkeeping needs no write barrier.
        db.commit()
    return Principal(
        token_id=token.id,
        scopes=frozenset(token.scopes).intersection(SCOPES),
        project_id=token.project_id,
    )


def list_tokens(db: Session) -> list[ApiToken]:
    return list(db.scalars(select(ApiToken).order_by(ApiToken.created_at.desc(), ApiToken.id)))


def create_token(
    db: Session, name: str, scopes: list[str], project_id: str | None, expires_in_days: int
) -> tuple[ApiToken, str]:
    """Store a new token's digest; the secret is returned once and never kept."""
    if project_id and db.get(Project, project_id) is None:
        raise NotFound("Project not found")
    if project_id and "projects:write" in scopes:
        raise Invalid("Project-restricted tokens cannot create projects")
    secret = generate_token()
    token = ApiToken(
        name=name,
        token_hash=digest(secret),
        display_prefix=secret[:DISPLAY_LENGTH],
        scopes=sorted(set(scopes)),
        project_id=project_id,
        expires_at=utcnow() + timedelta(days=expires_in_days),
    )
    db.add(token)
    db.commit()
    return token, secret


def revoke_token(db: Session, token_id: str) -> None:
    token = db.get(ApiToken, token_id)
    if token is None:
        raise NotFound("Token not found")
    if token.revoked_at is None:
        token.revoked_at = utcnow()
    db.commit()
