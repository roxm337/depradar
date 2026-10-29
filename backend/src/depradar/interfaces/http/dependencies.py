"""FastAPI dependencies: database session, settings, adapters, and request authentication."""

import hmac
from collections.abc import Callable
from functools import partial
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from depradar.application import auth
from depradar.application.errors import Unauthorized
from depradar.application.locking import lock_writes
from depradar.application.ports import InventoryStore, TelegramUpdates
from depradar.config import Settings, get_settings
from depradar.domain.entities import OwnerSession
from depradar.domain.security import Principal
from depradar.domain.tokens import well_formed
from depradar.infrastructure.database import get_db
from depradar.infrastructure.storage import LocalInventoryStore
from depradar.infrastructure.telegram import fetch_updates

COOKIE_NAME = "depradar_session"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
Db = Annotated[Session, Depends(get_db)]
Config = Annotated[Settings, Depends(get_settings)]


def inventory_store(settings: Config) -> InventoryStore:
    return LocalInventoryStore(settings.storage_dir)


def telegram_updates(settings: Config) -> TelegramUpdates:
    return partial(fetch_updates, settings)


Store = Annotated[InventoryStore, Depends(inventory_store)]
Updates = Annotated[TelegramUpdates, Depends(telegram_updates)]


def check_origin(request: Request, settings: Settings) -> None:
    origin = request.headers.get("origin")
    if origin is not None and origin != settings.allowed_origin:
        raise HTTPException(403, "Origin is not allowed")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Cross-site requests are not allowed")


def owner_session(request: Request, db: Session, settings: Settings) -> OwnerSession:
    session = auth.session_for(db, request.cookies.get(COOKIE_NAME, ""))
    if request.method not in SAFE_METHODS:
        check_origin(request, settings)
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), session.csrf_token):
            raise HTTPException(403, "Valid X-CSRF-Token required")
    return session


def require_session(request: Request, db: Db, settings: Config) -> OwnerSession:
    session = owner_session(request, db, settings)
    if request.method not in SAFE_METHODS:
        lock_writes(db)
    return session


Authenticated = Annotated[OwnerSession, Depends(require_session)]


def token_principal(db: Session, header: str) -> Principal:
    scheme, _, value = header.partition(" ")
    value = value.strip()
    challenge = {"WWW-Authenticate": "Bearer"}
    if scheme.lower() != "bearer" or not well_formed(value):
        raise HTTPException(401, "Valid bearer API token required", headers=challenge)
    try:
        return auth.principal_for(db, value)
    except Unauthorized as exc:
        raise HTTPException(401, str(exc), headers=challenge) from exc


def authorize(*scopes: str, lock: bool = True) -> Callable[[Request, Session, Settings], Principal]:
    """Accept the owner session or a bearer token holding every listed scope.

    Bearer requests carry no ambient browser credential, so they skip origin and CSRF checks.
    Pass lock=False when the endpoint must read a request body before taking the write barrier.
    """

    def dependency(request: Request, db: Db, settings: Config) -> Principal:
        header = request.headers.get("authorization")
        if header is None:
            owner_session(request, db, settings)
            principal = Principal()
        else:
            principal = token_principal(db, header)
            missing = sorted(set(scopes) - principal.scopes)
            if missing:
                raise HTTPException(403, "API token lacks required scope: " + ", ".join(missing))
        if lock and request.method not in SAFE_METHODS:
            lock_writes(db)
        return principal

    return dependency


ReadProjects = Annotated[Principal, Depends(authorize("projects:read"))]
WriteProjects = Annotated[Principal, Depends(authorize("projects:write"))]
ReadScans = Annotated[Principal, Depends(authorize("scans:read"))]
ReadFindings = Annotated[Principal, Depends(authorize("findings:read"))]
WriteInventories = Annotated[Principal, Depends(authorize("inventories:write"))]
# Upload endpoints stream the body first and take the write barrier themselves.
UploadInventories = Annotated[Principal, Depends(authorize("inventories:write", lock=False))]


async def read_limited(request: Request, limit: int) -> bytes:
    """Read the raw body before taking the write barrier so slow clients cannot block writers."""
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > limit:
            raise HTTPException(413, "Inventory exceeds upload limit")
        content.extend(chunk)
    return bytes(content)
