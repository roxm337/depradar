"""Owner sign-in: first-run setup, login, the current session, and logout."""

from typing import Annotated

from fastapi import APIRouter, Header, Request, Response

from depradar.application import auth
from depradar.config import Settings
from depradar.interfaces.http.dependencies import (
    COOKIE_NAME,
    Authenticated,
    Config,
    Db,
    check_origin,
)
from depradar.interfaces.http.schemas import PasswordInput

router = APIRouter(prefix="/api/auth")


def open_session(
    response: Response, settings: Settings, session: tuple[str, str]
) -> dict[str, str]:
    token, csrf = session
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="strict",
        secure=settings.secure_cookies,
        max_age=settings.session_hours * 3600,
    )
    response.headers["Cache-Control"] = "no-store"
    return {"csrf_token": csrf}


@router.get("/status")
def auth_status(db: Db) -> dict[str, bool]:
    return {"initialized": auth.initialized(db)}


@router.post("/bootstrap", status_code=201)
def bootstrap(
    body: PasswordInput,
    request: Request,
    response: Response,
    db: Db,
    settings: Config,
    x_bootstrap_token: Annotated[str, Header()] = "",
) -> dict[str, str]:
    check_origin(request, settings)
    session = auth.bootstrap(db, settings, body.password, x_bootstrap_token)
    return open_session(response, settings, session)


@router.post("/login")
def login(
    body: PasswordInput, request: Request, response: Response, db: Db, settings: Config
) -> dict[str, str]:
    check_origin(request, settings)
    return open_session(response, settings, auth.login(db, settings, body.password))


@router.get("/me")
def me(session: Authenticated) -> dict[str, str]:
    return {"user": "owner", "csrf_token": session.csrf_token}


@router.post("/logout", status_code=204)
def logout(session: Authenticated, db: Db, response: Response) -> None:
    auth.logout(db, session)
    response.delete_cookie(COOKIE_NAME)
