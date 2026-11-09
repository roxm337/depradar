"""Who is calling, and the per-call database session, audit record, and error mapping."""

import functools
import logging
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import ParamSpec, TypeVar

from mcp.server.mcpserver.exceptions import ToolError
from sqlalchemy.orm import Session, sessionmaker

from depradar.application import audit
from depradar.application.errors import ApplicationError
from depradar.config import Settings, get_settings
from depradar.domain.security import Principal
from depradar.infrastructure.database import session_factory

logger = logging.getLogger(__name__)
P = ParamSpec("P")
R = TypeVar("R")


@dataclass
class Runtime:
    """Process-wide dependencies of the MCP endpoint; tests swap them for their own."""

    settings: Callable[[], Settings] = get_settings
    factory: Callable[[], sessionmaker[Session]] = session_factory


RUNTIME = Runtime()


@dataclass
class Caller:
    """The authenticated request an MCP call belongs to."""

    principal: Principal
    client_name: str = ""


@dataclass
class Trail:
    """What the audit record says about one call."""

    project_id: str | None = None


@dataclass
class Call:
    db: Session
    caller: Caller
    settings: Settings
    trail: Trail

    def touches(self, project_id: str) -> None:
        """Name the project this call read or changed, for the audit record."""
        self.trail.project_id = project_id


CALLER: ContextVar[Caller | None] = ContextVar("depradar_mcp_caller", default=None)
CALL: ContextVar[Call | None] = ContextVar("depradar_mcp_call", default=None)


def caller() -> Caller:
    current = CALLER.get()
    # The endpoint authenticates every request before the SDK dispatches it.
    assert current is not None, "MCP call outside an authenticated request"
    return current


def call() -> Call:
    current = CALL.get()
    assert current is not None, "MCP tool body outside a call"
    return current


@contextmanager
def _session() -> Iterator[Session]:
    with RUNTIME.factory()() as db:
        yield db


def audited(
    kind: str, name: str, scopes: frozenset[str]
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Check the token's scopes, run the body with its own session, and record the call.

    Application errors reach the assistant as tool errors with their message; anything else is
    logged here and reported to the assistant without detail.
    """

    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            who = caller()
            settings = RUNTIME.settings()
            started = time.monotonic()
            project = kwargs.get("project_id")
            trail = Trail(str(project)[:36] if project is not None else None)
            outcome, detail = "ok", ""
            try:
                missing = sorted(scopes - who.principal.scopes)
                if missing:
                    outcome = "denied"
                    detail = "missing scope: " + ", ".join(missing)
                    raise ToolError(
                        f"This token lacks the {', '.join(missing)} scope. Create an AI "
                        "assistant token with that access in DepRadar under Settings."
                    )
                with _session() as db:
                    token = CALL.set(Call(db, who, settings, trail))
                    try:
                        return fn(*args, **kwargs)
                    finally:
                        CALL.reset(token)
            except ToolError as exc:
                # A tool body may refuse a call itself; a missing scope is already "denied".
                if outcome != "denied":
                    outcome, detail = "error", str(exc)
                raise
            except ApplicationError as exc:
                outcome, detail = "error", str(exc)
                raise ToolError(str(exc)) from exc
            except Exception:
                outcome, detail = "error", "internal error"
                logger.exception("MCP %s %s failed", kind, name)
                raise
            finally:
                try:
                    with _session() as db:
                        audit.record(
                            db,
                            who.principal,
                            kind=kind,
                            name=name,
                            outcome=outcome,
                            project_id=trail.project_id,
                            client_name=who.client_name,
                            detail=detail,
                            duration_ms=int((time.monotonic() - started) * 1000),
                        )
                except Exception:
                    # An audit failure must not hide the call's own result or error.
                    logger.exception("Could not record MCP %s %s", kind, name)

        return wrapper

    return decorator
