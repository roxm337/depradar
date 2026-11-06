"""The /api/mcp endpoint: Streamable HTTP, stateless, with JSON responses.

Each request is authenticated on its own with an AI assistant (MCP) token, so there are no
server-side sessions to keep, clean up, or lose on restart. The API runs as one process, so the
rate limit is kept in memory.
"""

import time
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import anyio.to_thread
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import Receive, Scope, Send

from depradar.application import auth
from depradar.application.errors import Unauthorized
from depradar.config import Settings
from depradar.domain.security import Principal
from depradar.domain.tokens import well_formed
from depradar.interfaces.mcp.context import CALLER, RUNTIME, Caller
from depradar.interfaces.mcp.server import server

# JSON escaping makes a lockfile longer than its upload limit; leave room for that.
BODY_HEADROOM = 1024 * 1024


class RateLimiter:
    """At most `limit` requests per token in any 60-second window."""

    def __init__(self) -> None:
        self.calls: dict[str, deque[float]] = {}

    def retry_after(self, key: str, limit: int, now: float | None = None) -> int | None:
        now = time.monotonic() if now is None else now
        window = self.calls.setdefault(key, deque())
        while window and window[0] <= now - 60:
            window.popleft()
        if len(window) >= limit:
            return max(1, int(window[0] + 60 - now) + 1)
        window.append(now)
        if len(self.calls) > 10000:
            # Drop idle tokens so revoked or expired ones cannot grow the table forever.
            for idle in [k for k, calls in self.calls.items() if not calls]:
                del self.calls[idle]
        return None


def _challenge(status: int, detail: str, error: str | None = None) -> Response:
    value = f'Bearer error="{error}"' if error else "Bearer"
    return JSONResponse({"detail": detail}, status_code=status, headers={"WWW-Authenticate": value})


def _authenticate(settings: Settings, header: str) -> Principal:
    scheme, _, value = header.partition(" ")
    value = value.strip()
    if scheme.lower() != "bearer" or not well_formed(value):
        raise Unauthorized("Valid bearer AI assistant (MCP) token required")
    with RUNTIME.factory()() as db:
        return auth.principal_for(db, value, audience="mcp")


class Endpoint:
    def __init__(self) -> None:
        self.manager: StreamableHTTPSessionManager | None = None
        self.limiter = RateLimiter()

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        """Run the SDK's request manager for the life of the API process."""
        settings = RUNTIME.settings()
        manager = StreamableHTTPSessionManager(
            app=server._lowlevel_server,
            stateless=True,
            json_response=True,
            max_request_body_size=settings.upload_limit_bytes + BODY_HEADROOM,
        )
        async with manager.run():
            self.manager = manager
            try:
                yield
            finally:
                self.manager = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        refusal, principal = await self.admit(Request(scope))
        if refusal is not None:
            await refusal(scope, receive, send)
            return
        assert principal is not None and self.manager is not None
        client = Request(scope).headers.get("user-agent", "")
        token = CALLER.set(Caller(principal, client_name=client[:100]))
        try:
            await self.manager.handle_request(scope, receive, send)
        finally:
            CALLER.reset(token)

    async def admit(self, request: Request) -> tuple[Response | None, Principal | None]:
        """The authenticated principal, or the response that refuses the request.

        Only headers are read here; the body is left for the SDK.
        """
        settings = RUNTIME.settings()
        if not settings.mcp_enabled:
            return JSONResponse({"detail": "Not Found"}, status_code=404), None
        origin = request.headers.get("origin")
        # Assistants connect from a server or a terminal and send no Origin. A browser page
        # may call only from an allowed origin, which blocks DNS rebinding attacks.
        allowed = {settings.allowed_origin, *settings.mcp_allowed_origins}
        if origin is not None and origin not in allowed:
            return JSONResponse({"detail": "Origin is not allowed"}, status_code=403), None
        if request.method != "POST":
            # Stateless: there is no session to open a stream for or to delete.
            refusal = JSONResponse(
                {"detail": "Use POST"}, status_code=405, headers={"Allow": "POST"}
            )
            return refusal, None
        header = request.headers.get("authorization")
        if header is None:
            return _challenge(401, "Bearer AI assistant (MCP) token required"), None
        try:
            principal = await anyio.to_thread.run_sync(_authenticate, settings, header)
        except Unauthorized as exc:
            return _challenge(401, str(exc), "invalid_token"), None
        assert principal.token_id is not None
        wait = self.limiter.retry_after(principal.token_id, settings.mcp_rate_limit_per_minute)
        if wait is not None:
            refusal = JSONResponse(
                {"detail": "Too many requests for this token"},
                status_code=429,
                headers={"Retry-After": str(wait)},
            )
            return refusal, None
        if self.manager is None:
            return JSONResponse({"detail": "MCP is starting; retry"}, status_code=503), None
        return None, principal


endpoint = Endpoint()
