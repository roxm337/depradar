"""The HTTP API: middleware, error mapping, and routers."""

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from depradar import __version__
from depradar.application.errors import (
    ApplicationError,
    Conflict,
    Forbidden,
    Invalid,
    NotFound,
    RateLimited,
    Unauthorized,
    Unavailable,
    UpstreamFailed,
)
from depradar.interfaces.http.routes import (
    auth,
    ci,
    findings,
    notifications,
    operations,
    projects,
    tokens,
)

STATUS: dict[type[ApplicationError], int] = {
    NotFound: 404,
    Conflict: 409,
    Invalid: 422,
    Forbidden: 403,
    Unauthorized: 401,
    RateLimited: 429,
    Unavailable: 503,
    UpstreamFailed: 502,
}

app = FastAPI(
    title="DepRadar",
    version=__version__,
    description="Dependency vulnerability monitoring with CI/CD gates. Automation clients "
    "authenticate with `Authorization: Bearer <token>` from Settings → CI/CD tokens.",
)


@app.middleware("http")
async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Pydantic errors may echo password/input values; return locations and messages only.
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
                for error in exc.errors()
            ]
        },
    )


@app.exception_handler(ApplicationError)
async def application_error(request: Request, exc: ApplicationError) -> JSONResponse:
    status = next(code for kind, code in STATUS.items() if isinstance(exc, kind))
    headers = {"Retry-After": str(exc.retry_after)} if isinstance(exc, RateLimited) else None
    return JSONResponse({"detail": str(exc)}, status_code=status, headers=headers)


for router in (
    operations.probes,
    operations.router,
    auth.router,
    projects.router,
    projects.owner,
    findings.router,
    notifications.router,
    tokens.router,
    ci.router,
):
    app.include_router(router)
