"""Private scanner process. Deploy separately with no database or application credentials."""

from fastapi import FastAPI, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from depradar.config import get_settings
from depradar.domain.inventory import InventoryError, canonical_filename, validate_inventory
from depradar.domain.scanning import ScanResponse
from depradar.infrastructure import osv

app = FastAPI(title="DepRadar private scanner", docs_url=None, redoc_url=None, openapi_url=None)
STATUS: dict[type[osv.OsvError], int] = {osv.Busy: 503, osv.TimedOut: 504, osv.NoPackages: 422}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(request: Request, filename: str) -> ScanResponse:
    settings = get_settings()
    try:
        filename = canonical_filename(filename)
    except InventoryError as exc:
        raise HTTPException(422, str(exc)) from exc
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > settings.upload_limit_bytes:
            raise HTTPException(413, "Inventory exceeds upload limit")
        data.extend(chunk)
    try:
        validate_inventory(filename, bytes(data))
    except InventoryError as exc:
        raise HTTPException(422, str(exc)) from exc
    try:
        return await run_in_threadpool(osv.scan, settings, bytes(data), filename)
    except osv.OsvError as exc:
        raise HTTPException(STATUS.get(type(exc), 502), str(exc)) from exc
