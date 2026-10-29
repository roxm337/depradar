"""HTTP client for the private scanner service."""

import httpx

from depradar.application.ports import ScannerFailure
from depradar.config import Settings
from depradar.domain.scanning import ScanResponse

RESPONSE_LIMIT = 32 * 1024 * 1024


class RemoteScanner:
    """Implements the Scanner and ScannerProbe ports over the scanner service API."""

    def __init__(self, settings: Settings) -> None:
        self.base_url = settings.scanner_url.rstrip("/")
        self.timeout = settings.scanner_timeout_seconds + 15

    def __call__(self, content: bytes, filename: str) -> ScanResponse:
        try:
            with httpx.Client(timeout=self.timeout, trust_env=False) as client:
                with client.stream(
                    "POST",
                    self.base_url + "/scan",
                    params={"filename": filename},
                    content=content,
                    headers={"Content-Type": "application/octet-stream"},
                ) as response:
                    response.raise_for_status()
                    data = bytearray()
                    for chunk in response.iter_bytes():
                        data.extend(chunk)
                        if len(data) > RESPONSE_LIMIT:
                            raise ValueError("Scanner response exceeds limit")
        # Only these fixed messages are stored; response bodies may echo inventory data.
        except httpx.HTTPStatusError as exc:
            raise ScannerFailure(
                f"Scanner service returned HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise ScannerFailure("Scanner service unavailable or timed out") from exc
        return ScanResponse.model_validate_json(data)

    def available(self) -> bool:
        try:
            with httpx.Client(timeout=3, trust_env=False) as client:
                response = client.get(self.base_url + "/health")
                response.raise_for_status()
                return bool(response.json().get("status") == "ok")
        except (httpx.HTTPError, ValueError, AttributeError):
            return False
