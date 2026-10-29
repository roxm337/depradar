"""What the application needs from the outside world. Infrastructure implements each port."""

from collections.abc import Callable
from datetime import datetime
from typing import Any, Protocol

from depradar.domain.messages import Message
from depradar.domain.scanning import ScanResponse


class DeliveryFailure(Exception):
    """A provider refused or could not take a message; the code is safe to store."""

    def __init__(self, code: str, *, permanent: bool = False, retry_after: int = 30):
        super().__init__(code)
        self.code = code
        self.permanent = permanent
        self.retry_after = min(max(retry_after, 1), 86400)


class ScannerFailure(Exception):
    """The scanner produced no report; the message is safe to store."""


class FeedUnavailable(Exception):
    """Public vulnerability intelligence could not be fetched or understood."""


# (manifest content, canonical filename) -> scanner report
Scanner = Callable[[bytes, str], ScanResponse]
# -> whether the scanner service answers its health check
ScannerProbe = Callable[[], bool]
# (connector id, connector config, message, delivery id) -> provider reference
NotificationSender = Callable[[str, dict[str, Any], Message, str], str]
# (update offset) -> pending Telegram bot updates
TelegramUpdates = Callable[[int], list[dict[str, Any]]]
# (CVE ids) -> (CISA KEV catalog, {CVE: (EPSS score, percentile)})
IntelligenceFeed = Callable[[list[str]], tuple[set[str], dict[str, tuple[float, float | None]]]]


class InventoryStore(Protocol):
    """Immutable manifest snapshots, addressed only by server-generated identifiers."""

    def save(self, inventory_id: str, content: bytes) -> None: ...

    def load(self, inventory_id: str) -> bytes:
        """Raises FileNotFoundError when the snapshot is gone."""
        ...

    def remove(self, inventory_id: str) -> None: ...

    def stale(self, before: datetime) -> list[str]:
        """Identifiers of stored snapshots last written before the cutoff."""
        ...
