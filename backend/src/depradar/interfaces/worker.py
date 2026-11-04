"""The background worker: scans, scheduled rechecks, alert delivery, and feed refreshes."""

import logging
import threading
import time
from collections.abc import Callable

from depradar.application.notifications import deliver_once
from depradar.application.operations import update_worker_health
from depradar.application.scans import run_once
from depradar.application.scheduling import tick
from depradar.application.threat_intel import refresh_if_due
from depradar.config import get_settings
from depradar.infrastructure.database import session_factory
from depradar.infrastructure.notifier import Notifier
from depradar.infrastructure.scanner_client import RemoteScanner
from depradar.infrastructure.storage import LocalInventoryStore
from depradar.infrastructure.threat_feeds import PublicFeeds

logger = logging.getLogger(__name__)
# A cycle can legitimately spend this long on one scan plus feed and provider calls.
CYCLE_ALLOWANCE_SECONDS = 300


class Liveness:
    """Report the heartbeat from a side thread, so one long scan does not look like a crash.

    The heartbeat is only written while the main loop has started a cycle within its budget;
    a loop that hangs past that budget stops beating and the health page reports it stale.
    """

    def __init__(self, budget_seconds: float, clock: Callable[[], float] = time.monotonic):
        self.budget = budget_seconds
        self.clock = clock
        self.cycle_started = clock()

    def cycle(self) -> None:
        self.cycle_started = self.clock()

    def alive(self) -> bool:
        return self.clock() - self.cycle_started <= self.budget


def heartbeat(liveness: Liveness, beat: Callable[[], None], stop: threading.Event) -> None:
    while True:
        if liveness.alive():
            try:
                beat()
            except Exception:
                logger.error("worker_heartbeat_failed; retrying")
        if stop.wait(5):
            return


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    factory = session_factory()
    store = LocalInventoryStore(settings.storage_dir)
    scanner = RemoteScanner(settings)
    notifier = Notifier(settings)
    feeds = PublicFeeds(settings)
    logger.info("DepRadar worker started")
    liveness = Liveness(settings.scanner_timeout_seconds + CYCLE_ALLOWANCE_SECONDS)
    stop = threading.Event()
    threading.Thread(
        target=heartbeat,
        args=(liveness, lambda: update_worker_health(factory, scanner.available), stop),
        name="depradar-heartbeat",
        daemon=True,
    ).start()
    try:
        while True:
            liveness.cycle()
            try:
                refresh_if_due(factory, settings, feeds)
                tick(factory, settings, store)
                delivered = deliver_once(factory, settings, notifier)
                scanned = run_once(factory, settings, store, scanner)
            except Exception:
                # Provider/DB exception strings can contain credentials; retry without logging them.
                logger.error("worker_cycle_failed; retrying")
                time.sleep(settings.worker_poll_seconds)
                continue
            if not scanned and not delivered:
                time.sleep(settings.worker_poll_seconds)
    except KeyboardInterrupt:
        logger.info("Worker stopped; active leases will be recovered")
    finally:
        stop.set()


if __name__ == "__main__":
    main()
