"""The background worker: scans, scheduled rechecks, alert delivery, and feed refreshes."""

import logging
import time

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


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    factory = session_factory()
    store = LocalInventoryStore(settings.storage_dir)
    scanner = RemoteScanner(settings)
    notifier = Notifier(settings)
    feeds = PublicFeeds(settings)
    logger.info("DepRadar worker started")
    try:
        while True:
            try:
                update_worker_health(factory, scanner.available)
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


if __name__ == "__main__":
    main()
