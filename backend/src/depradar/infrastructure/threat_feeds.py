"""CISA KEV and FIRST EPSS feeds over HTTPS."""

import httpx

from depradar.application.ports import FeedUnavailable
from depradar.config import Settings


class PublicFeeds:
    """Implements the IntelligenceFeed port with the public CISA and FIRST feeds."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def __call__(
        self, cve_ids: list[str]
    ) -> tuple[set[str], dict[str, tuple[float, float | None]]]:
        try:
            return fetch_public_intelligence(self.settings, cve_ids)
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            raise FeedUnavailable("Vulnerability intelligence feeds are unavailable") from exc


def fetch_public_intelligence(
    settings: Settings, cve_ids: list[str]
) -> tuple[set[str], dict[str, tuple[float, float | None]]]:
    with httpx.Client(timeout=30, trust_env=False, follow_redirects=True) as client:
        kev_response = client.get(settings.kev_feed_url)
        kev_response.raise_for_status()
        catalog = kev_response.json()
        vulnerabilities = catalog.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ValueError("Invalid CISA KEV feed")
        kev_ids = {
            str(item["cveID"]).upper()
            for item in vulnerabilities
            if isinstance(item, dict) and isinstance(item.get("cveID"), str)
        }
        scores: dict[str, tuple[float, float | None]] = {}
        # FIRST documents a 2000-character maximum for the comma-separated CVE filter.
        for start in range(0, len(cve_ids), 80):
            batch = cve_ids[start : start + 80]
            if not batch:
                continue
            response = client.get(settings.epss_api_url, params={"cve": ",".join(batch)})
            response.raise_for_status()
            payload = response.json()
            for row in payload.get("data", []):
                if not isinstance(row, dict) or not isinstance(row.get("cve"), str):
                    continue
                try:
                    score = float(row["epss"])
                    percentile = (
                        float(row["percentile"]) if row.get("percentile") is not None else None
                    )
                except (KeyError, TypeError, ValueError):
                    continue
                if 0 <= score <= 1 and (percentile is None or 0 <= percentile <= 1):
                    scores[row["cve"].upper()] = (score, percentile)
    return kev_ids, scores
