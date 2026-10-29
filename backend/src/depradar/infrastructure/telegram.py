"""Telegram channel: renders a notification as Telegram HTML and sends it via the Bot API."""

import html
import ipaddress
import logging
import re
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

import httpx

from depradar.application.ports import DeliveryFailure
from depradar.config import Settings
from depradar.domain.messages import (
    Message,
    Style,
    change_label,
    count_label,
    details,
    groups,
    link,
    plain,
    row_parts,
)

logger = logging.getLogger(__name__)


TELEGRAM_LIMIT = 4000
EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "unknown": "⚪",
    "ok": "✅",
    "resolved": "✅",
}


def tg(value: str) -> str:
    return html.escape(value, quote=False)


TELEGRAM = Style(
    text=tg,
    code=lambda value: f"<code>{tg(value)}</code>",
    link=lambda label, url: f'<a href="{tg(url).replace(chr(34), "&quot;")}">{tg(label)}</a>',
)


def linkable(url: str) -> bool:
    """Telegram refuses buttons for addresses it cannot open, such as localhost."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme not in {"http", "https"} or "." not in host:
        return False
    if host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def visible_length(text: str) -> int:
    # Telegram counts UTF-16 code units after removing markup.
    return len(html.unescape(re.sub(r"<[^>]+>", "", text)).encode("utf-16-le")) // 2


def telegram_html(message: Message, base_url: str) -> tuple[str, dict[str, Any] | None]:
    while True:
        text, markup = render_telegram(message, base_url)
        if visible_length(text) <= TELEGRAM_LIMIT or message.kind == "alert" or not message.items:
            return text, markup
        message = replace(message, items=message.items[:-1], more=message.more + 1)


def render_telegram(message: Message, base_url: str) -> tuple[str, dict[str, Any] | None]:
    lines = [f"{EMOJI.get(message.tone, EMOJI['unknown'])} <b>{tg(message.title)}</b>"]
    lines += ["", tg(message.lead)]
    lines += ["", f"<code>{tg(message.code)}</code>"] if message.code else []
    if message.counts:
        counts = (f"{EMOJI[key]} {count_label(key, n)}" for key, n in message.counts)
        lines += ["", " · ".join(counts)]
    if message.kind == "alert" and message.items:
        item = message.items[0]
        lines += ["", *(f"<b>{label}:</b> {value}" for label, value in details(item, TELEGRAM))]
        lines += ["", f"<blockquote>{tg(item.summary)}</blockquote>"] if item.summary else []
    else:
        for project, items in groups(message.items):
            lines += ["", f"<b>{tg(project)}</b>"]
            for item in items:
                parts = [f"<b>{tg(item.package)}</b> <code>{tg(item.version)}</code>"]
                parts += row_parts(item, TELEGRAM)
                parts += [f"<i>{tg(change_label(item))}</i>"] if item.change else []
                mark = EMOJI["resolved" if item.change == "resolved" else item.severity]
                lines.append(f"{mark} " + " · ".join(parts))
    lines += ["", f"<i>…and {message.more} more in DepRadar.</i>"] if message.more else []
    if message.facts:
        lines += ["", *(f"<b>{tg(label)}:</b> {tg(value)}" for label, value in message.facts)]
    lines += ["", f"<i>{tg(message.note)}</i>"] if message.note else []
    label, path = message.action
    url = link(base_url, path)
    if linkable(url):
        button = {"text": label, "url": url, "style": "primary"}
        return "\n".join(lines), {"inline_keyboard": [[button]]}
    return "\n".join([*lines, "", f"{tg(label)}: <code>{tg(url)}</code>"]), None


def telegram_call(settings: Settings, method: str, payload: dict[str, Any]) -> dict[str, Any]:
    token = settings.telegram_bot_token.get_secret_value()
    if not token:
        raise DeliveryFailure("telegram_token_missing", permanent=True)
    # httpx logs request URLs at INFO; Telegram places its credential in the URL.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    try:
        with httpx.Client(timeout=15, trust_env=False) as client:
            response = client.post(
                f"{settings.telegram_api_base_url}/bot{token}/{method}", json=payload
            )
            data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Invalid Telegram response")
        if response.status_code == 429 or data.get("error_code") == 429:
            raise DeliveryFailure(
                "telegram_rate_limited",
                retry_after=int(data.get("parameters", {}).get("retry_after", 30)),
            )
        if response.status_code >= 400 or not data.get("ok"):
            raise DeliveryFailure(
                "telegram_rejected", permanent=response.status_code in {400, 401, 403}
            )
        return dict(data)
    except DeliveryFailure:
        raise
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise DeliveryFailure("telegram_unavailable") from exc


def send_telegram(
    settings: Settings, config: dict[str, Any], message: Message, delivery_id: str
) -> str:
    text, buttons = telegram_html(message, settings.dashboard_url)
    payload: dict[str, Any] = {
        "chat_id": config["chat_id"],
        "text": text,
        "parse_mode": "HTML",
        "link_preview_options": {"is_disabled": True},
    }
    if buttons:
        payload["reply_markup"] = buttons
    try:
        result = telegram_call(settings, "sendMessage", payload)
    except DeliveryFailure as exc:
        if exc.code != "telegram_rejected" or not exc.permanent:
            raise
        # A refused format or button must not cost the alert, so resend it as plain text.
        logger.warning("telegram_rejected_formatting delivery_id=%s; sending plain", delivery_id)
        result = telegram_call(
            settings,
            "sendMessage",
            {
                "chat_id": config["chat_id"],
                "text": plain(message, settings.dashboard_url)[:4000],
                "link_preview_options": {"is_disabled": True},
            },
        )
    return str(result["result"]["message_id"])


def fetch_updates(settings: Settings, offset: int) -> list[dict[str, Any]]:
    """Pending bot updates from the given offset; pairing polls instead of using a webhook."""
    payload = {"offset": offset, "timeout": 0, "allowed_updates": ["message"]}
    return list(telegram_call(settings, "getUpdates", payload).get("result", []))
