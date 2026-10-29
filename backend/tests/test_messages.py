import json
from dataclasses import replace
from html.parser import HTMLParser

import httpx
from pydantic import SecretStr

from depradar.config import Settings
from depradar.domain.messages import (
    Item,
    alert_message,
    digest_message,
    plain,
    verification_message,
)
from depradar.infrastructure import telegram
from depradar.infrastructure.email import email_html, email_text
from depradar.infrastructure.notifier import Notifier
from depradar.infrastructure.telegram import telegram_html, visible_length

URL = "http://localhost:8000"
ITEM = Item(
    project="Acme <Shop> & Co",
    package="@scope/left-pad",
    version="1.2.5",
    ecosystem="npm",
    manifest="apps/web/package-lock.json",
    severity="critical",
    advisories=("CVE-2021-44906", "GHSA-xvch-5gv4-984h"),
    fixed=("1.2.6",),
    kev=True,
    epss=0.4321,
    summary='Prototype pollution via "__proto__" <script>',
    change="opened",
)
# Tags the Bot API accepts in HTML parse mode.
TELEGRAM_TAGS = {"b", "strong", "i", "em", "u", "ins", "s", "strike", "del", "span", "a"}
TELEGRAM_TAGS |= {"tg-spoiler", "tg-emoji", "tg-time", "code", "pre", "blockquote"}


class Parsed(HTMLParser):
    def __init__(self, markup: str) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.text: list[str] = []
        self.feed(markup)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def test_telegram_uses_supported_markup_and_escapes_content() -> None:
    text, buttons = telegram_html(alert_message(ITEM, details=True), URL)
    parsed = Parsed(text)
    visible = "".join(parsed.text)
    assert set(parsed.tags) <= TELEGRAM_TAGS
    assert "Acme <Shop> & Co" in visible and '"__proto__" <script>' in visible
    assert "<script>" not in text and "<br" not in text
    # Telegram rejects localhost buttons, so the link stays copyable text.
    assert buttons is None and "http://localhost:8000/findings" in visible


def test_telegram_button_only_for_addresses_telegram_can_open() -> None:
    _, buttons = telegram_html(alert_message(ITEM, True), "https://depradar.example.com/")
    assert buttons == {
        "inline_keyboard": [
            [
                {
                    "text": "Review findings",
                    "url": "https://depradar.example.com/findings",
                    "style": "primary",
                }
            ]
        ]
    }
    for url in ("http://10.0.0.5:3000", "https://radar.internal", "http://depradar"):
        assert telegram_html(alert_message(ITEM, True), url)[1] is None


def test_generic_messages_hide_project_package_and_advisory() -> None:
    for message in (alert_message(ITEM, False), digest_message([ITEM], False)):
        outputs = [message.subject, plain(message, URL), email_text(message, URL)]
        outputs += [email_html(message, URL), telegram_html(message, URL)[0]]
        for output in outputs:
            for secret in ("Acme", "left-pad", "CVE-2021-44906", "GHSA-xvch", "package-lock"):
                assert secret not in output


def test_email_is_escaped_self_contained_and_under_gmail_clipping() -> None:
    page = email_html(alert_message(ITEM, True), URL)
    assert "Acme &lt;Shop&gt; &amp; Co" in page and "<script>" not in page
    items = [replace(ITEM, package=f"package-{n}", project=f"Client {n % 4}") for n in range(40)]
    digest = digest_message(items, True)
    page = email_html(digest, URL)
    # Gmail clips bodies over 102 KB; nothing may load from the network when opened.
    assert len(page.encode()) < 102_000
    assert "<img" not in page and "url(" not in page and "@import" not in page
    assert digest.more == 20 and "…and 20 more in DepRadar." in page
    assert digest.subject == "Daily digest: 40 vulnerability updates across 4 projects"


def test_telegram_lists_stay_within_the_message_limit() -> None:
    items = [replace(ITEM, package="p" * 200 + str(n)) for n in range(20)]
    text, _ = telegram_html(digest_message(items, True), URL)
    assert visible_length(text) <= 4000 and "more in DepRadar." in text


def test_rejected_telegram_formatting_is_resent_as_plain_text(monkeypatch) -> None:
    sent = []

    def reply(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sent.append(body)
        if "parse_mode" in body:
            return httpx.Response(400, json={"ok": False, "error_code": 400})
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 7}})

    original = httpx.Client
    transport = httpx.MockTransport(reply)
    monkeypatch.setattr(telegram.httpx, "Client", lambda **kwargs: original(transport=transport))
    settings = Settings(
        telegram_bot_token=SecretStr("token"), dashboard_url="https://depradar.example.com"
    )
    message = alert_message(ITEM, True)
    assert Notifier(settings)("telegram", {"chat_id": "1"}, message, "d1") == "7"
    assert sent[0]["parse_mode"] == "HTML" and sent[0]["reply_markup"]
    assert "parse_mode" not in sent[1] and "reply_markup" not in sent[1]
    assert sent[1]["text"].startswith("Critical vulnerability in @scope/left-pad 1.2.5\n")


def test_alert_wording_follows_the_change() -> None:
    assert alert_message(ITEM, True).subject == (
        "Critical vulnerability in @scope/left-pad 1.2.5 · Acme <Shop> & Co"
    )
    resolved = alert_message(replace(ITEM, change="resolved"), True)
    assert resolved.title == "Resolved: critical vulnerability in @scope/left-pad 1.2.5"
    assert resolved.tone == "ok" and "Fix:" not in plain(resolved, URL)
    expired = alert_message(replace(ITEM, change="risk_expired", severity="unknown"), False)
    assert expired.title == "Accepted risk expired: vulnerability"


def test_verification_code_stays_on_the_second_line() -> None:
    # The sender reads the code back from this line; only its digest is stored.
    text = plain(verification_message("Abc_123-xyz", "owner@example.test"), URL)
    assert text.splitlines()[1] == "Abc_123-xyz"
