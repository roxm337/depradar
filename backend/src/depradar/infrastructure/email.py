"""Email channel: renders a notification as HTML and plain text and sends it over SMTP."""

import html
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate

from depradar.application.ports import DeliveryFailure
from depradar.config import Settings
from depradar.domain.connectors import EmailConfig
from depradar.domain.messages import (
    Item,
    Message,
    Style,
    change_label,
    clip,
    count_label,
    details,
    groups,
    link,
    plain,
    row_parts,
)

LABELS = {
    "alert": "Security alert",
    "digest": "Daily digest",
    "summary": "Alerts enabled",
    "test": "Test notification",
    "verification": "Email verification",
}


def email_footer(message: Message) -> str:
    if message.kind == "verification":
        return "You received this because this address was entered in DepRadar settings."
    return "You receive this because this address is a verified DepRadar alert destination."


def email_text(message: Message, base_url: str) -> str:
    return (
        f"{plain(message, base_url)}\n\n-- \n{email_footer(message)}\n"
        f"Notification settings: {link(base_url, '/notifications')}\n"
    )


INK, INK_2, INK_3 = "#121a16", "#3a443f", "#5f6863"
PAPER, SHEET, WELL, RULE, LINK = "#f3f1ea", "#fbfaf6", "#efede5", "#e2ded3", "#4a670c"
SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"
ACCENTS = {
    "critical": "#b8402b",
    "high": "#c9681f",
    "medium": "#a8840f",
    "low": "#4f7f69",
    "unknown": "#7c827e",
    "ok": "#3a7a50",
}
# Light text and tint, then the dark-mode pair; every pair clears 4.5:1 contrast.
BADGES = {
    "critical": ("#a3361f", "#f6e3dd", "#f4a28f", "#3b1f18"),
    "high": ("#984a0f", "#f7e7d6", "#f3b273", "#3a2615"),
    "medium": ("#735a06", "#f2ebd0", "#e6ca6c", "#332b10"),
    "low": ("#3b6552", "#e2ece5", "#97cdb0", "#1c2d24"),
    "unknown": ("#565c58", "#ebeae4", "#bcc2bd", "#262b28"),
    "resolved": ("#2d6741", "#e2eee5", "#9bd4ad", "#1b2e21"),
}
BASE_CSS = (
    "body{margin:0;padding:0;width:100%!important;-webkit-text-size-adjust:100%}"
    "table{mso-table-lspace:0pt;mso-table-rspace:0pt}"
    "@media (max-width:620px){.dr-pad{padding-left:20px!important;padding-right:20px!important}"
    ".dr-h1{font-size:20px!important;line-height:28px!important}"
    ".dr-code{font-size:15px!important;letter-spacing:0!important}}"
)
# Kept in its own block: some clients drop a whole style block they cannot parse.
DARK_CSS = (
    "@media (prefers-color-scheme:dark){"
    ".dr-bg{background:#0e1310!important}"
    ".dr-card{background:#161d19!important;border-color:#29322d!important}"
    ".dr-rule{border-color:#29322d!important}"
    ".dr-ink{color:#edf1ea!important}.dr-ink2{color:#c6cec8!important}"
    ".dr-ink3{color:#9aa49d!important}.dr-link{color:#cfe86a!important}"
    ".dr-ok{color:#9bd4ad!important}"
    ".dr-well{background:#1f2823!important;border-color:#323d37!important;color:#edf1ea!important}"
    ".dr-quote{background:#1f2823!important;color:#c6cec8!important}"
    ".dr-btn{background:#d6ef62!important}.dr-btn a{color:#121a16!important}"
    + "".join(
        f".dr-{key}{{background:{bg}!important;color:{fg}!important}}"
        for key, (_, _, fg, bg) in BADGES.items()
    )
    + "}"
)


def font(size: int, line: int, weight: int = 400, color: str = INK, family: str = SANS) -> str:
    return (
        f"font-family:{family};font-size:{size}px;line-height:{line}px;"
        f"font-weight:{weight};color:{color};"
    )


def esc(value: str) -> str:
    return html.escape(value, quote=True)


EMAIL = Style(
    text=esc,
    code=lambda value: f'<span style="font-family:{MONO};">{esc(value)}</span>',
    link=lambda label, url: (
        f'<a class="dr-link" href="{esc(url)}" style="color:{LINK};text-decoration:underline;">'
        f"{esc(label)}</a>"
    ),
)


def table(rows: str, style: str = "", cls: str = "", width: str = "100%") -> str:
    attributes = f' class="{cls}"' if cls else ""
    attributes += f' width="{width}"' if width else ""
    return (
        f'<table role="presentation"{attributes} cellpadding="0" cellspacing="0" border="0" '
        f'style="{style}">{rows}</table>'
    )


def badge(key: str, text: str) -> str:
    fg, bg, _, _ = BADGES.get(key, BADGES["unknown"])
    return (
        f'<span class="dr-{key}" style="display:inline-block;padding:2px 9px;border-radius:999px;'
        f'background:{bg};{font(12, 18, 600, fg)}white-space:nowrap;">{esc(text)}</span>'
    )


def fact_rows(rows: list[tuple[str, str]]) -> str:
    cells = []
    for index, (label, value) in enumerate(rows):
        edge = f"border-top:1px solid {RULE};"
        edge += f"border-bottom:1px solid {RULE};" if index == len(rows) - 1 else ""
        cells.append(
            f'<tr><td class="dr-ink3 dr-rule" valign="top" style="width:112px;'
            f'padding:11px 12px 11px 0;{edge}{font(13, 20, 500, INK_3)}">{esc(label)}</td>'
            f'<td class="dr-ink dr-rule" valign="top" style="padding:11px 0;{edge}'
            f'{font(14, 20, 400, INK)}word-break:break-word;">{value}</td></tr>'
        )
    return table("".join(cells), "margin:24px 0 0;")


def email_row(item: Item) -> str:
    resolved = item.change == "resolved"
    label_style = font(12, 20, 500, BADGES["resolved"][0] if resolved else INK_3)
    cells = (
        '<tr><td valign="top" style="width:86px;padding:1px 10px 0 0;">'
        f"{badge(item.severity, item.severity.title())}</td>"
        f'<td class="dr-ink" valign="top" style="{font(14, 20, 600, INK, MONO)}'
        f'word-break:break-word;">{esc(item.package)} <span class="dr-ink3" '
        f'style="font-weight:400;color:{INK_3};">{esc(item.version)}</span>'
        f'<div class="dr-ink3" style="margin-top:3px;{font(13, 19, 400, INK_3)}">'
        f"{' · '.join(row_parts(item, EMAIL))}</div></td>"
        f'<td class="{"dr-ok" if resolved else "dr-ink3"}" valign="top" align="right" '
        f'style="padding-left:10px;white-space:nowrap;{label_style}">'
        f"{esc(change_label(item))}</td></tr>"
    )
    return (
        f'<tr><td class="dr-rule" style="padding:12px 0;border-top:1px solid {RULE};">'
        f"{table(cells)}</td></tr>"
    )


def email_list(items: tuple[Item, ...]) -> str:
    blocks = []
    for project, rows in groups(items):
        heading = (
            f'<tr><td class="dr-ink" style="padding:0 0 8px;{font(13, 18, 600, INK)}">'
            f'{esc(project)} <span class="dr-ink3" style="font-weight:400;color:{INK_3};">'
            f"· {len(rows)}</span></td></tr>"
        )
        blocks.append(table(heading + "".join(map(email_row, rows)), "margin:26px 0 0;"))
    return "".join(blocks)


def email_body(message: Message, base_url: str) -> str:
    accent = ACCENTS.get(message.tone, ACCENTS["unknown"])
    lead = esc(message.lead).replace("\n", "<br>")
    parts = [
        f'<p class="dr-ink3" style="margin:0 0 10px;{font(11, 16, 600, INK_3, MONO)}'
        f'letter-spacing:0.08em;text-transform:uppercase;">{esc(message.eyebrow)}</p>'
        if message.eyebrow
        else "",
        f'<h1 class="dr-ink dr-h1" style="margin:0 0 10px;{font(22, 30, 600, INK)}'
        f'letter-spacing:-0.01em;word-break:break-word;">{esc(message.title)}</h1>'
        f'<p class="dr-ink2" style="margin:0;{font(15, 24, 400, INK_2)}">{lead}</p>',
    ]
    if message.code:
        parts.append(
            table(
                f'<tr><td class="dr-well dr-code" align="center" style="padding:18px 16px;'
                f"background:{WELL};border:1px solid {RULE};border-radius:10px;"
                f"{font(22, 30, 600, INK, MONO)}letter-spacing:0.06em;word-break:break-all;"
                f'-webkit-user-select:all;user-select:all;">'
                f"{esc(message.code)}</td></tr>",
                "margin:24px 0 0;",
            )
        )
    if message.counts:
        chips = "&nbsp; ".join(badge(key, count_label(key, n)) for key, n in message.counts)
        parts.append(f'<p style="margin:20px 0 0;line-height:30px;">{chips}</p>')
    if message.kind == "alert" and message.items:
        item = message.items[0]
        severity = ("Severity", badge(item.severity, item.severity.title()))
        parts.append(fact_rows([severity, *details(item, EMAIL)]))
        if item.summary:
            parts.append(
                table(
                    f'<tr><td class="dr-quote" style="padding:14px 16px;background:{WELL};'
                    f"border-left:3px solid {accent};border-radius:0 8px 8px 0;"
                    f'{font(14, 22, 400, INK_2)}">{esc(item.summary)}</td></tr>',
                    "margin:20px 0 0;",
                )
            )
    elif message.items:
        parts.append(email_list(message.items))
    if message.more:
        parts.append(
            f'<p class="dr-ink3" style="margin:16px 0 0;{font(13, 20, 400, INK_3)}">'
            f"…and {message.more} more in DepRadar.</p>"
        )
    if message.facts:
        parts.append(fact_rows([(label, esc(value)) for label, value in message.facts]))
    if message.note:
        parts.append(
            f'<p class="dr-ink3" style="margin:22px 0 0;{font(13, 20, 400, INK_3)}">'
            f"{esc(message.note)}</p>"
        )
    label, path = message.action
    button = (
        f'<tr><td class="dr-btn" bgcolor="{INK}" style="border-radius:8px;background:{INK};">'
        f'<a href="{esc(link(base_url, path))}" target="_blank" style="display:inline-block;'
        f"padding:12px 20px;{font(14, 20, 600, '#f3f5ef')}text-decoration:none;"
        f'border-radius:8px;">{esc(label)} &rarr;</a></td></tr>'
    )
    parts.append(table(button, "margin:28px 0 0;", width=""))
    return (
        f'<tr><td height="4" style="height:4px;line-height:4px;font-size:0;background:{accent};'
        'border-radius:11px 11px 0 0;">&nbsp;</td></tr>'
        f'<tr><td class="dr-pad" style="padding:28px 32px 32px;">{"".join(parts)}</td></tr>'
    )


def email_html(message: Message, base_url: str) -> str:
    brand = table(
        '<tr><td valign="middle">'
        + table(
            '<tr><td width="20" height="20" bgcolor="#d6ef62" style="width:20px;height:20px;'
            'background:#d6ef62;border-radius:6px;font-size:0;line-height:0;">&nbsp;</td>'
            f'<td class="dr-ink" style="padding-left:9px;{font(16, 20, 700, INK)}'
            f'letter-spacing:-0.01em;">dep<span class="dr-ink3" style="font-weight:400;'
            f'color:{INK_3};">radar</span></td></tr>',
            width="",
        )
        + f'</td><td class="dr-ink3" align="right" valign="middle" style="'
        f'{font(11, 20, 600, INK_3, MONO)}letter-spacing:0.08em;text-transform:uppercase;">'
        f"{esc(LABELS.get(message.kind, 'Notification'))}</td></tr>"
    )
    footer = (
        f'<p class="dr-ink3" style="margin:0;{font(12, 18, 400, INK_3)}">'
        f"{esc(email_footer(message))}<br>"
        f'<a class="dr-link" href="{esc(link(base_url, "/notifications"))}" '
        f'style="color:{INK_3};text-decoration:underline;">Notification settings</a>'
        " &middot; DepRadar, self-hosted dependency monitoring</p>"
    )
    page = table(
        f'<tr><td style="padding:0 4px 14px;">{brand}</td></tr>'
        f'<tr><td class="dr-card" style="background:{SHEET};border:1px solid {RULE};'
        f'border-radius:12px;">{table(email_body(message, base_url))}</td></tr>'
        f'<tr><td class="dr-pad" style="padding:20px 8px 0;">{footer}</td></tr>',
        "max-width:600px;",
    )
    # Outlook for Windows ignores max-width, so it gets a fixed 600px column.
    column = (
        '<!--[if mso]><table role="presentation" width="600" cellpadding="0" cellspacing="0" '
        f'border="0"><tr><td><![endif]-->{page}<!--[if mso]></td></tr></table><![endif]-->'
    )
    preheader = esc(clip(message.lead, 140)) + "&#847;&zwnj;&nbsp;" * 24
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="x-apple-disable-message-reformatting">'
        '<meta name="format-detection" content="telephone=no,date=no,address=no,email=no,url=no">'
        '<meta name="color-scheme" content="light dark">'
        '<meta name="supported-color-schemes" content="light dark">'
        f"<title>{esc(message.subject)}</title>"
        f"<style>{BASE_CSS}</style><style>{DARK_CSS}</style></head>"
        f'<body class="dr-bg" style="margin:0;padding:0;background:{PAPER};">'
        '<div style="display:none;max-height:0;max-width:0;overflow:hidden;opacity:0;'
        f'mso-hide:all;">{preheader}</div>'
        + table(
            f'<tr><td align="center" style="padding:32px 12px 40px;">{column}</td></tr>',
            f"background:{PAPER};",
            cls="dr-bg",
        )
        + "</body></html>"
    )


def send_email(settings: Settings, config: EmailConfig, message: Message, delivery_id: str) -> str:
    if config.tls_mode == "none" and not settings.allow_insecure_smtp:
        raise DeliveryFailure("smtp_tls_required", permanent=True)
    email = EmailMessage()
    email["Subject"] = message.subject
    email["From"] = formataddr(("DepRadar", config.sender))
    email["To"] = config.recipient
    email["Date"] = formatdate(usegmt=True)
    message_id = f"<{delivery_id}@{config.sender.split('@')[1]}>"
    email["Message-ID"] = message_id
    email["Auto-Submitted"] = "auto-generated"
    email.set_content(email_text(message, settings.dashboard_url))
    email.add_alternative(email_html(message, settings.dashboard_url), subtype="html")
    try:
        context = ssl.create_default_context()
        transport: smtplib.SMTP
        if config.tls_mode == "tls":
            transport = smtplib.SMTP_SSL(config.host, config.port, timeout=15, context=context)
        else:
            transport = smtplib.SMTP(config.host, config.port, timeout=15)
        with transport:
            transport.ehlo()
            if config.tls_mode == "starttls":
                transport.starttls(context=context)
                transport.ehlo()
            if config.username:
                transport.login(config.username, settings.smtp_password.get_secret_value())
            refused = transport.send_message(email)
            if refused:
                raise DeliveryFailure("smtp_recipient_refused", permanent=True)
        return message_id
    except DeliveryFailure:
        raise
    except smtplib.SMTPResponseException as exc:
        raise DeliveryFailure("smtp_rejected", permanent=500 <= exc.smtp_code < 600) from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise DeliveryFailure("smtp_unavailable") from exc
