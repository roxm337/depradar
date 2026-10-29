"""What a notification says, and its plain-text form.

Composition decides what a message may reveal; channel adapters only format it.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import quote

from depradar.domain.entities import Finding, NotificationPolicy

SEVERITIES = ("critical", "high", "medium", "low", "unknown")
LIST_LIMIT = 20
GENERIC = "Project and package names are hidden by your notification settings."
IMMEDIATE = {
    "critical": "Critical only",
    "high": "High and critical",
    "medium": "Medium and above",
    "low": "Low and above",
}
# change kind: (headline prefix, list label, lead, lead without project and package names)
CHANGES = {
    "opened": (
        "",
        "New",
        "A dependency of {project} is affected by a published advisory.",
        "A monitored project is affected by a published advisory.",
    ),
    "reopened": (
        "Reopened",
        "Reopened",
        "This finding was resolved earlier, and the latest scan of {project} detects it again.",
        "A resolved finding was detected again.",
    ),
    "updated": (
        "Updated",
        "Updated",
        "The advisory changed: its severity or fixed versions are different now.",
        "The advisory for an open finding changed.",
    ),
    "resolved": (
        "Resolved",
        "Resolved",
        "The latest complete scan of {project} no longer detects this vulnerability.",
        "The latest complete scan no longer detects a previous finding.",
    ),
    "risk_expired": (
        "Accepted risk expired",
        "Risk expired",
        "The accepted risk ended, so the finding is open again and needs a decision.",
        "An accepted risk ended, so its finding is open again and needs a decision.",
    ),
    "risk_revoked": (
        "Risk acceptance revoked",
        "Risk revoked",
        "The risk acceptance was revoked, so the finding is open again.",
        "A risk acceptance was revoked, so its finding is open again.",
    ),
    "ack_revoked": (
        "Back in triage",
        "Back in triage",
        "The acknowledgement was withdrawn, so the finding needs a decision again.",
        "An acknowledgement was withdrawn, so its finding needs a decision again.",
    ),
}


@dataclass(frozen=True)
class Item:
    """One finding as a notification shows it."""

    project: str
    package: str
    version: str
    ecosystem: str
    manifest: str
    severity: str
    advisories: tuple[str, ...] = ()
    fixed: tuple[str, ...] = ()
    kev: bool = False
    epss: float | None = None
    summary: str = ""
    change: str = ""


@dataclass(frozen=True)
class Message:
    kind: str
    subject: str
    title: str
    lead: str
    eyebrow: str = ""
    tone: str = "ok"
    items: tuple[Item, ...] = ()
    more: int = 0
    counts: tuple[tuple[str, int], ...] = ()
    facts: tuple[tuple[str, str], ...] = ()
    code: str = ""
    note: str = ""
    action: tuple[str, str] = ("Open DepRadar", "/")


def plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def severity_of(value: str) -> str:
    return value.lower() if value.lower() in SEVERITIES else "unknown"


def item_from(finding: Finding, project: str, change: str = "") -> Item:
    return Item(
        project=project,
        package=finding.package_name,
        version=finding.package_version,
        ecosystem=finding.ecosystem,
        manifest=finding.target_path or finding.target_filename,
        severity=severity_of(finding.severity),
        advisories=tuple(finding.advisory_ids),
        fixed=tuple(finding.fixed_versions),
        kev=finding.kev_known,
        epss=finding.epss_score,
        summary=clip(" ".join(finding.summary.split()), 280),
        change=change,
    )


def rank(item: Item) -> tuple[bool, int, str, str]:
    return (
        item.change == "resolved",
        SEVERITIES.index(item.severity),
        item.project.lower(),
        item.package.lower(),
    )


def tally(items: Iterable[Item]) -> tuple[tuple[str, int], ...]:
    keys = ["resolved" if item.change == "resolved" else item.severity for item in items]
    return tuple((key, keys.count(key)) for key in (*SEVERITIES, "resolved") if key in keys)


def rated(severity: str) -> str:
    return "vulnerability" if severity == "unknown" else f"{severity} vulnerability"


def alert_message(item: Item, details: bool) -> Message:
    prefix, _, lead, generic = CHANGES.get(item.change, CHANGES["updated"])
    if details:
        target = f"{rated(item.severity)} in {item.package} {item.version}"
    else:
        target = rated(item.severity) if prefix else f"new {rated(item.severity)}"
    title = f"{prefix}: {target}" if prefix else target[:1].upper() + target[1:]
    subject = f"{title} · {item.project}" if details else f"{title} in a monitored project"
    return Message(
        kind="alert",
        subject=clip(subject, 200),
        title=title,
        lead=lead.format(project=item.project) if details else f"{generic} {GENERIC}",
        eyebrow=prefix or "New finding",
        tone="ok" if item.change == "resolved" else item.severity,
        items=(item,) if details else (),
        action=("Review findings", "/findings"),
    )


def digest_message(items: list[Item], details: bool) -> Message:
    ordered = sorted(items, key=rank)
    projects = plural(len({item.project for item in ordered}), "project")
    title = plural(len(ordered), "vulnerability update")
    lead = f"Collected since the last digest across {projects}, most severe first."
    return Message(
        kind="digest",
        subject=f"Daily digest: {title}" + (f" across {projects}" if details else ""),
        title=title,
        lead=lead if details else f"Collected since the last digest. {GENERIC}",
        tone=next((item.severity for item in ordered if item.change != "resolved"), "ok"),
        items=tuple(ordered[:LIST_LIMIT]) if details else (),
        more=max(len(ordered) - LIST_LIMIT, 0) if details else 0,
        counts=tally(ordered),
        action=("Review findings", "/findings"),
    )


def summary_message(
    items: list[Item],
    counts: tuple[tuple[str, int], ...],
    projects: int,
    details: bool,
    channel: str,
    policy: NotificationPolicy | None,
) -> Message:
    total = sum(count for _, count in counts)
    lead = "There are no open findings right now. DepRadar alerts you here when that changes."
    if total:
        lead = (
            f"There {'is' if total == 1 else 'are'} {plural(total, 'open finding')} across "
            f"{plural(projects, 'project')}. "
            + ("Details are below, most severe first." if details else GENERIC)
        )
    return Message(
        kind="summary",
        subject="DepRadar alerts are on" + (f": {plural(total, 'open finding')}" if total else ""),
        title=f"Alerts are on for {'this chat' if channel == 'telegram' else 'this address'}",
        lead=lead,
        items=tuple(sorted(items, key=rank)) if details else (),
        more=max(total - len(items), 0) if details else 0,
        counts=counts,
        note=schedule_note(policy),
        action=("Review findings", "/findings"),
    )


def schedule_note(policy: NotificationPolicy | None) -> str:
    if policy is None:
        return ""
    level = policy.immediate_min_severity
    covered = {"critical": "critical findings", "high": "high and critical findings"}.get(
        level, f"{level} severity and above"
    )
    rest = "unrated findings" if level == "low" else "lower severities"
    text = (
        f"Immediate alerts cover {covered}; {rest} arrive in a daily digest at "
        f"{policy.digest_hour:02d}:00 ({policy.timezone})."
    )
    start, end = policy.quiet_hours_start, policy.quiet_hours_end
    if start is not None and end is not None:
        text += f" Alerts wait out quiet hours from {start:02d}:00 to {end:02d}:00."
    return text


def connector_test_message(channel: str, policy: NotificationPolicy | None) -> Message:
    facts: tuple[tuple[str, str], ...] = ()
    if policy:
        start, end = policy.quiet_hours_start, policy.quiet_hours_end
        quiet = "Off" if start is None or end is None else f"{start:02d}:00–{end:02d}:00"
        facts = (
            ("Immediate alerts", IMMEDIATE.get(policy.immediate_min_severity, "High and critical")),
            ("Daily digest", f"{policy.digest_hour:02d}:00 · {policy.timezone}"),
            ("Quiet hours", quiet),
            ("Project and package names", "Included" if policy.include_details else "Hidden"),
        )
    where = "This chat" if channel == "telegram" else "This address"
    return Message(
        kind="test",
        subject="DepRadar test notification",
        title="Test notification",
        lead=f"{where} is set up to receive DepRadar alerts. No action is needed.",
        facts=facts,
        action=("Notification settings", "/notifications"),
    )


def verification_message(code: str, recipient: str) -> Message:
    return Message(
        kind="verification",
        subject="Your DepRadar verification code",
        title="Your DepRadar verification code",
        lead=(
            "Enter this code in DepRadar under Notifications → Email to start receiving alerts at "
            f"{recipient or 'this address'}. It expires in 15 minutes."
        ),
        code=code,
        note=(
            "If you didn't request this, ignore this email. DepRadar sends nothing to this "
            "address until it is verified."
        ),
        action=("Open notification settings", "/notifications"),
    )


def link(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + path


def advisory_url(advisory: str) -> str:
    return f"https://osv.dev/vulnerability/{quote(advisory, safe='')}"


def primary(advisories: tuple[str, ...]) -> str:
    return next(
        (a for prefix in ("GHSA-", "CVE-") for a in advisories if a.startswith(prefix)),
        advisories[0] if advisories else "",
    )


def signals(item: Item, short: bool = False) -> list[str]:
    found = ["Known exploited" if short else "Known exploited (CISA KEV)"] if item.kev else []
    if item.epss is not None and item.epss >= 0.01:
        value = item.epss * 100
        percent = f"{value:.0f}%" if value >= 10 else f"{value:.1f}%"
        found.append(f"EPSS {percent}" if short else f"{percent} chance of exploitation in 30 days")
    return found


@dataclass(frozen=True)
class Style:
    """How a renderer writes text, code, and links."""

    text: Callable[[str], str]
    code: Callable[[str], str]
    link: Callable[[str, str], str]


PLAIN = Style(text=str, code=str, link=lambda label, _: label)


def details(item: Item, style: Style) -> list[tuple[str, str]]:
    s = style
    advisories = " · ".join(s.link(a, advisory_url(a)) for a in item.advisories[:6])
    if len(item.advisories) > 6:
        advisories += s.text(f" +{len(item.advisories) - 6} more")
    rows = [
        ("Project", s.text(item.project)),
        ("Package", f"{s.code(f'{item.package} {item.version}')} · {s.text(item.ecosystem)}"),
        ("Manifest", s.code(item.manifest)),
        ("Advisories", advisories or s.text("Not listed")),
    ]
    if item.change != "resolved":
        fixed = ", ".join(s.code(version) for version in item.fixed[:4])
        rows.append(("Fix", f"{s.text('Upgrade to')} {fixed}" if fixed else s.text("No fix yet")))
    if found := signals(item):
        rows.append(("Exploitation", s.text(" · ".join(found))))
    return rows


def groups(items: Iterable[Item]) -> list[tuple[str, list[Item]]]:
    grouped: dict[str, list[Item]] = {}
    for item in items:
        grouped.setdefault(item.project, []).append(item)
    return list(grouped.items())


def row_parts(item: Item, style: Style) -> list[str]:
    advisory = primary(item.advisories)
    parts = [style.link(advisory, advisory_url(advisory))] if advisory else []
    if item.fixed and item.change != "resolved":
        parts.append(f"{style.text('fixed in')} {style.code(item.fixed[0])}")
    return parts + [style.text(signal) for signal in signals(item, short=True)]


def change_label(item: Item) -> str:
    return CHANGES.get(item.change, CHANGES["updated"])[1] if item.change else ""


def count_label(key: str, count: int) -> str:
    return f"{count} {key}"


def plain(message: Message, base_url: str) -> str:
    lines = [message.title, *([message.code] if message.code else []), "", message.lead]
    if message.counts:
        lines += ["", " · ".join(count_label(key, count) for key, count in message.counts)]
    if message.kind == "alert" and message.items:
        item = message.items[0]
        lines += ["", *(f"{label}: {value}" for label, value in details(item, PLAIN))]
        lines += ["", item.summary] if item.summary else []
    else:
        for project, items in groups(message.items):
            lines += ["", project]
            for item in items:
                parts = [f"{item.package} {item.version}", *row_parts(item, PLAIN)]
                parts += [change_label(item)] if item.change else []
                lines.append(f"- {item.severity.title()}: " + " · ".join(parts))
    lines += ["", f"…and {message.more} more in DepRadar."] if message.more else []
    lines += ["", *(f"{label}: {value}" for label, value in message.facts)] if message.facts else []
    lines += ["", message.note] if message.note else []
    label, path = message.action
    return "\n".join([*lines, "", f"{label}: {link(base_url, path)}"])
