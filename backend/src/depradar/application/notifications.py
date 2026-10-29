"""Alert routing, digests, and delivery through the notification channels."""

import secrets
from datetime import datetime, timedelta

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from depradar.application.locking import lock_writes
from depradar.application.ports import DeliveryFailure, NotificationSender
from depradar.config import Settings
from depradar.domain.entities import (
    ChangeEvent,
    Connector,
    Delivery,
    DeliveryAttempt,
    Finding,
    NotificationPolicy,
    OutboxEvent,
    Project,
    new_id,
    utcnow,
)
from depradar.domain.messages import (
    LIST_LIMIT,
    SEVERITIES,
    Item,
    Message,
    alert_message,
    connector_test_message,
    digest_message,
    item_from,
    plain,
    severity_of,
    summary_message,
    verification_message,
)
from depradar.domain.schedule import next_digest, quiet_end_at

SEVERITY_RANK = case(
    (Finding.severity == "critical", 4),
    (Finding.severity == "high", 3),
    (Finding.severity == "medium", 2),
    (Finding.severity == "low", 1),
    else_=0,
)


def queue_message(
    db: Session,
    connector: Connector,
    message: Message,
    settings: Settings,
    available_at: datetime | None = None,
) -> Delivery:
    delivery = Delivery(
        connector_id=connector.id,
        generation=connector.generation,
        kind=message.kind,
        subject=message.subject[:200],
        body=plain(message, settings.dashboard_url),
        available_at=available_at or utcnow(),
    )
    db.add(delivery)
    return delivery


def source(db: Session, delivery: Delivery) -> tuple[ChangeEvent | None, Finding | None]:
    event = db.get(OutboxEvent, delivery.outbox_id) if delivery.outbox_id else None
    change = db.get(ChangeEvent, event.change_id) if event else None
    return change, db.get(Finding, change.finding_id) if change else None


def entry(db: Session, finding: Finding, change: str = "") -> Item:
    project = db.get(Project, finding.project_id)
    return item_from(finding, project.name if project else "Project", change)


def open_summary(db: Session, connector: Connector) -> Message:
    policy = db.get(NotificationPolicy, 1)
    is_open = Finding.status == "open"
    urgent = db.scalars(
        select(Finding)
        .where(is_open)
        .order_by(SEVERITY_RANK.desc(), Finding.first_seen_at)
        .limit(LIST_LIMIT)
    )
    totals: dict[str, int] = {}
    for severity, count in db.execute(
        select(Finding.severity, func.count()).where(is_open).group_by(Finding.severity)
    ):
        totals[severity_of(severity)] = totals.get(severity_of(severity), 0) + count
    projects = db.scalar(select(func.count(func.distinct(Finding.project_id))).where(is_open))
    return summary_message(
        [entry(db, finding) for finding in urgent],
        tuple((key, totals[key]) for key in SEVERITIES if key in totals),
        projects or 0,
        bool(policy and policy.include_details),
        connector.id,
        policy,
    )


def queue_initial_summary(db: Session, connector: Connector, settings: Settings) -> None:
    queue_message(db, connector, open_summary(db, connector), settings)


def compose(
    db: Session,
    delivery: Delivery,
    connector: Connector,
    policy: NotificationPolicy | None,
    children: list[Delivery],
) -> Message:
    """Rebuild a queued message from current records, so sends honor today's settings."""
    details = bool(policy and policy.include_details)
    if delivery.kind == "verification":
        # Only the code's digest is stored, so the code comes back from the queued text.
        recipient = str(connector.config.get("recipient", ""))
        return verification_message(delivery.body.splitlines()[1], recipient)
    if delivery.kind == "test":
        return connector_test_message(connector.id, policy)
    if delivery.kind == "summary":
        return open_summary(db, connector)
    if delivery.kind == "digest":
        sources = [source(db, child) for child in children]
        items = [entry(db, found, change.kind) for change, found in sources if change and found]
        return digest_message(items, details)
    change, finding = source(db, delivery)
    if change and finding:
        return alert_message(entry(db, finding, change.kind), details)
    return Message(delivery.kind, delivery.subject, delivery.subject, delivery.body)


def route_outbox(db: Session, settings: Settings) -> int:
    policy = db.get(NotificationPolicy, 1)
    assert policy is not None
    connectors = list(
        db.scalars(
            select(Connector).where(Connector.enabled.is_(True), Connector.verified_at.is_not(None))
        )
    )
    events = list(
        db.scalars(
            select(OutboxEvent)
            .where(OutboxEvent.processed_at.is_(None))
            .order_by(OutboxEvent.created_at, OutboxEvent.id)
            .limit(500)
        )
    )
    levels = ["unknown", "low", "medium", "high", "critical"]
    for event in events:
        change = db.get(ChangeEvent, event.change_id)
        finding = db.get(Finding, change.finding_id) if change else None
        if (
            finding
            and change
            and change.kind
            in {
                "opened",
                "reopened",
                "updated",
                "risk_expired",
                "risk_revoked",
                "ack_revoked",
                "resolved",
            }
        ):
            muted = finding.workflow_status in {"acknowledged", "risk_accepted"} or (
                finding.status == "resolved" and change.kind != "resolved"
            )
            if not muted or change.kind == "resolved":
                project = db.get(Project, finding.project_id)
                message = alert_message(
                    item_from(finding, project.name if project else "Project", change.kind),
                    policy.include_details,
                )
                body = plain(message, settings.dashboard_url)
                if project is None or project.notifications_enabled:
                    threshold = (
                        project.alert_min_severity
                        if project and project.alert_min_severity
                        else policy.immediate_min_severity
                    )
                    immediate = change.kind in {"risk_expired", "risk_revoked"} or levels.index(
                        finding.severity if finding.severity in levels else "unknown"
                    ) >= levels.index(threshold)
                    for connector in connectors:
                        # Summary covers pre-verification history; avoid replaying a flood.
                        if connector.verified_at and connector.verified_at > event.created_at:
                            continue
                        available_at = quiet_end_at(utcnow(), policy)
                        db.add(
                            Delivery(
                                connector_id=connector.id,
                                generation=connector.generation,
                                outbox_id=event.id,
                                project_id=finding.project_id,
                                status="queued" if immediate else "digest_pending",
                                available_at=available_at if immediate else utcnow(),
                                subject=message.subject[:200],
                                body=body,
                            )
                        )
        event.processed_at = utcnow()
    return len(events)


def prepare_digest(db: Session, settings: Settings) -> None:
    policy = db.get(NotificationPolicy, 1)
    assert policy is not None
    if policy.next_digest_at > utcnow():
        return
    if quiet_end_at(utcnow(), policy) > utcnow():
        return
    for connector in db.scalars(
        select(Connector).where(Connector.enabled.is_(True), Connector.verified_at.is_not(None))
    ):
        deliveries = list(
            db.scalars(
                select(Delivery)
                .where(
                    Delivery.connector_id == connector.id,
                    Delivery.generation == connector.generation,
                    Delivery.status == "digest_pending",
                )
                .order_by(Delivery.created_at)
                .limit(1000)
            )
        )
        active: list[Delivery] = []
        items: list[Item] = []
        for delivery in deliveries:
            change, finding = source(db, delivery)
            if (
                finding
                and (finding.workflow_status != "open" or finding.status == "resolved")
                and change
                and change.kind != "resolved"
            ):
                delivery.status = "cancelled"
            else:
                active.append(delivery)
                items += [entry(db, finding, change.kind)] if change and finding else []
        deliveries = active
        if deliveries:
            message = digest_message(items, policy.include_details)
            digest = queue_message(db, connector, message, settings)
            db.flush()
            for delivery in deliveries:
                delivery.status = "bundled"
                delivery.batch_id = digest.id
    policy.next_digest_at = next_digest(utcnow(), policy.timezone, policy.digest_hour)


def deliver_once(
    factory: sessionmaker[Session], settings: Settings, sender: NotificationSender
) -> bool:
    with factory.begin() as db:
        lock_writes(db)
        delivery = db.scalar(
            select(Delivery)
            .where(
                or_(
                    and_(Delivery.status == "queued", Delivery.available_at <= utcnow()),
                    and_(Delivery.status == "sending", Delivery.lease_until <= utcnow()),
                )
            )
            .order_by(Delivery.available_at, Delivery.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if delivery is None:
            return False
        connector = db.get(Connector, delivery.connector_id)
        if (
            connector is None
            or connector.generation != delivery.generation
            or not connector.enabled
            or (delivery.kind != "verification" and connector.verified_at is None)
        ):
            delivery.status = "cancelled"
            return True
        if delivery.attempts >= settings.delivery_max_attempts:
            delivery.status = "failed"
            delivery.last_error = "attempts_exhausted_after_interruption"
            return True
        if connector.next_send_at > utcnow():
            delivery.available_at = connector.next_send_at
            return True
        policy = db.get(NotificationPolicy, 1)
        if policy and delivery.kind not in {"verification", "test", "summary", "digest"}:
            allowed_at = quiet_end_at(utcnow(), policy)
            if allowed_at > utcnow():
                delivery.available_at = allowed_at
                return True
        active: list[Delivery] = []
        if delivery.kind == "digest":
            for child in db.scalars(select(Delivery).where(Delivery.batch_id == delivery.id)):
                change, finding = source(db, child)
                if (
                    finding
                    and change
                    and change.kind != "resolved"
                    and (finding.workflow_status != "open" or finding.status == "resolved")
                ):
                    child.status = "cancelled"
                else:
                    active.append(child)
            if not active:
                delivery.status = "cancelled"
                return True
        # Re-evaluate muting at send time as well as routing time.
        if delivery.outbox_id:
            change, finding = source(db, delivery)
            if (
                finding
                and (finding.workflow_status != "open" or finding.status == "resolved")
                and change
                and change.kind != "resolved"
            ):
                delivery.status = "cancelled"
                return True
        if delivery.status == "sending":
            previous_attempt = db.scalar(
                select(DeliveryAttempt)
                .where(
                    DeliveryAttempt.delivery_id == delivery.id,
                    DeliveryAttempt.status == "sending",
                )
                .order_by(DeliveryAttempt.attempt_number.desc())
                .limit(1)
            )
            if previous_attempt:
                previous_attempt.status = "uncertain"
                previous_attempt.completed_at = utcnow()
                previous_attempt.error_code = "worker_interrupted_after_send_started"
        delivery.status = "sending"
        delivery.attempts += 1
        attempt_number = (
            int(
                db.scalar(
                    select(func.max(DeliveryAttempt.attempt_number)).where(
                        DeliveryAttempt.delivery_id == delivery.id
                    )
                )
                or 0
            )
            + 1
        )
        attempt_id = new_id()
        db.add(
            DeliveryAttempt(
                id=attempt_id,
                delivery_id=delivery.id,
                attempt_number=attempt_number,
                status="sending",
            )
        )
        token = new_id()
        delivery.lease_token = token
        delivery.lease_until = utcnow() + timedelta(seconds=300)
        connector.next_send_at = utcnow() + timedelta(seconds=1)
        message = compose(db, delivery, connector, policy, active)
        delivery.subject = message.subject[:200]
        delivery.body = plain(message, settings.dashboard_url)
        delivery_id, connector_id, config = delivery.id, connector.id, dict(connector.config)
    failure: DeliveryFailure | None = None
    provider_id = ""
    try:
        provider_id = sender(connector_id, config, message, delivery_id)
    except DeliveryFailure as exc:
        failure = exc
    except Exception:
        failure = DeliveryFailure("provider_unavailable")
    with factory.begin() as db:
        lock_writes(db)
        current = db.get(Delivery, delivery_id)
        attempt = db.get(DeliveryAttempt, attempt_id)
        if current is None or current.lease_token != token or current.status != "sending":
            if attempt and attempt.status == "sending":
                attempt.status = "uncertain"
                attempt.completed_at = utcnow()
                attempt.error_code = "delivery_state_changed_while_provider_request_was_in_flight"
            return True
        current.lease_token = None
        current.lease_until = None
        if failure:
            terminal = failure.permanent or current.attempts >= settings.delivery_max_attempts
            current.status = "failed" if terminal else "queued"
            current.last_error = failure.code
            if attempt:
                attempt.status = "failed"
                attempt.error_code = failure.code
            delay = max(failure.retry_after, 2**current.attempts * 5) + secrets.randbelow(5)
            current.available_at = utcnow() + timedelta(seconds=delay)
        else:
            current.status = "accepted"
            current.provider_id = provider_id[:200]
            current.last_error = None
            current.accepted_at = utcnow()
            if attempt:
                attempt.status = "accepted"
                attempt.provider_id = provider_id[:200]
        if attempt:
            attempt.completed_at = utcnow()
    return True
