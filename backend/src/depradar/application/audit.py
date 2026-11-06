"""What AI assistants did through the MCP endpoint, for the owner to review."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from depradar.domain.entities import AuditEvent
from depradar.domain.security import Principal


def record(
    db: Session,
    principal: Principal,
    *,
    kind: str,
    name: str,
    outcome: str,
    project_id: str | None = None,
    client_name: str = "",
    detail: str = "",
    duration_ms: int = 0,
) -> None:
    """Append one call. Arguments and results are never stored: they can hold package names,
    manifest content, or other client data, and even a hash of a short value can be guessed.
    """
    db.add(
        AuditEvent(
            token_id=principal.token_id,
            token_name=principal.name[:100],
            client_name=client_name[:100],
            kind=kind,
            name=name[:100],
            project_id=project_id,
            outcome=outcome,
            detail=detail[:300],
            duration_ms=duration_ms,
        )
    )
    # Append-only and unreferenced, so no write barrier is needed, as for token bookkeeping.
    db.commit()


def recent(db: Session, limit: int, offset: int, token_id: str | None = None) -> list[AuditEvent]:
    query = select(AuditEvent)
    if token_id is not None:
        query = query.where(AuditEvent.token_id == token_id)
    return list(
        db.scalars(
            query.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
