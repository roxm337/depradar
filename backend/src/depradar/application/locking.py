from sqlalchemy import select
from sqlalchemy.orm import Session

from depradar.domain.entities import SystemState


def lock_writes(db: Session) -> SystemState:
    """One-owner write barrier: backups hold it while copying DB and immutable files."""
    return db.scalars(select(SystemState).where(SystemState.id == 1).with_for_update()).one()
