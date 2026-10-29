"""Manifest snapshots on local disk, named only by server-generated identifiers."""

from datetime import datetime
from pathlib import Path
from uuid import UUID


class LocalInventoryStore:
    """Implements the InventoryStore port in one private directory."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def path(self, inventory_id: str) -> Path:
        if str(UUID(inventory_id)) != inventory_id:
            raise ValueError("Inventory identifiers are canonical UUIDs")
        return self.root / inventory_id

    def save(self, inventory_id: str, content: bytes) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.path(inventory_id)
        with path.open("xb") as stream:
            path.chmod(0o600)
            stream.write(content)

    def load(self, inventory_id: str) -> bytes:
        return self.path(inventory_id).read_bytes()

    def remove(self, inventory_id: str) -> None:
        self.path(inventory_id).unlink(missing_ok=True)

    def stale(self, before: datetime) -> list[str]:
        if not self.root.exists():
            return []
        found = []
        for path in list(self.root.iterdir())[:10000]:
            try:
                identifier = str(UUID(path.name))
            except ValueError:
                continue
            if (
                identifier == path.name
                and not path.is_symlink()
                and path.is_file()
                and path.stat().st_mtime < before.timestamp()
            ):
                found.append(identifier)
        return found
