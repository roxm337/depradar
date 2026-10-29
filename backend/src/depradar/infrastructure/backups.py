"""Versioned logical backups for a single-owner installation, with a restore drill."""

import hashlib
import io
import json
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import create_engine, delete, event, func, insert, select, text
from sqlalchemy.orm import Session, sessionmaker

from depradar.application.locking import lock_writes
from depradar.domain.entities import Base, Inventory, UtcTimestamp, utcnow

REVISION = "0004"
MAX_BACKUP_BYTES = 2 * 1024 * 1024 * 1024
# Credentials are never archived: a restore must not resurrect a token revoked after the backup.
CREDENTIAL_TABLES = {"owner_session", "api_token"}

V2_ADDED_COLUMNS = {
    "project": {"notifications_enabled", "alert_min_severity"},
    "inventory": {"target_path", "revision"},
    "finding": {
        "target_path",
        "revision",
        "purl",
        "cvss_vectors",
        "epss_score",
        "epss_percentile",
        "kev_known",
        "intel_updated_at",
    },
    "notification_policy": {"quiet_hours_start", "quiet_hours_end"},
    "system_state": {
        "last_worker_heartbeat_at",
        "last_scanner_check_at",
        "scanner_available",
        "last_intelligence_refresh_at",
        "next_intelligence_refresh_at",
    },
}
V2_ADDED_TABLES = {"threat_intel", "delivery_attempt"}
V3_ADDED_COLUMNS = {"inventory": {"kind"}, "scan": {"mode", "results"}}
V3_ADDED_TABLES = {"api_token"}


def encode(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError("Unsupported backup value")


def add_bytes(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o600
    archive.addfile(info, io.BytesIO(data))


def upgrade_v2_rows(database: dict[str, Any]) -> None:
    for row in database["project"]:
        row.update(notifications_enabled=True, alert_min_severity=None)
    for row in database["inventory"]:
        row.update(target_path=row["filename"], revision=None)
    for row in database["finding"]:
        row.update(
            target_path=row["target_filename"],
            revision=None,
            purl=None,
            cvss_vectors=[],
            epss_score=None,
            epss_percentile=None,
            kev_known=False,
            intel_updated_at=None,
        )
    for row in database["notification_policy"]:
        row.update(quiet_hours_start=None, quiet_hours_end=None)
    for row in database["system_state"]:
        row.update(
            last_worker_heartbeat_at=None,
            last_scanner_check_at=None,
            scanner_available=None,
            last_intelligence_refresh_at=None,
            next_intelligence_refresh_at=None,
        )


def upgrade_v3_rows(database: dict[str, Any]) -> None:
    for row in database["inventory"]:
        row.update(kind="monitor")
    for row in database["scan"]:
        row.update(mode="monitor", results=None)


# (revision, tables added after it, columns added after it, defaults for the added columns)
UPGRADES = [
    ("0002", V2_ADDED_TABLES, V2_ADDED_COLUMNS, upgrade_v2_rows),
    ("0003", V3_ADDED_TABLES, V3_ADDED_COLUMNS, upgrade_v3_rows),
]


def upgrade_database(database: dict[str, Any], manifest: dict[str, Any]) -> None:
    """Upgrade a verified older snapshot in memory before restoring into the current schema."""
    revisions = [revision for revision, *_ in UPGRADES]
    pending = UPGRADES[revisions.index(manifest["revision"]) :]
    later_tables = {name for _, tables, _, _ in pending for name in tables}
    later_columns: dict[str, set[str]] = {}
    for _, _, columns, _ in pending:
        for name, added in columns.items():
            later_columns.setdefault(name, set()).update(added)
    previous_tables = set(Base.metadata.tables) - later_tables
    if set(database) != previous_tables or set(manifest["row_counts"]) != previous_tables:
        raise ValueError(f"Backup tables differ from schema revision {manifest['revision']}")
    for table in Base.metadata.sorted_tables:
        if table.name in later_tables:
            continue
        rows = database[table.name]
        old_columns = set(table.columns.keys()) - later_columns.get(table.name, set())
        if len(rows) != manifest["row_counts"][table.name] or any(
            set(row) != old_columns for row in rows
        ):
            raise ValueError(f"Backup rows differ from schema revision {manifest['revision']}")
    for _, tables, _, upgrade_rows in pending:
        upgrade_rows(database)
        for name in tables:
            database[name] = []
    manifest["revision"] = REVISION
    manifest["row_counts"] = {name: len(rows) for name, rows in database.items()}


def create_backup(
    factory: sessionmaker[Session], storage: Path, destination: Path
) -> dict[str, Any]:
    """Hold the common write barrier until the DB snapshot and immutable files are archived."""
    manifest: dict[str, Any] = {
        "format": 1,
        "revision": REVISION,
        "created_at": utcnow().isoformat(),
        "files": {},
        "row_counts": {},
    }
    created = False
    try:
        with factory.begin() as db:
            lock_writes(db)
            tables: dict[str, Any] = {}
            for table in Base.metadata.sorted_tables:
                rows = (
                    []
                    if table.name in CREDENTIAL_TABLES
                    else [dict(row) for row in db.execute(select(table)).mappings()]
                )
                tables[table.name] = rows
                manifest["row_counts"][table.name] = len(rows)
            database = json.dumps(tables, default=encode, ensure_ascii=False).encode()
            manifest["files"]["database.json"] = hashlib.sha256(database).hexdigest()
            # Exclusive creation protects an existing backup. Restrictive permissions precede data.
            with destination.open("xb") as output:
                created = True
                destination.chmod(0o600)
                with tarfile.open(fileobj=output, mode="w:gz") as archive:
                    add_bytes(archive, "database.json", database)
                    for inventory in db.scalars(select(Inventory)):
                        if str(UUID(inventory.id)) != inventory.id:
                            raise ValueError("Invalid inventory identifier")
                        source = storage / inventory.id
                        if source.is_symlink() or not source.is_file():
                            raise ValueError("Inventory file is missing or unsafe")
                        data = source.read_bytes()
                        if hashlib.sha256(data).hexdigest() != inventory.sha256:
                            raise ValueError("Inventory checksum mismatch; backup aborted")
                        name = "inventories/" + inventory.id
                        manifest["files"][name] = inventory.sha256
                        add_bytes(archive, name, data)
                    add_bytes(archive, "manifest.json", json.dumps(manifest).encode())
        return manifest
    except Exception:
        if created:
            destination.unlink(missing_ok=True)
        raise


def stage_backup(path: Path, stage: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    with tarfile.open(path, "r:gz") as archive:
        members: list[tarfile.TarInfo] = []
        total = 0
        for member in archive:
            total += max(member.size, 0)
            if len(members) >= 100000 or total > MAX_BACKUP_BYTES:
                raise ValueError("Backup exceeds entry or size limits")
            members.append(member)
        names = [member.name for member in members]
        if len(names) != len(set(names)) or sum(m.size for m in members) > MAX_BACKUP_BYTES:
            raise ValueError("Duplicate or oversized backup entries")
        if not members or any(not member.isfile() or member.size < 0 for member in members):
            raise ValueError("Backup may contain regular files only")
        for member in members:
            if member.name not in {"database.json", "manifest.json"}:
                prefix, _, identifier = member.name.partition("/")
                if prefix != "inventories" or str(UUID(identifier)) != identifier:
                    raise ValueError("Invalid backup path")
        member = archive.getmember("manifest.json")
        if member.size > 10 * 1024 * 1024:
            raise ValueError("Manifest exceeds size limit")
        stream = archive.extractfile(member)
        assert stream is not None
        manifest = json.load(stream)
        if manifest.get("format") != 1 or manifest.get("revision") not in {
            REVISION,
            *(revision for revision, *_ in UPGRADES),
        }:
            raise ValueError("Unsupported backup format/schema revision")
        if set(manifest["files"]) != set(names) - {"manifest.json"}:
            raise ValueError("Backup manifest does not match archive contents")
        for member in members:
            if member.name == "manifest.json":
                continue
            stream = archive.extractfile(member)
            assert stream is not None
            target = stage / (
                "database.json" if member.name == "database.json" else member.name.split("/")[1]
            )
            digest = hashlib.sha256()
            with target.open("xb") as output:
                target.chmod(0o600)
                while chunk := stream.read(65536):
                    output.write(chunk)
                    digest.update(chunk)
            if digest.hexdigest() != manifest["files"][member.name]:
                raise ValueError("Backup checksum verification failed")
    database = json.loads((stage / "database.json").read_text())
    if manifest["revision"] != REVISION:
        upgrade_database(database, manifest)
    if set(database) != set(Base.metadata.tables):
        raise ValueError("Backup tables differ from the application schema")
    if any(database[name] for name in CREDENTIAL_TABLES):
        raise ValueError("Backups must not contain reusable owner sessions or API tokens")
    for table in Base.metadata.sorted_tables:
        if len(database[table.name]) != manifest["row_counts"][table.name]:
            raise ValueError("Backup row counts differ from manifest")
        for row in database[table.name]:
            if set(row) != set(table.columns.keys()):
                raise ValueError("Backup columns differ from the application schema")
    inventory_names = {"inventories/" + row["id"] for row in database["inventory"]}
    if inventory_names != set(manifest["files"]) - {"database.json"}:
        raise ValueError("Backup inventory rows differ from files")
    for row in database["inventory"]:
        if row["sha256"] != manifest["files"]["inventories/" + row["id"]]:
            raise ValueError("Backup inventory checksum metadata differs")
    return manifest, database


def restore_backup(factory: sessionmaker[Session], storage: Path, source: Path) -> dict[str, Any]:
    """Restore into a migrated, empty installation only. Never replace an existing owner/data."""
    written: list[Path] = []
    with tempfile.TemporaryDirectory(prefix="depradar-restore-") as directory:
        stage = Path(directory)
        manifest, database = stage_backup(source, stage)
        storage.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(storage.iterdir()):
            raise ValueError("Restore requires an empty inventory directory")
        try:
            with factory.begin() as db:
                lock_writes(db)
                seeds = {"auth_guard", "system_state", "notification_policy"}
                for table in Base.metadata.sorted_tables:
                    if table.name not in seeds and db.scalar(
                        select(func.count()).select_from(table)
                    ):
                        raise ValueError("Restore requires an empty migrated database")
                for table in reversed(Base.metadata.sorted_tables):
                    db.execute(delete(table))
                for table in Base.metadata.sorted_tables:
                    rows = database[table.name]
                    for row in rows:
                        for column in table.columns:
                            if (
                                isinstance(column.type, UtcTimestamp)
                                and row[column.name] is not None
                            ):
                                row[column.name] = datetime.fromisoformat(row[column.name])
                        if table.name == "job" and row["status"] == "running":
                            row.update(
                                status="queued",
                                lease_token=None,
                                lease_until=None,
                                available_at=utcnow(),
                            )
                        if table.name == "scan" and row["status"] == "running":
                            row.update(status="queued", complete=False)
                        if table.name == "delivery" and row["status"] == "sending":
                            row.update(
                                status="failed",
                                lease_token=None,
                                lease_until=None,
                                last_error="restore_delivery_state_uncertain",
                            )
                    if rows:
                        db.execute(insert(table), rows)
                for row in database["inventory"]:
                    target = storage / row["id"]
                    with target.open("xb") as output, (stage / row["id"]).open("rb") as input_file:
                        written.append(target)
                        target.chmod(0o600)
                        shutil.copyfileobj(input_file, output)
            return manifest
        except Exception:
            for target in written:
                target.unlink(missing_ok=True)
            raise


def verify_backup(source: Path, database_url: str) -> dict[str, Any]:
    """A real restore in an isolated generated PostgreSQL schema; only that schema is removed."""
    from alembic import command
    from alembic.config import Config

    if not database_url.startswith("postgresql"):
        raise ValueError("Backup verification requires a PostgreSQL URL")
    schema = "depradar_verify_" + uuid4().hex
    admin = create_engine(database_url)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(database_url)

    @event.listens_for(engine, "connect")
    def set_schema(connection: Any, record: Any) -> None:
        with connection.cursor() as cursor:
            cursor.execute(f'SET search_path TO "{schema}"')
        connection.commit()

    try:
        # This module lives in src/depradar; image and repository both put alembic.ini at app root.
        ini = Path.cwd() / "alembic.ini"
        if not ini.is_file():
            ini = Path(__file__).parents[2] / "alembic.ini"
        config = Config(str(ini))
        with engine.connect() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        factory = sessionmaker(engine, expire_on_commit=False)
        with tempfile.TemporaryDirectory(prefix="depradar-verify-") as directory:
            storage = Path(directory)
            manifest = restore_backup(factory, storage, source)
            with factory() as db:
                for table in Base.metadata.sorted_tables:
                    count = db.scalar(select(func.count()).select_from(table))
                    if count != manifest["row_counts"][table.name]:
                        raise ValueError("Restored row counts differ from backup")
                for inventory in db.scalars(select(Inventory)):
                    if (
                        hashlib.sha256((storage / inventory.id).read_bytes()).hexdigest()
                        != inventory.sha256
                    ):
                        raise ValueError("Restored file checksum mismatch")
            return {
                "verified": True,
                "revision": REVISION,
                "tables": len(manifest["row_counts"]),
                "inventories": manifest["row_counts"]["inventory"],
            }
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()
