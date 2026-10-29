# Backup, restore, and verification

DepRadar produces versioned logical archives containing all application table rows and referenced
inventory files. A manifest records row counts and SHA-256 checksums. Session and CI/CD API tokens
are omitted, so restoring an older archive cannot revive a token revoked after it was taken.
SMTP passwords, Telegram tokens, and other environment credentials are not included; preserve the
private environment separately. Archives contain owner password hashes and private dependency data;
they are created with owner-only file permissions and must be stored privately.

## Create a verified archive

In Docker Compose:

```sh
docker compose exec api depradar backup /data/backups/depradar-backup.tar.gz
docker compose cp api:/data/backups/depradar-backup.tar.gz ./depradar-backup.tar.gz
```

The backups volume is private to the application. Existing archive names are never overwritten.
Use a new filename for every backup. For a local backend, run from `backend/`:

```sh
uv run depradar backup /private/tmp/depradar-backup.tar.gz
```

The command briefly blocks application writes while copying consistent database rows and immutable
files. It then creates a randomly named verification schema in PostgreSQL, applies migrations,
restores the archive, and compares row counts and file hashes. The verification schema is removed
afterward; normal application schemas are not dropped. The database role needs schema-creation rights.

Success prints `"verified": true`. A failed drill exits nonzero and leaves an **unverified** archive
for investigation. An archive merely existing is not proof of a successful backup. Re-run the drill:

```sh
uv run depradar verify-backup /private/tmp/depradar-backup.tar.gz
```

Use `--database-url postgresql+psycopg://...` to run the restore drill in another PostgreSQL instance.
Prefer environment-provided credentials over typing passwords into shell history. The default URL
comes from `DEPRADAR_DATABASE_URL`.

## Restore an installation

Restore only archives from trusted sources. Checksums detect corruption; they are not signatures
authenticating who created an archive. New archives use schema revision `0004`. Restore accepts
`0002` and `0003` archives and fills newly added fields with safe defaults for the current schema.

1. Prepare a new, empty PostgreSQL database and an empty inventory directory.
2. Configure that database and directory in a fresh backend environment, keeping API/worker stopped.
3. Run `uv run alembic upgrade head` from `backend/`.
4. Run `uv run depradar restore-backup /path/to/depradar-backup.tar.gz`.
5. Restore private environment credentials separately, start services, sign in again, and check projects,
   connector settings, inventory hashes, and a new scan.

Restore refuses an existing owner/application data or nonempty inventory directory. It validates
archive paths, file types, entry/size limits, schema fields, row counts, and checksums before writing.
It does not expose a destructive overwrite option. If data insertion fails, the transaction rolls back
and newly copied files are removed.

All sessions are revoked and no API tokens exist; create new CI/CD tokens and update pipeline
secrets. Interrupted scan jobs return to the queue. Interrupted deliveries are
marked failed with `restore_delivery_state_uncertain` because a provider may already have accepted
them; inspect delivery history before choosing a manual retry.

## Retain and protect backups

Store copies outside the host running DepRadar. Use encrypted storage if appropriate for your data.
Choose an archive retention schedule separately from application scan/delivery retention. Project
deletion does not alter historical archives. Never remove the only verified copy before another
verified copy exists. Periodically run a restore drill and record its timestamp/result.

The logical format targets a single developer installation, not large-database point-in-time recovery.
PostgreSQL infrastructure backups remain a separate option as usage grows.

## Full integration verification

From the repository root, with Docker running and download/network access available:

```sh
docker compose -f compose.verify.yaml up --build --abort-on-container-exit --exit-code-from tests
```

This uses disposable PostgreSQL storage, the real pinned OSV binary, captured SMTP through Mailpit,
and a local Telegram protocol fixture. It exercises uploads, findings, notifications, scheduled checks,
acknowledgement/risk expiry, fix verification, a PostgreSQL backup restore drill, and project deletion.
It never uses production email addresses, bot tokens, or normal application volumes.

After inspecting the result:

```sh
docker compose -f compose.verify.yaml down -v
```

Use this cleanup only with the verification file. It removes the disposable test environment.
Real Telegram-account delivery requires configuring and verifying your own bot afterward; the
integration fixture validates protocol handling, not Telegram service availability.
