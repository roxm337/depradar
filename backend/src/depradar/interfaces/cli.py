"""Local administration: owner setup, password recovery, and verified backups."""

import argparse
import getpass
import json
from pathlib import Path

from depradar.application.auth import set_owner_password
from depradar.application.errors import ApplicationError
from depradar.config import get_settings
from depradar.infrastructure.backups import create_backup, restore_backup, verify_backup
from depradar.infrastructure.database import session_factory


def main() -> None:
    parser = argparse.ArgumentParser(description="DepRadar local administration")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("reset-password")
    commands.add_parser("setup-owner")
    for name in ["backup", "verify-backup", "restore-backup"]:
        command = commands.add_parser(name)
        command.add_argument("path", type=Path)
        if name != "restore-backup":
            command.add_argument(
                "--database-url", default=None, help="PostgreSQL URL for an isolated restore drill"
            )
    args = parser.parse_args()
    settings = get_settings()
    if args.command not in {"reset-password", "setup-owner"}:
        try:
            if args.command == "backup":
                create_backup(session_factory(), settings.storage_dir, args.path)
                result = verify_backup(args.path, args.database_url or settings.database_url)
            elif args.command == "verify-backup":
                result = verify_backup(args.path, args.database_url or settings.database_url)
            else:
                restore_backup(session_factory(), settings.storage_dir, args.path)
                result = {"restored": True, "sessions_revoked": True}
            print(json.dumps(result))
        except Exception:
            parser.exit(
                1,
                "Backup/restore failed; artifact is unverified. Check paths, schema, "
                "database availability and privileges. Existing data is never overwritten.\n",
            )
        return
    password = getpass.getpass("New owner password (12–128 characters): ")
    if not 12 <= len(password) <= 128:
        parser.error("Password must contain 12–128 characters")
    if password != getpass.getpass("Confirm password: "):
        parser.error("Passwords do not match")
    try:
        set_owner_password(session_factory(), password, initialize=args.command == "setup-owner")
    except ApplicationError as exc:
        parser.error(str(exc))
    if args.command == "setup-owner":
        print("Owner initialized. Sign in through POST /api/auth/login.")
    else:
        print("Password updated; all sessions revoked.")


if __name__ == "__main__":
    main()
