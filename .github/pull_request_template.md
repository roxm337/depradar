## What and why

<!-- What changes, and why. Link the issue, for example: Closes #123. -->

## Validation

<!-- What you ran and what you checked by hand. Tick what applies. -->

- [ ] Backend: `ruff check`, `ruff format --check`, `mypy src`, `pytest`
- [ ] Frontend: `pnpm lint`, `pnpm test`, `pnpm build`
- [ ] Integration stack (`compose.verify.yaml`), for scanning, jobs, notifications, migrations, or backups
- [ ] `depradarctl` unit tests, for changes under `deploy/`

## Migration and configuration

<!-- New Alembic revision, backup REVISION, new settings or environment variables. Write "None" if there are none. -->

## Screenshots

<!-- Light and dark themes for visible UI changes. Delete this section otherwise. -->

## Checklist

- [ ] No [rule a change must not break](https://github.com/roxm337/depradar/blob/main/CONTRIBUTING.md#rules-a-change-must-not-break) is broken, and changed rules have tests.
- [ ] No credentials, tokens, or client project names in code, fixtures, logs, or screenshots.
