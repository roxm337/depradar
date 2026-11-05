# Contributing to DepRadar

Thank you for helping. DepRadar decides whether a pipeline may merge and ship, so a change has to
be correct before it is useful. This guide covers what to work on, how to set up, which checks
must pass, and the rules a change must not break.

## Before you start

- **Small fixes** (bugs, tests, documentation): open a pull request directly.
- **Larger changes** (features, new manifest formats, schema changes, or anything that touches
  scanning, gating, tokens, or notifications): open an issue first, so the approach is agreed
  before you write code.
- **Scope**: [PLAN.md](PLAN.md) and [docs/SECURITY_ROADMAP.md](docs/SECURITY_ROADMAP.md) list
  what is built and what comes next. Hosted multi-tenant service, billing, and public signup are
  out of scope. Team accounts are planned but need a design decision before work starts.
- **Security vulnerabilities**: never in a public issue. Follow [SECURITY.md](SECURITY.md).

## Set up

You need Docker with Compose, Python 3.12 to 3.14 with [uv](https://docs.astral.sh/uv/), and
Node 24 with pnpm (the version is pinned in `front/package.json`).

1. Start the stack: create `.env` and run `docker compose up --build`, as described in
   [Run with Docker Compose](README.md#run-with-docker-compose-development). Set
   `DEPRADAR_API_PORT` in `.env` if port 8000 is taken.
2. Create the owner account: `docker compose exec api depradar setup-owner`.
3. Run the dashboard: follow [front/README.md](front/README.md).

Backend tests run without the stack: `cd backend && uv sync && uv run pytest -q`. They use SQLite
unless `DEPRADAR_TEST_DATABASE_URL` points at a PostgreSQL database.

## Checks

Pull requests run these in CI, and they must pass before a change can merge. Run them locally
first.

| Area | From | Commands |
| --- | --- | --- |
| Backend | `backend/` | `uv run ruff check .` · `uv run ruff format --check .` · `uv run mypy src` · `uv run pytest -q` |
| Frontend | `front/` | `pnpm lint` · `pnpm test` · `pnpm build` |
| Installer | repository root | `python3 -m unittest discover -s deploy/tests -v` |
| Integration | repository root | `docker compose -f compose.verify.yaml up --build --abort-on-container-exit --exit-code-from tests`, then `docker compose -f compose.verify.yaml down -v` |

The integration stack runs the backend suite against PostgreSQL, the real pinned OSV scanner, and
captured SMTP and Telegram servers. Run it locally when you change scanning, jobs, notifications,
migrations, or backups. CI also runs the CI client on Python 3.9 and 3.14.

## Where code goes

The backend follows Clean Architecture; dependencies point inward.

- Business rules go in `domain/`, and use cases in `application/`.
- Anything that reaches the network, the filesystem, or another process goes behind a port in
  `application/ports.py`, with its adapter in `infrastructure/`.
- HTTP request and response schemas go in `interfaces/http/schemas.py`.
- The core may use only SQLAlchemy and Pydantic, and neither may perform I/O there.
  `tests/test_architecture.py` fails on any import that breaks these rules.

The [project layout](README.md#data-backups-and-project-layout) in the README describes each
directory.

## Rules a change must not break

People rely on DepRadar's verdicts. A pull request that breaks one of these rules is not merged,
even when its tests pass. If you change code behind a rule, add a test that covers it.

**Findings and gates**

- Failed, partial, empty, or superseded scans never resolve findings. Only a complete result for
  the latest inventory can.
- Pull request (check-mode) scans never change findings, alerts, or monitored inventories.
- Failed or superseded scans never pass a gate. Pipelines can tighten central policy but never
  relax it.
- Gate decisions are immutable, and reports are rendered from the stored decision.
- Incomplete scanner coverage is always shown to the user, never hidden.

**Credentials and untrusted input**

- Credentials never appear in source, logs, exports, backups, notifications, or scanner jobs.
  Configuration examples contain placeholders only.
- API tokens are stored only as SHA-256 digests and are never accepted as command-line arguments.
- Uploads and advisory text are untrusted. Keep the upload limits and the scanner's isolation,
  and never execute package install scripts.

**Compatibility**

- Schema changes add a new Alembic revision. Never edit a revision that is already on `main`, and
  update `REVISION` and the restore upgrade path in `backend/src/depradar/infrastructure/backups.py`,
  so backups taken on earlier versions still restore.
- A new manifest format needs a fixture in `backend/tests/fixtures/manifests` with a package that
  has a known advisory, and the pinned scanner must detect it through the scanner service.
- `backend/src/depradar/ci_client.py` and `deploy/depradarctl` run on customer CI images and fresh
  servers: Python 3.9 or later, standard library only, and no `depradar` imports.

## Frontend

Follow [front/DESIGN.md](front/DESIGN.md): use tokens only, write labels in sentence case, design
every state (loading, empty, error, partial, disabled), and keep every action reachable by
keyboard. Visible changes need screenshots in light and dark themes in the pull request.

## Commits and pull requests

- Branch from `main`. `main` is protected: changes land through pull requests with passing checks.
- Write [Conventional Commits](https://www.conventionalcommits.org/) with one short subject line,
  such as `fix(scans): keep findings open after a partial scan`. Prefer several small, focused
  commits to one large one.
- Keep a pull request to one change; unrelated cleanups go in their own pull request.
- The pull request template asks what changed and why, how you validated it, any migration or
  configuration changes, and screenshots for visible changes.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
