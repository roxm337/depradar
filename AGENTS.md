# Repository Guidelines

## Project Scope and Structure

DepRadar is a self-hosted dependency vulnerability monitor and CI/CD gate for an agency's client projects, with email and Telegram alerts. One owner account administers the installation; scoped API tokens give pipelines least-privilege access. Team accounts are a pending roadmap phase (see `PLAN.md`); tenants, billing, and hosted signup are outside scope.

The repository is split into a FastAPI backend and a Next.js interface:

- `backend/src/depradar/`: Clean Architecture layers. `domain/` holds entities and pure rules, `application/` holds use cases and the ports they need, `infrastructure/` implements those ports (database, file storage, scanner, email, Telegram, feeds, backups), and `interfaces/` holds the entry points (HTTP API, worker, CLI, private scanner service).
- `backend/migrations/`: Alembic schema revisions.
- `backend/tests/`: backend unit and integration coverage; `tests/fixtures/manifests` holds one verified fixture per manifest format.
- `backend/src/depradar/ci_client.py`: standard-library CI client (Python 3.9+); keep it free of third-party and `depradar` imports.
- `integrations/`: GitHub Action and GitLab CI template wrapping the client.
- `deploy/`: `depradarctl`, the standard-library server installer and operations tool (Python 3.9+), with its production Compose overlay and unit tests. Production runtime config lives in `/etc/depradar`, never in the repository.
- `front/app/`: Next.js App Router pages and global styles.
- `front/lib/`: frontend API and shared helpers.
- `docs/`: API, operations, and backup guidance.
- `PLAN.md` and `RESEARCH.md`: product scope, status, and market evidence.
- `CONTRIBUTING.md` and `SECURITY.md`: the contributor workflow and private vulnerability reporting.

## Build, Test, and Development Commands

Run `docker compose up --build` from the repository root to start PostgreSQL, API, worker, and scanner. Initialize the owner with `docker compose exec api depradar setup-owner`.

From `backend/`, use `uv sync`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, and `uv run pytest -q`. From `front/`, use `pnpm install`, `pnpm dev`, `pnpm lint`, `pnpm test`, or `pnpm build`. The isolated PostgreSQL/OSV verification stack is defined in root `compose.verify.yaml`.

## Coding Style and Naming

Use four-space indentation, type hints, and `snake_case` for Python functions/modules. Use TypeScript, PascalCase React components, and camelCase functions in the frontend. Use Ruff for Python formatting and ESLint for frontend linting. Keep HTTP request/response schemas in `interfaces/http/schemas.py`. Put business rules in `domain/` and use cases in `application/`; anything that reaches the network, filesystem, or another process goes behind a port in `application/ports.py` with its adapter in `infrastructure/`. Dependencies point inward. The core (`domain/` and `application/`) may use only two libraries, and neither may perform I/O: SQLAlchemy, to map entities and query through them, and Pydantic, to validate untrusted data shapes such as scanner reports and gate policies. Web frameworks, HTTP clients, and every other library stay in `interfaces/` and `infrastructure/`; `tests/test_architecture.py` enforces this.

Implement UI directly in code. Never use Superdesign.

## Testing Guidelines

Use pytest for backend rules and PostgreSQL integration checks for jobs/outbox behavior. Name Python test files `test_*.py`. Verify frontend changes with the lint, test, and build commands above.

Prioritize alias deduplication, incomplete scans, retry recovery, duplicate alerts, and fix/reopen transitions. Failed or partial scans must never resolve findings. Preserve migration compatibility and show incomplete scanner coverage clearly.

Check-mode (pull request) scans must never change findings, alerts, or monitored inventories, and failed or superseded scans must never pass a CI gate. Before accepting a new manifest format, add a fixture with a known advisory and confirm the pinned scanner detects it through the scanner service.

## Commits and Pull Requests

Use Conventional Commits (`feat(scope):`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`) with one short subject line, and keep each commit focused. `main` is protected: changes land through pull requests whose required checks pass. `CONTRIBUTING.md` is the full contributor guide.

PRs should explain behavior, validation performed, relevant issues, and configuration or migration changes. Include screenshots for visible UI changes.

## Security and Configuration

Keep credentials out of source, logs, exports, backups, and scanner jobs. API tokens are stored only as SHA-256 digests and never accepted as command-line arguments. Commit placeholder-only configuration examples. Isolate scanners, constrain uploads, and never execute package install scripts during ingestion. Use durable worker jobs for scans and notifications.
