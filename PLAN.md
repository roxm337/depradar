# DepRadar — agency edition

Status: single-owner workflow implemented; CI/CD integration (phase A below) implemented and verified; deep-audit fixes and manifest retirement verified on the full PostgreSQL/OSV stack; enforced CI policies and trusted runs (phase A.2, from the local security roadmap) implemented. Team accounts await a design decision. Updated: 5 November 2026.
Basis: [market and GitHub research](RESEARCH.md).
This plan supersedes the earlier multi-tenant enterprise proposal. The single-user sections below remain the foundation and their rules still apply.

## Agency edition roadmap

Goal: an internal, ready-to-use dependency security service for an agency that maintains many client projects. Every client repository's pipeline keeps its inventory current and gates its changes; the agency sees risk across all clients in one place. One installation serves one agency; tenants, billing, and hosted signup stay out of scope.

| Phase | Scope | Status |
| --- | --- | --- |
| A — CI/CD integration | Scoped, expiring, hash-stored API tokens (optionally per project); `/api/ci/uploads` with project auto-creation and unchanged-content reuse; `monitor` vs `check` modes so pull requests never alter monitored state; gate policy (severity, KEV, EPSS, unknown severity, new-only, acknowledged, incomplete coverage) honoring accepted risk; SARIF 2.1.0, JUnit, Markdown, and JSON reports; standard-library client (Python 3.9+) served by the server; GitHub Action; GitLab template; dashboard token management; 14 manifest formats plus CycloneDX 1.7, each verified with the pinned scanner; full KEV catalog caching; repository CI on current action majors. Also fixed: retention could prune the only snapshot of a clean monorepo manifest. | Done; 112 tests passed on the PostgreSQL/OSV stack |
| A.1 — Audit hardening | Deep audit of 4 November 2026: newest-snapshot rescans; "clear" shown only for verified complete monitor coverage; digests survive project deletion, follow project alert settings and quiet hours at send time; gates keep each scan's own detections and revision; advisory alias splits; Composer validation; worker liveness during long scans; CI client exit codes and wait budget; GitLab client download over HTTPS only; proxy body cap and no bootstrap injection; container installs from `uv.lock`; owner-retired manifests (migration 0005). | Done; 177 tests passed with no skips on the PostgreSQL/OSV stack |
| A.2 — Enforced policies and trusted runs | Security roadmap features 1–2: versioned installation and project policies that pipelines can tighten but never relax, with every override explained; required monitored manifests; immutable recorded gate decisions (policy versions, input hashes, scanner versions, intelligence freshness, applied exceptions, actor, verified commit) with reports rendered from the record; `inventories:check` scope for pull request tokens; GitHub Actions and GitLab OIDC trusted identities exchanged for 30-minute project-bound tokens, check-only for pull/merge requests; dashboard Decisions and Policies pages and Trusted identities settings (migration 0006). | Done; verified with SQLite tests, frontend lint/unit tests/build; PostgreSQL stack run pending |
| A.3 — AI assistants (MCP) | MCP endpoint at `/api/mcp` on the official SDK (stateless, JSON responses), off by default; assistant tokens that work on MCP only (audience on `api_token`) and hold read scopes, `components:read`, and `inventories:check` at most; read tools (portfolio and project overview, findings, scans, package search, gate preview and decisions), check scans of pasted lockfiles, and four prompts; untrusted text labelled and cleaned; per-token rate limit; audit of every call without arguments, with retention; dashboard AI assistants settings (migration 0008). OAuth for ChatGPT and claude.ai is deferred to phase B. | Done ([#13](https://github.com/roxm337/depradar/issues/13)) |
| A.4 — Assistant changes that only increase coverage | MCP tools `create_project`, `rescan_manifests`, `set_monitoring`, and `set_alerts`; new assistant-only scopes `scans:write` and `monitoring:tighten`, and `projects:write` for unrestricted assistant tokens; increase-only rules as pure domain functions; the scheduler and rescans share one selection of current manifests without an active scan; opt-in changes on the AI assistant token form. No migration. | In review ([#16](https://github.com/roxm337/depradar/issues/16)) |
| B — Team accounts | Named user accounts with roles (admin, member, viewer); per-user sessions and password reset; actor on decisions, tokens, and audit history; migration of the owner to the first admin; optional OIDC sign-in (for example Google Workspace). Requires a deliberate schema migration of `owner`, `owner_session`, and decision records. | Needs decision |
| C — Client portfolio | Client grouping and tags on projects; per-client alert routing; Slack/Teams/Discord and signed generic webhook connectors; centrally managed per-project gate defaults; exportable client reports. | Planned |
| D — Delivery and operations | Done: web interface container, Caddy edge proxy with automatic HTTPS, and `deploy/depradarctl` (guided install, status, upgrade with rollback, verified backups/restore, doctor, uninstall; CI-tested install cycle). Remaining: published images with SBOM and provenance; release workflow; repository update automation; CVSS v3 scoring for CVSS-only advisories; VEX export. | In progress |
| E — Source connectors | GitHub App and GitLab integration for repository sync and pull request comments, replacing the deferred token-based GitHub sync. | Planned |

Phase A keeps the single-owner security model: tokens cannot reach settings, connectors, decisions, jobs, health, or token management, and are never included in backups. See [CI/CD integration](docs/CI_CD.md).

## Objective

One developer monitors packages across multiple projects and receives vulnerability alerts through email and Telegram. One installation has one owner. There are no organizations, teams, invitations, roles, tenant IDs, billing, or enterprise SSO in v1.

Default deployment is Docker Compose on a developer machine, private server, or VPS. Monitoring runs while that host is running. Show last successful scans and overdue work after downtime. Keep accurate matching, evidence, reliable delivery, credential protection, and backups.

## Stack

| Layer | Choice |
| --- | --- |
| Frontend | Next.js, TypeScript, Tailwind CSS, shadcn/ui |
| API | Python, FastAPI, Pydantic |
| Database | PostgreSQL, SQLAlchemy, Alembic migrations |
| Background processing | Separate Python worker with PostgreSQL-backed durable jobs and outbox |
| HTTP integrations | HTTPX |
| Scanning | Pinned OSV-Scanner in an isolated scan container |
| Inventory storage | Private local Docker volume with retention limits |
| Email | Configurable authenticated SMTP with TLS |
| Telegram | Telegram Bot API, personal chat |
| Tooling | uv, Ruff, mypy; pnpm for frontend |
| Verification | pytest, PostgreSQL integration checks, Playwright |
| Deployment | Docker Compose |

Pin supported stable releases during implementation. AWS, Redis, Kubernetes, and a paid identity provider are not required for v1. Provider and scanner adapters remain small and replaceable.

The scan container receives read-only inputs and temporary output storage, with resource/time limits. It has no API secrets or database access. Do not mount the host Docker socket into the API or general worker. Validate a fixed scanner execution arrangement in the technical spike.

## First complete user flow

1. Start the installation and set the owner's password through one-time bootstrap.
2. Add a project with an uploaded dependency file or CycloneDX JSON SBOM.
3. Scan it; inspect affected packages, advisories, severity, evidence, and fixed versions.
4. Configure SMTP and a personal Telegram chat; verify both with test messages.
5. Choose immediate-alert severity, daily digest schedule, timezone, and project overrides.
6. Recheck stored inventories daily by default, even without code changes.
7. Upload updated dependencies or sync GitHub after an upgrade; verify resolution with a fresh complete scan.

Manual upload is the supported source flow. GitHub synchronization is intentionally excluded from the current implementation scope.

## Inventory and GitHub connector

Start with npm package-lock.json, Python poetry.lock, and CycloneDX JSON. Confirm format versions against the pinned scanner. Add pnpm, Yarn, uv, and other ecosystems according to actual use and verified support.

Each project initially monitors one selected branch or uploaded inventory, identified by commit or content hash. Preserve file paths, package origins, dependency scopes, and graph edges when available. Unpinned versions, missing lockfiles, unknown origins, and partial graphs must produce explicit coverage information.

When GitHub synchronization is revisited, use a read-only fine-grained token restricted to selected repositories. Poll configured dependency-file paths and fetch changed inventories. Handle expiration, revocation, API limits, repository removal, and partial sync failures. Never display or log the token. GitHub Apps and webhooks can follow later.

## Findings and intelligence

Use OSV-Scanner through an adapter; do not implement ecosystem parsers from scratch. Record engine/version, input hash, timestamps, errors, advisory evidence, and scan completeness. CISA KEV and FIRST EPSS are now cached and displayed when CVE identifiers are available.

Keep inventory age separate from last vulnerability check: rechecking an old upload cannot establish what current code contains. A source inventory does not prove what is deployed in production.

Support advisories without CVEs, including GHSA. Preserve source records, aliases, revisions, withdrawals, affected ranges, and fix information. Deduplicate aliases without discarding provenance. Unknown severity, exploitation signals, or reachability stay unknown.

Store immutable snapshots and link observations to findings scoped to project, target, package/version, and advisory alias group. Separate detection from workflow decisions:

- Detection: affected, no longer detected in a complete current snapshot, unknown/partial, withdrawn advisory.
- Workflow: open, acknowledged, in progress, risk accepted until an expiry, resolved, reopened.

Failed or partial scans cannot resolve findings. Risk acceptance is not a fix. Preserve history across resolution and reopening. Upgrade guidance must not claim compatibility or automatically merge changes.

## Email and Telegram

Start with one global email destination and one personal Telegram chat, plus per-project enable/disable and severity overrides. Offer an explicit initial-backlog summary, immediate urgent alerts, daily nonurgent digests, and quiet hours. Avoid resending unchanged findings after every scan.

Messages contain project, package/version, advisory, severity, available fix, and dashboard link. Explain when the configured dashboard URL only works on the owner's network. Let the owner control whether private project/package details appear in external messages.

SMTP: support TLS, connection tests, escaped templates, retries, and recorded failures. Server acceptance is not proof of inbox delivery or reading. Provider-specific bounce callbacks are deferred until needed.

Telegram: protect the bot token, bind the personal chat through a short-lived one-time challenge, and verify with a test message. Temporary long polling during setup avoids requiring a public webhook. Handle rate limits and token/destination revocation. State-changing chat commands and group workflows are deferred; use authenticated dashboard links.

Persist finding changes and outbox events in one database transaction. Track destination, attempts, retry time, provider response, and final status. Retry transient failures with bounded backoff and provider retry hints. Show exhausted deliveries and allow replay. Stable event/delivery keys suppress routine duplicates; an ambiguous provider timeout can still cause duplicate external delivery.

## Worker and data model

Use PostgreSQL as the initial durable job store. Claim due work using transactional row locking and leases. Recover expired leases after crashes; track attempts, next retry, last error, and terminal failure. Deduplicate scheduled occurrences. After downtime, run a fresh recheck instead of replaying every missed scheduled scan.

The worker scheduler persists due work transactionally. FastAPI enqueues jobs and returns job IDs; scans and important notifications do not run in request-local background tasks.

Core entities: Owner, Project, Target, ConnectorConfig, InventorySnapshot, ComponentOccurrence, DependencyEdge, Scan, AdvisoryRecord, AdvisoryAlias, Finding, FindingObservation, FindingDecision, NotificationSettings, Destination, Job, Schedule, OutboxEvent, Delivery, DeliveryAttempt, ChangeEvent.

No organization or tenant scaffolding. Add collaboration through a deliberate design and migration if it becomes a real requirement.

## Single-owner security and operations

- One owner account, no public registration; hashed password, secure server-side session, CSRF protection, rate-limited login, and documented credential reset.
- Localhost access by default. Remote access needs a private network or HTTPS reverse proxy and retains owner authentication.
- Encrypt connector secrets using an application key outside the database. Keep secrets out of logs, exports, and scanner jobs. Back up the key separately for recovery.
- Treat uploads and advisory text as untrusted: enforce size/decompression limits, safe paths, parser timeouts, output escaping, and scanner isolation. Do not execute package install scripts.
- Show job, connector, feed, and notification health. Apply retention and support project deletion.
- Document database and inventory-volume backups; verify a restore before the first stable release. Monitoring stops when the host is off.

## Implementation milestones

| Milestone | Deliverables | Exit gate |
| --- | --- | --- |
| 1 — First scan | Compose, API/schema, owner setup/login, upload, isolated OSV scan, projects/findings UI | Supported input produces evidence-backed findings; invalid input has actionable errors; scanner cannot access app secrets. |
| 2 — Alerts | Durable jobs/outbox, SMTP, Telegram pairing, immediate alerts/digest, delivery history | Crash recovery and retries work; unchanged rescans do not routinely duplicate alerts. |
| 3 — Monitoring | Scheduled rechecks, inventory path/revision, project alert controls, inventory/scan freshness, worker/scanner status | Newly disclosed advisories affect unchanged inventory; uploads and vulnerability checks show separate timestamps. |
| 4 — Stable developer release | Acknowledgement/exceptions, fix verification/reopen, KEV/EPSS, notification quiet hours, delivery-attempt history, retention, backups | Full add-project → alert → upgrade → rescan → resolution flow works; backup restore succeeds. |

Start with Milestone 1. Re-estimate effort after validating scanner isolation and representative fixtures; the earlier enterprise staffing/time estimate no longer applies.

## Verification and deferred scope

Initial target: one owner and up to 50 projects. Benchmark inputs up to 10 MB / 10,000 components and report measured capacity instead of promising commercial SLAs.

Meaningful fixtures cover versions, aliases, local workspace links, missing lockfiles, partial scans, package removal, advisory withdrawals, job leases, SMTP failures, Telegram rate limits, and fix/reopen transitions. Browser/API verification covers setup through resolution. Backend API/lifecycle tests now exist; see README.md for run commands and verification limits. No mobile app or mobile tests are in scope.

Deferred: tenants, SCIM, billing, hosted signup, cloud-specific infrastructure, automatic fix PRs/merges, custom reachability, container registries, SAST/DAST, and broad connector coverage. Team accounts and source connectors are now roadmap phases B and E.

## Implementation progress

Implemented: owner authentication, project/inventory/scan APIs, leased scan jobs and isolated OSV
service, finding evidence and alias handling, fix/reopen events, SMTP and Telegram verification,
durable notifications/retries/digests, scheduled vulnerability rechecks, acknowledgement and expiring
risk acceptance, transactional project deletion, retention, and versioned backup/restore with a
PostgreSQL restore drill. The follow-up implementation adds inventory path/revision identity, EPSS/
KEV enrichment, CVSS/PURL presentation, quiet hours, per-project alert controls, persisted delivery
attempts, and worker/scanner health. Phase A added migration 0004 (API tokens, check-mode inventories and scans), manifest retirement added 0005 (`inventory.retired_at`), and phase A.2 added 0006 (central policies, trusted identities, recorded gate decisions, identity token columns), and package search added 0007 (`component_occurrence`, the package index behind the Packages page). Migration head: 0007. GitHub sync remains deferred.

Latest verification, 4 November 2026 on macOS arm64: `compose.verify.yaml` ran 177 tests with no
skips, exit code 0. It covers PostgreSQL, the real pinned OSV scanner for every accepted manifest
format (each fixture must surface a recorded known advisory), captured SMTP, the Telegram protocol
fixture, scheduled checks, decisions, fix resolution, project deletion, migration round trips
including a populated 0003 → head upgrade, and backup restore drills from revisions 0003 and 0004.
Ruff, formatting, mypy, frontend lint, frontend unit tests (`node --test`), and the frontend
production build also passed. Earlier runs (23 October: 46 tests; phase A: 112 tests) predate these
additions.

Not yet verified: an automated browser flow (dashboard behavior is covered by frontend unit tests of
its coverage and snapshot logic, not by a browser), delivery to a real mailbox or Telegram account,
and capacity at 50 projects / 10 MB / 10,000 components. GitHub sync and capacity benchmarking
remain deferred. See README.md and docs/BACKUPS.md.
