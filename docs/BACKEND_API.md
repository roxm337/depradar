# Backend operations

All operations below require the owner session cookie. Mutations also require `X-CSRF-Token`
from login or `GET /api/auth/me`. Destination verification is separate from owner login.
Pipelines and other automation use scoped bearer tokens for projects, uploads, scans, findings,
and gate evaluation; see [CI/CD integration](CI_CD.md). The operations on this page stay
session-only.

## Email

Set `DEPRADAR_SMTP_PASSWORD` in your private environment if the SMTP server needs authentication.
Restart API and worker after changing environment values. Credentials are never stored in the
connector database record or returned by connector APIs.

`PUT /api/connectors/email`:

```json
{
  "host": "smtp.your-provider.example",
  "port": 587,
  "username": "your-smtp-user",
  "sender": "radar@your-domain.example",
  "recipient": "you@your-domain.example",
  "tls_mode": "starttls",
  "enabled": true
}
```

Supported TLS modes: `starttls` or `tls` (normally port 465). Plain SMTP is rejected unless the
server environment explicitly enables `DEPRADAR_ALLOW_INSECURE_SMTP` for a trusted local relay/test.

The worker queues and sends a verification code. Submit that code with
`POST /api/connectors/email/verify`, body `{"code":"the-code-from-your-email"}`.
Codes expire after 15 minutes and can be used once. Reconfiguring a connector requires verification
again and cancels unsent deliveries for its previous configuration. The verification message is sent
even if normal alerts are configured as disabled.

## Telegram

Create a dedicated personal bot and put its token in `DEPRADAR_TELEGRAM_BOT_TOKEN`.
Restart API and worker. Do not put the token into API requests, source files, or exported settings.

1. `POST /api/connectors/telegram/pair` returns a one-time `/start ...` command.
2. Send that command to your bot in a **private chat** within 15 minutes.
3. `POST /api/connectors/telegram/confirm` checks updates and returns `verified`, or a waiting status.

Pairing uses short polling, so no public inbound webhook is needed. Use a dedicated bot without an
existing webhook or another consumer of `getUpdates`. Group chats and state-changing bot commands
are not supported. Re-pair after switching to a different bot.

## Connector and delivery management

- `GET /api/connectors`: non-secret configuration, enabled state, verification state, and whether
  environment credentials are configured.
- `POST /api/connectors/{email|telegram}/test`: queue a test to a verified, enabled destination.
- `POST /api/connectors/{channel}/disable` or `/enable`: pause/resume normal delivery; enabling
  requires prior verification. An already in-flight provider request cannot be recalled.
- `GET /api/notifications/deliveries?limit=50&offset=0`: delivery state, attempts, timestamps,
  provider reference, and sanitized error code. Message bodies and verification codes are excluded.
- `GET /api/notifications/deliveries/{id}/attempts`: persisted provider attempt history, including
  uncertain outcomes after worker interruption.
- `POST /api/notifications/deliveries/{id}/retry`: replay a failed delivery with a fresh attempt budget.

States include `queued`, `sending`, `accepted`, `failed`, `cancelled`, `digest_pending`, and `bundled`.
`accepted` means accepted by SMTP or Telegram, not read by the recipient or guaranteed inbox delivery.
Retries honor provider rate-limit hints and use backoff/jitter. Ambiguous provider timeouts can still
cause duplicate external delivery; SMTP messages use a stable Message-ID.

## Message format

Email is sent as plain text plus an HTML version with light and dark styling, from the display name
"DepRadar". It loads nothing remote: no images, web fonts, or tracking. Telegram messages use HTML
formatting; the "Review findings" button appears only when `DEPRADAR_DASHBOARD_URL` is a public
address, because Telegram rejects buttons for localhost and private hosts. If Telegram refuses the
formatting, the same message is resent as plain text instead of failing. Advisory IDs link to
osv.dev.

## Routing and digests

`GET`/`PUT /api/notifications/policy`:

```json
{
  "immediate_min_severity": "high",
  "timezone": "Africa/Casablanca",
  "digest_hour": 8,
  "include_details": false,
  "quiet_hours_start": 22,
  "quiet_hours_end": 7
}
```

High/critical findings are immediate by default. Lower/unknown severities enter the daily digest.
Set the threshold to `low`, `medium`, `high`, or `critical`. Digest hours use an IANA timezone.
Risk expiry/revocation triggers immediate review. Project names, package names, and advisory IDs
are omitted unless the owner enables details; messages are composed when sent, so a changed setting
also covers alerts already queued. Set `DEPRADAR_DASHBOARD_URL` to an address reachable from
notification links.
Set both quiet-hour boundaries or leave both `null`; they use the configured timezone. Per-project
overrides are read and updated at `/api/projects/{id}/notifications` with `enabled` and
`immediate_min_severity` (`inherit`, `low`, `medium`, `high`, or `critical`).

Verification produces one initial summary. Events predating verification are not replayed as a flood
of individual alerts. Unchanged scans do not produce repeated opened events. When it prepares a
digest and again just before sending, the worker rechecks acknowledgement/risk status and the
project's `enabled` alert setting, so disabling a project also drops its queued alerts. Quiet hours
apply to digests at send time as well, including retries. Deleting a project removes its alerts
from unsent digests, which still deliver the other projects' alerts; sent digests are not replayed.

## Scheduled vulnerability monitoring

`PUT /api/projects/{id}/monitoring`, body `{"enabled":true,"interval_hours":24}` enables checks
of the latest uploaded inventory for each manifest path. Supported intervals are 1–168 hours.
The next worker cycle queues the first check unless one is already active. After downtime, one fresh
check is queued rather than replaying every missed interval. Set `enabled` to false to stop scheduling.

Project APIs show `monitoring_enabled`, `check_interval_hours`, and `next_check_at`.
`GET /api/projects/{id}/inventories` lists path, revision, upload time, and content hash. Upload may
include `target_path` and `revision` query parameters; separate monorepo manifests are monitored
independently. Scan history shows completion and errors. Rechecking vulnerability intelligence does
**not** refresh the dependency list: upload a new inventory when project packages change. GitHub
sync is intentionally deferred.

### Retiring a manifest

When a manifest is renamed or removed from a repository, its old path keeps being rechecked until
the owner retires it: `POST /api/projects/{id}/targets/retire`, body
`{"target_path":"web/package-lock.json"}` (owner session only; API tokens cannot retire). Every
snapshot of that path gets `retired_at`, scheduled and manual rechecks stop (a manual rescan returns
409), it no longer counts toward coverage, and its open findings resolve with a `retired` change
event that sends no alert. Scans already queued for the path are superseded. History is kept and
ages out under normal retention. Uploading the path again, from the dashboard or CI, creates a new
snapshot and resumes monitoring. Uploads, including CI pipelines that no longer find a manifest,
never retire anything on their own. Responds with `target_path`, `retired_inventories`, and
`resolved_findings`; 404 when no active monitored manifest exists at that path.

## Package search

`GET /api/components?name=lodash` answers which projects use a package, across the current
monitored manifest of every project (owner session only; API tokens cannot search). Optional
`ecosystem` (for example `npm` or `PyPI`) and `version` (exact match, as the manifest records it)
narrow the search. Each match gives the package as the manifest spells it, its version (empty when
unpinned), project, manifest path, revision, upload time, the scan that indexed it with its
completeness, and the number of open findings for that package in that manifest. At most 1,000
matches are returned; `truncated` says when there were more.

Names match the way their registry compares them: PyPI per PEP 503 (`Flask_SQLAlchemy` finds
`flask-sqlalchemy`), crates.io ignoring case and `-`/`_`, Packagist, NuGet, and Pub ignoring case.
Other ecosystems, including npm and Go, match exactly. Version ranges are not compared.

Every monitor scan that returns a report indexes every package it lists, including ones without
advisories and unpinned ones. A failed rescan keeps the earlier list. Check-mode (pull request)
scans, superseded scans, and retired manifests never enter the index, and only the newest
monitored snapshot of each manifest path is searched; older snapshots keep their lists until
retention removes them. Answers reflect the last uploaded manifest, not what is deployed.

Every response carries `coverage`, also available from `GET /api/components/coverage`: how many
current manifests are indexed, the ecosystems they list, `not_indexed` manifests (none of their
scans has indexed them yet, for example right after upgrading) and `partial` ones (indexed by an
incomplete scan, so a package may be missing). Recheck a manifest to index it. A package that is
not found in those manifests is unknown, not unused.

## Service and vulnerability intelligence

`GET /api/operations/health` reports database, worker heartbeat, OSV scanner probe, scan queue,
overdue schedules, alert queue, and the last successful EPSS/KEV refresh. CVE records receive FIRST
EPSS scores and CISA KEV membership; advisories without CVE aliases have no EPSS/KEV score. Scanner
PURLs and available CVSS vectors are exposed on findings. These enrichment signals supplement OSV
severity and do not prove reachability or deployment exposure.
The worker refreshes these public feeds every 24 hours by default; configure
`DEPRADAR_INTELLIGENCE_REFRESH_HOURS` from 1 to 168 to change the interval. A failed refresh leaves
the last successful cache intact and retries later.

## Acknowledgement and accepted risk

- `POST /api/findings/{id}/acknowledge`, body `{"note":"Investigating"}`, mutes future queued alerts
  while retaining the active detection. `DELETE` on the same path revokes acknowledgement.
- `POST /api/findings/{id}/risk-acceptance` requires a nonempty `reason` and `expires_at`, a
  timezone-aware future ISO 8601 timestamp within 365 days.
- `DELETE /api/findings/{id}/risk-acceptance` revokes an exception early.
- `GET /api/findings/{id}/decisions` returns decision history.

The worker expires accepted risk, restores open workflow state, and queues a new alert if still
affected. These decisions never mark a vulnerability fixed. Resolution needs a complete clean scan;
reopening a resolved finding resets its old acknowledgement/exception.

## Deletion and retention

`DELETE /api/projects/{id}` removes project inventories, scans/jobs, findings/decisions, events,
related deliveries, its restricted tokens, its project policy versions, trusted identities, and
recorded gate decisions. An active scan/delivery returns 409; wait for it to finish or its lease to expire.
File deletions are recorded transactionally and completed by the worker after commit. Global
connector configuration is retained. Existing backup archives are independent snapshots and are
not rewritten by project deletion.

`GET /api/maintenance/retention` reads the policy.
`PUT /api/maintenance/retention`, body `{"scan_days":30,"delivery_days":30}`, configures history
retention (1–3650 days). The worker runs cleanup daily; `POST /api/maintenance/retention/run`
triggers it manually. The latest inventory and scan, active work, and event-bearing audit evidence
are preserved. Superseded, unreferenced inventory files and older redundant scans are eligible for
cleanup. Old terminal delivery records are pruned, while pending/in-flight work remains. Gate
decisions older than the scan retention are pruned, except each project's most recent decision,
and exchanged OIDC tokens are removed a day after they expire. Central policy versions are kept.

See [backup and restore procedures](BACKUPS.md) for separate archive management.
