# CI/CD integration

DepRadar plugs into any pipeline that can run Python 3.9+. A pipeline uploads its lockfiles,
waits for the isolated OSV scan, and receives a pass/fail decision plus SARIF, JUnit, Markdown,
and JSON reports. Every decision is recorded with its evidence, and owner-defined
[central policies](#central-policies) set a minimum that pipelines can tighten but never relax.
Two modes keep pipelines from disturbing monitored state:

| Mode | Used for | Effect |
| --- | --- | --- |
| `monitor` | default-branch and release pipelines | The upload becomes the project's monitored inventory: findings open/resolve, alerts are routed, scheduled rechecks use it. |
| `check` | pull/merge requests and merge queues | Results are stored on the scan only. Findings, alerts, and monitored inventories never change. Accepted risk on the monitored manifest still applies. |

The client picks the mode automatically (`--mode auto`): change-request pipelines check,
everything else monitors. Re-uploading unchanged content for the same revision (a retried job)
rechecks the stored snapshot instead of storing another copy; a new commit with identical bytes
is stored as its own snapshot, so gate results always name the revision that was uploaded.

## 1. Make the API reachable

Pipelines need HTTPS access to one of:

- the API origin behind your reverse proxy (`https://depradar-api.example.com`), or
- the web interface, whose same-origin proxy forwards bearer tokens (`https://depradar.example.com/api/backend`).

For a private-network installation, run pipelines on self-hosted runners inside that network.
The client refuses plain HTTP to non-local hosts unless you pass `--allow-insecure-http`, and it
never follows redirects (that would leak the token). Use `--ca-file` for an internal CA.

## 2. Authenticate the pipeline

Use a [trusted identity](#trusted-identities-oidc) where the CI system issues OIDC job tokens
(GitHub Actions, GitLab): there is no stored secret, and pull/merge request runs are limited to
check uploads by the server. Use a token everywhere else.

### Tokens

Settings → **CI/CD access** → **New token**, or `POST /api/tokens` with the owner session:

```json
{"name": "acme-shop GitHub Actions", "scopes": ["projects:read", "inventories:write", "scans:read", "findings:read"], "project_id": null, "expires_in_days": 90}
```

The response contains the token once (`depradar_` + 38 characters, including a CRC32 checksum
so secret scanners and DepRadar can reject malformed values offline). DepRadar stores only its
SHA-256 digest. Store it as a masked secret named `DEPRADAR_TOKEN`.

| Scope | Allows |
| --- | --- |
| `projects:read` | List and read projects and their monitored manifests |
| `projects:write` | Create projects, including `create_project=true` on CI uploads |
| `inventories:write` | Upload monitored and check manifests, and queue rechecks |
| `inventories:check` | Upload check manifests only; can never change monitored state |
| `scans:read` | Read scans and evaluate gates and reports |
| `findings:read` | List project findings |
| `components:read` | Search packages; [AI assistant tokens](MCP.md) only |
| `scans:write` | Rescan stored monitored manifests; AI assistant tokens only |
| `monitoring:tighten` | Turn monitoring and alerts on or make them stricter, never looser; AI assistant tokens only |

- **One interface per token:** tokens default to `"audience": "api"` and work on the REST API
  only. `"audience": "mcp"` creates an [AI assistant token](MCP.md), which works on `/api/mcp`
  only. It can hold every scope except `inventories:write`, so it never uploads monitored
  manifests.
- **Restrict per client:** set `project_id` so a client's pipeline can only see and upload to
  its own project. Other projects return 404. Restricted tokens cannot create projects.
  Deleting the project deletes its restricted tokens.
- **Always session-only:** settings, connectors, notification policy, retention, finding
  decisions, jobs, service health, and token management itself.
- **Lifetime:** 1–365 days (default 90). Revoke immediately from Settings or
  `DELETE /api/tokens/{id}`. Usage is recorded as `last_used_at`.
- **Backups never contain tokens**, so a restore cannot revive a revoked token. Issue new
  tokens after restoring.
- **Pull requests:** give pull/merge request pipelines a separate **Pull request checks** token
  (`inventories:check`) so they cannot update monitored manifests. A secret is still visible to
  anyone who can edit the workflow in a same-repository branch, so prefer a trusted identity,
  which the server binds to the verified branch and event.

### Trusted identities (OIDC)

Settings → **Trusted identities** → **Add identity** binds a repository to one project:

| Field | Purpose |
| --- | --- |
| Provider and issuer | GitHub Actions (`https://token.actions.githubusercontent.com`; GitHub Enterprise Server uses `https://HOST/_services/token`) or GitLab (`https://gitlab.com` or your instance) |
| Repository and repository ID | `owner/repo` or `group/project`. The numeric ID (`gh api repos/OWNER/REPO --jq .id`, or the GitLab project ID) survives renames and rejects a deleted and re-created namesake; left empty, the first verified run's ID is pinned |
| Workflow | Optional: the only workflow file allowed to use the identity, such as `.github/workflows/depradar.yml` or `.gitlab-ci.yml` |
| Monitor branch | The branch whose runs may update monitored state, such as `refs/heads/main`; leave empty for checks only |

The pipeline sends its signed job token to `POST /api/ci/identity/exchange` and receives a
30-minute DepRadar token bound to that project. DepRadar verifies the RS256 signature with the
issuer's published keys (fetched only for issuers you trust), the audience, and the lifetime,
then decides the access:

| Run | Access |
| --- | --- |
| The trusted workflow on the protected monitor branch, started by `push`, `schedule`, or `workflow_dispatch` (GitLab: `push`, `schedule`, `web`) | `monitor`: monitored and check uploads |
| Pull and merge requests (including `pull_request_target`), merge queues, other branches, tags, and branches the token reports as unprotected | `check`: check uploads only |
| Another repository, repository ID, workflow, issuer, or audience | rejected |

Uploads made with an exchanged token are labelled with the verified branch and commit, whatever
the request says, and decisions record the run (repository, workflow, ref, event, run link). The
audience defaults to `DEPRADAR_DASHBOARD_URL`; set `DEPRADAR_OIDC_AUDIENCE` to override it.
Settings → Trusted identities shows the value. Removing an identity revokes its outstanding
tokens, which carry only `inventories:check` (plus `inventories:write` for monitor access) and
`scans:read`. Protect the monitor branch: GitHub and GitLab report protection in the token
(`ref_protected`), and runs of an unprotected branch get check access. Signing keys are cached
per issuer, and the last keys keep working for up to a day while an issuer is unreachable.

## 3. GitHub Actions

```yaml
name: Dependency gate
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write # only for upload-sarif

jobs:
  depradar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: <org>/depradar/integrations/github-action@<commit-sha>
        with:
          url: ${{ vars.DEPRADAR_URL }}
          token: ${{ secrets.DEPRADAR_TOKEN }}
          fail-on: high
          create-project: "true" # token needs projects:write
          upload-sarif: "true"   # private repositories need GitHub Code Security
          exclude: |
            tests/fixtures/*
```

With a trusted identity, drop the token and grant the job an OIDC token instead:

```yaml
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: <org>/depradar/integrations/github-action@<commit-sha>
        with:
          url: ${{ vars.DEPRADAR_URL }}
          auth: oidc
```

Pin the action to a full commit SHA. The project defaults to `owner/repo`. Violations appear as
annotations and in the job summary even without code scanning. Fork pull requests receive no
secrets; guard the job with
`github.event.pull_request.head.repo.full_name == github.repository`, as this repository's own
[dependency gate](../.github/workflows/dependency-gate.yml) does. Every input is listed in
[action.yml](../integrations/github-action/action.yml); its `result` output is `pass`, `fail`,
or `error`, and `decision-id` names the recorded decision. SARIF is uploaded before the gate is enforced, so failing builds still report.

## 4. GitLab CI/CD

```yaml
include:
  - remote: "https://raw.githubusercontent.com/<org>/depradar/<commit-sha>/integrations/gitlab/depradar.gitlab-ci.yml"
    inputs:
      url: "https://depradar.example.com"
      fail-on: high
      create-project: true
      extra-args: '--exclude "tests/fixtures/*"'
```

Add `DEPRADAR_TOKEN` as a masked, protected CI/CD variable, or use a trusted identity by giving
the included job an ID token with DepRadar's audience:

```yaml
depradar-gate:
  id_tokens:
    DEPRADAR_ID_TOKEN:
      aud: "https://depradar.example.com"
```

The job runs on merge requests,
the default branch, and tags; publishes JUnit results to the merge request widget; and keeps the
Markdown and JSON reports as artifacts. It downloads the client from your DepRadar server over
HTTPS and refuses redirects; set `DEPRADAR_CLIENT_SHA256` to pin it as well. Plain HTTP is
accepted only for loopback or when `DEPRADAR_ALLOW_INSECURE_HTTP` is `true` on a trusted private
network. To publish through the CI/CD Catalog, copy the template into
a component project's `templates/` directory.

## 5. Any other CI

```sh
# HTTPS only, no redirects: the script runs with this job's secrets.
curl -fsS --proto '=https' "$DEPRADAR_URL/api/ci/client.py" -o depradar_ci.py  # or /api/backend/...
echo "<expected-sha256>  depradar_ci.py" | sha256sum -c -                      # recommended pin
python3 -I depradar_ci.py scan --fail-on high --junit depradar.xml --sarif depradar.sarif
```

The client matches the server version that serves it. Repository, branch, and commit are
detected for GitHub Actions, GitLab, Bitbucket Pipelines, Azure Pipelines, Jenkins, and
CircleCI; elsewhere pass `--project` and `--revision`. Inside the DepRadar image the same client
is installed as `depradar-ci`.

## Client reference

`depradar-ci scan [PATH ...]` uploads explicit files, or searches directories (default: the
repository root) for lockfiles, skipping `node_modules`, `vendor`, `.venv`, `dist`, `build`,
`target`, and similar directories. SBOMs (`bom.json`, `*.cdx.json`) are only uploaded when
passed explicitly. `--exclude` patterns use shell globbing on repository-relative paths, where
`*` also crosses directories. At most 50 manifests per run, 10 MiB each.

| Option | Default | Purpose |
| --- | --- | --- |
| `--url` / `DEPRADAR_URL` | — | API origin or `/api/backend` URL |
| `--token-env NAME` | `DEPRADAR_TOKEN` | Environment variable holding the token (never pass tokens as arguments) |
| `--auth` | `auto` | `token`, `oidc`, or `auto`: the token when set, otherwise the job's OIDC identity (`id-token: write` on GitHub, `DEPRADAR_ID_TOKEN` on GitLab) |
| `--audience` / `DEPRADAR_AUDIENCE` | from the server | OIDC audience to request |
| `--project` / `DEPRADAR_PROJECT` | CI repository | Project name or ID |
| `--create-project` | off | Create a missing project; it is monitored every 24 hours |
| `--mode` | `auto` | `monitor`, `check`, or automatic |
| `--revision` | `branch@commit` | Revision label stored with the inventory |
| `--timeout` | 900 | Seconds to wait for scans |
| `--sarif`, `--junit`, `--markdown`, `--json` | — | Report files |
| `--no-summary` | off | Skip appending Markdown to `$GITHUB_STEP_SUMMARY` |

`depradar-ci evaluate SCAN_ID ...` records a new decision for finished scans of one project,
for example with different policy flags. Each
scan keeps the severity, advisories, and fixes it detected, so a later rescan never rewrites an
earlier result; owner decisions (acknowledgement, accepted risk) and cached KEV/EPSS data are
applied as they are now.

**Exit codes:** `0` gate passed · `1` policy violation · `2` error (authentication,
configuration, unreachable server, malformed server response, unreadable manifest or unwritable
report file, failed or replaced scan, timeout). `--timeout` bounds the whole wait, including each
status request.

## Gate policy

| Flag | Default | Rule |
| --- | --- | --- |
| `--fail-on` | `high` | Fail on findings at or above `low`, `medium`, `high`, `critical`, or `none` |
| `--fail-on-unknown` | off | Fail on advisories without published severity, whatever `--fail-on` says |
| `--no-fail-on-kev` | KEV fails | CVEs in the CISA KEV catalog fail regardless of severity |
| `--epss-threshold` | off | Fail when a CVE's EPSS probability reaches the value (0–1) |
| `--new-only` | off | Ignore findings already open in the monitored project |
| `--ignore-acknowledged` | off | Ignore acknowledged findings |
| `--fail-on-incomplete` | off | Fail when coverage is partial (private registries, local packages, unpinned versions) |
| `--require-monitored-manifests` | off | Fail unless every manifest the project monitors is part of the run |

Unexpired accepted risk is always ignored and is listed as such. Failed scans and scans replaced
by a newer upload of the same manifest are errors and never pass. Severity comes from advisory
metadata; CVSS-only advisories count as `unknown`. KEV covers the full cached catalog; EPSS is
cached for CVEs in open findings and in check scans from the last 7 days, refreshed daily, so
the first check of a new CVE may not have a score yet.

### Central policies

**Policies** in the dashboard hold the owner's minimum for the installation and, optionally, for
individual projects. The enforced gate is the strictest of the pipeline's request, the
installation policy, and the project policy, rule by rule: a lower severity threshold, a lower
EPSS threshold, and every `fail on` or `require` rule win, and `new-only` or
`ignore-acknowledged` are honored only where the policies allow them. A project policy can only
tighten the installation policy. Policies are versioned: each save records a new version with a
change note, and removing a project policy records a version too.

Every result lists `policy_sources` (the versions that applied, version 0 before the first
save), `requested_policy`, the enforced `policy`, and `adjustments`, which explain each rule a
central policy raised. The client prints the adjustments, and the Markdown report lists them.
`require-monitored-manifests` fails the gate when a monitored, non-retired manifest of the
project was not part of the decision; retire renamed or deleted manifests in the project view.

### Recorded decisions

The client records each gate with `POST /api/ci/decisions` (`{"scan_ids": [...], "policy": {...}}`,
scans of one project, `scans:read` plus `inventories:write` or `inventories:check`; read-only
tokens use the unrecorded preview). A decision is immutable and keeps:

- the status, counts, and every item with its reasons;
- the requested and enforced policy, the policy versions, and the adjustments;
- each input's manifest path, SHA-256, revision, scan status, coverage, and scanner version;
- the cached KEV/EPSS refresh time, and the acknowledgements and accepted risks that applied;
- who asked: the owner, a token, or a verified run with its commit.

`revision` comes from the inputs; `commit` is set only for verified runs whose inputs all came
from that run's commit. The
dashboard's **Decisions** page lists them. Decisions follow scan retention; each project keeps
its most recent decision.

### Require the gate before merging

A server-side decision cannot stop someone from skipping the pipeline. Make the gate a required
check: on GitHub, add the DepRadar job to a branch ruleset's required status checks (and require
branches to be up to date); on GitLab, enable **Pipelines must succeed** for merge requests and
keep the template's job without `allow-failure`. Protect the monitor branch so only reviewed
changes reach the runs that update monitored state.

## Reports

Reports for a recorded decision render from the stored result, so they always match it:
`GET /api/ci/decisions/{id}?format=json|sarif|junit|markdown`.
`GET /api/ci/evaluation?scan_id=…&format=…&fail_on=high` previews a gate without recording it;
central policies apply there too. Unknown query parameters are rejected. A scan that is still
running returns 409.

- **SARIF 2.1.0** — one run per manifest with a distinct category, `security-severity`
  (critical 9.5, high 8.0, medium 5.5, low 2.0), stable `primaryLocationLineHash` fingerprints,
  and the lockfile line of each package so pull request annotations land on changed lines.
  Accepted-risk findings are omitted.
- **JUnit XML** — a failing test per violation, skipped tests for ignored findings, and an
  error for failed scans; GitLab, Jenkins, and Azure show these natively.
- **Markdown** — job summaries and merge request comments; advisory text is escaped.
- **JSON** — the full decision, including the reason for every item.

## API

| Endpoint | Scope | Notes |
| --- | --- | --- |
| `POST /api/ci/uploads?project=&filename=&target_path=&revision=&mode=&create_project=` | `inventories:write`; `check` mode also accepts `inventories:check` (+ `projects:write` to create) | Raw file body; returns project, inventory, scan, and whether content was reused |
| `POST /api/ci/decisions` | `scans:read` and `inventories:write` or `inventories:check` | Record a gate decision for one project's finished scans |
| `GET /api/ci/decisions?project_id=&status=&limit=&offset=` | `scans:read` | Recorded decisions, newest first |
| `GET /api/ci/decisions/{id}?format=` | `scans:read` | Decision with its evidence, or its report |
| `GET /api/ci/evaluation` | `scans:read` | Unrecorded preview of a gate or report |
| `POST /api/ci/identity/exchange` | none (signed OIDC job token in the body) | `{"id_token": "...", "project": "optional"}` → 30-minute token, `access` `monitor` or `check` |
| `GET /api/ci/oidc` | none | The audience to request for OIDC job tokens |
| `GET /api/ci/client.py` | none | Client script; `X-Content-SHA256` header |
| `GET /api/scans/{id}` | `scans:read` | Poll until `succeeded`, `partial`, `failed`, or `superseded` |
| `GET /api/projects`, `GET /api/projects/{id}` | `projects:read` | `?name=` filters by exact name |
| `GET /api/projects/{id}/inventories?kind=monitor\|check\|all` | `projects:read` | Monitored manifests by default |
| `GET /api/projects/{id}/scans`, `GET /api/projects/{id}/findings` | `scans:read`, `findings:read` | |
| `POST /api/projects/{id}/inventories`, `POST /api/inventories/{id}/scans` | `inventories:write` | Dashboard-equivalent upload and recheck |
| `POST /api/projects` | `projects:write` | |
| `GET`/`POST /api/tokens`, `DELETE /api/tokens/{id}` | owner session | Token management |
| `GET /api/policies`, `GET /api/policies/versions[?project_id=]` | owner session | Current policies, effective project minimums, and history |
| `PUT /api/policies/installation`, `PUT /api/policies/projects/{id}` | owner session | `{"rules": {...}, "note": ""}` records a new version; project `rules: null` removes the override |
| `GET`/`POST /api/identities`, `DELETE /api/identities/{id}` | owner session | Trusted identities and the OIDC audience |

Send `Authorization: Bearer <token>`. Bearer requests need no CSRF token. The interactive
OpenAPI reference is at `/docs`.

## Supported manifests

Each format was verified against the pinned OSV-Scanner 2.7.0 with a fixture that pins a known
vulnerable version (`backend/tests/fixtures/manifests`):

| Ecosystem | Files |
| --- | --- |
| npm, pnpm, Yarn, Bun | `package-lock.json` (v2/v3), `pnpm-lock.yaml`, `yarn.lock` (v1 and Berry), `bun.lock` |
| PHP | `composer.lock` |
| Python | `poetry.lock`, `uv.lock`, `pylock.toml`, `Pipfile.lock`, `requirements*.txt` |
| Ruby, Rust, Go, Dart/Flutter | `Gemfile.lock`, `Cargo.lock`, `go.mod`, `pubspec.lock` |
| SBOM | CycloneDX JSON 1.4–1.7 (`bom.json`, `*.cdx.json`) |

Coverage notes mark scans partial (and prevent auto-resolution) for local, workspace, or Git
sources; unpinned or wildcard requirements; `-r`/`-c` includes, which must be uploaded
separately; Composer `dev-*` branches; and non-default npm registries. Cargo workspace crates
are reported under their crate names; a local crate sharing a published crate's name could match
that crate's advisories.
