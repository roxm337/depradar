# CI/CD integration

DepRadar plugs into any pipeline that can run Python 3.9+. A pipeline uploads its lockfiles,
waits for the isolated OSV scan, and receives a pass/fail decision plus SARIF, JUnit, Markdown,
and JSON reports. Two modes keep pipelines from disturbing monitored state:

| Mode | Used for | Effect |
| --- | --- | --- |
| `monitor` | default-branch and release pipelines | The upload becomes the project's monitored inventory: findings open/resolve, alerts are routed, scheduled rechecks use it. |
| `check` | pull/merge requests and merge queues | Results are stored on the scan only. Findings, alerts, and monitored inventories never change. Accepted risk on the monitored manifest still applies. |

The client picks the mode automatically (`--mode auto`): change-request pipelines check,
everything else monitors. Re-uploading unchanged content rechecks the stored snapshot instead of
storing another copy.

## 1. Make the API reachable

Pipelines need HTTPS access to one of:

- the API origin behind your reverse proxy (`https://depradar-api.example.com`), or
- the web interface, whose same-origin proxy forwards bearer tokens (`https://depradar.example.com/api/backend`).

For a private-network installation, run pipelines on self-hosted runners inside that network.
The client refuses plain HTTP to non-local hosts unless you pass `--allow-insecure-http`, and it
never follows redirects (that would leak the token). Use `--ca-file` for an internal CA.

## 2. Create a token

Settings → **CI/CD pipelines** → **Create token**, or `POST /api/tokens` with the owner session:

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
| `inventories:write` | Upload manifests and queue rechecks |
| `scans:read` | Read scans and evaluate gates and reports |
| `findings:read` | List project findings |

- **Restrict per client:** set `project_id` so a client's pipeline can only see and upload to
  its own project. Other projects return 404. Restricted tokens cannot create projects.
  Deleting the project deletes its restricted tokens.
- **Always session-only:** settings, connectors, notification policy, retention, finding
  decisions, jobs, service health, and token management itself.
- **Lifetime:** 1–365 days (default 90). Revoke immediately from Settings or
  `DELETE /api/tokens/{id}`. Usage is recorded as `last_used_at`.
- **Backups never contain tokens**, so a restore cannot revive a revoked token. Issue new
  tokens after restoring.

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

Pin the action to a full commit SHA. The project defaults to `owner/repo`. Violations appear as
annotations and in the job summary even without code scanning. Fork pull requests receive no
secrets; guard the job with
`github.event.pull_request.head.repo.full_name == github.repository`, as this repository's own
[dependency gate](../.github/workflows/dependency-gate.yml) does. Every input is listed in
[action.yml](../integrations/github-action/action.yml); its `result` output is `pass`, `fail`,
or `error`. SARIF is uploaded before the gate is enforced, so failing builds still report.

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

Add `DEPRADAR_TOKEN` as a masked, protected CI/CD variable. The job runs on merge requests,
the default branch, and tags; publishes JUnit results to the merge request widget; and keeps the
Markdown and JSON reports as artifacts. It downloads the client from your DepRadar server; set
`DEPRADAR_CLIENT_SHA256` to pin it. To publish through the CI/CD Catalog, copy the template into
a component project's `templates/` directory.

## 5. Any other CI

```sh
curl -fsSL "$DEPRADAR_URL/api/ci/client.py" -o depradar_ci.py   # or /api/backend/ci/client.py
echo "<expected-sha256>  depradar_ci.py" | sha256sum -c -        # optional pinning
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
| `--project` / `DEPRADAR_PROJECT` | CI repository | Project name or ID |
| `--create-project` | off | Create a missing project; it is monitored every 24 hours |
| `--mode` | `auto` | `monitor`, `check`, or automatic |
| `--revision` | `branch@commit` | Revision label stored with the inventory |
| `--timeout` | 900 | Seconds to wait for scans |
| `--sarif`, `--junit`, `--markdown`, `--json` | — | Report files |
| `--no-summary` | off | Skip appending Markdown to `$GITHUB_STEP_SUMMARY` |

`depradar-ci evaluate SCAN_ID ...` re-evaluates finished scans with different policy flags.

**Exit codes:** `0` gate passed · `1` policy violation · `2` error (authentication,
configuration, unreachable server, failed or replaced scan, timeout).

## Gate policy

| Flag | Default | Rule |
| --- | --- | --- |
| `--fail-on` | `high` | Fail on findings at or above `low`, `medium`, `high`, `critical`, or `none` |
| `--fail-on-unknown` | off | Also fail on advisories without published severity |
| `--no-fail-on-kev` | KEV fails | CVEs in the CISA KEV catalog fail regardless of severity |
| `--epss-threshold` | off | Fail when a CVE's EPSS probability reaches the value (0–1) |
| `--new-only` | off | Ignore findings already open in the monitored project |
| `--ignore-acknowledged` | off | Ignore acknowledged findings |
| `--fail-on-incomplete` | off | Fail when coverage is partial (private registries, local packages, unpinned versions) |

Unexpired accepted risk is always ignored and is listed as such. Failed scans and scans replaced
by a newer upload of the same manifest are errors and never pass. Severity comes from advisory
metadata; CVSS-only advisories count as `unknown`. KEV covers the full cached catalog; EPSS is
cached for CVEs in open findings and in check scans from the last 7 days, refreshed daily, so
the first check of a new CVE may not have a score yet.

## Reports

Request any format for up to 50 finished scans:
`GET /api/ci/evaluation?scan_id=…&scan_id=…&format=json|sarif|junit|markdown&fail_on=high`.
Unknown query parameters are rejected. A scan that is still running returns 409.

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
| `POST /api/ci/uploads?project=&filename=&target_path=&revision=&mode=&create_project=` | `inventories:write` (+ `projects:write` to create) | Raw file body; returns project, inventory, scan, and whether content was reused |
| `GET /api/ci/evaluation` | `scans:read` | Gate decision or report |
| `GET /api/ci/client.py` | none | Client script; `X-Content-SHA256` header |
| `GET /api/scans/{id}` | `scans:read` | Poll until `succeeded`, `partial`, `failed`, or `superseded` |
| `GET /api/projects`, `GET /api/projects/{id}` | `projects:read` | `?name=` filters by exact name |
| `GET /api/projects/{id}/inventories?kind=monitor\|check\|all` | `projects:read` | Monitored manifests by default |
| `GET /api/projects/{id}/scans`, `GET /api/projects/{id}/findings` | `scans:read`, `findings:read` | |
| `POST /api/projects/{id}/inventories`, `POST /api/inventories/{id}/scans` | `inventories:write` | Dashboard-equivalent upload and recheck |
| `POST /api/projects` | `projects:write` | |
| `GET`/`POST /api/tokens`, `DELETE /api/tokens/{id}` | owner session | Token management |

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
