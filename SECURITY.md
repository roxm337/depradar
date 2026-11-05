# Security policy

DepRadar holds client dependency inventories, alert credentials, and the access that lets
pipelines pass or fail. Please report vulnerabilities privately so they can be fixed before
they are public.

## Report a vulnerability

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/roxm337/depradar/security/advisories/new)
(Security tab → Advisories → Report a vulnerability).

Do not open a public issue, pull request, or discussion for a vulnerability.

A useful report includes:

- the affected commit or version (`sudo depradarctl status` shows the installed one);
- how DepRadar is deployed (`depradarctl`, Docker Compose, or other);
- steps to reproduce, or a proof of concept;
- the impact: what an attacker gains, and what access they need first.

Remove tokens, passwords, and client project names from logs before attaching them.

## What happens next

- The maintainer aims to acknowledge a report within 5 working days and to share an initial
  assessment within 14 days.
- Fixes are developed in a private advisory. You are kept informed and invited to review the fix.
- The advisory is published once a fix is on `main`. Reporters are credited unless they prefer
  not to be.

## Supported versions

DepRadar has no versioned releases yet. Security fixes land on `main`; upgrade an installation
with `sudo depradarctl upgrade`, which rolls back automatically if the new version fails to start.

## Scope

In scope:

- owner authentication, sessions, CSRF protection, and the setup bootstrap;
- API token scopes and OIDC trusted identities, for example a pull request run gaining write
  access, or a token reaching another project;
- gate bypasses: a failed, partial, or superseded scan passing a gate, a pull request scan
  changing findings, alerts, or monitored inventories, or a pipeline relaxing central policy;
- scanner isolation and upload handling, such as path traversal, decompression bombs, or code
  execution from a manifest;
- credentials exposed in logs, exports, backups, notifications, or the browser;
- backup and restore integrity;
- `deploy/depradarctl`, the CI client, the GitHub Action, and the GitLab template.

Out of scope:

- known vulnerabilities in third-party dependencies, unless DepRadar uses them in an exploitable
  way (report those upstream);
- attacks that already require the owner password or root access on the host;
- automated scanner output without a demonstrated impact;
- denial of service by sending large volumes of traffic.

Test only against an installation you run yourself. Good-faith research that follows this policy
is welcome.
