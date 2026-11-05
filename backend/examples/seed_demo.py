# ruff: noqa: E501  (the advisory catalogs read best as one row per finding)
"""Fill an EMPTY DepRadar database with demo data, for UI development and screenshots.

    cd backend
    DEPRADAR_DATABASE_URL=sqlite:///demo.db uv run python examples/seed_demo.py

Creates the owner (password from DEMO_OWNER_PASSWORD, default "demo-owner-password"), seven
projects with manifests and scan history, about ninety findings spread over five months, alert
channels with delivery history, and CI tokens. SQLite databases get their tables created for you;
for PostgreSQL run `alembic upgrade head` first. The script refuses any database that already has
an owner or projects, so it can never mix demo rows into real data. Advisory identifiers are
real-format but the findings are illustrative; every project description says so.
"""

import hashlib
import os
import random
import secrets
import sys
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from depradar.application.auth import set_owner_password
from depradar.config import get_settings
from depradar.domain.entities import (
    ApiToken,
    AuthGuard,
    Base,
    Connector,
    Delivery,
    Finding,
    FindingDecision,
    Inventory,
    NotificationPolicy,
    Owner,
    Project,
    Scan,
    SystemState,
    utcnow,
)
from depradar.infrastructure.database import get_engine, session_factory

random.seed(20261104)
NOW = utcnow()

# (package, version, advisories, severity, fixed versions, summary, EPSS, known exploited)
Catalog = list[tuple[str, str, list[str], str, list[str], str, float, bool]]

NPM: Catalog = [
    (
        "minimist",
        "1.2.5",
        ["GHSA-xvch-5gv4-984h", "CVE-2021-44906"],
        "critical",
        ["1.2.6"],
        "Prototype pollution in minimist",
        0.046,
        False,
    ),
    (
        "lodash",
        "4.17.15",
        ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"],
        "high",
        ["4.17.21"],
        "Command injection in lodash template",
        0.013,
        False,
    ),
    (
        "lodash",
        "4.17.15",
        ["GHSA-p6mc-m468-83gw", "CVE-2020-8203"],
        "high",
        ["4.17.19"],
        "Prototype pollution in lodash zipObjectDeep",
        0.012,
        False,
    ),
    (
        "node-fetch",
        "2.6.1",
        ["GHSA-r683-j2x4-v87g", "CVE-2022-0235"],
        "high",
        ["2.6.7", "3.1.1"],
        "node-fetch forwards secure headers to untrusted sites",
        0.006,
        False,
    ),
    (
        "tough-cookie",
        "4.0.0",
        ["GHSA-72xf-g2v4-qvf3", "CVE-2023-26136"],
        "medium",
        ["4.1.3"],
        "Prototype pollution in tough-cookie cookie memstore",
        0.004,
        False,
    ),
    (
        "axios",
        "0.21.1",
        ["GHSA-cph5-m8f7-6c5x", "CVE-2021-3749"],
        "high",
        ["0.21.2"],
        "Inefficient regular expression complexity in axios",
        0.009,
        False,
    ),
    (
        "qs",
        "6.5.2",
        ["GHSA-hrpp-h998-j3pp", "CVE-2022-24999"],
        "high",
        ["6.5.3", "6.10.3"],
        "qs prototype pollution via __proto__ keys",
        0.021,
        False,
    ),
    (
        "semver",
        "5.7.1",
        ["GHSA-c2qf-rxjj-qqgw", "CVE-2022-25883"],
        "medium",
        ["5.7.2", "7.5.2"],
        "semver regular expression denial of service",
        0.002,
        False,
    ),
    (
        "json5",
        "1.0.1",
        ["GHSA-9c47-m6qq-7p4h", "CVE-2022-46175"],
        "high",
        ["1.0.2", "2.2.2"],
        "Prototype pollution in json5 parse",
        0.033,
        False,
    ),
    (
        "word-wrap",
        "1.2.3",
        ["GHSA-j8xg-fqg3-53r7", "CVE-2023-26115"],
        "medium",
        ["1.2.4"],
        "word-wrap regular expression denial of service",
        0.003,
        False,
    ),
    (
        "ws",
        "7.4.5",
        ["GHSA-6fc8-4gx4-v693", "CVE-2021-32640"],
        "medium",
        ["7.4.6"],
        "ReDoS in Sec-Websocket-Protocol header",
        0.005,
        False,
    ),
    (
        "webpack",
        "5.75.0",
        ["GHSA-hc6q-2mpp-qw7j", "CVE-2023-28154"],
        "critical",
        ["5.76.0"],
        "Cross-realm object access in webpack",
        0.011,
        False,
    ),
    (
        "decode-uri-component",
        "0.2.0",
        ["GHSA-w573-4hg7-7wgq", "CVE-2022-38900"],
        "high",
        ["0.2.1"],
        "decode-uri-component denial of service",
        0.004,
        False,
    ),
    (
        "minimatch",
        "3.0.4",
        ["GHSA-f8q6-p94x-37v3", "CVE-2022-3517"],
        "high",
        ["3.0.5"],
        "minimatch ReDoS in braceExpand",
        0.006,
        False,
    ),
    (
        "moment",
        "2.29.1",
        ["GHSA-8hfj-j24r-96c4", "CVE-2022-24785"],
        "high",
        ["2.29.2"],
        "Path traversal in moment locale loading",
        0.007,
        False,
    ),
    (
        "braces",
        "3.0.2",
        ["GHSA-grv7-fg5c-xmjg", "CVE-2024-4068"],
        "high",
        ["3.0.3"],
        "Uncontrolled resource consumption in braces",
        0.001,
        False,
    ),
    (
        "ip",
        "1.1.5",
        ["GHSA-2p57-rm9w-gvfp", "CVE-2023-42282"],
        "critical",
        [],
        "SSRF through private IP misclassification in ip",
        0.003,
        False,
    ),
    (
        "cross-spawn",
        "7.0.3",
        ["GHSA-3xgq-45jj-v275", "CVE-2024-21538"],
        "high",
        ["7.0.5"],
        "ReDoS in cross-spawn",
        0.002,
        False,
    ),
]
PYPI: Catalog = [
    (
        "django",
        "4.2.8",
        ["GHSA-frmv-pr5f-9mcr", "CVE-2024-24680"],
        "high",
        ["4.2.10"],
        "Denial of service in Django intcomma",
        0.193,
        False,
    ),
    (
        "django",
        "4.2.8",
        ["GHSA-pv4p-cwwg-4rph", "CVE-2024-27351"],
        "medium",
        ["4.2.11"],
        "Potential ReDoS in django.utils.text.Truncator",
        0.015,
        False,
    ),
    (
        "requests",
        "2.28.1",
        ["GHSA-j8r2-6x86-q33q", "CVE-2023-32681"],
        "medium",
        ["2.31.0"],
        "Unintended leak of Proxy-Authorization header",
        0.004,
        False,
    ),
    (
        "urllib3",
        "1.26.5",
        ["GHSA-g4mx-q9vg-27p4", "CVE-2023-45803"],
        "medium",
        ["1.26.18", "2.0.7"],
        "urllib3 request body not stripped after redirect",
        0.002,
        False,
    ),
    (
        "pillow",
        "9.5.0",
        ["GHSA-j7hp-h8jx-5ppr", "CVE-2023-4863"],
        "critical",
        ["10.0.1"],
        "Heap buffer overflow in libwebp bundled with Pillow",
        0.711,
        True,
    ),
    (
        "jinja2",
        "3.1.2",
        ["GHSA-h5c8-rqwp-cp95", "CVE-2024-22195"],
        "medium",
        ["3.1.3"],
        "Cross-site scripting through the xmlattr filter",
        0.006,
        False,
    ),
    (
        "cryptography",
        "41.0.3",
        ["GHSA-jfhm-5ghh-2f97", "CVE-2023-49083"],
        "medium",
        ["41.0.6"],
        "NULL pointer dereference loading PKCS7 certificates",
        0.002,
        False,
    ),
    (
        "pyyaml",
        "5.3.1",
        ["GHSA-8q59-q68h-6hv4", "CVE-2020-14343"],
        "critical",
        ["5.4"],
        "Arbitrary code execution in PyYAML full_load",
        0.286,
        False,
    ),
    (
        "sqlparse",
        "0.4.3",
        ["GHSA-2m57-hf25-phgg", "CVE-2023-30608"],
        "high",
        ["0.4.4"],
        "ReDoS in sqlparse",
        0.005,
        False,
    ),
    (
        "werkzeug",
        "2.2.2",
        ["GHSA-xg9f-g7g7-2323", "CVE-2023-25577"],
        "high",
        ["2.2.3"],
        "Werkzeug multipart parsing resource exhaustion",
        0.012,
        False,
    ),
    (
        "flask",
        "2.2.2",
        ["GHSA-m2qf-hxjv-5gpq", "CVE-2023-30861"],
        "high",
        ["2.2.5", "2.3.2"],
        "Flask may cache responses with a session cookie",
        0.003,
        False,
    ),
    (
        "gunicorn",
        "20.1.0",
        ["GHSA-w3h3-4rj7-4ph4", "CVE-2024-1135"],
        "high",
        ["22.0.0"],
        "Request smuggling through Transfer-Encoding handling",
        0.002,
        False,
    ),
    (
        "certifi",
        "2022.9.24",
        ["GHSA-xqr8-7jwr-rhp7", "CVE-2023-37920"],
        "unknown",
        ["2023.7.22"],
        "Removal of e-Tugra root certificate",
        0.001,
        False,
    ),
    (
        "idna",
        "3.3",
        ["GHSA-jjg7-2v4v-x38h", "CVE-2024-3651"],
        "medium",
        ["3.7"],
        "Quadratic complexity in idna.encode",
        0.001,
        False,
    ),
]
RUBY: Catalog = [
    (
        "rack",
        "2.2.3",
        ["GHSA-wq4h-7r42-5hrr", "CVE-2022-30122"],
        "high",
        ["2.2.3.1"],
        "Denial of service in Rack multipart parsing",
        0.020,
        False,
    ),
    (
        "rack",
        "2.2.3",
        ["GHSA-hxqx-xwvh-44m2", "CVE-2022-30123"],
        "critical",
        ["2.2.3.1"],
        "Shell escape sequence injection in Rack::CommonLogger",
        0.017,
        False,
    ),
    (
        "nokogiri",
        "1.13.3",
        ["GHSA-2qc6-mcvw-92cw", "CVE-2022-29181"],
        "high",
        ["1.13.6"],
        "Improper handling of unexpected data types in Nokogiri",
        0.006,
        False,
    ),
    (
        "rails",
        "6.1.4",
        ["GHSA-3hhc-qp5v-9p2j", "CVE-2022-23633"],
        "medium",
        ["6.1.4.6"],
        "Information leak in Action Pack",
        0.004,
        False,
    ),
    (
        "loofah",
        "2.18.0",
        ["GHSA-228g-948r-83gx", "CVE-2022-23514"],
        "high",
        ["2.19.1"],
        "Inefficient regular expression in Loofah",
        0.003,
        False,
    ),
    (
        "puma",
        "5.6.4",
        ["GHSA-68xg-gqqm-vgj8", "CVE-2022-24790"],
        "critical",
        ["5.6.4.1", "4.3.12"],
        "HTTP request smuggling in Puma",
        0.018,
        False,
    ),
    (
        "devise",
        "4.7.3",
        ["GHSA-jxhc-q857-3j6g", "CVE-2019-16109"],
        "low",
        ["4.7.1"],
        "Confirmable race in Devise",
        0.001,
        False,
    ),
]
CRATES: Catalog = [
    (
        "smallvec",
        "1.6.0",
        ["GHSA-43w2-9j62-hq99", "RUSTSEC-2021-0003"],
        "critical",
        ["1.6.1"],
        "Buffer overflow in SmallVec::insert_many",
        0.017,
        False,
    ),
    (
        "time",
        "0.1.43",
        ["GHSA-wcg3-cvx6-7396", "RUSTSEC-2020-0071"],
        "medium",
        ["0.2.23"],
        "Potential segfault in the time crate",
        0.002,
        False,
    ),
    (
        "tokio",
        "1.18.0",
        ["GHSA-fg7r-2g4j-5cgr", "RUSTSEC-2023-0001"],
        "high",
        ["1.18.4", "1.20.3"],
        "Reject named pipes in Tokio on Windows",
        0.002,
        False,
    ),
    (
        "openssl",
        "0.10.38",
        ["GHSA-xcf7-rvmh-g6q4", "RUSTSEC-2023-0072"],
        "medium",
        ["0.10.55"],
        "X509VerifyParamRef::set_host buffer over-read",
        0.001,
        False,
    ),
]
COMPOSER: Catalog = [
    (
        "symfony/http-kernel",
        "5.4.10",
        ["CVE-2022-24894"],
        "medium",
        ["5.4.20"],
        "Symfony HttpKernel leaks the Set-Cookie header in cached responses",
        0.003,
        False,
    ),
    (
        "guzzlehttp/guzzle",
        "7.4.0",
        ["CVE-2022-31090"],
        "high",
        ["7.4.5"],
        "CURLOPT_HTTPAUTH option not cleared on redirect",
        0.004,
        False,
    ),
    (
        "league/commonmark",
        "2.2.0",
        ["CVE-2022-39261"],
        "medium",
        ["2.3.7"],
        "Twig template injection in commonmark extension",
        0.002,
        False,
    ),
    (
        "laravel/framework",
        "9.2.0",
        ["CVE-2022-31279"],
        "critical",
        ["9.52.5"],
        "Unserialize gadget chain in Laravel",
        0.045,
        False,
    ),
    (
        "phpmailer/phpmailer",
        "6.5.0",
        ["CVE-2021-3603"],
        "high",
        ["6.5.1"],
        "Insecure include_path usage in PHPMailer",
        0.006,
        False,
    ),
    (
        "monolog/monolog",
        "2.3.0",
        ["CVE-2022-3003"],
        "low",
        ["2.3.5"],
        "Local file inclusion in Monolog handlers",
        0.001,
        False,
    ),
]
PUB: Catalog = [
    (
        "http",
        "0.12.2",
        ["CVE-2020-35669"],
        "high",
        ["0.13.0"],
        "Dart http package leaks Authorization header on redirect",
        0.005,
        False,
    ),
    (
        "path",
        "1.7.0",
        ["GHSA-q7p8-6f9w-52m4"],
        "low",
        ["1.8.0"],
        "Path normalization difference on Windows",
        0.001,
        False,
    ),
]
GO: Catalog = [
    (
        "golang.org/x/text",
        "0.3.5",
        ["GHSA-ppp9-7jff-5vj2", "CVE-2021-38561"],
        "high",
        ["0.3.7"],
        "Out-of-bounds read in golang.org/x/text/language",
        0.007,
        False,
    ),
    (
        "golang.org/x/net",
        "0.1.0",
        ["GHSA-vvpx-j8f3-3w6h", "CVE-2022-41723"],
        "high",
        ["0.7.0"],
        "Denial of service via HPACK decoder",
        0.034,
        False,
    ),
    (
        "github.com/gin-gonic/gin",
        "1.7.7",
        ["GHSA-3vp4-m3rf-835h", "CVE-2023-26125"],
        "medium",
        ["1.9.0"],
        "Gin improper input validation of untrusted proxies",
        0.003,
        False,
    ),
    (
        "golang.org/x/crypto",
        "0.0.0-20210921155107",
        ["GHSA-45x7-px36-x8w8", "CVE-2023-48795"],
        "medium",
        ["0.17.0"],
        "Terrapin attack on the SSH protocol",
        0.489,
        False,
    ),
    (
        "github.com/containerd/containerd",
        "1.6.8",
        ["GHSA-5ffw-gxpp-mxpf", "CVE-2022-23648"],
        "high",
        ["1.6.1"],
        "Insecure handling of image volumes",
        0.021,
        False,
    ),
]

# name, description, manifests: (ecosystem label, target path, filename, catalog, share of catalog)
PROJECTS = [
    (
        "acme/api",
        "Customer-facing REST API.",
        [("PyPI", "services/api/requirements.txt", "requirements.txt", PYPI, 1.0)],
    ),
    (
        "acme/worker",
        "Background jobs and report generation.",
        [("PyPI", "services/worker/requirements.txt", "requirements.txt", PYPI, 0.8)],
    ),
    (
        "acme/storefront",
        "Web storefront and embeddable widgets.",
        [
            ("npm", "apps/web/package-lock.json", "package-lock.json", NPM, 0.75),
            ("npm", "packages/widgets/yarn.lock", "yarn.lock", NPM, 0.5),
        ],
    ),
    (
        "client-c/landing",
        "Marketing site for Client C.",
        [("npm", "bun.lock", "bun.lock", NPM, 0.45)],
    ),
    (
        "internal/billing",
        "Invoicing service and PDF renderer.",
        [
            ("RubyGems", "Gemfile.lock", "Gemfile.lock", RUBY, 1.0),
            ("crates.io", "renderer/Cargo.lock", "Cargo.lock", CRATES, 1.0),
        ],
    ),
    (
        "northwind/portal",
        "Customer portal for Northwind.",
        [("Packagist", "composer.lock", "composer.lock", COMPOSER, 1.0)],
    ),
    (
        "orbit/gateway",
        "API gateway for the Orbit apps.",
        [("npm", "pnpm-lock.yaml", "pnpm-lock.yaml", NPM, 0.7)],
    ),
    (
        "orbit/mobile",
        "Cross-platform mobile app.",
        [("Pub", "pubspec.lock", "pubspec.lock", PUB, 1.0)],
    ),
    ("harbor/infra", "Deployment tooling and controllers.", [("Go", "go.mod", "go.mod", GO, 1.0)]),
]
TOKENS = [
    (
        "GitHub Actions · acme",
        ["projects:read", "inventories:write", "scans:read", "findings:read"],
        None,
        75,
        0.1,
        False,
    ),
    (
        "GitLab CI · northwind",
        ["projects:read", "projects:write", "inventories:write", "scans:read"],
        None,
        40,
        3,
        False,
    ),
    ("Release pipeline", ["inventories:write", "scans:read"], "harbor/infra", 120, 26, False),
    ("Former contractor", ["projects:read", "scans:read"], None, 15, 61, True),
]


def refuse(reason: str) -> None:
    sys.exit(f"Refusing to seed: {reason}. Point DEPRADAR_DATABASE_URL at an empty database.")


def days_ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


def first_seen_days() -> float:
    pick = random.random()
    if pick < 0.34:
        return random.uniform(0.2, 14)
    if pick < 0.76:
        return random.uniform(14, 60)
    return random.uniform(60, 148)


def seed(db: Session) -> None:
    policy = db.get(NotificationPolicy, 1)
    assert policy is not None
    policy.immediate_min_severity = "high"
    policy.timezone = "UTC"
    policy.include_details = True
    policy.digest_hour = 8
    policy.quiet_hours_start, policy.quiet_hours_end = 22, 7
    policy.next_digest_at = NOW + timedelta(hours=9)
    state = db.get(SystemState, 1)
    assert state is not None
    state.last_worker_heartbeat_at = NOW
    state.last_scanner_check_at = NOW
    state.scanner_available = True
    state.last_intelligence_refresh_at = NOW - timedelta(minutes=6)
    state.next_intelligence_refresh_at = NOW + timedelta(hours=23)

    projects: dict[str, Project] = {}
    for index, (name, description, manifests) in enumerate(PROJECTS):
        project = Project(
            name=name,
            description=f"{description} (Demo data.)",
            created_at=days_ago(165 - index * 6),
            monitoring_enabled=name != "orbit/mobile",
            check_interval_hours=24,
            next_check_at=NOW + timedelta(hours=random.randint(1, 20)),
            notifications_enabled=name != "client-c/landing",
        )
        db.add(project)
        db.flush()
        projects[name] = project
        used: set[tuple[str, str, str]] = set()
        for _, target, filename, catalog, share in manifests:
            inventory = Inventory(
                project_id=project.id,
                filename=filename,
                target_path=target,
                revision=f"main@{secrets.token_hex(6)}",
                sha256=secrets.token_hex(32),
                size_bytes=random.randint(18_000, 640_000),
                created_at=days_ago(random.uniform(0.3, 6)),
                kind="monitor",
            )
            db.add(inventory)
            db.flush()
            for scan_index in range(7):
                age = 0.04 + scan_index * 3.4 + random.uniform(0, 0.8)
                status, complete, error, notes = "succeeded", True, None, []
                if scan_index == 0 and name == "northwind/portal":
                    status, complete, notes = (
                        "partial",
                        False,
                        ["Packages without pinned versions have partial coverage"],
                    )
                if scan_index == 0 and name == "orbit/mobile":
                    status, complete, error = "failed", False, "Scanner service returned HTTP 502"
                db.add(
                    Scan(
                        inventory_id=inventory.id,
                        project_id=project.id,
                        status=status,
                        complete=complete,
                        engine_version="osv-scanner 2.7.0",
                        error=error,
                        package_count=random.randint(140, 920),
                        coverage_notes=notes,
                        created_at=days_ago(age),
                        completed_at=days_ago(age - 0.0005),
                        mode="monitor",
                    )
                )
            # CI check runs against a separate, short-lived snapshot per pull request.
            for _ in range(random.randint(2, 5)):
                age = random.uniform(0.05, 6.5)
                snapshot = Inventory(
                    project_id=project.id,
                    filename=filename,
                    target_path=target,
                    revision=f"pr-{random.randint(100, 480)}@{secrets.token_hex(6)}",
                    sha256=secrets.token_hex(32),
                    size_bytes=random.randint(18_000, 640_000),
                    created_at=days_ago(age),
                    kind="check",
                )
                db.add(snapshot)
                db.flush()
                db.add(
                    Scan(
                        inventory_id=snapshot.id,
                        project_id=project.id,
                        status="succeeded",
                        complete=True,
                        engine_version="osv-scanner 2.7.0",
                        package_count=random.randint(140, 920),
                        created_at=days_ago(age),
                        completed_at=days_ago(age - 0.0005),
                        mode="check",
                        results=[],
                    )
                )
            available = [row for row in catalog if (row[0], row[1], row[2][0]) not in used]
            random.shuffle(available)
            take = (
                max(2, round(len(catalog) * share))
                if len(manifests) > 1 or share < 1
                else len(catalog)
            )
            for package, version, advisories, severity, fixed, summary, epss, kev in available[
                :take
            ]:
                used.add((package, version, advisories[0]))
                seen = first_seen_days()
                resolved = random.random() < (0.28 if severity in {"critical", "high"} else 0.45)
                resolved_at = None
                if resolved:
                    duration = (
                        random.uniform(0.5, 38)
                        if severity in {"critical", "high"}
                        else random.uniform(2, 70)
                    )
                    if seen - duration < 0.05:
                        duration = max(seen - 0.05, 0.1)
                    resolved_at = days_ago(seen - duration)
                workflow, acknowledged_at, risk_until, note = "open", None, None, ""
                if not resolved:
                    roll = random.random()
                    if roll < 0.18:
                        workflow, acknowledged_at, note = (
                            "acknowledged",
                            days_ago(random.uniform(0.2, min(seen, 20))),
                            "Triaged; fix scheduled for the next release.",
                        )
                    elif roll < 0.26:
                        workflow, risk_until, note = (
                            "risk_accepted",
                            NOW + timedelta(days=random.randint(6, 70)),
                            "Not reachable from production traffic.",
                        )
                        acknowledged_at = days_ago(random.uniform(0.2, min(seen, 20)))
                finding = Finding(
                    project_id=project.id,
                    target_filename=filename,
                    target_path=target,
                    revision=inventory.revision,
                    ecosystem=_ecosystem(catalog),
                    package_name=package,
                    package_version=version,
                    purl=None,
                    advisory_ids=sorted(advisories),
                    summary=summary,
                    severity=severity,
                    cvss_vectors=_vector(severity),
                    epss_score=epss,
                    epss_percentile=min(0.999, epss * 3 + 0.2),
                    kev_known=kev,
                    intel_updated_at=days_ago(0.004),
                    fixed_versions=fixed,
                    status="resolved" if resolved else "open",
                    evidence=[{"id": advisories[0], "summary": summary}],
                    first_seen_at=days_ago(seen),
                    last_seen_at=resolved_at or days_ago(0.04),
                    resolved_at=resolved_at,
                    workflow_status=workflow,
                    decision_note=note,
                    risk_until=risk_until,
                    acknowledged_at=acknowledged_at,
                )
                db.add(finding)
                db.flush()
                if workflow != "open":
                    db.add(
                        FindingDecision(
                            finding_id=finding.id,
                            action="acknowledge" if workflow == "acknowledged" else "risk_accept",
                            note=note,
                            expires_at=risk_until,
                            created_at=acknowledged_at or NOW,
                        )
                    )

    db.add(
        Connector(
            id="email",
            enabled=True,
            generation=1,
            verified_at=days_ago(48),
            config={
                "host": "smtp.agency.example",
                "port": 587,
                "username": "depradar",
                "sender": "depradar@agency.example",
                "recipient": "security@agency.example",
                "security": "starttls",
            },
        )
    )
    db.add(
        Connector(
            id="telegram",
            enabled=True,
            generation=1,
            verified_at=days_ago(30),
            config={"chat": "private"},
        )
    )
    for index in range(18):
        age = index * 0.55 + random.uniform(0, 0.3)
        failed = index in {3, 9}
        db.add(
            Delivery(
                connector_id="telegram" if index % 3 == 0 else "email",
                generation=1,
                project_id=random.choice(list(projects.values())).id,
                kind=random.choice(["alert", "alert", "alert", "digest", "summary"])
                if index
                else "test",
                subject="DepRadar update",
                body="Demo delivery",
                status="failed" if failed else ("queued" if index == 0 else "accepted"),
                attempts=3 if failed else 1,
                available_at=days_ago(age),
                created_at=days_ago(age),
                accepted_at=None if failed or index == 0 else days_ago(age - 0.001),
                last_error="smtp_timeout" if failed else None,
                provider_id=None if failed else f"demo-{index}",
            )
        )
    for name, scopes, restrict, ttl, used_days, revoked in TOKENS:
        secret = secrets.token_hex(24)
        db.add(
            ApiToken(
                name=name,
                token_hash=hashlib.sha256(secret.encode()).hexdigest(),
                display_prefix=f"depradar_{secret[:6]}",
                scopes=scopes,
                project_id=projects[restrict].id if restrict else None,
                created_at=days_ago(random.uniform(20, 90)),
                expires_at=NOW + timedelta(days=ttl),
                last_used_at=None if revoked else days_ago(used_days),
                revoked_at=days_ago(used_days) if revoked else None,
            )
        )


def _ecosystem(catalog: Catalog) -> str:
    return {
        id(NPM): "npm",
        id(PYPI): "PyPI",
        id(RUBY): "RubyGems",
        id(CRATES): "crates.io",
        id(COMPOSER): "Packagist",
        id(PUB): "Pub",
        id(GO): "Go",
    }[id(catalog)]


def _vector(severity: str) -> list[str]:
    return {
        "critical": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
        "high": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"],
        "medium": ["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"],
    }.get(severity, [])


def main() -> None:
    settings = get_settings()
    engine = get_engine()
    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(engine)
    factory = session_factory()
    with factory.begin() as db:
        if db.get(AuthGuard, 1) is None:
            db.add(AuthGuard(id=1))
        if db.get(SystemState, 1) is None:
            db.add(SystemState(id=1))
        if db.get(NotificationPolicy, 1) is None:
            db.add(NotificationPolicy(id=1))
    with factory() as db:
        if db.get(Owner, 1) is not None:
            refuse("an owner already exists")
        if db.scalar(select(Project.id).limit(1)) is not None:
            refuse("projects already exist")
    password = os.environ.get("DEMO_OWNER_PASSWORD", "demo-owner-password")
    set_owner_password(factory, password, initialize=True)
    with factory.begin() as db:
        seed(db)
    with factory() as db:
        total = len(list(db.scalars(select(Finding.id))))
        opened = len(list(db.scalars(select(Finding.id).where(Finding.status == "open"))))
    print(
        f"Seeded {len(PROJECTS)} projects, {total} findings ({opened} open) into {settings.database_url.split('@')[-1]}"
    )
    print(f"Sign in with the owner password: {password}")


if __name__ == "__main__":
    main()
