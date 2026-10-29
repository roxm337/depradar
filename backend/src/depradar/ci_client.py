#!/usr/bin/env python3
"""DepRadar CI/CD client: upload manifests, wait for scans, and enforce the dependency gate.

Standard library only (Python 3.9+), so it runs on any CI image that has Python. Download the
copy that matches your server from GET /api/ci/client.py, or use the bundled GitHub Action.

    export DEPRADAR_URL=https://depradar.example.com    # API, or the web UI's /api/backend
    export DEPRADAR_TOKEN=...                            # store as a masked CI secret
    python3 depradar_ci.py scan --fail-on high --sarif depradar.sarif

Pull/merge request pipelines run in check mode: results gate the change without touching the
monitored project. Default-branch pipelines run in monitor mode and keep inventories current.
Exit codes: 0 gate passed, 1 policy violation, 2 error (scan failure, timeout, auth, config).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import IO, Any

VERSION = "0.2.0"
DESCRIPTION = "Upload manifests to DepRadar, wait for scans, and enforce the gate."
# Keep in step with depradar.inventory.canonical_filename on the server.
LOCKFILES = (
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "composer.lock",
    "poetry.lock",
    "uv.lock",
    "pylock.toml",
    "Pipfile.lock",
    "requirements.txt",
    "Gemfile.lock",
    "Cargo.lock",
    "go.mod",
    "pubspec.lock",
)
REQUIREMENTS = re.compile(r"requirements[\w.-]{0,100}\.txt")
SBOM_NAMES = ("bom.json",)
SBOM_SUFFIX = ".cdx.json"
SKIP_DIRS = {
    ".git",
    ".hg",
    ".next",
    ".nuxt",
    ".tox",
    ".venv",
    ".yarn",
    "__pycache__",
    "bower_components",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
}
FINISHED = {"succeeded", "partial", "failed", "superseded"}
MAX_UPLOAD = 10 * 1024 * 1024
MAX_MANIFESTS = 50
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
PASS, FAIL, ERROR = 0, 1, 2


class ClientError(Exception):
    """Configuration, transport, or API failure; always exits with code 2."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    # urllib would forward the Authorization header to any redirect target.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class Api:
    def __init__(
        self, base: str, token: str, *, cafile: str | None = None, timeout: float = 60
    ) -> None:
        self.base = base
        self.token = token
        self.timeout = timeout
        context = ssl.create_default_context(cafile=cafile)
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=context)
        )

    def send(
        self,
        method: str,
        path: str,
        query: list[tuple[str, str]] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, bytes]:
        url = self.base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        headers = {
            "Authorization": "Bearer " + self.token,
            "Accept": "*/*",
            "User-Agent": f"depradar-ci/{VERSION}",
        }
        if body is not None:
            headers["Content-Type"] = "application/octet-stream"
        request = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return int(response.status), response.read(64 * 1024 * 1024)
        except urllib.error.HTTPError as error:
            return int(error.code), error.read(64 * 1024)
        except (urllib.error.URLError, OSError) as error:
            raise ClientError(f"Cannot reach DepRadar at {self.base}: {error}") from error

    def call(
        self,
        method: str,
        path: str,
        query: list[tuple[str, str]] | None = None,
        body: bytes | None = None,
    ) -> bytes:
        status, payload = self.send(method, path, query, body)
        if status >= 400:
            try:
                detail = json.loads(payload).get("detail", "")
            except (ValueError, AttributeError):
                detail = ""
            if not isinstance(detail, str):
                detail = json.dumps(detail)[:500]
            hint = {
                401: " (check the token secret and its expiry)",
                403: " (the token lacks a scope or project access)",
            }.get(status, "")
            raise ClientError(f"DepRadar returned HTTP {status}: {detail or 'error'}{hint}")
        return payload

    def json(
        self,
        method: str,
        path: str,
        query: list[tuple[str, str]] | None = None,
        body: bytes | None = None,
    ) -> dict[str, Any]:
        value = json.loads(self.call(method, path, query, body))
        if not isinstance(value, dict):
            raise ClientError("DepRadar returned an unexpected response")
        return value


def api_base(url: str, allow_http: bool) -> str:
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ClientError("Set --url or DEPRADAR_URL to http(s)://host[:port][/path]")
    if parsed.scheme == "http" and parsed.hostname not in LOCAL_HOSTS and not allow_http:
        raise ClientError(
            "Refusing to send the token over plain HTTP; use HTTPS, or pass "
            "--allow-insecure-http on a trusted private network"
        )
    path = parsed.path.rstrip("/")
    if not (path.endswith("/api") or path.endswith("/api/backend")):
        path += "/api"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def ci_context(env: Mapping[str, str]) -> dict[str, Any]:
    """Repository, revision, and whether this pipeline gates an unmerged change."""

    def pick(*names: str) -> str:
        return next((env[name] for name in names if env.get(name)), "")

    if env.get("GITHUB_ACTIONS") == "true":
        provider = "github"
        repository = pick("GITHUB_REPOSITORY")
        sha, ref = pick("GITHUB_SHA"), pick("GITHUB_HEAD_REF", "GITHUB_REF_NAME")
        change = env.get("GITHUB_EVENT_NAME") in {
            "pull_request",
            "pull_request_target",
            "merge_group",
        }
    elif env.get("GITLAB_CI") == "true":
        provider = "gitlab"
        repository, sha = pick("CI_PROJECT_PATH"), pick("CI_COMMIT_SHA")
        ref = pick("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "CI_COMMIT_REF_NAME")
        change = bool(env.get("CI_MERGE_REQUEST_IID"))
    elif env.get("BITBUCKET_BUILD_NUMBER"):
        provider = "bitbucket"
        repository, sha = pick("BITBUCKET_REPO_FULL_NAME"), pick("BITBUCKET_COMMIT")
        ref, change = pick("BITBUCKET_BRANCH"), bool(env.get("BITBUCKET_PR_ID"))
    elif env.get("TF_BUILD", "").lower() == "true":
        provider = "azure"
        repository, sha = pick("BUILD_REPOSITORY_NAME"), pick("BUILD_SOURCEVERSION")
        ref = pick("SYSTEM_PULLREQUEST_SOURCEBRANCH", "BUILD_SOURCEBRANCHNAME")
        change = env.get("BUILD_REASON") == "PullRequest"
    elif env.get("JENKINS_URL"):
        provider = "jenkins"
        repository, sha = pick("JOB_NAME"), pick("GIT_COMMIT")
        ref, change = pick("CHANGE_BRANCH", "BRANCH_NAME", "GIT_BRANCH"), bool(env.get("CHANGE_ID"))
    elif env.get("CIRCLECI") == "true":
        provider = "circleci"
        owner, name = pick("CIRCLE_PROJECT_USERNAME"), pick("CIRCLE_PROJECT_REPONAME")
        repository = f"{owner}/{name}" if owner and name else name
        sha, ref = pick("CIRCLE_SHA1"), pick("CIRCLE_BRANCH")
        change = bool(env.get("CIRCLE_PULL_REQUEST"))
    else:
        provider, repository, sha, ref, change = "local", "", pick("GIT_COMMIT"), "", False
    revision = "@".join(part for part in (ref, sha[:12]) if part)
    return {
        "provider": provider,
        "repository": repository,
        "revision": revision[:200],
        "change_request": change,
    }


def lockfile(name: str) -> bool:
    return name in LOCKFILES or bool(REQUIREMENTS.fullmatch(name))


def supported(name: str) -> bool:
    return lockfile(name) or name in SBOM_NAMES or name.endswith(SBOM_SUFFIX)


def discover(root: Path, paths: list[str], excludes: list[str]) -> list[Path]:
    """Explicit files are used as given; directories are searched for lockfiles only."""
    found: list[Path] = []
    for value in paths or ["."]:
        path = (root / value).resolve()
        if path.is_file():
            if not supported(path.name):
                raise ClientError(f"Unsupported manifest: {value}")
            found.append(path)
        elif path.is_dir():
            found.extend(_walk(path))
        else:
            raise ClientError(f"Path not found: {value}")
    unique = sorted(set(found))
    kept = [
        path
        for path in unique
        if not any(fnmatch.fnmatch(relative(root, path), pattern) for pattern in excludes)
    ]
    if not kept:
        raise ClientError(
            "No supported lockfiles found (" + ", ".join(LOCKFILES) + "; pass SBOM files "
            "such as bom.json or *.cdx.json explicitly)"
        )
    if len(kept) > MAX_MANIFESTS:
        raise ClientError(f"Found {len(kept)} manifests; narrow paths or use --exclude")
    return kept


def _walk(directory: Path) -> Iterator[Path]:
    for current, directories, files in os.walk(directory):
        directories[:] = sorted(d for d in directories if d not in SKIP_DIRS)
        for name in sorted(files):
            if lockfile(name):
                yield Path(current) / name


def relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def escape_command(value: str, property_value: bool = False) -> str:
    """Escape GitHub workflow-command data so untrusted text cannot inject commands."""
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


def policy_query(args: argparse.Namespace) -> list[tuple[str, str]]:
    query = [
        ("fail_on", args.fail_on),
        ("fail_on_unknown", str(args.fail_on_unknown).lower()),
        ("fail_on_kev", str(not args.no_fail_on_kev).lower()),
        ("new_only", str(args.new_only).lower()),
        ("ignore_acknowledged", str(args.ignore_acknowledged).lower()),
        ("fail_on_incomplete", str(args.fail_on_incomplete).lower()),
    ]
    if args.epss_threshold is not None:
        query.append(("epss_threshold", str(args.epss_threshold)))
    return query


def wait_for(
    api: Api, scan_ids: list[str], timeout: float, sleep: Callable[[float], None], out: IO[str]
) -> None:
    deadline = time.monotonic() + timeout
    pending = list(scan_ids)
    delay = 2.0
    while True:
        for scan_id in list(pending):
            status = api.json("GET", f"/scans/{scan_id}").get("status")
            if status in FINISHED:
                pending.remove(scan_id)
        if not pending:
            return
        if time.monotonic() >= deadline:
            raise ClientError(
                f"Timed out after {timeout:g}s waiting for {len(pending)} scan(s); check the "
                "DepRadar worker and scanner health"
            )
        print(f"Waiting for {len(pending)} scan(s)...", file=out)
        sleep(delay)
        delay = min(delay * 1.5, 15.0)


def write_reports(
    api: Api, args: argparse.Namespace, scan_ids: list[str], env: Mapping[str, str]
) -> None:
    targets = [("sarif", args.sarif), ("junit", args.junit), ("markdown", args.markdown)]
    summary = env.get("GITHUB_STEP_SUMMARY") if args.summary else None
    query = [("scan_id", scan_id) for scan_id in scan_ids] + policy_query(args)
    for fmt, destination in targets:
        if not destination and not (fmt == "markdown" and summary):
            continue
        content = api.call("GET", "/ci/evaluation", query + [("format", fmt)])
        if destination:
            Path(destination).write_bytes(content)
        if fmt == "markdown" and summary:
            with open(summary, "ab") as stream:
                stream.write(content)


def report(result: dict[str, Any], env: Mapping[str, str], out: IO[str]) -> None:
    status = str(result["status"]).upper()
    print(
        f"DepRadar gate {status}: {result['violations']} violation(s), {result['ignored']} "
        f"ignored, {result['below_threshold']} below threshold",
        file=out,
    )
    github = env.get("GITHUB_ACTIONS") == "true"
    for gate in result["scans"]:
        line = f"  {gate['mode']} scan of {gate['target_path']}: {gate['status']}"
        if gate.get("error"):
            line += f" ({gate['error']})"
        elif not gate["complete"]:
            line += " (incomplete coverage: " + "; ".join(gate["coverage_notes"]) + ")"
        print(line, file=out)
        for item in gate["items"]:
            if item["outcome"] != "violation":
                continue
            fixed = ", ".join(item["fixed_versions"]) or "no fix published"
            advisory = ", ".join(item["advisory_ids"])
            message = (
                f"{item['package_name']}@{item['package_version']} {advisory}: "
                f"{'; '.join(item['reasons'])}. Fixed in: {fixed}"
            )
            print(f"    x {item['severity']:<8} {message}", file=out)
            if github:
                title = escape_command(f"DepRadar {item['severity']} vulnerability", True)
                file = escape_command(gate["target_path"], True)
                print(f"::error file={file},title={title}::{escape_command(message)}", file=out)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="depradar-ci", description=DESCRIPTION)
    parser.add_argument("--version", action="version", version=f"depradar-ci {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Upload manifests, wait for scans, and gate.")
    scan.add_argument("paths", nargs="*", help="Manifests or directories (default: --root).")
    scan.add_argument("--project", help="Project name or ID (default: the CI repository).")
    scan.add_argument(
        "--create-project",
        action="store_true",
        help="Create a missing project (token needs projects:write).",
    )
    scan.add_argument("--mode", choices=["auto", "monitor", "check"], default="auto")
    scan.add_argument("--revision", help="Revision label (default: CI branch@commit).")
    scan.add_argument("--root", default=".", help="Repository root for manifest paths.")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    scan.add_argument("--timeout", type=float, default=900)
    evaluate = commands.add_parser("evaluate", help="Gate already uploaded scans.")
    evaluate.add_argument("scan_ids", nargs="+", metavar="SCAN_ID")
    for command in (scan, evaluate):
        command.add_argument("--url", default=None, help="DepRadar URL (env DEPRADAR_URL).")
        command.add_argument("--token-env", default="DEPRADAR_TOKEN", metavar="NAME")
        command.add_argument("--ca-file", help="PEM bundle for a private certificate authority.")
        command.add_argument("--allow-insecure-http", action="store_true")
        command.add_argument(
            "--fail-on",
            choices=["none", "low", "medium", "high", "critical"],
            default="high",
        )
        command.add_argument("--fail-on-unknown", action="store_true")
        command.add_argument("--no-fail-on-kev", action="store_true")
        command.add_argument("--epss-threshold", type=float, default=None, metavar="0-1")
        command.add_argument(
            "--new-only", action="store_true", help="Ignore findings already open in DepRadar."
        )
        command.add_argument("--ignore-acknowledged", action="store_true")
        command.add_argument("--fail-on-incomplete", action="store_true")
        command.add_argument("--sarif", metavar="FILE")
        command.add_argument("--junit", metavar="FILE")
        command.add_argument("--markdown", metavar="FILE")
        command.add_argument("--json", metavar="FILE")
        command.add_argument(
            "--no-summary",
            dest="summary",
            action="store_false",
            help="Do not append Markdown to $GITHUB_STEP_SUMMARY.",
        )
    return parser


def run(
    argv: list[str] | None = None,
    env: Mapping[str, str] | None = None,
    api_factory: Callable[[str, str, argparse.Namespace], Api] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    out: IO[str] = sys.stdout,
) -> int:
    env = os.environ if env is None else env
    args = build_parser().parse_args(argv)
    try:
        token = env.get(args.token_env, "")
        if not token:
            raise ClientError(f"Set the {args.token_env} environment variable to a DepRadar token")
        base = api_base(args.url or env.get("DEPRADAR_URL", ""), args.allow_insecure_http)
        if api_factory is not None:
            api = api_factory(base, token, args)
        else:
            api = Api(base, token, cafile=args.ca_file)
        if args.command == "scan":
            scan_ids = upload_all(api, args, env, out)
            wait_for(api, scan_ids, args.timeout, sleep, out)
        else:
            scan_ids = list(dict.fromkeys(args.scan_ids))
        query = [("scan_id", scan_id) for scan_id in scan_ids] + policy_query(args)
        result = api.json("GET", "/ci/evaluation", query + [("format", "json")])
        if args.json:
            Path(args.json).write_text(json.dumps(result, indent=2) + "\n")
        write_reports(api, args, scan_ids, env)
        report(result, env, out)
        return {"pass": PASS, "fail": FAIL}.get(str(result["status"]), ERROR)
    except ClientError as error:
        print(f"depradar-ci: error: {error}", file=out)
        return ERROR


def upload_all(
    api: Api, args: argparse.Namespace, env: Mapping[str, str], out: IO[str]
) -> list[str]:
    context = ci_context(env)
    project = args.project or env.get("DEPRADAR_PROJECT") or context["repository"]
    if not project:
        raise ClientError("Pass --project or set DEPRADAR_PROJECT")
    mode = args.mode
    if mode == "auto":
        mode = "check" if context["change_request"] else "monitor"
    root = Path(args.root)
    revision = args.revision or context["revision"]
    scan_ids = []
    for path in discover(root, args.paths, args.exclude):
        content = path.read_bytes()
        if len(content) > MAX_UPLOAD:
            raise ClientError(f"{relative(root, path)} exceeds the 10 MiB upload limit")
        query = [
            ("project", project),
            ("filename", path.name),
            ("target_path", relative(root, path)),
            ("mode", mode),
            ("create_project", str(args.create_project).lower()),
        ]
        if revision:
            query.append(("revision", revision))
        upload = api.json("POST", "/ci/uploads", query, content)
        scan_ids.append(str(upload["scan"]["id"]))
        state = "unchanged, rechecking" if upload["reused_inventory"] else "uploaded"
        print(f"{relative(root, path)}: {state} ({mode} scan {upload['scan']['id']})", file=out)
    return scan_ids


def main() -> int:
    return run()


if __name__ == "__main__":
    sys.exit(main())
