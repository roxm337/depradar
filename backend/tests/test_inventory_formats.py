import json
from pathlib import Path

import pytest

from depradar.domain.inventory import (
    LOCAL_NOTE,
    InventoryError,
    canonical_filename,
    validate_inventory,
)

from .conftest import Harness

# Each fixture pins a version with a known advisory and was verified against the pinned scanner.
FIXTURES = Path(__file__).parent / "fixtures" / "manifests"


@pytest.mark.parametrize("path", sorted(FIXTURES.iterdir()), ids=lambda path: path.name)
def test_fixtures_validate_with_complete_coverage(path: Path) -> None:
    assert validate_inventory(canonical_filename(path.name), path.read_bytes()) == []


def test_requirement_files_report_coverage_gaps() -> None:
    assert canonical_filename("requirements-dev.txt") == "requirements.txt"
    assert canonical_filename("requirements_prod.txt") == "requirements.txt"
    content = b"""-r base.txt
--index-url https://pypi.org/simple
-e .
flask>=2  # unpinned
django==4.*
requests==2.31.0 ; python_version >= "3.9"
pkg @ https://example.com/pkg.whl
"""
    assert validate_inventory("requirements.txt", content) == [
        "Included requirement files are not scanned; upload each one separately",
        LOCAL_NOTE,
        "Unpinned requirements have partial coverage",
    ]
    with pytest.raises(InventoryError, match="no requirements"):
        validate_inventory("requirements.txt", b"# comment\n--index-url https://x.example\n")


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        (
            "pnpm-lock.yaml",
            b"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lib:\n"
            b"        specifier: link:../lib\n        version: link:../lib\n",
        ),
        ("yarn.lock", b'# yarn lockfile v1\n\n"lib@file:../lib":\n  version "1.0.0"\n'),
        (
            "bun.lock",
            b'{\n  "lockfileVersion": 1,\n  "workspaces": {"": {"dependencies": {"lib": '
            b'"workspace:*"}}}\n}\n',
        ),
        (
            "Gemfile.lock",
            b"PATH\r\n  remote: ../engine\r\n\r\nGEM\r\n  specs:\r\n    rack (2.2.3)\r\n",
        ),
        ("go.mod", b"module example.com/app\n\nreplace example.com/lib => ../lib\n"),
        ("pubspec.lock", b'packages:\n  lib:\n    source: path\n    version: "1.0.0"\n'),
        (
            "uv.lock",
            b'version = 1\n[[package]]\nname = "app"\nsource = { editable = "." }\n'
            b'[[package]]\nname = "lib"\nversion = "0.1.0"\n'
            b'source = { editable = "packages/lib" }\n',
        ),
        (
            "composer.lock",
            json.dumps(
                {"packages": [{"name": "acme/theme", "version": "1.0.0", "dist": {"type": "path"}}]}
            ).encode(),
        ),
        ("Cargo.lock", b'[[package]]\nname = "lib"\nversion = "0.1.0"\nsource = "git+https://x"\n'),
        ("pylock.toml", b'lock-version = "1.0"\n[[packages]]\nname = "lib"\nvcs = { url = "x" }\n'),
    ],
)
def test_local_sources_mark_partial_coverage(filename: str, content: bytes) -> None:
    assert LOCAL_NOTE in validate_inventory(filename, content)


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("pnpm-lock.yaml", b"name: not-a-lockfile\n"),
        ("yarn.lock", b"left-pad@1.0.0:\n"),
        ("bun.lock", b"{}"),
        ("go.mod", b"require golang.org/x/text v0.3.5\n"),
        ("Gemfile.lock", b"DEPENDENCIES\n  rack\n"),
        ("pubspec.lock", b"sdks:\n  dart: any\n"),
        ("composer.lock", b'{"packages": [{"name": "acme/x"}]}'),
        ("composer.lock", b'{"packages": []}'),
        ("composer.lock", b"\xff\xfe"),
        ("Pipfile.lock", b'{"default": []}'),
        ("uv.lock", b"version = 1\n"),
        ("Cargo.lock", b'[[package]]\nversion = "1.0.0"\n'),
        ("pylock.toml", b'lock-version = "1.0"\npackages = "x"\n'),
    ],
)
def test_malformed_manifests_are_rejected(filename: str, content: bytes) -> None:
    with pytest.raises(InventoryError):
        validate_inventory(filename, content)


def test_uploads_accept_new_formats_and_keep_requirement_variant_targets(
    harness: Harness, project_id: str
) -> None:
    for name, target in (("pnpm-lock.yaml", "pnpm-lock.yaml"), ("requirements-dev.txt", None)):
        source = FIXTURES / ("requirements.txt" if name.startswith("requirements") else name)
        response = harness.client.post(
            f"/api/projects/{project_id}/inventories",
            params={"filename": name},
            headers=harness.headers,
            content=source.read_bytes(),
        )
        assert response.status_code == 202, response.text
        inventory = response.json()["inventory"]
        assert inventory["filename"] == canonical_filename(name)
        assert inventory["target_path"] == (target or name)
