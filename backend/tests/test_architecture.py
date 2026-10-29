"""The dependency rule: interfaces → application → domain, and infrastructure implements ports.

SQLAlchemy is the one framework allowed in the core: entities are mapped with it and use cases
query through it. Everything else that talks to the outside world stays in infrastructure.
"""

import ast
import sys
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "depradar"
# Standard-library modules that reach networks, processes, or the filesystem in bulk.
IO_MODULES = {
    "http.client",
    "shutil",
    "smtplib",
    "socket",
    "ssl",
    "subprocess",
    "tarfile",
    "tempfile",
    "urllib.request",
}
# layer: (first-party packages it may import, third-party distributions, may perform I/O)
RULES = {
    "domain": ({"domain"}, {"pydantic", "sqlalchemy"}, False),
    "application": ({"domain", "application", "config"}, {"pydantic", "sqlalchemy"}, False),
    "infrastructure": (
        {"domain", "application", "infrastructure", "config"},
        {"alembic", "httpx", "pydantic", "pydantic_settings", "sqlalchemy"},
        True,
    ),
}


def imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(), str(path))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module)
    return found


def violations(path: Path, packages: set[str], distributions: set[str], io: bool) -> list[str]:
    problems = []
    for name in sorted(imports(path)):
        top, _, rest = name.partition(".")
        if top == "depradar":
            if rest.split(".")[0] not in packages:
                problems.append(f"{name} (first-party layer not allowed)")
        elif top in sys.stdlib_module_names:
            if not io and any(name == m or name.startswith(m + ".") for m in IO_MODULES):
                problems.append(f"{name} (I/O belongs in infrastructure)")
        elif top not in distributions:
            problems.append(f"{name} (third-party dependency not allowed)")
    return problems


@pytest.mark.parametrize("layer", sorted(RULES))
def test_layer_depends_only_inward(layer: str) -> None:
    packages, distributions, io = RULES[layer]
    modules = sorted((PACKAGE / layer).rglob("*.py"))
    assert modules
    found = {
        str(path.relative_to(PACKAGE)): problems
        for path in modules
        if (problems := violations(path, packages, distributions, io))
    }
    assert not found


def test_ci_client_stays_standard_library_only() -> None:
    # Pipelines download and run this file on its own with any Python 3.9+.
    assert not violations(PACKAGE / "ci_client.py", set(), set(), io=True)


def test_no_modules_outside_the_layers() -> None:
    loose = {path.name for path in PACKAGE.glob("*.py")}
    assert loose == {"__init__.py", "ci_client.py", "config.py"}


def test_rules_flag_outward_dependencies(tmp_path: Path) -> None:
    module = tmp_path / "use_case.py"
    module.write_text(
        "import httpx\nimport subprocess\nfrom depradar.infrastructure import storage\n"
    )
    packages, distributions, io = RULES["application"]
    assert violations(module, packages, distributions, io) == [
        "depradar.infrastructure (first-party layer not allowed)",
        "httpx (third-party dependency not allowed)",
        "subprocess (I/O belongs in infrastructure)",
    ]
