import json
import re
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

# OSV-Scanner selects its parser from these exact names (verified with the pinned release).
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
SUPPORTED = ", ".join(LOCKFILES) + ", requirements*.txt, bom.json, *.cdx.json"
LOCAL_NOTE = "Local, workspace, or Git package sources require manual coverage review"


class InventoryError(ValueError):
    pass


def canonical_filename(filename: str) -> str:
    if filename != Path(filename).name or "/" in filename or "\\" in filename:
        raise InventoryError("Filename must not contain a path")
    if filename in LOCKFILES:
        return filename
    # Variants such as requirements-dev.txt keep their path but use the standard parser name.
    if REQUIREMENTS.fullmatch(filename):
        return "requirements.txt"
    if filename == "bom.json" or (filename.endswith(".cdx.json") and len(filename) <= 120):
        return "bom.json"
    raise InventoryError("Supported files: " + SUPPORTED)


def default_target(uploaded: str, canonical: str) -> str:
    """Requirement variants keep their own name; SBOMs keep the historical bom.json target."""
    return uploaded if canonical == "requirements.txt" else canonical


def canonical_target_path(target_path: str | None, filename: str) -> str:
    """Normalize a display-only repository path without ever using it as a filesystem path."""
    value = (target_path or filename).strip().replace("\\", "/")
    path = PurePosixPath(value)
    if (
        not value
        or len(value) > 512
        or path.is_absolute()
        or any(part in {"..", "."} for part in path.parts)
        or any(ord(character) < 32 for character in value)
    ):
        raise InventoryError(
            "Target path must be a safe project-relative path under 512 characters"
        )
    normalized = str(path)
    if normalized in {"", "."}:
        raise InventoryError("Target path is required")
    return normalized


def canonical_revision(revision: str | None) -> str | None:
    if revision is None or not revision.strip():
        return None
    value = revision.strip()
    if len(value) > 200 or any(ord(character) < 32 for character in value):
        raise InventoryError(
            "Revision must be under 200 characters and contain no control characters"
        )
    return value


JSON_FILES = {"package-lock.json", "composer.lock", "Pipfile.lock", "bom.json"}
TOML_FILES = {"poetry.lock", "uv.lock", "pylock.toml", "Cargo.lock"}


def validate_inventory(filename: str, content: bytes) -> list[str]:
    """Validate input shape; do not resolve dependencies or implement a package parser."""
    if not content:
        raise InventoryError("Inventory is empty")
    try:
        text = content.decode("utf-8")
    except UnicodeError as exc:
        raise InventoryError("Inventory must be valid UTF-8") from exc
    if filename not in JSON_FILES | TOML_FILES:
        return sorted(set(validate_text(filename, text)))
    try:
        data: Any = tomllib.loads(text) if filename in TOML_FILES else json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise InventoryError("Inventory must be valid UTF-8 JSON or TOML") from exc
    if not isinstance(data, dict):
        raise InventoryError("Inventory must contain an object")
    notes: list[str] = []
    if filename in {"composer.lock", "Pipfile.lock", "uv.lock", "pylock.toml", "Cargo.lock"}:
        return sorted(set(validate_structured(filename, data)))
    if filename == "package-lock.json":
        if data.get("lockfileVersion") not in (2, 3) or not isinstance(data.get("packages"), dict):
            raise InventoryError("Use an npm lockfileVersion 2 or 3 with a packages object")
        if len(data["packages"]) > 10000:
            raise InventoryError("Inventory exceeds 10,000 components")
        for location, package in data["packages"].items():
            if not isinstance(package, dict):
                raise InventoryError("Invalid npm package entry")
            if not location:
                continue
            if package.get("link") or not isinstance(package.get("version"), str):
                notes.append("Local links or unresolved packages require manual coverage review")
            resolved = package.get("resolved", "")
            if not isinstance(resolved, str):
                raise InventoryError("Invalid npm package origin")
            if resolved and not resolved.startswith("https://registry.npmjs.org/"):
                notes.append("Non-default npm package origins require manual coverage review")
    elif filename == "poetry.lock":
        packages = data.get("package")
        if not isinstance(packages, list) or not packages:
            raise InventoryError("Poetry lockfile must contain package entries")
        if len(packages) > 10000:
            raise InventoryError("Inventory exceeds 10,000 components")
        for package in packages:
            if not isinstance(package, dict) or not all(
                isinstance(package.get(k), str) and package[k] for k in ("name", "version")
            ):
                raise InventoryError("Poetry package requires name and version")
            if package.get("source"):
                notes.append("Custom Poetry sources require manual coverage review")
    else:
        if data.get("bomFormat") != "CycloneDX" or data.get("specVersion") not in (
            "1.4",
            "1.5",
            "1.6",
            "1.7",
        ):
            raise InventoryError("Use a CycloneDX 1.4–1.7 JSON SBOM")
        components = data.get("components")
        if not isinstance(components, list) or not components:
            raise InventoryError("SBOM must contain components")
        if len(components) > 10000:
            raise InventoryError("Inventory exceeds 10,000 components")
        for component in components:
            if not isinstance(component, dict):
                raise InventoryError("Invalid SBOM component")
            if not component.get("purl") or not component.get("version"):
                notes.append(
                    "SBOM components without package URLs or versions have partial coverage"
                )
            if component.get("components"):
                notes.append("Nested SBOM components require manual coverage review")
    return sorted(set(notes))


def _entries(data: dict[str, Any], key: str, label: str) -> list[dict[str, Any]]:
    entries = data.get(key, [])
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        raise InventoryError(f"{label} must contain {key} entries")
    if len(entries) > 10000:
        raise InventoryError("Inventory exceeds 10,000 components")
    return entries


def validate_structured(filename: str, data: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    if filename == "composer.lock":
        packages = _entries(data, "packages", "Composer lockfile") + _entries(
            data, "packages-dev", "Composer lockfile"
        )
        for package in packages:
            if not isinstance(package.get("name"), str) or not isinstance(
                package.get("version"), str
            ):
                raise InventoryError("Composer package requires name and version")
            if package["version"].startswith("dev-"):
                notes.append("Composer branch versions (dev-*) have partial coverage")
            if "path" in {
                str((package.get("dist") or {}).get("type")),
                str((package.get("source") or {}).get("type")),
            }:
                notes.append(LOCAL_NOTE)
    elif filename == "Pipfile.lock":
        groups = [data.get("default", {}), data.get("develop", {})]
        if not all(isinstance(group, dict) for group in groups):
            raise InventoryError("Pipfile.lock must contain default/develop package objects")
        packages = [entry for group in groups for entry in group.values()]
        if len(packages) > 10000:
            raise InventoryError("Inventory exceeds 10,000 components")
        for package in packages:
            if not isinstance(package, dict):
                raise InventoryError("Invalid Pipfile.lock package entry")
            if not str(package.get("version", "")).startswith("=="):
                notes.append(LOCAL_NOTE)
    else:
        key = "packages" if filename == "pylock.toml" else "package"
        packages = _entries(data, key, filename)
        for package in packages:
            if not isinstance(package.get("name"), str) or not package["name"]:
                raise InventoryError(f"{filename} package requires a name")
            source = package.get("source")
            if filename == "uv.lock" and isinstance(source, dict):
                # The project itself is a virtual or editable "." entry in every uv lockfile.
                local = {"editable", "path", "directory", "git", "virtual"} & set(source)
                if local and source.get("virtual") != "." and source.get("editable") != ".":
                    notes.append(LOCAL_NOTE)
            elif filename == "pylock.toml" and {"vcs", "directory", "archive"} & set(package):
                notes.append(LOCAL_NOTE)
            elif filename == "Cargo.lock" and str(source or "").startswith("git+"):
                notes.append(LOCAL_NOTE)
            if filename != "uv.lock" and not isinstance(package.get("version"), str):
                notes.append("Packages without pinned versions have partial coverage")
    if not packages:
        raise InventoryError("Lockfile contains no packages")
    return notes


def validate_text(filename: str, text: str) -> list[str]:
    """Line-based shape checks for YAML and text manifests; OSV-Scanner does the parsing."""
    lines = text.splitlines()
    if len(lines) > 500000:
        raise InventoryError("Inventory has too many lines")
    notes: list[str] = []
    marker = {
        "pnpm-lock.yaml": r"lockfileVersion:",
        "yarn.lock": r"(# yarn lockfile v1|__metadata:)",
        "bun.lock": r'\s*"lockfileVersion"\s*:',
        "Gemfile.lock": r"GEM",
        "go.mod": r"module\s+\S+",
        "pubspec.lock": r"packages:",
    }.get(filename)
    if marker and not any(re.match(marker, line) for line in lines):
        raise InventoryError(f"File does not look like a {filename}")
    if filename == "requirements.txt":
        return validate_requirements(lines)
    # Anchored patterns: settings such as pnpm's excludeLinksFromLockfile are not local sources.
    local_source = {
        "pnpm-lock.yaml": r"(:\s*'?|@)(link|file):",
        "yarn.lock": r"@(workspace|link|file|portal):",
        "bun.lock": r'"(workspace|link|file):',
        "Gemfile.lock": r"^(PATH|GIT)\s*$",
        "go.mod": r"=>\s*(\.{1,2}/|/)",
        "pubspec.lock": r"^\s*source:\s*(path|git)\s*$",
    }[filename]
    if re.search(local_source, text, re.MULTILINE):
        notes.append(LOCAL_NOTE)
    return notes


def validate_requirements(lines: list[str]) -> list[str]:
    notes: list[str] = []
    logical: list[str] = []
    for line in lines:
        # pip-compile output continues hash lists with trailing backslashes.
        if logical and logical[-1].endswith("\\"):
            logical[-1] = logical[-1][:-1] + " " + line.strip()
        else:
            logical.append(line.strip())
    requirements = 0
    for line in logical:
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "-c", "--requirement", "--constraint")):
            notes.append("Included requirement files are not scanned; upload each one separately")
        elif line.startswith(("-e", "--editable")):
            notes.append(LOCAL_NOTE)
        elif line.startswith("-"):
            continue  # Index URLs, hashes, and other pip options.
        elif "://" in line or line.startswith((".", "/")):
            notes.append(LOCAL_NOTE)
        else:
            requirements += 1
            # Exact pins only: wildcards such as ==4.* cannot be matched to one version.
            if not re.search(r"===?\s*[\w.!+-]+(?![\w.!+*-])", line.split(";", 1)[0]):
                notes.append("Unpinned requirements have partial coverage")
    if not requirements:
        raise InventoryError("requirements file contains no requirements")
    if requirements > 10000:
        raise InventoryError("Inventory exceeds 10,000 components")
    return notes
