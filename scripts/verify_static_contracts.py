from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations"
CHECKSUMS = ROOT / "tests" / "contracts" / "migrations.sha256"
ROUTES = ROOT / "tests" / "contracts" / "routes.json"
WORKSTATION_PATH = re.compile(r"(?i)\b[A-Z]:[\\/](?:self|projects)[\\/]")
REMOVED_ADAPTER_CLAIMS = (
    "Actix Web, Axum/Tower, and tonic adapters",
    "Actix Web、Axum/Tower、tonic adapter",
    "TowerResourceServerLayer",
    "authorize_tonic_request",
)
GLOB_REEXPORT = re.compile(r"(?m)^\s*pub(?:\([^)]*\))?\s+use\s+[^;]*::\*\s*;")
PRELUDE_MODULE = re.compile(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+prelude\s*;")


def migration_line(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"{digest}  {path.relative_to(ROOT).as_posix()}"


def migration_lines() -> list[str]:
    return [migration_line(path) for path in sorted(MIGRATIONS.glob("*/*.sql"))]


def write_migration_checksums() -> None:
    if CHECKSUMS.exists():
        raise SystemExit("checksum manifest already exists; use --append-migration")
    CHECKSUMS.write_text("\n".join(migration_lines()) + "\n", encoding="utf-8")


def check_migration_checksums() -> None:
    expected = [line for line in CHECKSUMS.read_text(encoding="utf-8").splitlines() if line]
    actual = migration_lines()
    if actual != expected:
        raise SystemExit("migration history or manifest changed unexpectedly")


def append_migration(directory_name: str) -> None:
    directory = MIGRATIONS / directory_name
    paths = sorted(directory.glob("*.sql"))
    if [path.name for path in paths] != ["down.sql", "up.sql"]:
        raise SystemExit("new migration must contain exactly down.sql and up.sql")
    expected = [line for line in CHECKSUMS.read_text(encoding="utf-8").splitlines() if line]
    recorded_paths = [line.split("  ", 1)[1] for line in expected]
    recorded_directories = [Path(path).parent.name for path in recorded_paths]
    if directory_name in recorded_directories or directory_name <= max(recorded_directories):
        raise SystemExit("migration append must use a new monotonically later directory")
    CHECKSUMS.write_text(
        "\n".join([*expected, *(migration_line(path) for path in paths)]) + "\n",
        encoding="utf-8",
    )


def check_route_fixture() -> None:
    payload = json.loads(ROUTES.read_text(encoding="utf-8"))
    if payload.get("schema") != 1 or not payload.get("routes"):
        raise SystemExit("route contract fixture is missing or invalid")
    paths = [item["path"] for item in payload["routes"]]
    if len(paths) != len(set(paths)):
        raise SystemExit("route contract contains duplicate paths")
    for item in payload["routes"]:
        methods = item.get("methods")
        if not methods or methods != sorted(set(methods)):
            raise SystemExit("route methods must be non-empty, unique, and sorted")
        if item.get("condition") not in {"always", "dynamic_client_registration", "perf_metrics"}:
            raise SystemExit("route condition is invalid")


def public_document_paths() -> list[Path]:
    paths = [ROOT / "README.md", ROOT / "README.zh-CN.md"]
    paths.extend(
        path
        for path in (ROOT / "docs").rglob("*.md")
        if "superpowers" not in path.relative_to(ROOT / "docs").parts
    )
    return paths


def check_documentation_boundaries() -> None:
    for path in public_document_paths():
        text = path.read_text(encoding="utf-8")
        if WORKSTATION_PATH.search(text):
            raise SystemExit(
                f"public documentation contains a workstation-specific path: "
                f"{path.relative_to(ROOT)}"
            )
        for obsolete in REMOVED_ADAPTER_CLAIMS:
            if obsolete in text:
                raise SystemExit(
                    f"public documentation advertises a removed adapter in "
                    f"{path.relative_to(ROOT)}: {obsolete}"
                )


def check_server_import_boundaries() -> None:
    for path in sorted((ROOT / "crates" / "server" / "src").rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        if GLOB_REEXPORT.search(text):
            raise SystemExit(f"server source contains a glob re-export: {relative}")
        if PRELUDE_MODULE.search(text):
            raise SystemExit(f"server source declares a prelude module: {relative}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-migrations", action="store_true")
    parser.add_argument("--append-migration")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write_migrations:
        write_migration_checksums()
    if args.append_migration:
        append_migration(args.append_migration)
    if args.check:
        check_migration_checksums()
        check_route_fixture()
        check_documentation_boundaries()
        check_server_import_boundaries()


if __name__ == "__main__":
    main()
