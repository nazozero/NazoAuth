from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations"
CHECKSUMS = ROOT / "tests" / "contracts" / "migrations.sha256"
ROUTES = ROOT / "tests" / "contracts" / "routes.json"
RFC9967_MATRIX = ROOT / "tests" / "contracts" / "rfc9967-scim-set-matrix.json"
RFC9967_RUNNER = ROOT / "scripts" / "rfc9967_scim_set_e2e.py"
SECURITY_NON_IMPLEMENTATION_POLICY = (
    ROOT / "docs" / "protocol" / "not-implemented-security-policy.md"
)
WORKSTATION_PATH = re.compile(r"(?i)\b[A-Z]:[\\/](?:self|projects)[\\/]")
REMOVED_ADAPTER_CLAIMS = (
    "Actix Web, Axum/Tower, and tonic adapters",
    "Actix Web、Axum/Tower、tonic adapter",
    "TowerResourceServerLayer",
    "authorize_tonic_request",
)
GLOB_REEXPORT = re.compile(r"(?m)^\s*pub(?:\([^)]*\))?\s+use\s+[^;]*::\*\s*;")
PRELUDE_MODULE = re.compile(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+prelude\s*;")
EXACT_RUST_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
FORBIDDEN_CRATE_DEPENDENCIES = {
    "authorization-server-core": {
        "actix-web",
        "diesel",
        "diesel-async",
        "fred",
        "nazo-http-actix",
        "nazo-postgres",
        "nazo-valkey",
    },
    "identity": {
        "actix-web",
        "diesel",
        "diesel-async",
        "fred",
        "nazo-auth",
        "nazo-http-actix",
        "nazo-postgres",
        "nazo-valkey",
    },
    "resource-server": {
        "actix-web",
        "nazo-auth",
        "nazo-http-actix",
        "nazo-identity",
    },
    "http-actix": {"diesel", "diesel-async", "fred", "nazo-postgres", "nazo-valkey"},
}

RFC9967_CASES = {
    "discovery_exact_event_uris",
    "poll_authorization_boundaries",
    "create_notice_set_claims",
    "receiver_audience_and_ack_isolation",
    "ack_is_terminal_for_receiver",
    "set_error_requires_content_language",
    "patch_notice_and_deactivate_events",
    "put_notice_and_activate_events",
    "poll_pagination_preserves_order",
    "long_poll_wakes_on_new_event",
    "invalid_poll_shapes_fail_closed",
}


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
        if item.get("condition") not in {"always", "perf_metrics"}:
            raise SystemExit("route condition is invalid")


def public_document_paths() -> list[Path]:
    paths = [ROOT / "README.md", ROOT / "README.zh-CN.md"]
    paths.extend((ROOT / "docs").rglob("*.md"))
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


def check_authorization_server_import_boundaries() -> None:
    for path in sorted((ROOT / "crates" / "authorization-server" / "src").rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        if GLOB_REEXPORT.search(text):
            raise SystemExit(
                f"authorization-server source contains a glob re-export: {relative}"
            )
        if PRELUDE_MODULE.search(text):
            raise SystemExit(
                f"authorization-server source declares a prelude module: {relative}"
            )


def check_toolchain_pins() -> None:
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    version = toolchain.get("toolchain", {}).get("channel")
    if not isinstance(version, str) or not EXACT_RUST_VERSION.fullmatch(version):
        raise SystemExit("rust-toolchain.toml must pin an exact stable Rust version")

    containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
    rust_builder = re.search(
        r"FROM docker\.io/library/rust:(\d+\.\d+\.\d+)-slim"
        r"@sha256:[0-9a-f]{64} AS builder",
        containerfile,
    )
    if rust_builder is None or rust_builder.group(1) != version:
        raise SystemExit("Containerfile Rust builder pin differs from rust-toolchain.toml")
    if not re.search(
        r"FROM docker\.io/library/debian:[^\s@]+@sha256:[0-9a-f]{64} AS runtime-base",
        containerfile,
    ):
        raise SystemExit("Containerfile runtime base image must be pinned by digest")
    if "RUN cargo build --release --locked" not in containerfile:
        raise SystemExit("Containerfile release build must use Cargo.lock")

    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    rust_actions = []
    for path in workflows:
        rust_actions.extend(
            (path, match.group(1))
            for match in re.finditer(r"dtolnay/rust-toolchain@(\d+\.\d+\.\d+)", path.read_text())
        )
    if not rust_actions:
        raise SystemExit("CI has no exact dtolnay/rust-toolchain pin")
    mismatches = [path.relative_to(ROOT) for path, pin in rust_actions if pin != version]
    if mismatches:
        raise SystemExit(f"CI Rust toolchain pins differ from {version}: {mismatches}")

    renovate_candidates = [
        ROOT / "renovate.json",
        ROOT / "renovate.jsonc",
        ROOT / "renovate.json5",
        ROOT / ".github" / "renovate.json",
        ROOT / ".github" / "renovate.jsonc",
        ROOT / ".github" / "renovate.json5",
    ]
    present_renovate_configs = [path for path in renovate_candidates if path.exists()]
    if present_renovate_configs != [ROOT / "renovate.json"]:
        relative = [path.relative_to(ROOT) for path in present_renovate_configs]
        raise SystemExit(
            "Renovate must have one authoritative root renovate.json; "
            f"found: {relative}"
        )

    renovate = json.loads((ROOT / "renovate.json").read_text(encoding="utf-8"))
    enabled_managers = renovate.get("enabledManagers")
    if enabled_managers is not None:
        required_managers = {
            "cargo",
            "custom.regex",
            "docker-compose",
            "dockerfile",
            "github-actions",
            "pip_requirements",
        }
        missing_managers = required_managers - set(enabled_managers)
        if missing_managers:
            raise SystemExit(
                "Renovate enabledManagers disables required update coverage: "
                f"{sorted(missing_managers)}"
            )
    managers = renovate.get("customManagers")
    if not isinstance(managers, list) or not any(
        manager.get("datasourceTemplate") == "rust-version" for manager in managers
    ):
        raise SystemExit("Renovate must update the coordinated Rust stable pins")


def check_crate_dependency_boundaries() -> None:
    for crate, forbidden in FORBIDDEN_CRATE_DEPENDENCIES.items():
        manifest_path = ROOT / "crates" / crate / "Cargo.toml"
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        declared = set()
        for section in ("dependencies", "build-dependencies"):
            declared.update(manifest.get(section, {}))
        violations = sorted(declared & forbidden)
        if violations:
            raise SystemExit(
                f"{manifest_path.relative_to(ROOT)} violates dependency boundaries: {violations}"
            )


def check_workspace_package_metadata() -> None:
    workspace_manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    for member in workspace_manifest["workspace"]["members"]:
        manifest_path = ROOT / member / "Cargo.toml"
        package = tomllib.loads(manifest_path.read_text(encoding="utf-8"))["package"]
        for field in ("edition", "license", "repository"):
            if package.get(field) != {"workspace": True}:
                raise SystemExit(
                    f"{manifest_path.relative_to(ROOT)} must inherit package.{field} "
                    "from [workspace.package]"
                )


def check_rfc9967_test_boundaries() -> None:
    production_sources = [
        *(ROOT / "crates" / "scim-events" / "src").rglob("*.rs"),
        ROOT / "crates" / "http-actix" / "src" / "scim.rs",
    ]
    forbidden_markers = ("#[cfg(test)]", "#[test]", "#[tokio::test]", "mod tests")
    for path in production_sources:
        source = path.read_text(encoding="utf-8")
        markers = [marker for marker in forbidden_markers if marker in source]
        if markers:
            raise SystemExit(
                f"{path.relative_to(ROOT)} embeds tests in production source: {markers}"
            )

    required_test_files = [
        ROOT / "crates" / "scim-events" / "tests" / "domain_contract.rs",
        ROOT / "crates" / "http-actix" / "tests" / "scim_transport.rs",
        ROOT / "scripts" / "test_rfc9967_scim_set_e2e_source_policy.py",
    ]
    missing = [path.relative_to(ROOT) for path in required_test_files if not path.is_file()]
    if missing:
        raise SystemExit(f"RFC 9967 separated test files are missing: {missing}")

    payload = json.loads(RFC9967_MATRIX.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    names = [case.get("name") for case in cases]
    if (
        payload.get("schema") != 1
        or payload.get("standard") != "RFC 9967"
        or set(names) != RFC9967_CASES
        or len(names) != len(RFC9967_CASES)
        or any(not case.get("handler") for case in cases)
    ):
        raise SystemExit("RFC 9967 black-box matrix must contain the exact required cases")

    runner = RFC9967_RUNNER.read_text(encoding="utf-8")
    forbidden_tables = ("scim_security_" + "events", "scim_security_event_" + "receipts")
    if any(table in runner for table in forbidden_tables):
        raise SystemExit("RFC 9967 black-box runner must not inspect event persistence tables")

    workflow = (ROOT / ".github" / "workflows" / "conformance-security.yml").read_text(
        encoding="utf-8"
    )
    required_workflow_fragments = (
        "ENABLE_SCIM_SECURITY_EVENTS: true",
        "python scripts/rfc9967_scim_set_e2e.py",
        "python scripts/test_rfc9967_scim_set_e2e_source_policy.py",
    )
    if any(fragment not in workflow for fragment in required_workflow_fragments):
        raise SystemExit("conformance-security workflow does not enforce the RFC 9967 matrix")


def check_removed_security_capabilities() -> None:
    active_files = [
        *(ROOT / "crates").glob("*/src/**/*.rs"),
        *(ROOT / "scripts").glob("*.py"),
        *(ROOT / "scripts").glob("*.sh"),
        *(ROOT / "perf").glob("*.py"),
        *(ROOT / "perf").glob("*.yaml"),
        *(ROOT / ".github" / "workflows").glob("*.yml"),
    ]
    forbidden = (
        "ENABLE_REQUEST_URI_" + "PARAMETER",
        "ENABLE_LEGACY_AUDIENCE_" + "PARAM",
        "SCIM_BEARER_" + "TOKEN",
        "allow_authorization_code_" + "without_pkce",
        "enable_request_uri_" + "parameter",
        "enable_legacy_audience_" + "param",
        "RequestObject" + "Mode",
        "unsigned_request_object_" + "allowed",
    )
    violations = []
    for path in active_files:
        source = path.read_text(encoding="utf-8")
        markers = [marker for marker in forbidden if marker in source]
        if markers:
            violations.append((path.relative_to(ROOT).as_posix(), markers))
    if violations:
        raise SystemExit(f"removed security capabilities reappeared: {violations}")

    removed_test_harness = [
        ROOT / "crates" / "authorization-server" / "src" / "http" / "scim.rs",
        ROOT / "crates" / "authorization-server" / "src" / "http" / "scim",
    ]
    present = [path.relative_to(ROOT) for path in removed_test_harness if path.exists()]
    if present:
        raise SystemExit(f"SCIM test-only transport implementation reappeared: {present}")

    policy = SECURITY_NON_IMPLEMENTATION_POLICY.read_text(encoding="utf-8")
    required_policy_evidence = (
        "RFC 9700",
        "RFC 9101",
        "RFC 9126",
        "RFC 8707",
        "RFC 6750",
        "RFC 8314",
        "Not implemented by security policy",
    )
    missing = [item for item in required_policy_evidence if item not in policy]
    if missing:
        raise SystemExit(f"security non-implementation policy lacks evidence: {missing}")


def check_fapi_ciba_boundaries() -> None:
    delivery = (
        ROOT / "crates" / "authorization-server" / "src" / "domain" / "ciba_ping_delivery.rs"
    ).read_text(encoding="utf-8")
    forbidden_test_markers = ("#[cfg(test)]", "mod tests", "#[test]")
    if any(marker in delivery for marker in forbidden_test_markers):
        raise SystemExit("CIBA ping delivery tests must remain outside production source")
    required_delivery_guards = (
        "reqwest::redirect::Policy::none()",
        ".resolve_to_addrs(host, &addresses)",
        ".bearer_auth(&delivery.client_notification_token)",
        "is_blocked_ip(address.ip())",
        "classify_ciba_ping_status(response.status().as_u16())",
    )
    missing = [guard for guard in required_delivery_guards if guard not in delivery]
    if missing:
        raise SystemExit(f"CIBA ping delivery security guards are missing: {missing}")

    delivery_policy = (
        ROOT / "crates" / "authorization-server-core" / "src" / "ciba_ping.rs"
    ).read_text(encoding="utf-8")
    if any(marker in delivery_policy for marker in forbidden_test_markers):
        raise SystemExit("CIBA ping policy tests must remain outside production source")
    for guard in (
        'parsed.scheme() != "https"',
        "200..=299 => CibaPingResponseAction::Delivered",
        "300..=499 => CibaPingResponseAction::TerminalFailure",
        "_ => CibaPingResponseAction::Retry",
        "3 => 9",
        "next < expires_at",
    ):
        if guard not in delivery_policy:
            raise SystemExit(f"CIBA ping delivery policy guard is missing: {guard}")
    delivery_policy_test = (
        ROOT
        / "crates"
        / "authorization-server-core"
        / "tests"
        / "ciba_ping_delivery_policy.rs"
    )
    if not delivery_policy_test.is_file():
        raise SystemExit("CIBA ping delivery policy tests must remain outside production source")

    workflow = (ROOT / ".github" / "workflows" / "oidf-conformance-full.yml").read_text(
        encoding="utf-8"
    )
    expected_variants = (
        "[client_auth_type=private_key_jwt][fapi_ciba_profile=plain_fapi][ciba_mode=poll]",
        "[client_auth_type=mtls][fapi_ciba_profile=plain_fapi][ciba_mode=poll]",
        "[client_auth_type=private_key_jwt][fapi_ciba_profile=plain_fapi][ciba_mode=ping]",
        "[client_auth_type=mtls][fapi_ciba_profile=plain_fapi][ciba_mode=ping]",
    )
    missing = [variant for variant in expected_variants if variant not in workflow]
    if missing:
        raise SystemExit(f"OIDF workflow lacks FAPI-CIBA combinations: {missing}")
    if "[ciba_mode=push]" in workflow:
        raise SystemExit("FAPI-CIBA push must not enter the supported matrix")
    materializer = (ROOT / "scripts" / "materialize_oidf_plan_config.py").read_text(
        encoding="utf-8"
    )
    for marker in (
        "derive_fapi_ciba_matrix_configs",
        "--derive-fapi-ciba-matrix-configs",
        "backchannel_client_notification_endpoint",
    ):
        if marker not in materializer:
            raise SystemExit(f"official FAPI-CIBA config materialization lacks {marker}")
    for marker in (
        "--derive-fapi-ciba-matrix-configs",
        "--ciba-notification-base-url https://www.certification.openid.net",
    ):
        if marker not in workflow:
            raise SystemExit(f"official FAPI-CIBA workflow lacks {marker}")

    migration = (
        ROOT / "migrations" / "20260715000400_ciba_delivery_modes" / "up.sql"
    ).read_text(encoding="utf-8")
    for constraint in (
        "ck_oauth_clients_ciba_delivery_mode",
        "ck_oauth_clients_ciba_notification_endpoint",
        "ck_oauth_clients_ciba_user_code_disabled",
    ):
        if constraint not in migration:
            raise SystemExit(f"CIBA persistence constraint is missing: {constraint}")


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
        check_authorization_server_import_boundaries()
        check_toolchain_pins()
        check_crate_dependency_boundaries()
        check_workspace_package_metadata()
        check_rfc9967_test_boundaries()
        check_removed_security_capabilities()
        check_fapi_ciba_boundaries()


if __name__ == "__main__":
    main()
