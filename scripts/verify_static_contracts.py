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
        r"@sha256:[0-9a-f]{64} AS build-base",
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
        "Never supported by security policy",
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
        "apply_ciba_ping_tls_policy(reqwest::Client::builder())",
        "reqwest::redirect::Policy::none()",
        ".resolve_to_addrs(host, &addresses)",
        ".bearer_auth(&delivery.client_notification_token)",
        "is_blocked_ip(address.ip())",
        "classify_ciba_ping_status(response.status().as_u16())",
    )
    missing = [guard for guard in required_delivery_guards if guard not in delivery]
    if missing:
        raise SystemExit(f"CIBA ping delivery security guards are missing: {missing}")

    tls_policy = (
        ROOT / "crates" / "authorization-server" / "src" / "domain" / "ciba_ping_tls.rs"
    ).read_text(encoding="utf-8")
    if any(marker in tls_policy for marker in forbidden_test_markers):
        raise SystemExit("CIBA ping TLS policy tests must remain outside production source")
    if "tls_version_min(reqwest::tls::Version::TLS_1_2)" not in tls_policy:
        raise SystemExit("CIBA ping delivery must reject TLS versions below 1.2")
    if "tls_version_max(reqwest::tls::Version::TLS_1_3)" not in tls_policy:
        raise SystemExit("CIBA ping delivery must offer TLS 1.3")
    if ".use_rustls_tls()" not in tls_policy:
        raise SystemExit("CIBA ping delivery must use the Rustls TLS backend")
    if 'std::env::var_os("SSL_CERT_FILE")' not in tls_policy:
        raise SystemExit("CIBA ping delivery must explicitly load its configured trust bundle")
    tls_policy_test = (
        ROOT
        / "crates"
        / "authorization-server"
        / "tests"
        / "in_source"
        / "src"
        / "domain"
        / "tests"
        / "ciba_ping_delivery.rs"
    )
    if not tls_policy_test.is_file():
        raise SystemExit("CIBA ping TLS policy tests must remain outside production source")
    tls_policy_test_source = tls_policy_test.read_text(encoding="utf-8")

    delivery_policy = (
        ROOT / "crates" / "authorization-server-core" / "src" / "ciba_ping.rs"
    ).read_text(encoding="utf-8")
    for required_test in (
        "ciba_ping_transport_rejects_tls11",
        "ciba_ping_transport_supports_the_tls12_fapi_baseline",
        "ciba_ping_transport_supports_tls13",
    ):
        if required_test not in tls_policy_test_source:
            raise SystemExit(f"missing CIBA ping TLS policy test: {required_test}")
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
        '--ciba-notification-base-url "$CONFORMANCE_SERVER"',
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


def check_openid4vc_boundaries() -> None:
    production_roots = (
        ROOT / "crates" / "digital-credentials" / "src",
        ROOT / "crates" / "openid4vci" / "src",
        ROOT / "crates" / "openid4vp" / "src",
        ROOT / "crates" / "openid4vc-http-actix" / "src",
    )
    forbidden_test_markers = ("#[cfg(test)]", "#[test]", "#[tokio::test]", "mod tests")
    for production_root in production_roots:
        for source_file in production_root.rglob("*.rs"):
            source = source_file.read_text(encoding="utf-8")
            if any(marker in source for marker in forbidden_test_markers):
                raise SystemExit(
                    f"OpenID4VC tests must remain outside production source: {source_file}"
                )

    required_test_files = (
        ROOT / "crates" / "digital-credentials" / "tests" / "domain_contract.rs",
        ROOT / "crates" / "digital-credentials" / "tests" / "jwe_contract.rs",
        ROOT / "crates" / "openid4vci" / "tests" / "protocol_contract.rs",
        ROOT / "crates" / "openid4vci" / "tests" / "service_contract.rs",
        ROOT / "crates" / "openid4vp" / "tests" / "protocol_contract.rs",
        ROOT / "crates" / "openid4vp" / "tests" / "service_contract.rs",
        ROOT / "crates" / "openid4vc-http-actix" / "tests" / "transport_contract.rs",
        ROOT / "crates" / "openid4vc-http-actix" / "tests" / "transport_contract.rs",
    )
    missing_tests = [str(path.relative_to(ROOT)) for path in required_test_files if not path.is_file()]
    if missing_tests:
        raise SystemExit(f"OpenID4VC separated test contracts are missing: {missing_tests}")

    registry_path = ROOT / "tests" / "contracts" / "openid4vc-oidf-matrix.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    expected_plans = {
        "oid4vci-1_0-issuer-test-plan",
        "oid4vci-1_0-issuer-haip-test-plan",
        "oid4vp-1final-verifier-test-plan",
        "oid4vp-1final-verifier-haip-test-plan",
    }
    actual_plans = {item.get("plan") for item in registry.get("plans", [])}
    if actual_plans != expected_plans:
        raise SystemExit(
            f"OpenID4VC OIDF registry must contain the exact four upstream plans: {actual_plans}"
        )
    if registry.get("suite_commit") != "dee9a25160e789f0f80517674693ef7989ab9fa1":
        raise SystemExit("OpenID4VC OIDF matrix must remain pinned to the audited v5.2.0 commit")
    if registry.get("status") != "alpha-regression-not-certification":
        raise SystemExit("OpenID4VC OIDF evidence must not be described as certification")

    workflow = (ROOT / ".github" / "workflows" / "openid4vc-conformance.yml").read_text(
        encoding="utf-8"
    )
    materializer = (
        ROOT / "scripts" / "materialize_openid4vc_oidf_config.py"
    ).read_text(encoding="utf-8")
    driver = (ROOT / "scripts" / "run_openid4vc_conformance.py").read_text(
        encoding="utf-8"
    )
    server_settings = (
        ROOT / "crates" / "authorization-server" / "src" / "settings.rs"
    ).read_text(encoding="utf-8")
    server_routes = (
        ROOT / "crates" / "authorization-server" / "src" / "bootstrap" / "routes.rs"
    ).read_text(encoding="utf-8")
    dataset_admin = (
        ROOT / "crates" / "authorization-server" / "src" / "http" / "admin" / "openid4vc.rs"
    ).read_text(encoding="utf-8")
    openid4vc_protocol_adapter = (
        ROOT / "crates" / "openid4vc-http-actix" / "src" / "vci.rs"
    ).read_text(encoding="utf-8")
    openid4vc_server_domain = (
        ROOT / "crates" / "authorization-server" / "src" / "domain" / "openid4vc_endpoints.rs"
    ).read_text(encoding="utf-8")
    for plan in expected_plans:
        if plan not in materializer:
            raise SystemExit(f"OpenID4VC materializer lacks upstream plan: {plan}")
    for marker in (
        "nazo-openid4vc-oidf-private-key-jwt",
        "nazo-openid4vc-oidf-client-attestation",
    ):
        if marker not in materializer:
            raise SystemExit(f"OpenID4VC materializer lacks bounded client identity: {marker}")
    for marker in (
        "dee9a25160e789f0f80517674693ef7989ab9fa1",
        "run_openid4vc_conformance.py",
        "target_origin",
        "${{ inputs.target_origin || vars.OPENID4VC_TARGET_ORIGIN }}",
        "openid4vc-plan-set.json",
        "openid4vc-expected-skips.json",
        "openid4vc-expected-warnings.json",
        "--expected-failures-file",
        "--expected-skips-file",
        "openid4vc-driver.json",
    ):
        if marker not in workflow:
            raise SystemExit(f"OpenID4VC workflow lacks hard boundary: {marker}")
    for marker in (
        "VCI_UNSUPPORTED_ENCRYPTION_MODULE",
        "VCI_REFRESH_TOKEN_MODULE",
        "expected_warnings_for_cases",
        "expected_skips_for_cases",
        "vci_credential_encryption",
        "request_object_trust_anchor_pem",
    ):
        if marker not in materializer:
            raise SystemExit(f"OpenID4VC materializer lacks expected-skip boundary: {marker}")
    for forbidden in ("openid4vci_offers", "openid4vp_transactions", "result_ciphertext"):
        if forbidden in driver:
            raise SystemExit(f"OpenID4VC black-box driver accesses persistence: {forbidden}")
    for forbidden in (
        "OPENID4VCI_CREDENTIAL_DATASET_MANAGEMENT_TOKEN",
        "/openid4vci/management/credential-datasets",
    ):
        if forbidden in server_settings or forbidden in server_routes or forbidden in driver:
            raise SystemExit(f"OpenID4VC dataset control plane exposes retired bearer surface: {forbidden}")
    for marker in (
        "require_admin_or_forbidden_with_handles",
        "has_valid_csrf_token_for_cookies",
        "admin.user_id().as_uuid()",
        "json_response_no_store",
    ):
        if marker not in dataset_admin:
            raise SystemExit(f"OpenID4VC dataset admin boundary is missing: {marker}")
    for forbidden in (
        "PutCredentialDatasetRequest",
        "CredentialDatasetResponse",
        "put_dataset",
        "delete_dataset",
    ):
        if forbidden in openid4vc_protocol_adapter:
            raise SystemExit(
                f"non-standard dataset administration polluted the OpenID4VC protocol adapter: {forbidden}"
            )
    for marker in (
        "CredentialDatasetAdminService",
        "#[serde(deny_unknown_fields)]",
        "validate_managed_dataset",
    ):
        if marker not in openid4vc_server_domain:
            raise SystemExit(f"OpenID4VC internal control-plane boundary is missing: {marker}")
    for marker in (
        "OIDF_ADMIN_EMAIL",
        "OIDF_ADMIN_PASSWORD",
        "/admin/openid4vci/credential-datasets/",
        "dedicated_conformance_subject",
        "ControlPlaneSession",
        "NoRedirectHandler",
    ):
        if marker not in driver:
            raise SystemExit(f"OpenID4VC driver lacks production admin boundary: {marker}")
    containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
    runtime_start = containerfile.index("FROM runtime-base AS runtime")
    runtime_body = containerfile[runtime_start:]
    if "conformance" in runtime_body.lower() or "oidf" in runtime_body.lower():
        raise SystemExit("production runtime image must not contain conformance provisioning")
    keyctl = (ROOT / "crates" / "authorization-server" / "src" / "keyctl.rs").read_text(
        encoding="utf-8"
    )
    key_store = (ROOT / "crates" / "key-management" / "src" / "store.rs").read_text(
        encoding="utf-8"
    )
    for marker in (
        "generate-local",
        "LocalKeyRegistration",
    ):
        if marker not in keyctl:
            raise SystemExit(f"OpenID4VC purpose-scoped key CLI boundary is missing: {marker}")
    for marker in ('entry.get("purposes").is_some()', "key_entry_purposes"):
        if marker not in key_store:
            raise SystemExit(f"OpenID4VC purpose-scoped rotation boundary is missing: {marker}")
    for doc_name in ("openid4vc-final-matrix.md", "openid4vc-final-matrix.zh-CN.md"):
        doc = (ROOT / "docs" / "conformance" / doc_name).read_text(encoding="utf-8")
        if "generate-local --alg ES256 --purposes credential,presentation_request" not in doc:
            raise SystemExit(f"OpenID4VC purpose-scoped key procedure missing from {doc_name}")
        for statement in ("alpha", "not an OpenID Foundation certification claim") if doc_name.endswith(".md") and not doc_name.endswith("zh-CN.md") else ("alpha", "不能称为 OpenID Foundation 正式认证"):
            if statement not in doc:
                raise SystemExit(f"OpenID4VC evidence boundary missing from {doc_name}: {statement}")

    migration = (
        ROOT / "migrations" / "20260716000100_openid4vc_final" / "up.sql"
    ).read_text(encoding="utf-8")
    for forbidden in ("verifier_attestation", "decentralized_identifier", "dc_api"):
        if forbidden in migration:
            raise SystemExit(f"unsupported OpenID4VP mechanism entered persistence: {forbidden}")
    dataset_migration = (
        ROOT / "migrations" / "20260718000100_openid4vci_credential_datasets" / "up.sql"
    ).read_text(encoding="utf-8")
    for marker in (
        "openid4vci_credential_dataset_events",
        "fk_openid4vci_dataset_subject_tenant",
        "fk_openid4vci_dataset_event_actor_tenant",
        "claims_ciphertext BYTEA",
        "ck_openid4vci_dataset_ciphertext",
        "source = 'admin-session'",
    ):
        if marker not in dataset_migration:
            raise SystemExit(f"OpenID4VC dataset persistence boundary is missing: {marker}")


def check_conformance_provisioning_boundaries() -> None:
    """Conformance onboarding must use the public production control plane only."""

    if (ROOT / "compose.oidf.local.yml").exists():
        raise SystemExit("private OIDF product stack must not coexist with public black-box testing")
    black_box_materializer = (
        ROOT / "scripts" / "prepare_oidf_black_box.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "write_nginx",
        "write_env_yaml",
        "write_ui",
        "ensure_server_oidf_keyset",
        "listen 9443",
    ):
        if forbidden in black_box_materializer:
            raise SystemExit(
                f"black-box materializer contains private product environment: {forbidden}"
            )

    forbidden_runtime_markers = (
        "oidcc-",
        "fapi-ciba-id1-test-plan",
        "www.certification.openid.net",
        "/test/a/",
        "oidf-fapi-ciba",
        "fapi-ciba-id1-plain-private-key-jwt-poll",
        "OpenID4VC OIDF Test Issuer",
        "openid4vc-oidf-placeholder",
    )
    for source_file in (ROOT / "crates").glob("*/src/**/*.rs"):
        source = source_file.read_text(encoding="utf-8")
        for marker in forbidden_runtime_markers:
            if marker in source:
                raise SystemExit(
                    f"product runtime contains conformance-runner marker {marker}: {source_file}"
                )

    server_manifest = (
        ROOT / "crates" / "authorization-server" / "Cargo.toml"
    ).read_text(encoding="utf-8")
    server_library = (
        ROOT / "crates" / "authorization-server" / "src" / "lib.rs"
    ).read_text(encoding="utf-8")
    if "conformance-provisioning" in server_manifest or "oidf_seed" in server_library:
        raise SystemExit(
            "production server must not compile or expose conformance provisioning"
        )

    deploy = (ROOT / "scripts" / "deploy_live.ps1").read_text(encoding="utf-8")
    release = (
        ROOT / ".github" / "workflows" / "release-security.yml"
    ).read_text(encoding="utf-8")
    containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
    workspace_manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    retired = (
        "conformance-provisioning",
        "nazo_conformance_provision",
        "nazo-conformance-provisioner",
        "nazo_oauth_seed_oidf",
        "nazo_openid4vc_seed_oidf",
        "OidfPublicSeedArtifact",
        "OidfSuiteBaseUrl",
        "RemoteOidfMtlsCaPath",
    )
    for marker in retired:
        for name, source in (
            ("workspace", workspace_manifest),
            ("release workflow", release),
            ("container image", containerfile),
            ("deployment", deploy),
        ):
            if marker in source:
                raise SystemExit(f"retired direct conformance provisioner remains in {name}: {marker}")

    onboarding = (
        ROOT / "scripts" / "apply_public_conformance_onboarding.py"
    ).read_text(encoding="utf-8")
    for marker in (
        "/auth/me/access-requests",
        "/admin/access-requests/",
        "/auth/me/mtls-trust-requests",
        "/admin/mtls-trust-requests/",
        "canonical_https_origin",
        "NoRedirectHandler",
    ):
        if marker not in onboarding:
            raise SystemExit(f"public conformance onboarding lacks production boundary: {marker}")
    for forbidden in (
        "DATABASE_URL",
        "psycopg",
        "sqlx",
        "nazo_postgres",
        "INSERT INTO",
        "UPDATE oauth_clients",
        "auth.nazo.run",
        "nginx:8443",
    ):
        if forbidden in onboarding or forbidden in black_box_materializer:
            raise SystemExit(f"public conformance tooling contains a forbidden deployment coupling: {forbidden}")

    public_black_box_sources = [
        onboarding,
        black_box_materializer,
        (ROOT / "scripts" / "run_oidf_conformance.py").read_text(encoding="utf-8"),
        (ROOT / "scripts" / "run_openid4vc_conformance.py").read_text(encoding="utf-8"),
        (ROOT / ".github" / "workflows" / "oidf-conformance-full.yml").read_text(encoding="utf-8"),
        (ROOT / ".github" / "workflows" / "openid4vc-conformance.yml").read_text(encoding="utf-8"),
    ]
    for forbidden in ("https://nginx:8443", "https://localhost:8443", "https://auth.nazo.run"):
        if any(forbidden in source for source in public_black_box_sources):
            raise SystemExit(f"public black-box conformance tooling hard-codes an operator endpoint: {forbidden}")

    retired_owner = "bymoye" + "/NazoAuth"
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(
            part in {".git", ".worktrees", "target", "runtime"} for part in path.parts
        ):
            continue
        if path.suffix.lower() not in {".md", ".toml", ".yml", ".yaml", ".json", ".py", ".rs", ".ps1", ".sh"}:
            continue
        if retired_owner in path.read_text(encoding="utf-8", errors="ignore"):
            raise SystemExit(f"retired repository owner remains referenced: {path}")

    mtls_migration = (
        ROOT / "migrations" / "20260718000200_mtls_trust_anchor_lifecycle" / "up.sql"
    ).read_text(encoding="utf-8")
    mtls_repository = (
        ROOT / "crates" / "persistence-postgres" / "src" / "repositories" / "mtls_trust.rs"
    ).read_text(encoding="utf-8")
    for marker in (
        "oauth_client_mtls_trust_anchor_events",
        "role = 'admin' AND admin_level > 0",
        "user_id <> $3",
        "require_mtls_bound_tokens = TRUE",
        "pg_advisory_xact_lock",
        "MAX_ACTIVE_TRUST_ANCHORS_PER_CLIENT",
        "MAX_ACTIVE_TRUST_ANCHORS_PER_TENANT",
        "MAX_PENDING_TRUST_REQUESTS_PER_CLIENT",
        "MAX_PENDING_TRUST_REQUESTS_PER_USER",
    ):
        if marker not in mtls_migration and marker not in mtls_repository:
            raise SystemExit(f"mTLS trust control plane lacks hard boundary: {marker}")

    mtls_runtime = (
        ROOT / "crates" / "authorization-server" / "src" / "http" / "mtls.rs"
    ).read_text(encoding="utf-8")
    mtls_key_management = (
        ROOT / "crates" / "key-management" / "src" / "client_registration.rs"
    ).read_text(encoding="utf-8")
    for marker in (
        "rfc4514_dn_matches",
        "registered_ip_values_match",
        "registered_dns_values_match",
        "registered_email_values_match",
    ):
        if marker not in mtls_runtime:
            raise SystemExit(f"RFC 8705 certificate selector boundary is missing: {marker}")
    for marker in ("x509_cert::name::Name::from_str", "X509Name::from_der", "try_cmp"):
        if marker not in mtls_key_management:
            raise SystemExit(f"RFC 4514 distinguished-name boundary is missing: {marker}")

    public_onboarding_workflow = (
        ROOT / ".github" / "workflows" / "oidf-public-onboarding-material.yml"
    ).read_text(encoding="utf-8")
    for marker in (
        "materialize_openid4vc_oidf_config.py",
        "openid4vc-plan-configs.json",
        "openid4vc-conformance-datasets.json",
    ):
        if marker not in public_onboarding_workflow:
            raise SystemExit(
                f"public conformance onboarding artifact omits OpenID4VC material: {marker}"
            )

    openid4vc_runtime = (
        ROOT
        / "crates"
        / "authorization-server"
        / "src"
        / "domain"
        / "openid4vc_endpoints.rs"
    ).read_text(encoding="utf-8")
    if "Openid4vciDatasetRepository" not in openid4vc_runtime:
        raise SystemExit("OpenID4VC runtime lacks an issuer-authoritative dataset repository")
    openid4vc_repository = (
        ROOT
        / "crates"
        / "persistence-postgres"
        / "src"
        / "repositories"
        / "openid4vc.rs"
    ).read_text(encoding="utf-8")
    openid4vc_admin = (
        ROOT
        / "crates"
        / "authorization-server"
        / "src"
        / "http"
        / "admin"
        / "openid4vc.rs"
    ).read_text(encoding="utf-8")
    for marker in ("Aes256Gcm", "dataset_aad", "claims_ciphertext"):
        if marker not in openid4vc_repository:
            raise SystemExit(f"OpenID4VC dataset encryption boundary is missing: {marker}")
    for marker in (
        "admin.principal.tenant.tenant_id.as_uuid()",
        "require_configured_tenant",
    ):
        if marker not in openid4vc_admin and marker not in openid4vc_runtime:
            raise SystemExit(f"OpenID4VC dataset tenant boundary is missing: {marker}")
    for forbidden in (
        "active_subject_claims_by_tenant_id",
        "issuing_authority\".to_owned()",
        "driving_privileges\".to_owned()",
        "document_number\".to_owned()",
    ):
        if forbidden in openid4vc_runtime:
            raise SystemExit(
                f"OpenID4VC runtime still synthesizes credential evidence: {forbidden}"
            )

    setup = (ROOT / "scripts" / "prepare_oidf_black_box.py").read_text(
        encoding="utf-8"
    )
    for marker in (
        '"onboarding_profile": "operator-black-box"',
        '"run_namespace": RUN_NAMESPACE',
        'RUNTIME / "oidf-onboarding-contract.json"',
        'RUNTIME / "oidf-onboarding-manifest.json"',
        '"clients": onboarding_clients(configs)',
    ):
        if marker not in setup:
            raise SystemExit(f"operator black-box onboarding contract is missing: {marker}")


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
        check_openid4vc_boundaries()
        check_conformance_provisioning_boundaries()


if __name__ == "__main__":
    main()
