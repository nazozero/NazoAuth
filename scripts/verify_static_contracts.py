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
    "authorization-server": {"fred", "nazo-valkey"},
    "authorization-server-postgres": {"fred", "nazo-valkey"},
    "authorization-server-valkey": {
        "diesel",
        "diesel-async",
        "nazo-postgres",
        "tokio-postgres",
    },
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

# Canonical package roles, shared with the Cargo graph guard.
PACKAGE_ROLES = {
    "nazo-oauth-server": "application",
    "nazo-auth": "domain",
    "nazo-oauth-server-object-store": "adapter",
    "nazo-oauth-server-postgres": "adapter",
    "nazo-oauth-server-valkey": "adapter",
    "nazo-digital-credentials": "domain",
    "nazo-http-actix": "adapter",
    "nazo-http-signatures": "domain",
    "nazo-identity": "domain",
    "nazo-key-management": "domain",
    "nazoauth": "host",
    "nazo-openid4vc-http-actix": "adapter",
    "nazo-openid4vci": "domain",
    "nazo-openid4vp": "domain",
    "nazo-operator-protocol": "domain",
    "nazo-persistence": "domain",
    "nazo-postgres": "adapter",
    "nazo-resource-server": "domain",
    "nazo-runtime-modules": "domain",
    "nazo-scim-events": "domain",
    "nazo-valkey": "adapter",
}
ALLOWED_DEPENDENCY_ROLES = {
    "domain": {"domain"},
    "application": {"domain", "application"},
    "adapter": {"domain", "application", "adapter"},
    "host": {"domain", "application", "adapter", "host"},
}


# Reviewed direct third-party dependencies. New entries require an owner review:
# data/algorithm libraries are distinct from concrete network/runtime/Host execution.
NEUTRAL_DEPENDENCIES = {
    "aes-gcm", "anyhow", "arc-swap", "argon2", "aws-lc-rs", "base64", "blake3",
    "chrono", "ciborium", "coset", "der", "ed25519-dalek", "flate2", "futures-util",
    "hmac", "http", "httpsig", "image", "jsonwebtoken", "lru", "p256", "passkey-auth",
    "pem", "pkcs8", "rand", "rcgen", "semver", "serde", "serde_json", "sfv", "sha1",
    "sha2", "subtle", "tar", "thiserror", "time", "tracing", "url", "urlencoding",
    "uuid", "x509-cert", "x509-parser", "yaml_serde", "yasna", "zeroize",
}
EXECUTION_DEPENDENCIES = {
    "actix", "actix-cors", "actix-files", "actix-multipart", "actix-rt", "actix-tls",
    "actix-web", "async-std", "atomicwrites", "aws-credential-types", "aws-sigv4",
    "axum", "diesel", "diesel-async", "diesel_migrations", "fred", "fs2",
    "futures-executor", "hyper", "lettre_email", "opentelemetry",
    "opentelemetry-appender-tracing", "opentelemetry-otlp", "opentelemetry_sdk",
    "process-wrap", "reqwest", "rustix", "smol", "tokio", "tokio-postgres",
    "tokio-postgres-rustls", "tonic", "tracing-opentelemetry", "tracing-subscriber",
}
# These crates expose both neutral values/algorithms and optional execution APIs.
# Inner consumers retain only their reviewed neutral API use (checked below).
MIXED_DEPENDENCIES = {"lettre", "rustls", "rustls-webpki", "mdoc-rs", "futures-channel"}
INNER_ROLES = {"domain", "application"}
REMOVED_BOUNDARY_SYMBOLS = {"SendCibaResponse", "OAuthJsonErrorFields", "RequestContext"}
CONCRETE_INNER_TYPES = {
    "HttpRequest", "HttpResponse", "FromRequest", "Responder", "JoinHandle",
    "WebRequest", "WebResponse", "HttpServer", "ServerHandle",
}
HOST_PATHS = re.compile(
    r"^(?:std::(?:fs|process|thread)(?:::|$)"
    r"|std::env::(?:args|args_os|var|var_os|vars|vars_os|current_dir|current_exe|temp_dir|"
    r"set_var|remove_var|set_current_dir|home_dir)(?:::|$)"
    r"|std::net::(?:TcpListener|TcpStream|UdpSocket|ToSocketAddrs)(?:::|$)"
    r"|std::io::(?:stdin|stdout|stderr)(?:::|$)"
    r"|rustls::(?:ClientConnection|ServerConnection|Connection|Stream|StreamOwned)(?:::|$)"
    r"|lettre::(?:AsyncSmtpTransport|SmtpTransport|AsyncTransport|Transport|transport)(?:::|$)"
    r"|mdoc_rs::(?:runtime|transport|http|ble|nfc)(?:::|$)"
    r"|image::(?:open|save_buffer|save_buffer_with_format|ImageReader::open|io::Reader::open)(?:::|$))"
)


# T02 canonical contracts. Paths are definition owners, not re-export facades.
T02_CONTRACT_OWNERS = {
    "crates/authorization-server/src/contracts/authorization_decision.rs": (
        "AuthorizationDecisionFuture",
        "AuthorizationDecisionCommand",
        "AuthorizationDecisionResponse",
        "AuthorizationDecisionError",
        "AuthorizationDecisionOperations",
    ),
    "crates/authorization-server/src/contracts/local_registration.rs": (
        "LocalRegistrationFuture",
        "LocalRegistrationOperations",
        "AuthenticationRateLimitError",
        "AuthenticationRateLimit",
    ),
    "crates/authorization-server/src/contracts/password_login.rs": (
        "PasswordLoginFuture",
        "PasswordLoginOperations",
    ),
    "crates/authorization-server/src/contracts/passkey.rs": (
        "PasskeyFuture",
        "PasskeyEndpointError",
        "PasskeyLoginFinishCommand",
        "PasskeyLoginOperations",
        "PasskeyProfileContext",
        "PasskeyRegistrationFinishCommand",
        "PasskeyProfileOperations",
    ),
    "crates/authorization-server/src/contracts/mfa_profile.rs": (
        "MfaProfileFuture",
        "MfaRequestContext",
        "MfaCodeCommand",
        "MfaChallengeCommand",
        "MfaSessionRotation",
        "MfaTotpEnrollment",
        "MfaTotpConfirmation",
        "MfaChallengeSuccess",
        "MfaStepUpSuccess",
        "MfaBackupCodesRegenerated",
        "MfaProfileErrorKind",
        "MfaProfileError",
        "MfaProfileOperations",
    ),
    "crates/authorization-server/src/contracts/profile_account.rs": (
        "ProfileAccountFuture",
        "ProfileMe",
        "ProfileAccountError",
        "ProfileAccountOperations",
    ),
    "crates/authorization-server/src/contracts/oidc_logout.rs": (
        "OidcLogoutFuture",
        "OidcLogoutRequest",
        "OidcLogoutCommand",
        "OidcLogoutSuccess",
        "OidcLogoutError",
        "OidcLogoutOperations",
    ),
    "crates/authorization-server/src/contracts/session_management.rs": (
        "SessionManagementFuture",
        "SessionManagementOriginFuture",
        "SessionManagementAvailability",
        "SessionManagementError",
        "SessionManagementOperations",
    ),
    "crates/authorization-server/src/contracts/metadata.rs": (
        "MetadataEndpointConfig",
        "MetadataSnapshot",
        "MetadataSnapshotSource",
    ),
    "crates/authorization-server/src/contracts/runtime_modules.rs": (
        "RuntimeModuleAdminFuture",
        "RuntimeModuleAdminError",
        "RuntimeModuleAdministration",
    ),
    "crates/authorization-server/src/contracts/fapi_resource.rs": (
        "FapiFuture",
        "FapiAuthorizationError",
        "FapiResourceAuthorizer",
        "FapiSignatureVerificationError",
        "FapiSignatureOperationError",
        "FapiResponseSignature",
        "FapiHttpMessageSignatures",
    ),
    "crates/authorization-server/src/contracts/token_management.rs": (
        "TOKEN_INTROSPECTION_JWT_MEDIA_TYPE",
        "TokenManagementFuture",
        "TokenManagementRateLimitError",
        "TokenManagementError",
        "TokenIntrospectionRepresentation",
        "TokenManagementRequestFacts",
        "TokenManagementRequestGuard",
        "TokenManagementOperations",
    ),
    "crates/authorization-server/src/contracts/dynamic_client_registration.rs": (
        "RemoteJwksFuture",
        "RemoteJwksResolverPort",
        "DynamicRegistrationRateLimitError",
        "DynamicRegistrationRequestGuard",
        "DynamicRegistrationSecurityServices",
    ),
    "crates/authorization-server/src/contracts/scim.rs": (
        "ScimFuture", "ScimAuthorizedRequest", "ScimAuthorizationError",
        "ScimRequestAuthorizer", "ScimDependencyError", "ScimCursorProtector",
        "ScimBootstrapPasswordProvider",
    ),
    "crates/authorization-server/src/contracts/userinfo.rs": (
        "AccessTokenAuthScheme", "UserinfoFuture", "UserinfoRepresentation",
        "UserinfoSuccess", "UserinfoDpopError", "UserinfoError", "UserinfoOperations",
    ),
    "crates/authorization-server/src/contracts/request_facts.rs": (
        "DpopErrorContext",
    ),
    "crates/authorization-server/src/contracts/token_client_auth.rs": (
        "BasicAuthorizationCredentials",
        "ClientCertificateFacts",
        "TokenClientAuthTransportFacts",
    ),
    "crates/authorization-server/src/contracts/token_forms.rs": (
        "TokenForm",
        "TokenOnlyForm",
        "PreAuthorizedTokenParameters",
        "ParsedTokenForm",
        "TokenFormError",
        "TokenManagementFormError",
    ),
    "crates/openid4vci/src/application.rs": (
        "CredentialIssuerFuture",
        "AccessTokenScheme",
        "CredentialRequestContext",
        "CredentialResponseBody",
        "CredentialEndpointResponse",
        "CredentialRequestBody",
        "PreAuthorizedTokenRequest",
        "PreAuthorizedTokenResponse",
        "CreateCredentialOfferRequest",
        "CreateCredentialOfferResponse",
        "CredentialHttpError",
        "CredentialIssuerOperations",
    ),
    "crates/openid4vp/src/application.rs": (
        "PresentationFuture",
        "PresentationResponseBody",
        "PresentationResponseInput",
        "PresentationHttpError",
        "CreatePresentationRequest",
        "CreatePresentationResponse",
        "PresentationOperations",
    ),
}


def cfg_is_production_possible(expression: str) -> bool:
    """Only exclude cfg expressions proven false when test=false; features stay unknown."""
    def evaluate(value):
        value = value.strip()
        if value == "test":
            return False
        operator = re.fullmatch(r"(all|any|not)\s*\((.*)\)", value, re.DOTALL)
        if not operator:
            return None
        body = operator[2]
        parts, start, depth = [], 0, 0
        for index, char in enumerate(body):
            depth += (char == "(") - (char == ")")
            if char == "," and depth == 0:
                if body[start:index].strip():
                    parts.append(body[start:index])
                start = index + 1
        if body[start:].strip():
            parts.append(body[start:])
        values = [evaluate(part) for part in parts]
        if operator[1] == "not":
            return None if len(values) != 1 or values[0] is None else not values[0]
        if operator[1] == "all":
            return False if False in values else (None if None in values else True)
        return True if True in values else (None if None in values else False)
    return evaluate(expression) is not False


def rust_production_source(source: str) -> str:
    """Mask comments/literals and explicit test-only items, retaining feature code."""
    non_code = re.compile(
        r'r(?P<hashes>#{0,255})"[\s\S]*?"(?P=hashes)'
        r'|"(?:\\.|[^"\\])*"'
        r"|'(?:\\.|[^'\\\n])'"
        r"|//[^\n]*|/\*[\s\S]*?\*/"
    )
    source = non_code.sub(lambda match: re.sub(r"[^\n]", " ", match[0]), source)
    test_items = []
    for match in re.finditer(r"#(?P<file>!)?\[\s*cfg\s*\(", source):
        end, depth = match.end(), 1
        while end < len(source) and depth:
            depth += (source[end] == "(") - (source[end] == ")")
            end += 1
        if depth or cfg_is_production_possible(source[match.end():end - 1]):
            continue
        if match["file"]:
            return re.sub(r"[^\n]", " ", source)
        closing = re.match(r"\s*\]", source[end:])
        if closing:
            test_items.append((match.start(), end + closing.end()))
    for start, attribute_end in reversed(test_items):
        item = re.match(r"\s*(?:#\[[^\]]*\]\s*)*", source[attribute_end:])
        cursor = attribute_end + item.end()
        boundary = re.search(r"[;{]", source[cursor:])
        if boundary is None:
            continue
        end = cursor + boundary.end()
        if source[end - 1] == "{":
            depth = 1
            while end < len(source) and depth:
                depth += (source[end] == "{") - (source[end] == "}")
                end += 1
        source = source[:start] + re.sub(r"[^\n]", " ", source[start:end]) + source[end:]
    return source


def check_contract_definition_owners() -> None:
    owners = {
        symbol: path
        for path, symbols in T02_CONTRACT_OWNERS.items()
        for symbol in symbols
    }
    definitions: dict[str, list[str]] = {symbol: [] for symbol in owners}
    definition = re.compile(
        r"\b(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?"
        r"(?:struct|enum|trait|type|const)\s+(\w+)\b"
    )
    exports = re.compile(r"\bpub(?:\([^)]*\))?\s+use\s+([^;]+);", re.DOTALL)
    imports = re.compile(r"\buse\s+([^;]+);", re.DOTALL)
    adapter_directories = {"http-actix", "openid4vc-http-actix"}
    workspace_manifest = ROOT / "Cargo.toml"
    workspace = (
        tomllib.loads(workspace_manifest.read_text(encoding="utf-8")).get("workspace", {})
        if workspace_manifest.is_file() else {}
    )
    adapter_aliases = {}
    violations = []
    for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        source = rust_production_source(path.read_text(encoding="utf-8"))
        retired_symbols = REMOVED_BOUNDARY_SYMBOLS & set(re.findall(r"\b\w+\b", source))
        if retired_symbols:
            violations.append(f"{relative} retains removed boundary symbols: {sorted(retired_symbols)}")
        for match in definition.finditer(source):
            symbol = match[1]
            # This pre-existing resource-server enum is a distinct protocol type.
            if symbol == "AccessTokenScheme" and relative == "crates/resource-server/src/service.rs":
                continue
            if symbol in definitions:
                definitions[symbol].append(relative)
        if path.relative_to(ROOT).parts[1] not in adapter_directories:
            continue
        adapter_directory = path.relative_to(ROOT).parts[1]
        if adapter_directory not in adapter_aliases:
            manifest_path = ROOT / "crates" / adapter_directory / "Cargo.toml"
            adapter_aliases[adapter_directory] = {
                spec["_alias"].replace("-", "_"): name.replace("-", "_")
                for name, spec in resolved_production_dependencies(manifest_path, workspace)
            } if manifest_path.is_file() else {}
        aliases = adapter_aliases[adapter_directory].copy()
        for original, alias in re.findall(r"\bextern\s+crate\s+(\w+)\s+as\s+(\w+)\s*;", source):
            aliases[alias] = resolved_rust_path(original, aliases)
        for match in imports.finditer(source):
            for imported, alias in rust_use_bindings(match[1]):
                if alias not in {"*", "_"} and imported != alias:
                    aliases[alias] = resolved_rust_path(imported, aliases)
        contract_roots = (
            "nazo_oauth_server::contracts", "nazo_openid4vci::application",
            "nazo_openid4vp::application",
        )
        for match in exports.finditer(source):
            for exported, _alias in rust_use_bindings(match[1]):
                resolved = resolved_rust_path(exported, aliases)
                identifiers = set(resolved.split("::"))
                if identifiers & owners.keys() or any(
                    resolved == origin or resolved.startswith(origin + "::")
                    for origin in contract_roots
                ):
                    violations.append(f"{relative} re-exports migrated contracts: {match[1].strip()}")
                    break
    for symbol, expected in owners.items():
        if definitions[symbol] != [expected]:
            violations.append(
                f"{symbol} must be defined once in {expected}; found {definitions[symbol]}"
            )
    retired = ROOT / "crates" / "http-actix" / "src" / "request_context.rs"
    if retired.exists():
        violations.append("unused HTTP RequestContext source must be removed")
    if violations:
        raise SystemExit("contract ownership boundary violated:\n" + "\n".join(violations))


def production_dependency_entries(manifest: dict, workspace: dict):
    """Yield every explicit normal/build edge, including disabled target/optional edges."""
    sections = [(None, manifest), *manifest.get("target", {}).items()]
    for target, section in sections:
        for table, kind in (("dependencies", "normal"), ("build-dependencies", "build")):
            for alias, value in section.get(table, {}).items():
                spec = value.copy() if isinstance(value, dict) else {"version": value}
                if spec.get("workspace"):
                    inherited = workspace.get("dependencies", {}).get(alias, {})
                    inherited = inherited if isinstance(inherited, dict) else {"version": inherited}
                    # Cargo adds member features to workspace dependency features.
                    features = [*inherited.get("features", []), *spec.get("features", [])]
                    spec = {**inherited, **spec}
                    if features:
                        spec["features"] = features
                yield alias, spec.get("package", alias), spec, kind, target


def declared_production_dependencies(manifest: dict, workspace: dict):
    """Compatibility for existing policy callers; all edge contexts are still scanned."""
    for _alias, package, spec, _kind, _target in production_dependency_entries(manifest, workspace):
        yield package, spec


def resolved_production_dependencies(manifest_path: Path, workspace: dict):
    """Resolve Cargo aliases and local package identity once for both architecture guards.

    Returned specs also carry _alias, _kind, _target and the resolved absolute crate
    directory _path. These are guard metadata, not Cargo manifest fields.
    """
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    for alias, package, spec, kind, target in production_dependency_entries(manifest, workspace):
        local_path = None
        if "path" in spec:
            base = ROOT if spec.get("workspace") else manifest_path.parent
            local_path = (base / spec["path"]).resolve()
            candidate = local_path / "Cargo.toml"
            if candidate.is_file():
                package = tomllib.loads(candidate.read_text(encoding="utf-8"))["package"]["name"]
        yield package, {
            **spec, "_alias": alias, "_kind": kind, "_target": target,
            "_path": str(local_path) if local_path is not None else None,
        }


def package_manifests():
    return sorted((ROOT / "crates").glob("*/Cargo.toml"))


def check_package_roles() -> None:
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    reviewed = NEUTRAL_DEPENDENCIES | EXECUTION_DEPENDENCIES | MIXED_DEPENDENCIES
    violations = []
    for path in package_manifests():
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        package = manifest["package"]["name"]
        role = PACKAGE_ROLES.get(package)
        if role is None:
            violations.append(f"unclassified local package requires owner review: {package}")
            continue
        for dependency, spec in resolved_production_dependencies(path, workspace):
            dependency_role = PACKAGE_ROLES.get(dependency)
            edge = f"{package} ({role}) -> {dependency} [{spec['_kind']}, target={spec['_target']}, alias={spec['_alias']}]"
            if dependency_role:
                if dependency_role not in ALLOWED_DEPENDENCY_ROLES[role]:
                    violations.append(f"{edge}: forbidden {dependency_role} dependency")
            elif spec["_path"] is not None or dependency not in reviewed:
                violations.append(f"{edge}: unclassified dependency requires owner review")
            elif role in INNER_ROLES and dependency in EXECUTION_DEPENDENCIES:
                violations.append(f"{edge}: concrete execution dependency in an inner package")
            if role in INNER_ROLES and dependency == "lettre":
                transport_features = [feature for feature in spec.get("features", []) if
                    feature.startswith(("smtp-", "sendmail-", "file-", "tokio", "async-std", "pool"))]
                if transport_features:
                    violations.append(f"{edge}: SMTP execution features {transport_features}")
    if violations:
        raise SystemExit("package dependency boundary violated:\n" + "\n".join(violations))


def rust_use_bindings(expression: str, prefix: str = ""):
    """Expand Rust use trees sufficiently to inspect imports and renamed paths."""
    depth = 0
    start = 0
    parts = []
    for index, character in enumerate(expression):
        depth += (character == "{") - (character == "}")
        if character == "," and depth == 0:
            parts.append(expression[start:index])
            start = index + 1
    parts.append(expression[start:])
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "{" in part:
            head, nested = part.split("{", 1)
            nested = nested.rsplit("}", 1)[0]
            head = re.sub(r"\s+", "", head).strip(":")
            yield from rust_use_bindings(nested, "::".join(filter(None, (prefix, head))))
            continue
        item, *renamed = re.split(r"\s+as\s+", part)
        item = re.sub(r"\s+", "", item).strip(":")
        path = prefix if item == "self" else "::".join(filter(None, (prefix, item)))
        alias = renamed[0].strip() if renamed else path.rsplit("::", 1)[-1]
        yield path, alias


def resolved_rust_path(path: str, aliases: dict[str, str]) -> str:
    path = re.sub(r"\s+", "", path).lstrip(":")
    seen = set()
    while True:
        root, separator, suffix = path.partition("::")
        if root in seen:
            break
        seen.add(root)
        replacement = aliases.get(root)
        if replacement is None or replacement == root:
            break
        path = replacement + (separator + suffix if separator else "")
    return path


def check_inner_source_boundaries() -> None:
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    concrete_crates = {name.replace("-", "_") for name in EXECUTION_DEPENDENCIES}
    concrete_crates.update(name.replace("-", "_") for name, role in PACKAGE_ROLES.items() if role in {"adapter", "host"})
    violations = []
    imports = re.compile(r"\buse\s+([^;]+);", re.DOTALL)
    qualified = re.compile(r"(?<!\w)(?:::)?[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)+")
    for manifest_path in package_manifests():
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        if PACKAGE_ROLES.get(manifest["package"]["name"]) not in INNER_ROLES:
            continue
        dependency_aliases = {
            spec["_alias"].replace("-", "_"): name.replace("-", "_")
            for name, spec in resolved_production_dependencies(manifest_path, workspace)
        }
        for path in sorted((manifest_path.parent / "src").rglob("*.rs")):
            source = rust_production_source(path.read_text(encoding="utf-8"))
            aliases = dependency_aliases.copy()
            for original, alias in re.findall(r"\bextern\s+crate\s+(\w+)\s+as\s+(\w+)\s*;", source):
                aliases[alias] = resolved_rust_path(original, aliases)
            bindings = [binding for match in imports.finditer(source) for binding in rust_use_bindings(match[1])]
            for imported, alias in bindings:
                if alias not in {"*", "_"} and imported != alias:
                    aliases[alias] = resolved_rust_path(imported, aliases)
            candidates = [imported for imported, _ in bindings]
            candidates.extend(match[0] for match in qualified.finditer(source))
            forbidden_paths = set()
            for candidate in candidates:
                resolved = resolved_rust_path(candidate, aliases)
                if resolved.partition("::")[0] in concrete_crates or HOST_PATHS.match(resolved):
                    forbidden_paths.add(resolved)
            forbidden_types = CONCRETE_INNER_TYPES & set(re.findall(r"\b\w+\b", source))
            if forbidden_paths or forbidden_types:
                relative = path.relative_to(ROOT).as_posix()
                violations.append(f"{relative}: concrete execution/types {sorted(forbidden_paths | forbidden_types)}")
    if violations:
        raise SystemExit("inner source boundary violated:\n" + "\n".join(violations))


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


def read_rust_module_tree(root_file: Path) -> str:
    """Read a Rust module facade and every source file in its child directory."""
    sources = [root_file]
    child_directory = root_file.with_suffix("")
    if child_directory.is_dir():
        sources.extend(sorted(child_directory.rglob("*.rs")))
    return "\n".join(source.read_text(encoding="utf-8") for source in sources)


def read_rust_source_family(directory: Path, prefix: str) -> str:
    """Read a facade plus private sibling modules sharing a capability prefix."""
    return "\n".join(
        source.read_text(encoding="utf-8")
        for source in sorted(directory.glob(f"{prefix}*.rs"))
    )


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
    for path in sorted([*(ROOT / "crates" / "authorization-server" / "src").rglob("*.rs"), *(ROOT / "crates" / "nazoauth" / "src").rglob("*.rs")]):
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
    if f"ENV RUSTUP_TOOLCHAIN={version}" not in containerfile:
        raise SystemExit(
            "Containerfile must select the preinstalled Rust toolchain without network sync"
        )
    if not re.search(
        r"FROM docker\.io/library/debian:[^\s@]+@sha256:[0-9a-f]{64} AS runtime-base",
        containerfile,
    ):
        raise SystemExit("Containerfile runtime base image must be pinned by digest")
    if "cargo build --release --locked" not in containerfile:
        raise SystemExit("Containerfile release build must use Cargo.lock")
    if "--package nazoauth --bin nazoauth" not in containerfile:
        raise SystemExit("Containerfile must build the nazoauth aggregate executable")
    if (
        "COPY Cargo.toml Cargo.lock rust-toolchain.toml .env.yaml.example ./"
        not in containerfile
    ):
        raise SystemExit("Containerfile builder must include the embedded initial config template")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    if ".env.*" not in dockerignore or "!.env.yaml.example" not in dockerignore:
        raise SystemExit(
            ".dockerignore must exclude local environment files but include the initial template"
        )

    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    rust_actions = []
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        rust_actions.extend(
            (path, match.group("revision"), match.group("version"))
            for match in re.finditer(
                r"dtolnay/rust-toolchain@(?P<revision>[0-9a-f]{40})"
                r"\s+#\s+(?P<version>\d+\.\d+\.\d+)",
                text,
            )
        )
    if not rust_actions:
        raise SystemExit("CI has no immutable dtolnay/rust-toolchain revision pin")
    referenced_workflows = {
        path
        for path in workflows
        if "dtolnay/rust-toolchain@" in path.read_text(encoding="utf-8")
    }
    parsed_workflows = {path for path, _, _ in rust_actions}
    if referenced_workflows != parsed_workflows:
        missing = sorted(path.relative_to(ROOT) for path in referenced_workflows - parsed_workflows)
        raise SystemExit(f"CI Rust toolchain actions lack an immutable revision and version: {missing}")
    revisions = {revision for _, revision, _ in rust_actions}
    if len(revisions) != 1:
        raise SystemExit("CI Rust toolchain actions must share one reviewed immutable revision")
    mismatches = [
        path.relative_to(ROOT)
        for path, _, declared_version in rust_actions
        if declared_version != version
    ]
    if mismatches:
        raise SystemExit(f"CI Rust toolchain version annotations differ from {version}: {mismatches}")

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
    check_package_roles()
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    for crate, forbidden in FORBIDDEN_CRATE_DEPENDENCIES.items():
        manifest_path = ROOT / "crates" / crate / "Cargo.toml"
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        declared = {name for name, _ in resolved_production_dependencies(manifest_path, workspace)}
        violations = sorted(declared & forbidden)
        if violations:
            raise SystemExit(
                f"{manifest_path.relative_to(ROOT)} violates dependency boundaries: {violations}"
            )


def check_transient_state_backend_boundary() -> None:
    server_root = ROOT / "crates" / "authorization-server" / "src"
    forbidden = ("nazo_valkey", "ValkeyConnection", "VALKEY_")
    violations = []
    for path in sorted([*server_root.rglob("*.rs"), *(ROOT / "crates" / "nazoauth" / "src").rglob("*.rs")]):
        if path.is_relative_to(ROOT / "crates" / "nazoauth" / "src" / "launchers"):
            continue
        source = path.read_text(encoding="utf-8")
        markers = [marker for marker in forbidden if marker in source]
        if markers:
            violations.append((path.relative_to(ROOT).as_posix(), markers))
    if violations:
        detail = ", ".join(f"{path}: {markers}" for path, markers in violations)
        raise SystemExit(f"transient-state backend leaked into authorization server: {detail}")

    postgres_root = ROOT / "crates" / "authorization-server-postgres" / "src"
    violations = []
    for path in sorted(postgres_root.rglob("*.rs")):
        source = path.read_text(encoding="utf-8")
        markers = [marker for marker in forbidden if marker in source]
        if markers:
            violations.append((path.relative_to(ROOT).as_posix(), markers))
    if violations:
        detail = ", ".join(f"{path}: {markers}" for path, markers in violations)
        raise SystemExit(f"transient-state adapter leaked into PostgreSQL launcher: {detail}")

    postgres_library = postgres_root / "lib.rs"
    if "valkey" in postgres_library.read_text(encoding="utf-8").lower():
        raise SystemExit("PostgreSQL launcher library must not select or reference Valkey")


def check_aggregate_package_boundary() -> None:
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    if workspace.get("default-members") != ["crates/nazoauth"]:
        raise SystemExit("workspace default-members must contain only the nazoauth aggregate")

    manifest_path = ROOT / "crates" / "nazoauth" / "Cargo.toml"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    if "bin" not in manifest or manifest["bin"][0]["name"] != "nazoauth":
        raise SystemExit("Native Host must retain the nazoauth executable")
    native_root = ROOT / "crates" / "nazoauth" / "src"
    for relative in ("lib.rs", "main.rs", "launchers/mod.rs", "launchers/postgres.rs", "launchers/valkey.rs", "launchers/object_store.rs"):
        if not (native_root / relative).is_file():
            raise SystemExit(f"Native Host ownership is missing: {relative}")
    application = ROOT / "crates" / "authorization-server" / "src"
    for retired in ("bootstrap", "cli.rs", "config.rs", "operator_task", "recovery_root.rs"):
        if (application / retired).exists():
            raise SystemExit(f"Native Host source remains in Application: {retired}")

    source = (ROOT / "crates" / "nazoauth" / "src" / "main.rs").read_text(
        encoding="utf-8"
    )
    forbidden = ("nazo_postgres", "nazo_valkey", "ValkeyConnection", "DbPool")
    leaked = [marker for marker in forbidden if marker in source]
    if leaked:
        raise SystemExit(f"nazoauth aggregate bypasses launcher boundaries: {leaked}")


def check_connection_url_configuration_boundary() -> None:
    forbidden = tuple(
        f"{prefix}_URL_FILE"
        for prefix in ("DATABASE", "VALKEY", "AUDIT_ANCHOR_DATABASE")
    )
    paths = [
        *(ROOT / "crates").rglob("*.rs"),
        *(ROOT / "deploy").rglob("*.yaml"),
        *(ROOT / "deploy").rglob("*.yml"),
        *(ROOT / "deploy").rglob("*.md"),
        *(ROOT / "docs").rglob("*.md"),
        ROOT / "compose.yml",
        ROOT / ".env.yaml.example",
    ]
    violations = []
    for path in paths:
        if not path.exists():
            continue
        source = path.read_text(encoding="utf-8")
        markers = [marker for marker in forbidden if marker in source]
        if markers:
            violations.append((path.relative_to(ROOT).as_posix(), markers))
    if violations:
        detail = ", ".join(f"{path}: {markers}" for path, markers in violations)
        raise SystemExit(f"connection URLs must be configured directly: {detail}")


def check_workspace_package_metadata() -> None:
    workspace_manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    for member in workspace_manifest["workspace"]["members"]:
        manifest_path = ROOT / member / "Cargo.toml"
        package = tomllib.loads(manifest_path.read_text(encoding="utf-8"))["package"]
        for field in ("version", "edition", "license", "repository"):
            if package.get(field) != {"workspace": True}:
                raise SystemExit(
                    f"{manifest_path.relative_to(ROOT)} must inherit package.{field} "
                    "from [workspace.package]"
                )


def check_rust_test_structure() -> None:
    inline_test_module = re.compile(
        r"(?m)^\s*#\[cfg\(test\)\]\s*"
        r"(?:#\[[^\]]+\]\s*)*"
        r"(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{"
    )
    test_attribute = re.compile(r"(?m)^\s*#\[(?:tokio::)?test(?:\([^\]]*\))?\]")
    top_level_cfg = re.compile(r"(?m)^#\[cfg\(test\)\]$")
    top_level_hook = re.compile(
        r"(?m)^#\[cfg\(test\)\]\r?\n"
        r"(?:(?:#\[[^\r\n]+\]\r?\n)*)"
        r"(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*;"
    )
    top_level_test_import = re.compile(
        r"(?:\r?\n#\[[^\r\n]+\])*\r?\n"
        r"\s*(?:pub(?:\([^)]*\))?\s+)?use\b"
    )
    nested_cfg = re.compile(
        r"(?m)^(?P<indent>[ \t]+)#\[cfg\(test\)\]\r?\n"
        r"(?P=indent)(?P<item>[^\r\n]+)"
    )
    allowed_nested_seams = {
        "crates/nazoauth/src/bootstrap/startup/tenant_runtime.rs": (
            "pub(super) fn for_test(binding: TenantDirectoryBinding) -> Arc<Self> {",
            "pub(super) fn for_test_reusing(",
            "pub(super) fn shares_lifecycle_with(&self, other: &Self) -> bool {",
        ),
    }

    violations = []
    for crate in (ROOT / "crates").iterdir():
        source_root = crate / "src"
        if not source_root.is_dir():
            continue
        legacy_files = [
            *source_root.rglob("tests.rs"),
            *source_root.rglob("*_tests.rs"),
        ]
        if legacy_files:
            violations.append(
                f"{crate.relative_to(ROOT).as_posix()} keeps test files under src: "
                f"{[path.relative_to(ROOT).as_posix() for path in legacy_files]}"
            )

        for source_file in source_root.rglob("*.rs"):
            source = source_file.read_text(encoding="utf-8")
            relative = source_file.relative_to(ROOT).as_posix()
            if inline_test_module.search(source) or test_attribute.search(source):
                violations.append(f"{relative} embeds executable tests in production source")
            if "include!(" in source:
                violations.append(f"{relative} includes another source file")

            hook_matches = list(top_level_hook.finditer(source))
            for cfg_match in top_level_cfg.finditer(source):
                if not any(
                    hook.start() == cfg_match.start() for hook in hook_matches
                ) and top_level_test_import.match(source[cfg_match.end() :]) is None:
                    violations.append(f"{relative} has a non-mount top-level cfg(test) item")

            actual_nested = tuple(
                match.group("item").strip() for match in nested_cfg.finditer(source)
            )
            expected_nested = allowed_nested_seams.get(relative, ())
            if len(actual_nested) != len(expected_nested) or any(
                not actual.startswith(expected)
                for actual, expected in zip(actual_nested, expected_nested, strict=True)
            ):
                violations.append(
                    f"{relative} has unreviewed nested test seams: {actual_nested}"
                )

            for hook in hook_matches:
                hook_source = hook.group(0)
                path_match = re.search(r'#\[path\s*=\s*"([^"]+)"\]', hook_source)
                if path_match is None:
                    violations.append(f"{relative} has a test module without an explicit path")
                    continue
                target = (source_file.parent / path_match.group(1)).resolve()
                if not target.is_file():
                    violations.append(
                        f"{relative} mounts a missing test file: {path_match.group(1)}"
                    )

        seam_root = crate / "tests" / "support" / "seams"
        seam_files = list(seam_root.rglob("*.rs")) if seam_root.is_dir() else []
        if seam_files:
            violations.append(
                f"{crate.relative_to(ROOT).as_posix()} retains forbidden tests/support/seams: "
                f"{[path.relative_to(ROOT).as_posix() for path in seam_files]}"
            )
        if (crate / "tests" / "source_mounted").exists():
            violations.append(
                f"{crate.relative_to(ROOT).as_posix()} retains tests/source_mounted"
            )

        test_root = crate / "tests"
        if test_root.is_dir():
            for test_file in test_root.rglob("*.rs"):
                relative_parts = test_file.relative_to(test_root).parts
                if "src" in relative_parts or relative_parts.count("tests") > 0:
                    violations.append(
                        f"{test_file.relative_to(ROOT).as_posix()} repeats production/test layout"
                    )
                source = test_file.read_text(encoding="utf-8")
                if "include!(" in source:
                    violations.append(
                        f"{test_file.relative_to(ROOT).as_posix()} includes another source file"
                    )
                for literal in re.finditer(
                    r'#\[path\s*=\s*"([^"]+)"\]|include!\("([^"]+)"\)', source
                ):
                    raw_target = literal.group(1) or literal.group(2)
                    target = (test_file.parent / raw_target).resolve()
                    try:
                        target.relative_to(source_root.resolve())
                    except ValueError:
                        continue
                    violations.append(
                        f"{test_file.relative_to(ROOT).as_posix()} recompiles production source "
                        f"through {raw_target}"
                    )

    if violations:
        raise SystemExit("Rust test structure violations:\n- " + "\n- ".join(violations))


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
        ROOT / "tests" / "unit" / "test_rfc9967_scim_set_e2e_source_policy.py",
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
        "python scripts/rfc9967_scim_set_e2e.py",
        "python tests/unit/test_rfc9967_scim_set_e2e_source_policy.py",
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
        ROOT / "crates" / "nazoauth" / "src" / "http" / "scim.rs",
        ROOT / "crates" / "nazoauth" / "src" / "http" / "scim",
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
        ROOT / "crates" / "nazoauth" / "src" / "adapters" / "ciba_ping_sender.rs"
    ).read_text(encoding="utf-8")
    # External cfg(test) mounts are allowed; executable tests still live under tests/.
    forbidden_test_markers = ("#[test]", "#[tokio::test]", "#[actix_web::test]")
    if any(marker in delivery for marker in forbidden_test_markers) or re.search(r"mod\s+tests\s*\{", delivery):
        raise SystemExit("CIBA ping delivery tests must remain outside production source")
    required_delivery_guards = (
        "apply_ciba_ping_tls_policy(reqwest::Client::builder().no_proxy())",
        "reqwest::redirect::Policy::none()",
        ".resolve_to_addrs(host, &addresses)",
        ".bearer_auth(&delivery.client_notification_token)",
        "is_blocked_ip(address.ip())",
        ".connect_timeout(Duration::from_secs(3))",
        ".timeout(Duration::from_secs(5))",
    )
    missing = [guard for guard in required_delivery_guards if guard not in delivery]
    if missing:
        raise SystemExit(f"CIBA ping delivery security guards are missing: {missing}")

    delivery_worker = (
        ROOT / "crates" / "authorization-server" / "src" / "workers" / "ciba_ping.rs"
    ).read_text(encoding="utf-8")
    for marker in (
        "classify_ciba_ping_status(status.as_u16())", "next_ciba_ping_retry_at(",
        ".finish(&delivery, outcome)", ".buffer_unordered(DELIVERY_CONCURRENCY)",
        ".collect::<Vec<_>>()", "CibaPingFinishResult::Missing | CibaPingFinishResult::Conflict",
    ):
        if marker not in delivery_worker:
            raise SystemExit(f"CIBA ping application delivery policy is missing: {marker}")
    if re.search(r"#\[\s*cfg\s*\(\s*not\s*\(\s*test\s*\)", delivery_worker):
        raise SystemExit("CIBA ping tests must compile the production batch worker")

    tls_policy = (
        ROOT / "crates" / "nazoauth" / "src" / "adapters" / "ciba_ping_tls.rs"
    ).read_text(encoding="utf-8")
    if any(marker in tls_policy for marker in forbidden_test_markers):
        raise SystemExit("CIBA ping TLS policy tests must remain outside production source")
    if (
        "CIBA_PING_TLS_MIN: reqwest::tls::Version = reqwest::tls::Version::TLS_1_2"
        not in tls_policy
        or ".tls_version_min(CIBA_PING_TLS_MIN)" not in tls_policy
    ):
        raise SystemExit("CIBA ping delivery must reject TLS versions below 1.2")
    if (
        "CIBA_PING_TLS_MAX: reqwest::tls::Version = reqwest::tls::Version::TLS_1_3"
        not in tls_policy
        or ".tls_version_max(CIBA_PING_TLS_MAX)" not in tls_policy
    ):
        raise SystemExit("CIBA ping delivery must offer TLS 1.3")
    if ".use_rustls_tls()" not in tls_policy:
        raise SystemExit("CIBA ping delivery must use the Rustls TLS backend")
    if 'std::env::var_os("CIBA_PING_TLS_TRUST_BUNDLE")' not in tls_policy:
        raise SystemExit("CIBA ping delivery must explicitly load its configured trust bundle")
    tls_policy_test = (
        ROOT
        / "crates"
        / "nazoauth"
        / "tests"
        / "unit"
        / "domain"
        / "ciba_ping_delivery.rs"
    )
    if not tls_policy_test.is_file():
        raise SystemExit("CIBA ping TLS policy tests must remain outside production source")
    tls_policy_test_source = tls_policy_test.read_text(encoding="utf-8")

    delivery_policy = (
        ROOT / "crates" / "authorization-server-core" / "src" / "ciba_ping.rs"
    ).read_text(encoding="utf-8")
    for required_test in (
        "ciba_ping_transport_policy_is_bounded_to_tls12_and_tls13",
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

    server_settings = read_rust_module_tree(
        ROOT / "crates" / "nazoauth" / "src" / "settings.rs"
    )
    server_config = (
        ROOT / "crates" / "nazoauth" / "src" / "config.rs"
    ).read_text(encoding="utf-8")
    server_routes = (
        ROOT / "crates" / "nazoauth" / "src" / "bootstrap" / "routes.rs"
    ).read_text(encoding="utf-8")
    dataset_admin = (
        ROOT / "crates" / "nazoauth" / "src" / "http" / "admin" / "openid4vc.rs"
    ).read_text(encoding="utf-8")
    openid4vc_protocol_adapter = (
        ROOT / "crates" / "openid4vc-http-actix" / "src" / "vci.rs"
    ).read_text(encoding="utf-8")
    openid4vc_server_domain = read_rust_module_tree(
        ROOT / "crates" / "authorization-server" / "src" / "domain" / "openid4vc_endpoints.rs"
    )
    for forbidden in (
        "OPENID4VCI_CREDENTIAL_DATASET_MANAGEMENT_TOKEN",
        "/openid4vci/management/credential-datasets",
    ):
        if forbidden in server_settings or forbidden in server_routes:
            raise SystemExit(f"OpenID4VC dataset control plane exposes retired bearer surface: {forbidden}")
    for marker in (
        "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON",
        "OPENID4VC_KEY_ATTESTATION_JWKS_JSON",
        "client_attestation_jwks",
        "key_attestation_jwks",
        "public verification keys only",
    ):
        if marker not in server_settings:
            raise SystemExit(f"OpenID4VC purpose-scoped attestation trust boundary is missing: {marker}")
    if "OPENID4VC_ATTESTATION_JWKS_JSON" in server_settings or "OPENID4VC_ATTESTATION_JWKS_JSON" in server_config:
        raise SystemExit("OpenID4VC generic attestation trust store must not be reintroduced")
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
    keyctl = (ROOT / "crates" / "nazoauth" / "src" / "keyctl.rs").read_text(
        encoding="utf-8"
    )
    key_store = "\n".join(
        (
            ROOT / "crates" / "key-management" / "src" / name
        ).read_text(encoding="utf-8")
        for name in ("database.rs", "serialization.rs")
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


def check_admin_provision_boundary() -> None:
    server_root = ROOT / "crates" / "nazoauth"
    persistence_root = ROOT / "crates" / "persistence-postgres"
    retired_http_module = "bootstrap" + "_" + "admin.rs"
    retired_repository_module = "initial" + "_" + "admin" + "_" + "bootstrap.rs"
    retired_paths = (
        server_root / "src" / "http" / retired_http_module,
        server_root / "tests" / "unit" / "http" / retired_http_module,
        persistence_root / "src" / "repositories" / retired_repository_module,
        persistence_root / "tests" / retired_repository_module,
    )
    present = [str(path.relative_to(ROOT)) for path in retired_paths if path.exists()]
    if present:
        raise SystemExit(f"retired administrator bootstrap assets remain: {present}")

    routes = (server_root / "src" / "bootstrap" / "routes.rs").read_text(
        encoding="utf-8"
    )
    server_sources = "\n".join(
        (server_root / relative).read_text(encoding="utf-8")
        for relative in (
            Path("src/bootstrap/routes.rs"),
            Path("src/bootstrap/startup/configuration.rs"),
            Path("src/bootstrap/startup/services/factory.rs"),
            Path("src/http/mod.rs"),
            Path("src/cli.rs"),
        )
    )
    persistence_sources = "\n".join(
        (persistence_root / relative).read_text(encoding="utf-8")
        for relative in (
            Path("src/schema.rs"),
            Path("src/lib.rs"),
            Path("src/repositories/mod.rs"),
            Path("src/repositories/audit.rs"),
        )
    )
    retired_route = 'route("/' + "bootstrap" + "-" + 'admin"'
    if retired_route in routes:
        raise SystemExit("authorization server still exposes the retired setup route")
    retired_references = (
        "bootstrap" + "_" + "admin",
        "Initial" + "Admin" + "Bootstrap",
        "Initial" + "Admin" + "ClaimOutcome",
        "initial" + "_" + "admin" + "_" + "bootstrap" + "_receipts",
        "initial" + "-" + "admin" + "-" + "token",
    )
    for forbidden in retired_references:
        if forbidden in server_sources or forbidden in persistence_sources:
            raise SystemExit(f"retired administrator bootstrap reference remains: {forbidden}")
    for marker in (
        '"admin-provision"',
        "ADMIN_PROVISION_CREDENTIAL_FILE_ENV",
        "AdminProvisionRepository",
        "admin_provision_receipts",
    ):
        if marker not in server_sources + persistence_sources:
            raise SystemExit(f"admin provisioning boundary is missing: {marker}")

    migration = (
        ROOT / "migrations" / "20260830000100_admin_user_provisioning" / "up.sql"
    ).read_text(encoding="utf-8")
    retired_receipts = (
        "initial" + "_" + "admin" + "_" + "bootstrap" + "_receipts"
    )
    if f"DROP TABLE IF EXISTS {retired_receipts}" not in migration:
        raise SystemExit("admin provisioning migration does not remove the retired receipt table")
    if "admin_user_created" not in migration:
        raise SystemExit("admin provisioning migration lacks the durable audit event type")


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
        check_contract_definition_owners()
        check_inner_source_boundaries()
        check_transient_state_backend_boundary()
        check_aggregate_package_boundary()
        check_connection_url_configuration_boundary()
        check_workspace_package_metadata()
        check_rust_test_structure()
        check_rfc9967_test_boundaries()
        check_removed_security_capabilities()
        check_fapi_ciba_boundaries()
        check_openid4vc_boundaries()
        check_admin_provision_boundary()


if __name__ == "__main__":
    main()
