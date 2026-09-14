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
RFC9967_MATRIX = ROOT / "tests" / "contracts" / "rfc9967-scim-set-matrix.json"
RFC9967_RUNNER = ROOT / "scripts" / "rfc9967_scim_set_e2e.py"
WORKSTATION_PATH = re.compile(r"(?i)\b[A-Z]:[\\/](?:self|projects)[\\/]")
EXACT_RUST_VERSION = re.compile(r"^\d+\.\d+\.\d+$")

# Canonical package roles: the single architectural dependency model shared by
# this gate, the persistence graph guard, and the crypto boundary guard.
PACKAGE_ROLES = {
    "nazo-oauth-server": "application",
    "nazo-auth": "domain",
    "nazo-crypto": "domain",
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
INNER_ROLES = {"domain", "application"}

# Concrete runtime, network and storage implementations an inner (domain or
# application) package must not bind to. This is a denylist, not an allowlist:
# ordinary data/algorithm crates need no review entry.
EXECUTION_DEPENDENCIES = {
    "actix", "actix-cors", "actix-files", "actix-multipart", "actix-rt", "actix-tls",
    "actix-web", "async-std", "atomicwrites", "aws-credential-types", "aws-sigv4",
    "axum", "diesel", "diesel-async", "diesel_migrations", "fred", "fs2",
    "futures-executor", "hyper", "lettre_email", "opentelemetry",
    "opentelemetry-appender-tracing", "opentelemetry-otlp", "opentelemetry_sdk",
    "process-wrap", "reqwest", "rustix", "smol", "tokio", "tokio-postgres",
    "tokio-postgres-rustls", "tonic", "tracing-opentelemetry", "tracing-subscriber",
}
# Host/OS execution surfaces that inner source must not call even through a
# non-denied dependency. Checked against resolved Rust paths, not bare names.
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


def mask_rust_non_code(source: str) -> str:
    """Blank comments and string/char literal contents without moving offsets."""
    non_code = re.compile(
        r'r(?P<hashes>#{0,255})"[\s\S]*?"(?P=hashes)'
        r'|"(?:\\[\s\S]|[^"\\])*"'
        r"|'(?:\\.|[^'\\\n])'"
        r"|//[^\n]*|/\*[\s\S]*?\*/"
    )
    return non_code.sub(lambda match: re.sub(r"[^\n]", " ", match[0]), source)


def rust_production_source(source: str) -> str:
    """Mask comments/literals and explicit test-only items, retaining feature code."""
    source = mask_rust_non_code(source)
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
    """Enforce the workspace role model and the inner-layer execution denylist."""
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
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
            edge = (
                f"{package} ({role}) -> {dependency} "
                f"[{spec['_kind']}, target={spec['_target']}, alias={spec['_alias']}]"
            )
            if dependency_role is not None:
                if dependency_role not in ALLOWED_DEPENDENCY_ROLES[role]:
                    violations.append(f"{edge}: forbidden {dependency_role} dependency")
            elif spec["_path"] is not None:
                violations.append(f"{edge}: unclassified local dependency requires owner review")
            elif role in INNER_ROLES and dependency in EXECUTION_DEPENDENCIES:
                violations.append(f"{edge}: concrete execution dependency in an inner package")
            if role in INNER_ROLES and dependency == "lettre":
                transport_features = [
                    feature for feature in spec.get("features", [])
                    if feature.startswith(("smtp-", "sendmail-", "file-", "tokio", "async-std", "pool"))
                ]
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
    """Inner layers must not call concrete runtime/storage/Host surfaces.

    Detection is based on Cargo dependencies and resolved Rust paths, not on
    bare identifiers: a type named like a framework type is not a violation.
    """
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    concrete_crates = {name.replace("-", "_") for name in EXECUTION_DEPENDENCIES}
    concrete_crates.update(
        name.replace("-", "_")
        for name, role in PACKAGE_ROLES.items()
        if role in {"adapter", "host"}
    )
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
            if forbidden_paths:
                relative = path.relative_to(ROOT).as_posix()
                violations.append(f"{relative}: concrete execution paths {sorted(forbidden_paths)}")
    if violations:
        raise SystemExit("inner source boundary violated:\n" + "\n".join(violations))


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


def check_aggregate_package_boundary() -> None:
    """nazoauth stays the single aggregate host binary; direction is checked by roles."""
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    if workspace.get("default-members") != ["crates/nazoauth"]:
        raise SystemExit("workspace default-members must contain only the nazoauth aggregate")

    manifest = tomllib.loads(
        (ROOT / "crates" / "nazoauth" / "Cargo.toml").read_text(encoding="utf-8")
    )
    if "bin" not in manifest or manifest["bin"][0]["name"] != "nazoauth":
        raise SystemExit("Native Host must retain the nazoauth executable")


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


def _attribute_cluster(source: str, start: int) -> tuple[str, int]:
    """Return (cluster text, item offset) for the contiguous ``#[...]`` cluster at start."""
    end = start
    while True:
        close = source.find("]", end)
        if close == -1:
            return source[start:], len(source)
        end = close + 1
        if re.match(r"\s*#", source[end:]) is None:
            return source[start:end], end


def _cfg_is_test_only(block: str) -> bool:
    """True when every cfg() in the attribute cluster is proven false in production."""
    expressions = re.findall(r"cfg\s*\(((?:[^]()]|\([^]()\n]*\))*)\)", block)
    return bool(expressions) and all(
        not cfg_is_production_possible(expression) for expression in expressions
    )


def check_rust_test_structure() -> None:
    """Enforce physical separation: test code lives under tests/, never inside src/.

    Production ``src/**`` may carry only declaration-only test mounts
    (``#[cfg(test)] #[path = "../tests/..."] mod x;``). Any other test-only item
    (``#[cfg(test)] fn/impl/const/use/...``) is test code embedded in production
    source and must live under ``tests/**`` instead. Test files must not
    recompile production source through ``include!`` or ``#[path]``.
    """
    test_attribute = re.compile(
        r"#\[\s*(?:(?:tokio|actix_web|actix_rt)\s*::\s*)?test(?:\s*\([^\]]*\))?\s*\]"
    )
    module_item = re.compile(
        r"(?P<attrs>(?:\s*#\[[^\]]*\])*)\s*"
        r"(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*(?P<term>[;{])"
    )
    attr_cluster = re.compile(r"(?:\s*#\[[^\]]*\])+")
    item_keyword = re.compile(
        r"\s*(?:pub(?:\s*\([^)]*\))?\s+)?"
        r"(?:(?:async|unsafe|extern(?:\s*\"[^\"]*\")?|const|default)\s+)*"
        r"(mod|use|fn|impl|const|static|struct|enum|union|trait|type|macro)\b"
    )
    inner_cfg = re.compile(r"#\s*!\s*\[\s*cfg\s*\((?P<expr>[^]]*)\)\s*\]")
    path_attribute = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')
    violations = []
    for crate in sorted((ROOT / "crates").iterdir()):
        source_root = (crate / "src").resolve()
        if not source_root.is_dir():
            continue
        for source_file in sorted(source_root.rglob("*.rs")):
            relative = source_file.relative_to(ROOT).as_posix()
            relative_parts = source_file.relative_to(source_root).parts
            if (
                source_file.name == "tests.rs"
                or source_file.name.endswith("_tests.rs")
                or "tests" in relative_parts[:-1]
            ):
                violations.append(f"{relative} is a test file inside src")
            source = source_file.read_text(encoding="utf-8")
            masked = mask_rust_non_code(source)
            if test_attribute.search(masked):
                violations.append(f"{relative} declares an executable test in production source")
            if "include!(" in masked:
                violations.append(f"{relative} includes another source file")
            for inner in inner_cfg.finditer(masked):
                if not cfg_is_production_possible(inner["expr"]):
                    violations.append(
                        f"{relative} gates the whole file behind a test-only cfg"
                    )
            for cluster in attr_cluster.finditer(masked):
                block = cluster[0]
                if "cfg" not in block or not _cfg_is_test_only(block):
                    continue
                item = item_keyword.match(masked, cluster.end())
                if item is not None and item.group(1) == "mod":
                    continue  # module mounts are validated below
                violations.append(
                    f"{relative} declares a test-only item in production source"
                )
            for match in module_item.finditer(masked):
                block = match["attrs"]
                test_only = _cfg_is_test_only(block)
                if match["term"] == "{":
                    if test_only:
                        violations.append(f"{relative} embeds an inline test module")
                    continue
                real_block = source[match.start("attrs"):match.end("attrs")]
                path_match = path_attribute.search(real_block)
                if path_match is None:
                    if test_only:
                        violations.append(
                            f"{relative} declares a test module without an external mount"
                        )
                    continue
                target = (source_file.parent / path_match.group(1)).resolve()
                inside_src = target.is_relative_to(source_root)
                if not target.is_file():
                    violations.append(
                        f"{relative} mounts a missing file: {path_match.group(1)}"
                    )
                elif test_only and inside_src:
                    violations.append(
                        f"{relative} mounts production source as a test module"
                    )
                elif not test_only and not inside_src:
                    violations.append(
                        f"{relative} compiles test-side file into production source"
                    )
        test_root = crate / "tests"
        if not test_root.is_dir():
            continue
        for test_file in sorted(test_root.rglob("*.rs")):
            source = test_file.read_text(encoding="utf-8")
            masked = mask_rust_non_code(source)
            if "include!(" in masked:
                violations.append(
                    f"{test_file.relative_to(ROOT).as_posix()} includes another source file"
                )
            for literal in path_attribute.finditer(source):
                target = (test_file.parent / literal.group(1)).resolve()
                if target.is_relative_to(source_root):
                    violations.append(
                        f"{test_file.relative_to(ROOT).as_posix()} recompiles production "
                        f"source through {literal.group(1)}"
                    )
    if violations:
        raise SystemExit("Rust test structure violations:\n- " + "\n- ".join(violations))


def check_ciba_ping_connection_pinning() -> None:
    """The CIBA ping sender must dial exactly the addresses it validated.

    The binding produced by lookup_host must be the same binding iterated by
    is_blocked_ip and passed to resolve_to_addrs; pinning any other collection
    re-opens the DNS rebinding window between validation and connect. Redirect
    and environment-proxy behavior are covered by end-to-end tests; this single
    invariant remains because no black-box test can distinguish a pinned
    connection from re-resolution.
    """
    path = ROOT / "crates" / "nazoauth" / "src" / "adapters" / "ciba_ping_sender.rs"
    source = rust_production_source(path.read_text(encoding="utf-8"))
    reference = path.relative_to(ROOT)
    binding = re.search(
        r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*=[^;]*?\blookup_host\b[^;]*;",
        source,
        re.DOTALL,
    )
    if binding is None:
        raise SystemExit(
            f"{reference} must bind lookup_host(...) results to a local variable"
        )
    variable = binding.group(1)
    rest = source[binding.end() :]
    validation = re.search(
        rf"\b{re.escape(variable)}\s*\.\s*iter\(\)\s*\.\s*any\s*\([^;]*?is_blocked_ip",
        rest,
    )
    if validation is None:
        raise SystemExit(
            f"{reference} must validate every element of `{variable}` against "
            "is_blocked_ip before dialing"
        )
    pinning = re.search(
        rf"\.resolve_to_addrs\s*\([^;]*?&{re.escape(variable)}\b",
        rest[validation.end() :],
    )
    if pinning is None:
        raise SystemExit(
            f"{reference} must pin the connection to `&{variable}` via "
            "resolve_to_addrs; dialing any other address collection bypasses "
            "the blocked-network validation"
        )


def check_rfc9967_matrix() -> None:
    """The JSON matrix is the single RFC 9967 case registry; the runner must not
    read event persistence tables, and CI must execute the matrix."""
    payload = json.loads(RFC9967_MATRIX.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    names = [case.get("name") for case in cases]
    if (
        payload.get("schema") != 1
        or payload.get("standard") != "RFC 9967"
        or not names
        or any(not isinstance(name, str) or not name for name in names)
        or len(names) != len(set(names))
        or any(not case.get("handler") for case in cases)
    ):
        raise SystemExit("RFC 9967 case registry is invalid")

    runner = RFC9967_RUNNER.read_text(encoding="utf-8")
    forbidden_tables = ("scim_security_" + "events", "scim_security_event_" + "receipts")
    if any(table in runner for table in forbidden_tables):
        raise SystemExit("RFC 9967 black-box runner must not inspect event persistence tables")

    workflow = (ROOT / ".github" / "workflows" / "conformance-security.yml").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "python scripts/rfc9967_scim_set_e2e.py",
        "test_rfc9967_scim_set_e2e_source_policy",
    ):
        if fragment not in workflow:
            raise SystemExit(
                "conformance-security workflow does not execute the RFC 9967 matrix"
            )


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
        check_documentation_boundaries()
        check_toolchain_pins()
        check_package_roles()
        check_inner_source_boundaries()
        check_aggregate_package_boundary()
        check_workspace_package_metadata()
        check_rust_test_structure()
        check_ciba_ping_connection_pinning()
        check_rfc9967_matrix()


if __name__ == "__main__":
    main()
