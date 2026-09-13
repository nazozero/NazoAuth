#!/usr/bin/env python3
"""Verify that concrete crypto backends stay behind the nazo-crypto boundary.

Exit 0 prints PASS; exit 1 prints every violation as
``relative/path:line-or-0: rule: detail`` sorted and deduplicated.
"""

import argparse
import re
import sys
import tomllib
from pathlib import Path

import verify_static_contracts as contracts

BACKEND_PACKAGES = {
    "aes", "aes-gcm", "aes-gcm-siv", "argon2", "aws-lc-rs",
    "curve25519-dalek", "ed25519-dalek", "jsonwebtoken", "js-sys",
    "k256", "openssl", "openssl-sys", "p256", "p384", "p521",
    "pbkdf2", "rcgen", "ring", "rsa", "rscrypto", "scrypt",
    "web-sys", "wolfssl", "wolfssl-sys",
}

CRYPTO_DEPENDENCIES = {
    "aes-gcm", "argon2", "aws-lc-rs", "base64", "der",
    "ed25519-dalek", "jsonwebtoken", "p256", "pkcs8", "rand",
    "rcgen", "rustls", "serde", "serde_json", "thiserror",
    "x509-cert", "x509-parser", "zeroize",
}

TLS_EXCEPTIONS = {
    "crates/nazoauth/src/bootstrap/transport.rs": {
        "rustls::crypto::CryptoProvider",
        "rustls::crypto::aws_lc_rs::default_provider",
    },
    "crates/nazoauth/src/bootstrap/startup/services/factory.rs": {
        "rustls::crypto::aws_lc_rs::default_provider",
    },
    "crates/persistence-postgres/src/pool.rs": {
        "rustls::crypto::aws_lc_rs::default_provider",
    },
}

DTO_EXPORTS = {
    "jwt": {"Algorithm", "Header", "TokenData", "Validation"},
    "certificate": {
        "BasicConstraints", "CertificateParams",
        "CertificateRevocationListParams", "CrlDistributionPoint",
        "CustomExtension", "DistinguishedName", "DnType", "DnValue",
        "IsCa", "KeyIdMethod", "KeyUsagePurpose", "RevokedCertParams",
        "SerialNumber", "PrintableString",
    },
}

_CRYPTO_FEATURES = {"aead", "ecdh", "ed25519", "jose", "password", "x509"}
_X509_VERIFY_FEATURES = {"ring", "verify", "verify-aws"}
_ALLOWED_SIGNATURE_PATHS = {
    "x509_parser::certificate::X509Certificate",
    "x509_parser::x509::SubjectPublicKeyInfo",
}
_VERIFIER_PATHS = {
    "rustls::server::WebPkiClientVerifier",
    "rustls::server::danger::ClientCertVerifier",
}
_VERIFIER_FILES = {
    "crates/nazoauth/src/bootstrap/transport.rs",
    "crates/nazoauth/src/http/mtls.rs",
}
_WEBPKI_FILES = {"crates/nazoauth/src/bootstrap/transport.rs"}

_QUALIFIED = re.compile(r"(?<!\w)(?:::)?[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)+")
_USES = re.compile(r"\buse\s+([^;]+);", re.DOTALL)
_PUB_USES = re.compile(r"\bpub\s+use\s+([^;]+);", re.DOTALL)
_EXTERN = re.compile(r"\bextern\s+crate\s+(\w+)\s+as\s+(\w+)\s*;")
_PUB_FN = re.compile(r"\bpub\s+(?:async\s+|unsafe\s+|extern\s+\S+\s+)*fn\s+\w+")
_PUB_STRUCT = re.compile(r"\bpub\s+struct\s+\w+")
_PUB_ENUM = re.compile(r"\bpub\s+enum\s+\w+")
_PUB_TYPE = re.compile(r"\bpub\s+type\s+\w+")
_PUB_FIELD = re.compile(r"\bpub(\s*\(\s*crate\s*\))?\s+(\w+)\s*:\s*([^,})]+)")
_PUB_TRAIT = re.compile(r"\bpub\s+trait\b")
_FORBIDDEN_IMPL = re.compile(r"\bimpl\b[^{]*\b(?:Deref|DerefMut|AsRef|Borrow)\b")
_PATH_ATTR = re.compile(r"#\[\s*path\s*=\s*\"([^\"]+)\"\s*\]")
_INCLUDE = re.compile(r"\binclude!\s*\(")


def _load_manifest(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _all_dependency_packages(manifest: dict, workspace: dict) -> dict:
    """Map every declared dependency alias (normal/dev/build/target) to its package."""
    packages = {}
    sections = [manifest, *manifest.get("target", {}).values()]
    for section in sections:
        for table in ("dependencies", "dev-dependencies", "build-dependencies"):
            for alias, value in section.get(table, {}).items():
                spec = value if isinstance(value, dict) else {}
                if spec.get("workspace"):
                    inherited = workspace.get("dependencies", {}).get(alias, {})
                    if isinstance(inherited, dict):
                        spec = {**inherited, **spec}
                packages[alias] = spec.get("package", alias)
    return packages


def manifest_violations(root: Path) -> list:
    """Check Cargo manifests for backend edges, feature forwarding, and identity."""
    consumer_features = {
        "nazo-auth": ["ecdh", "jose"],
        "nazo-digital-credentials": ["aead", "ecdh"],
        "nazo-http-signatures": ["jose"],
        "nazo-identity": ["password"],
        "nazo-key-management": ["aead", "ecdh", "jose"],
        "nazo-oauth-server": ["aead", "ecdh", "jose", "x509"],
        "nazo-operator-protocol": ["ed25519"],
        "nazo-postgres": ["aead", "password"],
        "nazo-resource-server": ["jose"],
        "nazoauth": ["ed25519", "jose", "password", "x509"],
        "nazoauth-fuzz": ["ed25519"],
    }
    violations = []
    workspace = _load_manifest(root / "Cargo.toml").get("workspace", {})
    crypto_dir = (root / "crates" / "crypto").resolve()
    crypto_manifest = crypto_dir / "Cargo.toml"
    if not crypto_manifest.is_file():
        violations.append("crates/crypto/Cargo.toml:0: missing crypto crate manifest")
    manifests = sorted((root / "crates").glob("*/Cargo.toml"))
    fuzz_manifest = root / "fuzz" / "Cargo.toml"
    if fuzz_manifest.is_file():
        manifests.append(fuzz_manifest)
    reviewed = (
        contracts.NEUTRAL_DEPENDENCIES | contracts.EXECUTION_DEPENDENCIES
        | contracts.MIXED_DEPENDENCIES
    )
    for manifest_path in manifests:
        manifest = _load_manifest(manifest_path)
        name = manifest.get("package", {}).get("name", "")
        relative = manifest_path.relative_to(root).as_posix()
        is_crypto = manifest_path.parent.resolve() == crypto_dir
        is_fuzz = manifest_path.parent.resolve() == (root / "fuzz").resolve()
        if name == "nazo-crypto" and not is_crypto:
            violations.append(
                f"{relative}:0: crypto identity: package 'nazo-crypto' must live in crates/crypto"
            )
        dependencies = list(
            contracts.resolved_production_dependencies(manifest_path, workspace)
        )
        if is_crypto:
            packages = {package for package, _spec in dependencies}
            for package, spec in dependencies:
                if spec["_path"] or package in contracts.PACKAGE_ROLES:
                    violations.append(
                        f"{relative}:0: crypto isolation: local dependency {package}"
                    )
            for package in sorted(packages - CRYPTO_DEPENDENCIES):
                violations.append(
                    f"{relative}:0: crypto dependency: unlisted dependency {package}"
                )
            for package in sorted(CRYPTO_DEPENDENCIES - packages):
                violations.append(
                    f"{relative}:0: crypto dependency: missing required dependency {package}"
                )
            features = manifest.get("features", {})
            keys = set(features)
            if features.get("default") == []:
                keys.discard("default")
            if keys != _CRYPTO_FEATURES:
                violations.append(
                    f"{relative}:0: crypto features: expected {sorted(_CRYPTO_FEATURES)}, "
                    f"found {sorted(set(features))}"
                )
            continue
        for package, spec in dependencies:
            context = spec["_kind"] + (f" target {spec['_target']}" if spec["_target"] else "")
            if package in BACKEND_PACKAGES:
                violations.append(
                    f"{relative}:0: backend dependency: {spec['_alias']} ({package}) "
                    f"as {context} dependency"
                )
            if package == "x509-parser":
                banned = set(spec.get("features") or []) & _X509_VERIFY_FEATURES
                if banned:
                    violations.append(
                        f"{relative}:0: x509 verification feature: "
                        f"x509-parser features {sorted(banned)}"
                    )
            if package == "nazo-crypto":
                edge_path = Path(spec["_path"]).resolve() if spec["_path"] else None
                if edge_path != crypto_dir:
                    violations.append(
                        f"{relative}:0: crypto dependency: nazo-crypto must resolve "
                        f"to crates/crypto"
                    )
                if name not in consumer_features:
                    violations.append(
                        f"{relative}:0: crypto consumer: {name} is not a registered consumer"
                    )
                elif sorted(spec.get("features") or []) != consumer_features[name]:
                    violations.append(
                        f"{relative}:0: crypto features: {name} expects "
                        f"{consumer_features[name]}, found {sorted(spec.get('features') or [])}"
                    )
            if spec["_path"] and package not in contracts.PACKAGE_ROLES:
                violations.append(
                    f"{relative}:0: unreviewed dependency: unregistered local package "
                    f"{package}"
                )
            if (
                not is_fuzz
                and not spec["_path"]
                and package not in reviewed
                and package not in contracts.PACKAGE_ROLES
            ):
                violations.append(
                    f"{relative}:0: unreviewed dependency: {package}"
                )
        aliases = _all_dependency_packages(manifest, workspace)
        for feature, entries in manifest.get("features", {}).items():
            for entry in entries if isinstance(entries, list) else []:
                match = re.fullmatch(r"dep:([\w-]+)", entry) or re.fullmatch(
                    r"([\w-]+)\??/[\w-]+", entry
                )
                if not match:
                    continue
                package = aliases.get(match[1], match[1])
                if package in BACKEND_PACKAGES or (
                    package == "x509-parser" and "/" in entry
                    and entry.rsplit("/", 1)[1] in _X509_VERIFY_FEATURES
                ):
                    violations.append(
                        f"{relative}:0: backend feature forwarding: {feature} = {entry}"
                    )
    return violations


def _line_number(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def _decl_region(masked: str, start: int) -> str:
    """Return the declaration/signature text up to the first body or semicolon."""
    end = len(masked)
    for marker in "{;":
        index = masked.find(marker, start)
        if index != -1:
            end = min(end, index)
    return masked[start:end]


def _brace_region(masked: str, start: int) -> str:
    """Return the balanced-brace body following a declaration, or the decl itself."""
    open_index = masked.find("{", start)
    close_index = masked.find(";", start)
    if open_index == -1 or (close_index != -1 and close_index < open_index):
        return masked[start:close_index if close_index != -1 else len(masked)]
    depth = 0
    for index in range(open_index, len(masked)):
        depth += masked[index] == "{"
        depth -= masked[index] == "}"
        if not depth:
            return masked[start:index + 1]
    return masked[open_index:]


def _backend_paths(region: str):
    for match in _QUALIFIED.finditer(region):
        path = re.sub(r"\s+", "", match[0]).lstrip(":")
        if path.partition("::")[0] in {name.replace("-", "_") for name in BACKEND_PACKAGES}:
            yield match.start(), path


def _crypto_source_violations(relative: str, masked: str) -> list:
    """Check the public surface of crates/crypto: DTOs only, opaque types."""
    stem = Path(relative).stem
    violations = []
    for match in _PUB_USES.finditer(masked):
        for imported, _alias in contracts.rust_use_bindings(match[1]):
            root = re.sub(r"\s+", "", imported).lstrip(":").partition("::")[0]
            leaf = re.sub(r"\s+", "", imported).rpartition("::")[2]
            if root in {name.replace("-", "_") for name in BACKEND_PACKAGES} and (
                leaf not in DTO_EXPORTS.get(stem, set())
            ):
                violations.append((
                    match.start(), "crypto public surface",
                    f"backend re-export {imported.strip()}",
                ))
    for match in _PUB_FN.finditer(masked):
        region = _decl_region(masked, match.end())
        for _pos, path in _backend_paths(region):
            if path not in _ALLOWED_SIGNATURE_PATHS:
                violations.append((
                    match.start(), "crypto public surface",
                    f"backend path {path} in public signature",
                ))
    for match in _PUB_STRUCT.finditer(masked):
        region = _brace_region(masked, match.end())
        for field in _PUB_FIELD.finditer(region):
            crate_visible, field_name, field_type = field[1], field[2], field[3]
            paths = [p for _p, p in _backend_paths(field_type)]
            if not paths:
                continue
            if crate_visible and stem == "jwt" and field_name == "inner":
                continue
            violations.append((
                match.start(), "crypto public surface",
                f"public field {field_name} exposes {paths[0]}",
            ))
    for match in list(_PUB_ENUM.finditer(masked)) + list(_PUB_TYPE.finditer(masked)):
        region = _brace_region(masked, match.end())
        for _pos, path in _backend_paths(region):
            violations.append((
                match.start(), "crypto public surface",
                f"public type exposes {path}",
            ))
            break
    for match in _PUB_TRAIT.finditer(masked):
        violations.append((match.start(), "crypto public surface", "public trait"))
    for match in _FORBIDDEN_IMPL.finditer(masked):
        violations.append((
            match.start(), "crypto public surface",
            "Deref/AsRef/Borrow impl exposes backend internals",
        ))
    for match in re.finditer(r"\binto_inner\b", masked):
        violations.append((
            match.start(), "crypto public surface", "into_inner exposes backend key",
        ))
    return violations


def source_violations(root: Path) -> list:
    """Check production sources for backend paths and banned method calls."""
    violations = []
    workspace = _load_manifest(root / "Cargo.toml").get("workspace", {})
    crypto_dir = (root / "crates" / "crypto").resolve()
    backend_rust = {name.replace("-", "_") for name in BACKEND_PACKAGES}
    for manifest_path in sorted((root / "crates").glob("*/Cargo.toml")):
        crate_dir = manifest_path.parent
        manifest = _load_manifest(manifest_path)
        is_crypto = crate_dir.resolve() == crypto_dir
        dependency_aliases = {
            alias.replace("-", "_"): package.replace("-", "_")
            for alias, package in _all_dependency_packages(manifest, workspace).items()
        }
        src_dir = crate_dir / "src"
        if not src_dir.is_dir():
            continue
        for path in sorted(src_dir.rglob("*.rs")):
            relative = path.relative_to(root).as_posix()
            text = path.read_text(encoding="utf-8")
            masked = contracts.rust_production_source(text)
            if is_crypto:
                for position, rule, detail in _crypto_source_violations(
                    relative, masked
                ):
                    violations.append(
                        f"{relative}:{_line_number(text, position)}: {rule}: {detail}"
                    )
                continue
            aliases = dict(dependency_aliases)
            for original, alias in _EXTERN.findall(masked):
                aliases[alias] = contracts.resolved_rust_path(original, aliases)
            bindings = [
                binding
                for match in _USES.finditer(masked)
                for binding in contracts.rust_use_bindings(match[1])
            ]
            for imported, alias in bindings:
                if alias not in {"*", "_"} and imported != alias:
                    aliases[alias] = contracts.resolved_rust_path(
                        imported, aliases
                    )
            candidates = [(m.start(), i) for m in _USES.finditer(masked) for i, _a in contracts.rust_use_bindings(m[1])]
            candidates.extend(
                (m.start(), m[0]) for m in _QUALIFIED.finditer(masked)
            )
            reported = set()
            for position, candidate in candidates:
                resolved = contracts.resolved_rust_path(candidate, aliases)
                root_name = resolved.partition("::")[0]
                detail = None
                if root_name in backend_rust:
                    detail = f"backend path {resolved}"
                elif resolved.startswith("rustls::crypto::"):
                    allowed = TLS_EXCEPTIONS.get(relative, set())
                    if not any(resolved.startswith(prefix) for prefix in allowed):
                        detail = f"TLS provider path {resolved} outside fixed exceptions"
                elif (
                    any(
                        resolved == item or resolved.startswith(item + "::")
                        for item in _VERIFIER_PATHS
                    )
                    and relative not in _VERIFIER_FILES
                ):
                    detail = f"verifier type {resolved} outside fixed files"
                elif root_name == "webpki" and relative not in _WEBPKI_FILES:
                    detail = f"webpki path {resolved} outside transport"
                if detail and resolved not in reported:
                    reported.add(resolved)
                    violations.append(
                        f"{relative}:{_line_number(text, position)}: backend use: {detail}"
                    )
            for pattern, rule in (
                (r"\.verify_signature\s*\(", "native verify_signature call"),
                (r"\bX509Certificate\s*::\s*verify_signature", "native verify_signature call"),
                (r"\.signed_by\s*\(", "rcgen signing call"),
                (r"\.self_signed\s*\(", "rcgen signing call"),
            ):
                for match in re.finditer(pattern, masked):
                    violations.append(
                        f"{relative}:{_line_number(text, match.start())}: "
                        f"{rule}: {match[0].strip()} outside nazo-crypto"
                    )
            for match in _INCLUDE.finditer(masked):
                violations.append(
                    f"{relative}:{_line_number(text, match.start())}: "
                    f"include macro: include! is forbidden in production code"
                )
            for match in _PATH_ATTR.finditer(text):
                if not masked[match.start():match.end()].strip():
                    continue
                target = (path.parent / match[1]).resolve()
                if not str(target).startswith(str((crate_dir / "src").resolve())):
                    violations.append(
                        f"{relative}:{_line_number(text, match.start())}: "
                        f"production path attribute: {match[1]} escapes crate src"
                    )
    return violations


def collect_violations(root: Path) -> list:
    """Run both guard phases with the shared contract helpers pointed at root."""
    saved_root = contracts.ROOT
    contracts.ROOT = Path(root).resolve()
    try:
        return manifest_violations(contracts.ROOT) + source_violations(contracts.ROOT)
    finally:
        contracts.ROOT = saved_root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: two levels above this script)",
    )
    args = parser.parse_args()
    violations = sorted(set(collect_violations(args.root.resolve())))
    if violations:
        print("crypto boundary violated:")
        print("\n".join(violations))
        return 1
    print("PASS: crypto boundary holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
