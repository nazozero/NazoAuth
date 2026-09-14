#!/usr/bin/env python3
"""Verify that concrete crypto backends stay behind the nazo-crypto boundary.

The guard freezes architectural invariants only: dependency direction, backend
type/key/provider non-leakage, and the sanctioned bypass rules. It deliberately
does not freeze implementation shape (exact dependency sets, feature member
lists, or public API names) so the crypto implementation can evolve without a
second architecture database. Exit 0 prints PASS; exit 1 prints every
violation as ``relative/path:line-or-0: rule: detail`` sorted and deduplicated.
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

# Backend DTOs sanctioned to appear in nazo-crypto's public API (and therefore
# in upper layers). Any other backend type re-export or signature path leaks.
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

# The six capability features are the architectural contract consumers select;
# their internal member lists are implementation detail and are not frozen.
_CRYPTO_FEATURES = {"aead", "ecdh", "ed25519", "jose", "password", "x509"}
# Types wrapping secret/backend key material: their fields must never be public.
_CRYPTO_OPAQUE_TYPES = {"VerificationKey", "P256SecretKey", "SigningKey", "VerifyingKey"}
_PROVIDER_PREFIX = "rustls::crypto::"
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
_PUB_FN = re.compile(r"\bpub\s+(?:async\s+|unsafe\s+|extern\s+\S+\s+)*fn\s+(\w+)")
_PUB_STRUCT = re.compile(r"\bpub\s+struct\s+(\w+)")
_PUB_ENUM = re.compile(r"\bpub\s+enum\s+(\w+)")
_PUB_TYPE = re.compile(r"\bpub\s+type\s+(\w+)")
_PUB_FIELD = re.compile(r"\bpub(\s*\(\s*crate\s*\))?\s+(\w+)\s*:\s*([^,})]+)")
_ACCESS_IMPL = re.compile(r"\bimpl\b[^{]*\b(?:Deref|DerefMut|AsRef|Borrow)\b")


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
    for manifest_path in manifests:
        manifest = _load_manifest(manifest_path)
        name = manifest.get("package", {}).get("name", "")
        relative = manifest_path.relative_to(root).as_posix()
        is_crypto = manifest_path.parent.resolve() == crypto_dir
        if name == "nazo-crypto" and not is_crypto:
            violations.append(
                f"{relative}:0: crypto identity: package 'nazo-crypto' must live in crates/crypto"
            )
        dependencies = list(
            contracts.resolved_production_dependencies(manifest_path, workspace)
        )
        if is_crypto:
            for package, spec in dependencies:
                if spec["_path"] or package in contracts.PACKAGE_ROLES:
                    violations.append(
                        f"{relative}:0: crypto isolation: local dependency {package}"
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


def _rust_aliases(masked: str, dependency_aliases: dict) -> dict:
    """Map local names to canonical paths via use bindings and extern crates."""
    aliases = dict(dependency_aliases)
    for original, alias in _EXTERN.findall(masked):
        aliases[alias] = contracts.resolved_rust_path(original, aliases)
    for match in _USES.finditer(masked):
        for imported, alias in contracts.rust_use_bindings(match[1]):
            if alias not in {"*", "_"} and imported != alias:
                aliases[alias] = contracts.resolved_rust_path(imported, aliases)
    return aliases


def _backend_roots() -> set:
    return {name.replace("-", "_") for name in BACKEND_PACKAGES}


def _is_backend_path(path: str) -> bool:
    """A path rooted at a concrete backend, or a TLS provider type."""
    return (
        path.partition("::")[0] in _backend_roots()
        or path.startswith(_PROVIDER_PREFIX)
    )


def _backend_paths(region: str, aliases: dict | None = None):
    """Yield (position, resolved-path) for backend/provider paths in a region."""
    aliases = aliases or {}
    for match in _QUALIFIED.finditer(region):
        path = contracts.resolved_rust_path(match[0], aliases)
        if _is_backend_path(path):
            yield match.start(), path
    for alias, target in aliases.items():
        if not _is_backend_path(target):
            continue
        for match in re.finditer(rf"(?<![\w:]){re.escape(alias)}\b(?!\s*::)", region):
            yield match.start(), target


def _tuple_fields(decl: str):
    """Yield the field texts of a tuple-struct declaration body `(a, b, c)`."""
    paren = decl.find("(")
    if paren == -1:
        return
    field_start = paren + 1
    depth = 0
    for index in range(paren, len(decl)):
        char = decl[index]
        depth += char in "(<["
        depth -= char in ")>]"
        if char == "," and depth == 1:
            yield decl[field_start:index]
            field_start = index + 1
        elif depth == 0:
            yield decl[field_start:index]
            return


def _crypto_source_violations(relative: str, masked: str, dependency_aliases: dict) -> list:
    """Check that crates/crypto's public surface never leaks backend types.

    Free functions, methods, modules, and type names are unconstrained — only
    backend key/provider/error/type leakage and provider-style abstractions are
    violations. Sanctioned DTO leaves are exempt.
    """
    aliases = _rust_aliases(masked, dependency_aliases)
    allowed_dto = DTO_EXPORTS.get(Path(relative).stem, set())
    violations = []

    def leaked(path: str) -> bool:
        return path.rpartition("::")[2] not in allowed_dto and _is_backend_path(path)

    for match in _PUB_USES.finditer(masked):
        for imported, _alias in contracts.rust_use_bindings(match[1]):
            resolved = contracts.resolved_rust_path(imported, aliases)
            if leaked(resolved):
                violations.append((
                    match.start(), "crypto public surface",
                    f"backend re-export {resolved}",
                ))
    for match in _PUB_FN.finditer(masked):
        region = _decl_region(masked, match.end())
        for _pos, path in _backend_paths(region, aliases):
            if path in _ALLOWED_SIGNATURE_PATHS or not leaked(path):
                continue
            violations.append((
                match.start(), "crypto public surface",
                f"backend path {path} in public signature",
            ))
    for match in _PUB_STRUCT.finditer(masked):
        opaque = match[1] in _CRYPTO_OPAQUE_TYPES
        region = _brace_region(masked, match.end())
        for field in _PUB_FIELD.finditer(region):
            crate_visible, field_name, field_type = field[1], field[2], field[3]
            if crate_visible and Path(relative).stem == "jwt" and field_name == "inner":
                continue
            paths = [p for _p, p in _backend_paths(field_type, aliases) if leaked(p)]
            if paths:
                violations.append((
                    match.start(), "crypto public surface",
                    f"public field {field_name} exposes {paths[0]}",
                ))
            elif opaque and not crate_visible:
                violations.append((
                    match.start(), "crypto public surface",
                    f"public field {field_name} on opaque type {match[1]}",
                ))
        for field in _tuple_fields(_decl_region(masked, match.end())):
            stripped = re.sub(r"^#\[[^\]]*\]\s*", "", field.strip())
            if not re.match(r"pub\b", stripped) or re.match(r"pub\s*\(", stripped):
                continue
            field_type = stripped[3:].strip()
            paths = [p for _p, p in _backend_paths(field_type, aliases) if leaked(p)]
            if paths:
                violations.append((
                    match.start(), "crypto public surface",
                    f"public tuple field exposes {paths[0]}",
                ))
            elif opaque:
                violations.append((
                    match.start(), "crypto public surface",
                    f"public tuple field on opaque type {match[1]}",
                ))
    for match in list(_PUB_ENUM.finditer(masked)) + list(_PUB_TYPE.finditer(masked)):
        region = _brace_region(masked, match.end())
        for _pos, path in _backend_paths(region, aliases):
            if not leaked(path):
                continue
            violations.append((
                match.start(), "crypto public surface",
                f"public type exposes {path}",
            ))
            break
    # Accessor-style impls are allowed; they fail only when the impl itself
    # names a concrete backend or secret representation.
    for match in _ACCESS_IMPL.finditer(masked):
        region = _brace_region(masked, match.start())
        for _pos, path in _backend_paths(region, aliases):
            if leaked(path):
                violations.append((
                    match.start(), "crypto public surface",
                    f"Deref/AsRef/Borrow impl exposes {path}",
                ))
                break
    return violations


def source_violations(root: Path) -> list:
    """Check production sources for backend paths and banned native calls."""
    violations = []
    workspace = _load_manifest(root / "Cargo.toml").get("workspace", {})
    crypto_dir = (root / "crates" / "crypto").resolve()
    backend_rust = _backend_roots()
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
                    relative, masked, dependency_aliases
                ):
                    violations.append(
                        f"{relative}:{_line_number(text, position)}: {rule}: {detail}"
                    )
                continue
            aliases = _rust_aliases(masked, dependency_aliases)
            candidates = [
                (m.start(), i)
                for m in _USES.finditer(masked)
                for i, _a in contracts.rust_use_bindings(m[1])
            ]
            candidates.extend(
                (m.start(), m[0]) for m in _QUALIFIED.finditer(masked)
            )
            reported = set()
            for position, candidate in candidates:
                resolved = contracts.resolved_rust_path(candidate, aliases)
                root_name = resolved.partition("::")[0]
                if resolved.startswith("x509_parser::") and resolved.endswith(
                    "::verify_signature"
                ):
                    violations.append(
                        f"{relative}:{_line_number(text, position)}: "
                        f"native verify_signature call: {resolved} outside nazo-crypto"
                    )
                detail = None
                if root_name in backend_rust:
                    detail = f"backend path {resolved}"
                elif resolved.startswith(_PROVIDER_PREFIX):
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
