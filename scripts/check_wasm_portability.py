#!/usr/bin/env python3
"""Compile the architecture-owned inner boundary and inspect its WASM runtime graph."""

from __future__ import annotations

import argparse
import subprocess

import verify_static_contracts as contracts

TARGET = "wasm32-unknown-unknown"
PORTABLE_CRYPTO_FEATURES = ("jose", "ecdh", "aead", "password", "ed25519", "x509")
# C helpers and procedural macros execute on the build host; this check follows
# normal dependencies only. AWS-LC/OpenSSL are native algorithm backends, not
# portable data types such as rustls-pki-types or webpki-roots.
NATIVE_PACKAGES = contracts.EXECUTION_DEPENDENCIES | {
    "aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys", "openssl", "openssl-sys",
    "native-tls", "socket2", "mio",
}
NATIVE_FEATURES = {
    "jiff": {"tz-system", "tzdb-zoneinfo", "tzdb-concatenated"},
    "nazo-crypto": {"certificate-issuance"},
}


def runtime_violations(tree: str) -> set[str]:
    """Cargo resolves package aliases; {f} exposes active transitive features."""
    packages = set()
    native = set()
    for line in tree.splitlines():
        if not line.strip():
            continue
        identity, _, features = line.partition("|")
        package = identity.split()[0]
        packages.add(package)
        active = set(features.removesuffix(" (*)").strip().split(","))
        native.update(
            f"{package}/{feature}"
            for feature in active & NATIVE_FEATURES.get(package, set())
        )
    native.update(packages & NATIVE_PACKAGES)
    native.update(
        package for package in packages
        if contracts.PACKAGE_ROLES.get(package) in {"host", "adapter", "http-adapter"}
    )
    return native


def check(packages: tuple[str, ...]) -> None:
    selection = [argument for package in packages for argument in ("-p", package)]
    common = ["--target", TARGET, "--locked", *selection]
    if "nazo-crypto" in packages:
        common.extend([
            "--features", ",".join(f"nazo-crypto/{feature}" for feature in PORTABLE_CRYPTO_FEATURES),
        ])
    tree = subprocess.check_output(
        ["cargo", "tree", *common, "--edges", "normal,no-proc-macro", "--prefix", "none", "--format", "{p}|{f}"],
        cwd=contracts.ROOT,
        text=True,
    )
    violations = runtime_violations(tree)
    if violations:
        raise SystemExit(
            f"{', '.join(packages)} has native WASM runtime dependencies: "
            + ", ".join(sorted(violations))
        )
    print(f"Checking {', '.join(packages)} for {TARGET}", flush=True)
    subprocess.run(
        ["cargo", "check", "--lib", *common], cwd=contracts.ROOT, check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print the architecture-owned package set")
    args = parser.parse_args()
    if args.list:
        print("\n".join(contracts.PORTABLE_PACKAGES))
        return
    read_manifest = contracts.manifest_reader()
    contracts.check_package_roles(read_manifest)
    contracts.check_inner_source_boundaries(read_manifest)
    # Separate checks catch accidental feature-unification dependencies. The
    # combined check covers all portable crypto capabilities together. Local
    # certificate provisioning is an explicit native-host capability, excluded
    # from this graph rather than silently removed from protocol behavior.
    for package in contracts.PORTABLE_PACKAGES:
        check((package,))
    check(contracts.PORTABLE_PACKAGES)


if __name__ == "__main__":
    main()
