"""Verify separate native and Workers production dependency closures."""

import re
import subprocess


FORBIDDEN_PACKAGES = {
    "nazo-server", "nazo-http-actix", "nazo-postgres", "nazo-valkey",
    "nazo-oauth-server-postgres", "nazo-oauth-server-valkey",
    "nazo-oauth-server-object-store",
    "nazo-kevy", "kevy-embedded", "kevy-store",
    "actix-web", "actix-http", "actix-server", "axum", "hyper", "reqwest",
    "diesel", "diesel-async", "tokio-postgres", "rusqlite", "libsqlite3-sys",
    "fred", "redis", "rustls", "native-tls", "openssl-sys", "aws-lc-sys",
    "process-wrap",
}
FORBIDDEN_TOKIO_FEATURES = {"full", "rt", "rt-multi-thread", "net", "process", "fs", "time", "signal"}
WORKER_PACKAGES = {
    "nazo-server-worker", "nazo-http-worker", "nazo-oauth-server-d1",
    "worker", "worker-sys", "worker-macros", "wasm-bindgen", "js-sys",
    "web-sys", "wasm-streams", "rusqlite", "libsqlite3-sys",
}


def packages(tree: str):
    for line in tree.splitlines():
        match = re.match(r"(\S+) v\S+(?: \([^)]*\))?\s*(.*)", line)
        if match is not None:
            name, features = match.groups()
            yield name, set(filter(None, features.replace("(*)", "").strip().split(",")))


def violations(tree: str) -> list[str]:
    errors = []
    for name, active in packages(tree):
        if name in FORBIDDEN_PACKAGES:
            errors.append(f"native dependency in Worker: {name}")
        if name == "tokio":
            for feature in sorted(active & FORBIDDEN_TOKIO_FEATURES):
                errors.append(f"native Tokio execution feature in Worker: {feature}")
        if name == "nazoauth" and "deployment-control" in active:
            errors.append("native deployment-control facade in Worker")
        if name == "nazo-crypto" and "certificate-issuance" in active:
            errors.append("native certificate provisioning in Worker")
    return errors


def native_violations(tree: str) -> list[str]:
    return [
        f"Worker dependency in native server: {name}"
        for name, _ in packages(tree) if name in WORKER_PACKAGES
    ]


def kevy_violations(tree: str) -> list[str]:
    errors = native_violations(tree)
    for name, active in packages(tree):
        if name in {"fred", "redis", "nazo-valkey", "nazo-oauth-server-valkey"}:
            errors.append(f"Valkey transport dependency in embedded server: {name}")
        if name == "kevy-embedded" and active - {"core", "persist"}:
            errors.append("embedded server enables an unused Kevy subsystem")
    return errors


def production_tree(package: str, target: str, *, no_default_features: bool = False,
                    features: str | None = None) -> str:
    return subprocess.check_output([
        "cargo", "tree", "--locked", "--target", target,
        *(["--no-default-features"] if no_default_features else []),
        *(["--features", features] if features else []),
        "-p", package, "--edges", "normal,no-proc-macro", "--prefix", "none",
        "--format", "{p} {f}",
    ], text=True)


def main() -> None:
    host = next(line.split(": ", 1)[1] for line in subprocess.check_output(
        ["rustc", "-vV"], text=True).splitlines() if line.startswith("host: "))
    native_tree = production_tree("nazo-server", host)
    embedded_tree = production_tree("nazo-server", host, no_default_features=True, features="kevy")
    target = "wasm32-unknown-unknown"
    tree = production_tree("nazo-server-worker", target, no_default_features=True)
    errors = native_violations(native_tree) + kevy_violations(embedded_tree) + violations(tree)
    if any(name == "nazo-kevy" for name, _ in packages(native_tree)):
        errors.append("default server includes the optional embedded backend")
    actix_tree = production_tree("nazo-http-actix", host)
    if any(name == "nazoauth" and "deployment-control" in active for name, active in packages(actix_tree)):
        errors.append("Actix adapter enables deployment-control")
    if errors:
        raise SystemExit("\n".join(errors))
    subprocess.run([
        "cargo", "check", "--locked", "--no-default-features", "--target", target, "-p", "nazo-server-worker",
    ], check=True)
    print("Native production graph: no Worker, D1 or WASM runtime dependencies")
    print("Embedded production graph: no Valkey transport; Kevy core/persist only")
    print("Workers production graph: no native execution dependencies")


if __name__ == "__main__":
    main()
