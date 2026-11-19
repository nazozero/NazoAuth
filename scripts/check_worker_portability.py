"""Verify the concrete Workers host's WASM production dependency closure."""

import re
import subprocess


FORBIDDEN_PACKAGES = {
    "nazo-server", "nazo-http-actix", "nazo-postgres", "nazo-valkey",
    "nazo-oauth-server-postgres", "nazo-oauth-server-valkey",
    "actix-web", "actix-http", "actix-server", "axum", "hyper", "reqwest",
    "diesel", "diesel-async", "tokio-postgres", "rusqlite", "libsqlite3-sys",
    "fred", "redis", "rustls", "native-tls", "openssl-sys", "aws-lc-sys",
    "process-wrap",
}
FORBIDDEN_TOKIO_FEATURES = {"full", "rt", "rt-multi-thread", "net", "process", "fs", "time", "signal"}


def violations(tree: str) -> list[str]:
    errors = []
    for line in tree.splitlines():
        match = re.match(r"(\S+) v\S+(?: \([^)]*\))?\s*(.*)", line)
        if match is None:
            continue
        name, features = match.groups()
        if name in FORBIDDEN_PACKAGES:
            errors.append(f"native dependency in Worker: {name}")
        if name == "tokio":
            active = set(features.replace(" (*)", "").split(","))
            for feature in sorted(active & FORBIDDEN_TOKIO_FEATURES):
                errors.append(f"native Tokio execution feature in Worker: {feature}")
    return errors


def main() -> None:
    target = "wasm32-unknown-unknown"
    tree = subprocess.check_output([
        "cargo", "tree", "--locked", "--target", target,
        "-p", "nazo-server-worker", "--edges", "normal", "--prefix", "none",
        "--format", "{p} {f}",
    ], text=True)
    errors = violations(tree)
    if errors:
        raise SystemExit("\n".join(errors))
    subprocess.run([
        "cargo", "check", "--locked", "--target", target, "-p", "nazo-server-worker",
    ], check=True)
    print("Workers production graph: no native execution dependencies")


if __name__ == "__main__":
    main()
