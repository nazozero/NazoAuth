#!/usr/bin/env python3
"""Check the resolved native transport graph, including feature unification."""
import json
import subprocess


def main():
    host = next(line.split(": ", 1)[1] for line in subprocess.check_output(
        ["rustc", "-vV"], text=True).splitlines() if line.startswith("host: "))
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--format-version", "1", "--locked",
        "--all-features", "--filter-platform", host,
    ], text=True))
    packages = {package["id"]: package for package in metadata["packages"]}
    errors = []
    for node in metadata["resolve"]["nodes"]:
        package = packages[node["id"]]
        name = package["name"]
        if name in {"actix-web", "actix-http", "actix-router"}:
            if not (package.get("source") or "").startswith("registry+"):
                errors.append(f"{name} must use an official registry release")
            if "http2" in node["features"]:
                errors.append(f"{name}/http2 is enabled by feature unification")
        if name == "actix-http":
            version = tuple(int(part) for part in package["version"].split("-")[0].split("."))
            if version < (3, 21, 3):
                errors.append(
                    f"actix-http {package['version']} is affected by "
                    "RUSTSEC-2026-0552, RUSTSEC-2026-0553 or RUSTSEC-2026-0554"
                )
        if name == "h2":
            version = tuple(int(part) for part in package["version"].split("-")[0].split("."))
            if version < (0, 4, 16):
                errors.append(f"h2 {package['version']} is affected by RUSTSEC-2026-0258")
    if errors:
        raise SystemExit("\n".join(errors))
    print("Native transport: patched official Actix, inbound HTTP/2 disabled, no affected h2 version")


if __name__ == "__main__":
    main()
