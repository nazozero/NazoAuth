"""Install the WASM test runner matching the ABI in the workspace lockfile."""

import subprocess
import tomllib
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    with (root / "Cargo.lock").open("rb") as lockfile:
        packages = tomllib.load(lockfile)["package"]
    version = next(package["version"] for package in packages if package["name"] == "wasm-bindgen")
    subprocess.run(["cargo", "install", "wasm-bindgen-cli", "--version", version, "--locked"], cwd=root, check=True)


if __name__ == "__main__":
    main()
