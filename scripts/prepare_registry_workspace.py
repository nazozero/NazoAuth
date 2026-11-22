"""Prepare a checkout of HEAD for Cargo's registry packaging commands."""

import argparse
import shutil
import subprocess
import tomllib
from pathlib import Path


def prepare(destination: Path) -> None:
    source = Path(__file__).resolve().parents[1]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    destination.mkdir(parents=True, exist_ok=False)
    subprocess.run(["git", "clone", "--quiet", "--shared", "--no-checkout", str(source), "."],
                   cwd=destination, check=True)
    subprocess.run(["git", "checkout", "--quiet", "--detach", revision], cwd=destination, check=True)

    root = destination / "Cargo.toml"
    manifest = root.read_text(encoding="utf-8")
    workspace = tomllib.loads(manifest)["workspace"]
    version = workspace["package"]["version"]
    registry_packages = set()
    for path in sorted((destination / "crates").glob("*/Cargo.toml")):
        package = tomllib.loads(path.read_text(encoding="utf-8"))["package"]
        if package["publish"] == {"workspace": True}:
            registry_packages.add(package["name"])
            shutil.copyfile(destination / "LICENSE", path.parent / "LICENSE")

    requirements = [
        f'{name}.version = "={version}"'
        for name, spec in workspace["dependencies"].items()
        if isinstance(spec, dict) and "path" in spec and spec.get("package", name) in registry_packages
    ]
    manifest = manifest.replace("publish = false\n", 'publish = ["crates-io"]\n', 1)
    manifest = manifest.replace("[workspace.dependencies]\n",
                                "[workspace.dependencies]\n" + "\n".join(requirements) + "\n", 1)
    root.write_text(manifest, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new directory for the prepared checkout")
    prepare(parser.parse_args().destination)
