"""Prepare a checkout of HEAD for Cargo's registry packaging commands."""

import argparse
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path


def prepare_manifests(destination: Path) -> None:
    root = destination / "Cargo.toml"
    manifest = root.read_text(encoding="utf-8")
    workspace = tomllib.loads(manifest)["workspace"]
    version = workspace["package"]["version"]
    registry_packages = set()
    for path in (destination / "crates").glob("*/Cargo.toml"):
        package = tomllib.loads(path.read_text(encoding="utf-8"))["package"]
        if package.get("publish") is False:
            continue
        if package.get("publish") != {"workspace": True}:
            raise ValueError(f"{path}: set publish.workspace = true or publish = false")
        registry_packages.add(package["name"])
        shutil.copyfile(destination / "LICENSE", path.parent / "LICENSE")

    requirements = [
        f'{name}.version = "={version}"'
        for name, spec in workspace["dependencies"].items()
        if isinstance(spec, dict) and "path" in spec and spec.get("package", name) in registry_packages
    ]
    manifest = manifest.replace("publish = false\n", 'publish = ["crates-io"]\n', 1)
    manifest = manifest.replace(
        "[workspace.dependencies]\n", "[workspace.dependencies]\n" + "\n".join(requirements) + "\n", 1
    )
    if tomllib.loads(manifest)["workspace"]["package"]["publish"] != ["crates-io"]:
        raise ValueError("registry checkout must select crates-io")
    root.write_text(manifest, encoding="utf-8")


def prepare(destination: Path) -> None:
    source = Path(__file__).resolve().parents[1]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp:
        checkout = Path(temp) / "checkout"
        subprocess.run(
            ["git", "clone", "--quiet", "--shared", "--no-checkout", str(source), str(checkout)], check=True
        )
        subprocess.run(["git", "checkout", "--quiet", "--detach", revision], cwd=checkout, check=True)
        prepare_manifests(checkout)
        checkout.rename(destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new directory for the prepared checkout")
    prepare(parser.parse_args().destination)
