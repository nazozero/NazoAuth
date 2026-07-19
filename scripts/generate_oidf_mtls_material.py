#!/usr/bin/env python3
"""Generate a dedicated RFC 5280 mTLS CA and client identities for OIDF plans."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


CLIENT_BINDINGS = (("client", "mtls"), ("client2", "mtls2"))


def fail(message: str) -> None:
    raise SystemExit(message)


def run(command: list[str], *, cwd: Path) -> None:
    try:
        subprocess.run(command, cwd=cwd, check=True, capture_output=True)
    except FileNotFoundError as error:
        fail("openssl is required to generate OIDF mTLS material")
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode("utf-8", errors="replace").strip()
        fail(f"openssl failed while generating OIDF mTLS material: {detail}")


def read_config(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read OIDF public config {path}: {error}")
    if not isinstance(value, dict):
        fail(f"OIDF public config {path} must contain an object")
    return value


def required_client_ids(config_directory: Path) -> set[str]:
    result: set[str] = set()
    config_paths = sorted(config_directory.glob("oidf-*.json"))
    if not config_paths:
        fail("OIDF public config directory contains no oidf-*.json plan configs")
    for path in config_paths:
        config = read_config(path)
        for client_field, mtls_field in CLIENT_BINDINGS:
            mtls = config.get(mtls_field)
            if mtls is None:
                continue
            if not isinstance(mtls, dict) or not isinstance(mtls.get("cert"), str):
                fail(f"{path.name}.{mtls_field} must contain a public certificate")
            client = config.get(client_field)
            client_id = client.get("client_id") if isinstance(client, dict) else None
            if not isinstance(client_id, str) or not client_id:
                fail(f"{path.name}.{client_field}.client_id is required for {mtls_field}")
            result.add(client_id)
    if not result:
        fail("OIDF public plan configs contain no mTLS clients")
    return result


def generate_ca(work: Path) -> tuple[Path, Path]:
    key = work / "ca.key.pem"
    certificate = work / "ca.cert.pem"
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-sha256",
            "-nodes",
            "-days",
            "825",
            "-subj",
            "/CN=OIDF Conformance mTLS Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        cwd=work,
    )
    return key, certificate


def generate_client(
    work: Path,
    ca_key: Path,
    ca_certificate: Path,
    logical_client_id: str,
) -> dict[str, str]:
    identifier = hashlib.sha256(logical_client_id.encode("utf-8")).hexdigest()[:24]
    key = work / f"client-{identifier}.key.pem"
    request = work / f"client-{identifier}.csr.pem"
    certificate = work / f"client-{identifier}.cert.pem"
    extensions = work / f"client-{identifier}.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=clientAuth\n",
        encoding="ascii",
    )
    run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-subj",
            f"/CN=oidf-client-{identifier}",
            "-keyout",
            str(key),
            "-out",
            str(request),
        ],
        cwd=work,
    )
    run(
        [
            "openssl",
            "x509",
            "-req",
            "-sha256",
            "-days",
            "397",
            "-in",
            str(request),
            "-CA",
            str(ca_certificate),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-extfile",
            str(extensions),
            "-out",
            str(certificate),
        ],
        cwd=work,
    )
    run(
        ["openssl", "verify", "-CAfile", str(ca_certificate), str(certificate)],
        cwd=work,
    )
    return {
        "cert": certificate.read_text(encoding="ascii"),
        "key": key.read_text(encoding="ascii"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-config-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        fail(f"output already exists: {args.output}")
    client_ids = required_client_ids(args.public_config_directory)
    with tempfile.TemporaryDirectory(prefix="oidf-mtls-") as temporary:
        work = Path(temporary)
        ca_key, ca_certificate = generate_ca(work)
        clients = {
            client_id: generate_client(work, ca_key, ca_certificate, client_id)
            for client_id in sorted(client_ids)
        }
        material = {
            "schema": 1,
            "ca": ca_certificate.read_text(encoding="ascii"),
            "clients": clients,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(material, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(args.output, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
