"""Prepare single-use ES256 client assertions for the existing Goose driver.

Use the private state produced by provision.py. Run this again before every
window: reusing an assertion fixture measures rejected replays, not issuance.
Only the proof summary is public; the output request file contains credentials.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
from urllib.parse import urlencode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from api import Api, ApiError, compact


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def prepare(state, target, rate, warm, seconds, host, port):
    if min(rate, warm, seconds) <= 0 or warm + seconds >= 295:
        raise ValueError("positive windows must fit the 300-second assertion lifetime")
    api = Api(host, port)
    try:
        api.login(state["admin"])
    except ApiError as error:
        # A preceding fixture can have consumed this TOTP time step. This wait
        # is preparation, before assertions are signed or measurement starts.
        totp = state["admin"].get("totp")
        if error.status != 400 or not totp or json.loads(api.last_body).get("error") != "invalid_grant":
            raise
        period = int(totp["period"])
        time.sleep(period - time.time() % period + .1)
        api = Api(host, port)
        api.login(state["admin"])
    key = state["dpop_private_jwk"]
    public = {field: key[field] for field in ("kty", "crv", "x", "y")}
    public.update(kid="goose-client-assertion", alg="ES256", use="sig")
    client, _, _ = api.call("POST", "/admin/clients", {
        "client_name": "Goose durable assertion replay",
        "client_type": "confidential", "redirect_uris": [state["redirect_uri"]],
        "allowed_audiences": ["resource://default"], "scopes": ["profile"],
        "grant_types": ["client_credentials"], "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256", "jwks": {"keys": [public]},
    }, (201,))
    client_id = client["client_id"]
    secret = base64.urlsafe_b64decode(key["d"] + "=" * (-len(key["d"]) % 4))
    signing_key = ec.derive_private_key(int.from_bytes(secret, "big"), ec.SECP256R1())
    header = b64(compact({"alg": "ES256", "typ": "JWT", "kid": public["kid"]}).encode())
    run_id = secrets.token_hex(16)

    def fields(slot, issued):
        claims = {"iss": client_id, "sub": client_id, "aud": state["issuer"],
                  "iat": issued, "exp": issued + 300, "jti": f"{run_id}:{slot}"}
        content = f"{header}.{b64(compact(claims).encode())}".encode()
        r, s = utils.decode_dss_signature(signing_key.sign(content, ec.ECDSA(hashes.SHA256())))
        assertion = content.decode() + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return {"grant_type": "client_credentials", "client_id": client_id, "scope": "profile",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion}

    probe = fields("probe", int(time.time()))
    grant, _, _ = api.form("POST", "/token", probe)
    if not grant.get("access_token") or grant.get("token_type", "").lower() != "bearer":
        raise RuntimeError("client assertion preflight did not issue a bearer token")
    rejected, _, _ = api.form("POST", "/token", probe, expected=(400, 401))
    if rejected.get("error") != "invalid_client":
        raise RuntimeError("repeated assertion was not rejected as invalid_client")
    issued = int(time.time())
    count = rate * (warm + seconds)
    url = f"http://{host}:{port}/token"
    latest_start = issued + 300 - warm - seconds - 5
    with target.open("x") as output:
        output.write("[")
        for slot in range(count):
            if slot:
                output.write(",")
            json.dump({"method": "POST", "url": url, "operation": "machine",
                       "headers": [["Host", "localhost:8080"], ["Content-Type", "application/x-www-form-urlencoded"]],
                       "body": urlencode(fields(slot, issued))}, output, separators=(",", ":"))
        output.write("]")
    if time.time() > latest_start:
        raise RuntimeError("assertion preparation exhausted the measurement expiry budget")
    with target.open("rb") as source:
        fixture_hash = hashlib.file_digest(source, "sha256").hexdigest()
    return {"fixture_contract": "single-use-private-key-jwt", "algorithm": "ES256",
            "fixtures": count, "rate": rate, "warm_seconds": warm, "seconds": seconds,
            "fixture_sha256": fixture_hash,
            "latest_safe_start_epoch": latest_start,
            "successful_grant_verified": True, "repeated_assertion_rejected": True}


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--rate", type=int, required=True)
    parser.add_argument("--warm-seconds", type=int, default=10)
    parser.add_argument("--seconds", type=int, default=36)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    proof = prepare(json.loads(args.state.read_text()), args.output, args.rate,
                    args.warm_seconds, args.seconds, args.host, args.port)
    print(json.dumps(proof, indent=2))
