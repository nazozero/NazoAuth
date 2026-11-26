"""Build a private Goose request set from OAuth clients provisioned by the service API."""
import argparse
import base64
import json
import os
import random
import ssl
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from urllib.error import HTTPError

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def auth(client):
    raw = (client["id"] + ":" + client["secret"]).encode()
    return [("Authorization", "Basic " + base64.b64encode(raw).decode())]


def form(operation, url, values, headers):
    return {"operation": operation, "method": "POST", "url": url,
            "headers": [("Content-Type", "application/x-www-form-urlencoded"), *headers],
            "body": urlencode(values)}


def call(opener, request):
    data = request.get("body")
    try:
        with opener.open(Request(request["url"], data.encode() if data is not None else None,
                                 dict(request.get("headers", [])), method=request.get("method", "GET")),
                         timeout=8) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        # The response may include sensitive data. Keep just status.
        return error.code, {}


def proof(token, keys, issuer):
    parts = token.split(".")
    header = json.loads(b64(parts[0])) if len(parts) in (3, 5) else {}
    result = {"parts": len(parts), "alg": header.get("alg"), "enc": header.get("enc")}
    if header.get("alg") == "RS256" and keys is not None:
        h, p, sig = parts
        jwk = next(k for k in keys["keys"] if k["kid"] == header["kid"])
        n = int.from_bytes(b64(jwk["n"]), "big")
        e = int.from_bytes(b64(jwk["e"]), "big")
        key = rsa.RSAPublicNumbers(e, n).public_key()
        key.verify(b64(sig), f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        claims = json.loads(b64(p))
        if issuer:
            assert claims["iss"] == issuer
        result.update(rsa_bits=key.key_size, jwt_lifetime=claims["exp"] - claims["iat"], signature_verified=True)
    return result


def build(profile, count, seed, opener):
    keys = None
    headers = list(profile.get("headers", {}).items())
    if profile.get("jwks"):
        status, keys = call(opener, {"url": profile["jwks"], "headers": headers})
        assert status == 200
    issue, inspect, unique, proofs = [], [], set(), []
    for client in profile["clients"]:
        params = {"grant_type": "client_credentials", "scope": profile["scope"]}
        style = profile.get("token_auth", "basic")
        assert style in ("basic", "form")
        if style == "form":
            params.update(client_id=client["id"], client_secret=client["secret"])
        request = form("machine", profile["token"], params, headers + (auth(client) if style == "basic" else []))
        issue.append(request)
        for _ in range(count):
            status, response = call(opener, request)
            assert status == 200 and response["token_type"].lower() == "bearer"
            token = response["access_token"]
            if profile.get("admin_introspection"):
                from hydra_signing import KEY_ID
                header = token.split(".")[0]
                import base64
                assert json.loads(base64.urlsafe_b64decode(header + "==="))["kid"].endswith(KEY_ID)
            assert token
            unique.add(token)
            req = form("introspect", profile["introspect"], {"token": token, "token_type_hint": "access_token"},
                       headers + ([] if profile.get("admin_introspection") else auth(client)))
            status, active = call(opener, req)
            assert status == 200 and active["active"] is True
            p = proof(token, keys, profile.get("issuer"))
            p.update(expires_in=response["expires_in"], scope=active.get("scope", response.get("scope")))
            if p not in proofs:
                proofs.append(p)
            inspect.append(req)
    random.Random(seed).shuffle(inspect)
    return issue, inspect, {"clients": len(issue), "tokens_requested": len(inspect), "unique_tokens": len(unique),
                            "all_introspected_active": True, "observed_tokens": proofs}


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--per-client", type=int, default=32)
    parser.add_argument("--seed", type=int, default=19716)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_bytes())
    assert profile["clients"] and args.per_client > 0
    context = ssl.create_default_context(cafile=profile.get("ca"))
    opener = build_opener(HTTPSHandler(context=context), NoRedirect())
    issue, inspect, result = build(profile, args.per_client, args.seed, opener)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, requests in (("machine", issue), ("introspect", inspect)):
        (args.output / (name + ".json")).write_text(json.dumps(requests))
    print(json.dumps(result, indent=2))
