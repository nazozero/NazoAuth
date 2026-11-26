"""Pin the isolated Hydra benchmark's signing configuration via its Admin API."""
import base64
import json

from cryptography.hazmat.primitives.asymmetric import rsa

from api import Api

KEY_ID = "machine-retest-rsa-2048"


def encoded(value):
    return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).decode().rstrip("=")


def configure(public_api):
    path = "/.well-known/jwks.json"
    current, _, _ = public_api.call("GET", path)
    if any(key.get("kid", "").endswith(KEY_ID) for key in current["keys"]):
        return

    numbers = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_numbers()
    public = {
        "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "public:" + KEY_ID,
        "n": encoded(numbers.public_numbers.n), "e": encoded(numbers.public_numbers.e),
    }
    private = {
        **public, "kid": "private:" + KEY_ID, "d": encoded(numbers.d),
        "p": encoded(numbers.p), "q": encoded(numbers.q), "dp": encoded(numbers.dmp1),
        "dq": encoded(numbers.dmq1), "qi": encoded(numbers.iqmp),
    }
    admin = Api(public_api.host, 8081)
    admin.call("PUT", "/admin/keys/hydra.jwt.access-token", {"keys": [private, public]})


if __name__ == "__main__":
    configure(Api("oidc-bench-hydra"))
