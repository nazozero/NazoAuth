"""Run in the perf runner: python -m unittest perf.tests.test_seed_jwk -v."""
import base64
import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from perf.seed import ec_private_jwk, ec_public_jwk


class EcJwkEncodingTests(unittest.TestCase):
    def test_p256_fields_keep_leading_zero_octets(self):
        # Fixed scalars cover short d and both short public coordinates.
        covered = set()
        for scalar in (1, 43, 379):
            key = ec.derive_private_key(scalar, ec.SECP256R1())
            public = key.public_key().public_numbers()
            if public.x.bit_length() <= 248:
                covered.add("x")
            if public.y.bit_length() <= 248:
                covered.add("y")
            for jwk in (ec_public_jwk(key, "test"), ec_private_jwk(key, "test")):
                for field in ("x", "y", "d"):
                    if field in jwk:
                        raw = base64.urlsafe_b64decode(jwk[field] + "=" * (-len(jwk[field]) % 4))
                        with self.subTest(scalar=scalar, field=field):
                            self.assertEqual(len(raw), 32)
                        expected = scalar if field == "d" else getattr(public, field)
                        self.assertEqual(int.from_bytes(raw, "big"), expected)
        self.assertEqual(covered, {"x", "y"})


if __name__ == "__main__":
    unittest.main()
