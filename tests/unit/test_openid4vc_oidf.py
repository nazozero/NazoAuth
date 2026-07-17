import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class Openid4vcOidfTests(unittest.TestCase):
    def test_tokenless_openid4vc_driver_is_restricted_to_local_suite(self):
        module = load("run_openid4vc_conformance.py")
        local = module.Openid4vcDriver(
            {
                "conformance_server": "https://localhost:8443",
                "conformance_no_api_token": True,
                "aliases": [],
            },
            module.threading.Event(),
        )
        with patch.object(module, "module_entries", return_value=[]):
            local.drive_once()

        public = module.Openid4vcDriver(
            {
                "conformance_server": "https://www.certification.openid.net",
                "conformance_no_api_token": True,
                "aliases": [],
            },
            module.threading.Event(),
        )
        with self.assertRaisesRegex(RuntimeError, "restricted to loopback"):
            public.drive_once()

    def test_module_entries_merge_runner_exposed_values_with_info_metadata(self):
        module = load("run_openid4vc_conformance.py")
        with (
            patch.object(
                module.oidf,
                "fetch_alias_plans",
                return_value=[
                    {
                        "planName": "oid4vci-1_0-issuer-test-plan",
                        "modules": [{"instances": ["module-id"]}],
                    }
                ],
            ),
            patch.object(
                module.oidf,
                "oidf_api_request",
                side_effect=[
                    (
                        200,
                        {
                            "_id": "module-id",
                            "alias": "issuer-alias",
                            "variant": {
                                "vci_authorization_code_flow_variant": "issuer_initiated"
                            },
                            "status": "WAITING",
                        },
                    ),
                    (
                        200,
                        {
                            "id": "module-id",
                            "exposed": {
                                "credential_offer_endpoint": "https://suite.example/credential_offer"
                            },
                        },
                    ),
                ],
            ) as request,
        ):
            entries = module.module_entries("https://suite.example", None, {"issuer-alias"})

        self.assertEqual(entries[0]["alias"], "issuer-alias")
        self.assertEqual(
            entries[0]["exposed"]["credential_offer_endpoint"],
            "https://suite.example/credential_offer",
        )
        self.assertEqual(
            [call.args[2] for call in request.call_args_list],
            ["api/info/module-id", "api/runner/module-id"],
        )

    def test_module_entries_do_not_fetch_runner_for_non_waiting_modules(self):
        module = load("run_openid4vc_conformance.py")
        with (
            patch.object(
                module.oidf,
                "fetch_alias_plans",
                return_value=[
                    {
                        "planName": "oid4vci-1_0-issuer-test-plan",
                        "modules": [{"instances": ["finished-module"]}],
                    }
                ],
            ),
            patch.object(
                module.oidf,
                "oidf_api_request",
                return_value=(
                    200,
                    {
                        "_id": "finished-module",
                        "alias": "issuer-alias",
                        "status": "FINISHED",
                    },
                ),
            ) as request,
        ):
            entries = module.module_entries("https://suite.example", None, {"issuer-alias"})

        self.assertEqual(entries[0]["_driver_module_id"], "finished-module")
        self.assertEqual(
            [call.args[2] for call in request.call_args_list],
            ["api/info/finished-module"],
        )

    def test_driver_caches_terminal_modules_between_scans(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://localhost:8443",
                "conformance_no_api_token": True,
                "aliases": ["issuer-alias"],
            },
            module.threading.Event(),
        )
        with patch.object(
            module,
            "module_entries",
            return_value=[
                {
                    "_driver_module_id": "finished-module",
                    "_driver_plan": "oid4vci-1_0-issuer-test-plan",
                    "status": "FINISHED",
                }
            ],
        ) as entries:
            driver.drive_once()
            driver.drive_once()

        self.assertEqual(driver.terminal_modules, {"finished-module"})
        self.assertEqual(entries.call_args_list[1].kwargs["ignored_module_ids"], {"finished-module"})

    def test_driver_loop_scans_before_first_sleep(self):
        module = load("run_openid4vc_conformance.py")
        stop = module.threading.Event()
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://localhost:8443",
                "conformance_no_api_token": True,
                "aliases": [],
                "poll_interval_seconds": 60,
            },
            stop,
        )
        calls = 0

        def drive_once() -> None:
            nonlocal calls
            calls += 1
            stop.set()

        with patch.object(driver, "drive_once", side_effect=drive_once):
            driver.run()

        self.assertEqual(calls, 1)

    def test_wrapper_applies_insecure_local_suite_tls_to_parent_driver(self):
        module = load("run_openid4vc_conformance.py")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as config:
            json.dump({"aliases": []}, config)
            config_path = config.name
        module.oidf.OIDF_API_SSL_CONTEXT = None
        try:
            with (
                patch(
                    "sys.argv",
                    [
                        "run_openid4vc_conformance.py",
                        "--driver-config-json-file",
                        config_path,
                        "--",
                        "--disable-ssl-verify",
                    ],
                ),
                patch.object(module.Openid4vcDriver, "run"),
                patch.object(module.subprocess, "run", return_value=type("Result", (), {"returncode": 0})()),
            ):
                self.assertEqual(module.main(), 0)

            self.assertIsNotNone(module.oidf.OIDF_API_SSL_CONTEXT)
        finally:
            module.oidf.OIDF_API_SSL_CONTEXT = None
            Path(config_path).unlink(missing_ok=True)

    def test_driver_callback_get_uses_oidf_ssl_context(self):
        module = load("run_openid4vc_conformance.py")
        context = object()
        module.oidf.OIDF_API_SSL_CONTEXT = context

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def read(self):
                return b""

        try:
            with patch.object(module.urllib.request, "urlopen", return_value=Response()) as urlopen:
                module.get_url("https://localhost:8443/test/a/alias/callback")

            self.assertIs(urlopen.call_args.kwargs["context"], context)
        finally:
            module.oidf.OIDF_API_SSL_CONTEXT = None

    def test_suite_internal_urls_are_rewritten_to_control_plane(self):
        module = load("run_openid4vc_conformance.py")

        rewritten = module.suite_reachable_url(
            "https://localhost:8443",
            "https://suite.example/test/a/issuer/credential_offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer",
        )

        self.assertEqual(
            rewritten,
            "https://suite.example/test/a/issuer/credential_offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer",
        )
        self.assertEqual(
            module.suite_reachable_url(
                "https://localhost:8443",
                "https://certification.openid.net/test/a/issuer/credential_offer",
            ),
            "https://certification.openid.net/test/a/issuer/credential_offer",
        )

    def test_credential_issuer_metadata_is_registered_inside_the_single_well_known_scope(self):
        routes = (ROOT / "crates" / "authorization-server" / "src" / "bootstrap" / "routes.rs").read_text(
            encoding="utf-8"
        )

        self.assertEqual(routes.count('web::scope("/.well-known")'), 1)
        self.assertIn('"/openid-credential-issuer"', routes)
        self.assertNotIn('"/.well-known/openid-credential-issuer"', routes)

    def test_matrix_is_bounded_and_covers_each_final_role_format(self):
        module = load("materialize_openid4vc_oidf_config.py")
        cases = module.matrix_cases()
        self.assertEqual(len(cases), 17)
        self.assertEqual({plan for plan, _, _ in cases}, {
            module.VCI_STANDARD, module.VCI_HAIP, module.VP_STANDARD, module.VP_HAIP
        })
        for plan in (module.VCI_STANDARD, module.VCI_HAIP):
            self.assertEqual({v["credential_format"] for p, _, v in cases if p == plan}, {"sd_jwt_vc", "mdoc"})
        for plan in (module.VP_STANDARD, module.VP_HAIP):
            self.assertEqual({v["credential_format"] for p, _, v in cases if p == plan}, {"sd_jwt_vc", "iso_mdl"})
        self.assertFalse(any("wallet" in plan for plan, _, _ in cases))

    def test_registry_is_alpha_evidence_not_certification_claim(self):
        registry = json.loads((ROOT / "tests" / "contracts" / "openid4vc-oidf-matrix.json").read_text(encoding="utf-8"))
        self.assertEqual(registry["status"], "alpha-regression-not-certification")
        self.assertEqual(registry["roles"], ["issuer", "verifier"])

    def test_openid4vc_target_boundary_allows_external_attester_role(self):
        module = load("run_oidf_conformance.py")

        module.assert_config_target_boundaries(
            {
                "vci": {
                    "credential_issuer_url": "https://issuer.example",
                    "client_attester_issuer": "https://client-attester.example.org",
                }
            },
            "openid4vc-vci-haip-sd-wallet.json",
            "https://issuer.example",
        )
        module.assert_config_target_boundaries(
            {
                "client": {
                    "client_id": "issuer.example",
                    "request_object_trust_anchor_uri": "https://trust-anchor.example.org/root.pem",
                }
            },
            "openid4vc-vp-haip-sd.json",
            "https://issuer.example",
        )

    def test_openid4vc_target_boundary_rejects_local_targets(self):
        module = load("run_oidf_conformance.py")

        with self.assertRaisesRegex(SystemExit, "local-only URL"):
            module.assert_config_target_boundaries(
                {
                    "vci": {
                        "credential_issuer_url": "https://issuer.example",
                        "credential_offer_endpoint": "https://nginx:8443/test/a/issuer/offer",
                    }
                },
                "openid4vc-vci-sd-wallet-plain.json",
                "https://issuer.example",
            )

    def test_openid4vc_target_boundary_requires_role_target_binding(self):
        module = load("run_oidf_conformance.py")

        with self.assertRaisesRegex(SystemExit, "credential_issuer_url"):
            module.assert_config_target_boundaries(
                {"vci": {"credential_issuer_url": "https://wrong.example"}},
                "openid4vc-vci-sd-wallet-plain.json",
                "https://issuer.example",
            )
        with self.assertRaisesRegex(SystemExit, "verifier client_id"):
            module.assert_config_target_boundaries(
                {"client": {"client_id": "wrong.example"}},
                "openid4vc-vp-haip-sd.json",
                "https://issuer.example",
            )

    def test_openid4vc_plan_config_writer_does_not_require_oidc_discovery_url(self):
        module = load("run_oidf_conformance.py")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite_scripts = root / "suite" / "scripts"
            suite_scripts.mkdir(parents=True)
            config_json = root / "configs.json"
            config_json.write_text(
                json.dumps(
                    {
                        "configs": {
                            "openid4vc-vci-sd-wallet-plain.json": {
                                "alias": "openid4vc-vci-sd-wallet-plain",
                                "vci": {
                                    "credential_issuer_url": "https://issuer.example",
                                    "client_attester_issuer": "https://client-attester.example.org",
                                },
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            written, aliases = module.write_plan_configs(
                suite_scripts,
                "ignored.json",
                "OPENID4VC_CONFIGS",
                str(config_json),
                "https://issuer.example",
            )

        self.assertEqual(written, {"openid4vc-vci-sd-wallet-plain.json"})
        self.assertEqual(
            aliases,
            {
                "openid4vc-vci-sd-wallet-plain.json": "openid4vc-vci-sd-wallet-plain"
            },
        )

    def test_openid4vc_issuer_user_reject_module_denies_consent(self):
        module = load("run_oidf_conformance.py")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite_scripts = root / "suite" / "scripts"
            suite_scripts.mkdir(parents=True)
            config_json = root / "configs.json"
            config_json.write_text(
                json.dumps(
                    {
                        "configs": {
                            "openid4vc-vci-haip-sd-wallet.json": {
                                "alias": "openid4vc-vci-haip-sd-wallet",
                                "vci": {"credential_issuer_url": "https://issuer.example"},
                                "nazo": {
                                    "oidf_user_email": "user@example.test",
                                    "oidf_user_password": "correct horse battery staple",
                                },
                                "browser": [
                                    {
                                        "match": "https://issuer.example/authorize*",
                                        "tasks": [
                                            {
                                                "task": "Complete login page",
                                                "match": "https://issuer.example/ui/auth*",
                                                "commands": [],
                                            },
                                            {
                                                "task": "Complete consent page",
                                                "match": "https://issuer.example/ui/consent*",
                                                "commands": [],
                                            },
                                        ],
                                    }
                                ],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            module.write_plan_configs(
                suite_scripts,
                "ignored.json",
                "OPENID4VC_CONFIGS",
                str(config_json),
                "https://issuer.example",
            )
            written = json.loads(
                (suite_scripts / "openid4vc-vci-haip-sd-wallet.json").read_text(
                    encoding="utf-8"
                )
            )

        user_reject_override = written["override"][
            "fapi2-security-profile-final-user-rejects-authentication"
        ]["browser"][0]
        deny_task = user_reject_override["tasks"][1]
        self.assertEqual(deny_task["task"], "Deny consent page")
        self.assertIn(["click", "id", "nazo-consent-deny"], deny_task["commands"])

    def test_verifier_driver_emits_format_specific_dcql_meta(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://localhost:8443",
                "target_origin": "https://issuer.example",
                "verifier": {
                    "management_token": "management-token",
                    "credential_type_values": {
                        "sd_jwt_vc": "urn:eudi:pid:1",
                        "iso_mdl": "org.iso.18013.5.1.mDL",
                    },
                },
            },
            module.threading.Event(),
        )
        cases = {
            "sd_jwt_vc": ("dc+sd-jwt", {"vct_values": ["urn:eudi:pid:1"]}),
            "iso_mdl": ("mso_mdoc", {"doctype_value": "org.iso.18013.5.1.mDL"}),
        }
        for credential_format, (expected_format, expected_meta) in cases.items():
            with self.subTest(credential_format=credential_format), patch.object(
                module,
                "request_json",
                return_value={"authorization_url": "https://localhost:8443/authorize"},
            ) as request, patch.object(module, "get_url"):
                driver.drive_verifier(
                    "module-id",
                    {"alias": "vp-alias", "testName": "oid4vp-1final-verifier-happy-flow"},
                    {
                        "credential_format": credential_format,
                        "client_id_prefix": "x509_san_dns",
                        "request_method": "request_uri_signed",
                        "response_mode": "direct_post.jwt",
                    },
                    False,
                )
                payload = request.call_args.args[3]
                credential = payload["dcql_query"]["credentials"][0]
                self.assertEqual(credential["format"], expected_format)
                self.assertEqual(credential["meta"], expected_meta)
                self.assertEqual(payload["request_method"], "request_uri_signed_get")

    def test_verifier_driver_uses_post_only_for_the_post_request_uri_module(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://localhost:8443",
                "target_origin": "https://issuer.example",
                "verifier": {
                    "management_token": "management-token",
                    "credential_type_values": {
                        "sd_jwt_vc": "urn:eudi:pid:1",
                        "iso_mdl": "org.iso.18013.5.1.mDL",
                    },
                },
            },
            module.threading.Event(),
        )
        with patch.object(
            module,
            "request_json",
            return_value={"authorization_url": "https://localhost:8443/authorize"},
        ) as request, patch.object(module, "get_url"):
            driver.drive_verifier(
                "module-id",
                {
                    "alias": "vp-alias",
                    "testName": "oid4vp-1final-verifier-request-uri-method-post",
                },
                {
                    "credential_format": "sd_jwt_vc",
                    "request_method": "request_uri_signed",
                },
                False,
            )

        self.assertEqual(request.call_args.args[3]["request_method"], "request_uri_signed_post")

    def test_materializer_creates_unique_aliases_and_exact_plan_count(self):
        module = load("materialize_openid4vc_oidf_config.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            driver = root / "driver.json"
            output = root / "output"
            base.write_text(json.dumps({
                name: {
                    "alias": f"nazo-{name}",
                    **(
                        {
                            "vci": {},
                            "client": {
                                "client_id": "upstream-placeholder",
                                "scope": "openid pid-scope",
                                "jwks": {
                                    "keys": [
                                        {
                                            "kty": "EC",
                                            "crv": "P-256",
                                            "kid": "client-key",
                                            "x": "x",
                                            "y": "y",
                                            "d": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
                                        }
                                    ]
                                },
                            },
                            "client2": {
                                "client_id": "upstream-second-client",
                                "scope": "openid pid-scope",
                                "jwks": {
                                    "keys": [
                                        {
                                            "kty": "RSA",
                                            "alg": "PS256",
                                            "n": "modulus",
                                            "e": "AQAB",
                                            "d": "private",
                                        }
                                    ]
                                },
                            },
                        }
                        if name.startswith("vci")
                        else {"client": {"client_id": "{HOSTNAME}"}}
                    ),
                }
                for name in ("vci", "vci_haip", "vp", "vp_haip")
            }), encoding="utf-8")
            driver.write_text(json.dumps({
                "issuer": {
                    "credential_configuration_ids": {
                        "sd_jwt_vc": "pid-sd-jwt",
                        "mdoc": "org.iso.18013.5.1.mDL",
                    },
                    "tx_code": "123456",
                },
                "verifier": {
                    "request_object_trust_anchor_pem": (
                        "-----BEGIN CERTIFICATE-----\n"
                        "test-root\n"
                        "-----END CERTIFICATE-----\n"
                    ),
                    "credential_type_values": {
                        "sd_jwt_vc": "eu.europa.ec.eudi.pid.1",
                        "iso_mdl": "org.iso.18013.5.1.mDL",
                    }
                },
            }), encoding="utf-8")
            with patch("sys.argv", [
                "materialize_openid4vc_oidf_config.py",
                "--base-config-json-file", str(base),
                "--driver-config-json-file", str(driver),
                "--conformance-server", "https://suite.example",
                "--target-origin", "https://issuer.example",
                "--output-dir", str(output),
            ]):
                self.assertEqual(module.main(), 0)
            plans = json.loads((output / "openid4vc-plan-set.json").read_text(encoding="utf-8"))
            materialized_driver = json.loads((output / "openid4vc-driver.json").read_text(encoding="utf-8"))
            configs = json.loads((output / "openid4vc-plan-configs.json").read_text(encoding="utf-8"))["configs"]
            expected_skips = json.loads((output / "openid4vc-expected-skips.json").read_text(encoding="utf-8"))
            expected_warnings = json.loads((output / "openid4vc-expected-warnings.json").read_text(encoding="utf-8"))
            self.assertEqual(len(plans), 17)
            self.assertEqual(len(configs), 17)
            self.assertEqual(len(set(materialized_driver["aliases"])), 17)
            self.assertEqual(
                expected_skips,
                [
                    {
                        "test-name": module.VCI_UNSUPPORTED_ENCRYPTION_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-sd-wallet-plain.json",
                    },
                    {
                        "test-name": module.VCI_UNSUPPORTED_ENCRYPTION_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-mdoc-issuer-plain.json",
                    },
                    {
                        "test-name": module.VCI_UNSUPPORTED_ENCRYPTION_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-sd-preauth.json",
                    },
                    {
                        "test-name": module.VCI_REFRESH_TOKEN_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-haip-sd-wallet.json",
                    },
                    {
                        "test-name": module.VCI_REFRESH_TOKEN_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-haip-mdoc-wallet.json",
                    },
                    {
                        "test-name": module.VCI_REFRESH_TOKEN_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-haip-sd-issuer.json",
                    },
                    {
                        "test-name": module.VCI_REFRESH_TOKEN_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-haip-mdoc-issuer.json",
                    },
                ],
            )
            self.assertEqual(expected_warnings, [])
            self.assertEqual(materialized_driver["target_origin"], "https://issuer.example")
            self.assertEqual(
                materialized_driver["verifier"]["credential_type_values"]["sd_jwt_vc"],
                "urn:eudi:pid:1",
            )
            for filename, config in configs.items():
                if "vp-" in filename:
                    self.assertEqual(config["client"]["client_id"], "issuer.example")
                    if "redirect-query" in filename:
                        self.assertNotIn("request_object_trust_anchor_pem", config["client"])
                    else:
                        self.assertEqual(
                            config["client"]["request_object_trust_anchor_pem"],
                            "-----BEGIN CERTIFICATE-----\n"
                            "test-root\n"
                            "-----END CERTIFICATE-----\n",
                        )
            for filename, config in configs.items():
                if "vci-" not in filename:
                    continue
                self.assertEqual(config["vci"]["credential_issuer_url"], "https://issuer.example")
                expected = "org.iso.18013.5.1.mDL" if "mdoc" in filename else "pid-sd-jwt"
                self.assertEqual(config["vci"]["credential_configuration_id"], expected)
                if "preauth" in filename:
                    self.assertEqual(config["vci"]["static_tx_code"], "123456")
                client2_keys = config["client2"]["jwks"]["keys"]
                self.assertEqual(
                    {(key["kty"], key["crv"], key["alg"]) for key in client2_keys},
                    {("EC", "P-256", "ES256")},
                )
                self.assertEqual(client2_keys[0]["kid"], "client-key-client2")
                self.assertNotEqual(
                    client2_keys[0]["d"],
                    config["client"]["jwks"]["keys"][0]["d"],
                )
                self.assertNotEqual(client2_keys[0]["x"], "x")
                self.assertNotEqual(client2_keys[0]["y"], "y")
            private_key_clients = {
                config["client"]["client_id"]
                for config in configs.values()
                if config.get("nazo", {}).get("client_auth_type") == "private_key_jwt"
            }
            attested_clients = {
                config["client"]["client_id"]
                for config in configs.values()
                if config.get("nazo", {}).get("client_auth_type") == "client_attestation"
            }
            self.assertEqual(private_key_clients, {module.VCI_PRIVATE_KEY_CLIENT_ID})
            self.assertEqual(attested_clients, {module.VCI_ATTESTED_CLIENT_ID})
            self.assertTrue(private_key_clients.isdisjoint(attested_clients))
            private_key_client2 = {
                config["client2"]["client_id"]
                for config in configs.values()
                if "vci-" in config["alias"]
                and config.get("nazo", {}).get("client_auth_type") == "private_key_jwt"
            }
            attested_client2 = {
                config["client2"]["client_id"]
                for config in configs.values()
                if "vci-" in config["alias"]
                and config.get("nazo", {}).get("client_auth_type") == "client_attestation"
            }
            self.assertEqual(private_key_client2, {module.VCI_PRIVATE_KEY_CLIENT2_ID})
            self.assertEqual(attested_client2, {module.VCI_ATTESTED_CLIENT2_ID})
            self.assertTrue(private_key_client2.isdisjoint(attested_client2))


if __name__ == "__main__":
    unittest.main()
