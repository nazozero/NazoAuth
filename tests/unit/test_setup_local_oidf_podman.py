import importlib.util
import unittest
from pathlib import Path
from unittest import mock


def load_setup_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "setup_local_oidf_podman.py"
    spec = importlib.util.spec_from_file_location("setup_local_oidf_podman", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    with mock.patch.dict(
        "os.environ",
        {
            "OIDF_TARGET_ISSUER": "https://issuer.example",
            "OIDF_MTLS_TARGET_ISSUER": "https://mtls.issuer.example",
            "OIDF_SUITE_BASE_URL": "https://suite.example",
        },
        clear=False,
    ):
        spec.loader.exec_module(module)
    return module


class SetupLocalOidfPodmanTests(unittest.TestCase):
    def test_every_callback_completion_wait_has_a_thirty_second_floor(self):
        module = load_setup_module()

        configs = [
            module.write_basic_plan_config(),
            module.write_dynamic_plan_config(),
            module.write_formpost_plan_config(),
            module.write_third_party_init_plan_config(),
        ]
        commands = [
            command
            for config in configs
            for entry in config.get("browser", [])
            for task in entry.get("tasks", [])
            for command in task.get("commands", [])
        ]
        callback_waits = [
            command
            for command in commands
            if command[:3] == ["wait", "id", "submission_complete"]
        ]

        self.assertTrue(callback_waits)
        self.assertTrue(all(command[3] >= 30 for command in callback_waits))

    def test_session_management_browser_automation_waits_for_result_pages(self):
        module = load_setup_module()

        automation = module.browser_automation()
        commands = [
            command
            for entry in automation
            for task in entry.get("tasks", [])
            for command in task.get("commands", [])
        ]

        self.assertIn(["wait", "contains", "/session_result?state=unchanged", 30], commands)
        self.assertIn(
            ["wait", "contains", "/second_session_result?state=changed", 30],
            commands,
        )

    def test_frontchannel_logout_uses_single_authorize_automation(self):
        module = load_setup_module()

        config = module.write_frontchannel_logout_plan_config()

        authorize_entries = [
            entry
            for entry in config.get("browser", [])
            if entry.get("match") == f"{module.ISSUER}/authorize*"
        ]
        self.assertEqual(len(authorize_entries), 1)
        self.assertNotIn("override", config)

    def test_local_reverse_proxy_uses_operator_supplied_issuer_host(self):
        module = load_setup_module()

        module.write_nginx()
        nginx = (module.RUNTIME / "nginx.conf").read_text(encoding="utf-8")

        self.assertIn("proxy_set_header Host issuer.example;", nginx)
        self.assertIn("proxy_set_header X-Forwarded-Host issuer.example;", nginx)
        self.assertNotIn("auth.nazo.run", nginx)

    def test_fapi_ciba_plans_are_the_orthogonal_supported_combinations(self):
        module = load_setup_module()

        configs = module.write_fapi_ciba_plan_config()
        self.assertEqual(
            {
                (config["nazo"]["client_auth_type"], config["nazo"]["ciba_mode"])
                for config in configs.values()
            },
            {
                ("private_key_jwt", "poll"),
                ("mtls", "poll"),
                ("private_key_jwt", "ping"),
                ("mtls", "ping"),
            },
        )
        for config in configs.values():
            self.assertEqual(config["nazo"]["sender_constrain"], "mtls")
            self.assertIn("mtls", config)
            self.assertIn("mtls2", config)
            for key in ("client", "client2"):
                self.assertEqual(
                    config[key]["backchannel_token_delivery_mode"],
                    config["nazo"]["ciba_mode"],
                )
                self.assertEqual(
                    config[key]["backchannel_authentication_request_signing_alg"],
                    "PS256",
                )
                self.assertEqual(
                    "backchannel_client_notification_endpoint" in config[key],
                    config["nazo"]["ciba_mode"] == "ping",
                )
                if config["nazo"]["ciba_mode"] == "ping":
                    self.assertEqual(
                        config[key]["backchannel_client_notification_endpoint"],
                        f"https://suite.example/test/a/{config['alias']}"
                        "/ciba-notification-endpoint",
                    )

    def test_plan_manifest_description_uses_the_actual_plan_count(self):
        module = load_setup_module()
        configs = {
            "first.json": {"description": "first"},
            "second.json": {"description": "second"},
        }

        manifest = module.plan_manifest_for_expressions(
            ["first-plan first.json", "second-plan second.json"], configs
        )

        self.assertIn("2-plan", manifest["description"])
        self.assertEqual(len(manifest["plans"]), 2)

    def test_dynamic_op_certification_is_not_in_supported_matrix(self):
        module = load_setup_module()
        configs = {
            "oidf-oidcc-basic-plan-config.json": module.write_basic_plan_config(),
            "oidf-oidcc-dynamic-plan-config.json": module.write_dynamic_plan_config(),
        }
        expressions = module.plan_expressions_for_configs(configs)

        self.assertFalse(
            any("oidcc-dynamic-certification-test-plan" in item for item in expressions)
        )
        self.assertTrue(
            any("client_registration=dynamic_client" in item for item in expressions)
        )

    def test_unsigned_compatibility_skips_are_explicit_and_bounded(self):
        module = load_setup_module()

        skips = module.expected_skips()

        self.assertEqual(len(skips), 8)
        self.assertEqual(
            {item["configuration-filename"] for item in skips},
            {
                "oidf-oidcc-basic-plan-config.json",
                "oidf-oidcc-dynamic-plan-config.json",
                "oidf-oidcc-formpost-plan-config.json",
            },
        )
        self.assertEqual({item["variant"] for item in skips}, {"*"})

    def test_dynamic_plan_uses_terminal_browser_flow_for_local_redirect_errors(self):
        module = load_setup_module()

        config = module.dynamic_plan_config()

        for module_name in (
            "oidcc-ensure-registered-redirect-uri",
            "oidcc-ensure-redirect-uri-in-authorization-request",
            "oidcc-redirect-uri-query-mismatch",
            "oidcc-redirect-uri-query-added",
        ):
            tasks = config["override"][module_name]["browser"][0]["tasks"]
            self.assertEqual(
                [task["task"] for task in tasks],
                ["Capture authorization error response"],
            )

    def test_plan_partition_is_complete_and_isolates_browser_sensitive_plans(self):
        module = load_setup_module()
        parallel = "oidcc-basic-certification-test-plan basic.json"
        frontchannel = (
            "oidcc-frontchannel-rp-initiated-logout-certification-test-plan "
            "frontchannel.json"
        )
        session = (
            "oidcc-session-management-certification-test-plan session.json"
        )
        ciba = "fapi-ciba-id1-test-plan[client_auth_type=mtls] ciba.json"

        concurrent, ciba_only, frontchannel_only, session_only = module.partition_plan_expressions(
            [parallel, frontchannel, session, ciba]
        )

        self.assertEqual(concurrent, [parallel])
        self.assertEqual(ciba_only, [ciba])
        self.assertEqual(frontchannel_only, [frontchannel])
        self.assertEqual(session_only, [session])

    def test_all_generated_plans_allow_the_native_sso_metadata_extension(self):
        module = load_setup_module()

        configs = [
            module.write_basic_plan_config(),
            module.write_dynamic_plan_config(),
            module.write_oidcc_config_plan_config(),
            module.write_frontchannel_logout_plan_config(),
            module.write_session_management_plan_config(),
        ]
        configs.extend(module.write_fapi_plan_configs().values())
        configs.extend(module.write_fapi_ciba_plan_config().values())
        configs.extend(module.write_fapi_matrix_plan_configs().values())

        self.assertGreaterEqual(len(configs), 21)
        for config in configs:
            self.assertEqual(
                config["server"]["allow_unexpected_metadata_fields"],
                ["native_sso_supported"],
            )

    def test_bounded_parallel_groups_cover_the_full_matrix_once(self):
        module = load_setup_module()
        configs = {
            "oidf-oidcc-basic-plan-config.json": module.write_basic_plan_config(),
            "oidf-oidcc-dynamic-plan-config.json": module.write_dynamic_plan_config(),
            "oidf-oidcc-formpost-plan-config.json": module.write_formpost_plan_config(),
            "oidf-oidcc-third-party-init-plan-config.json": module.write_third_party_init_plan_config(),
            "oidf-oidcc-config-plan-config.json": module.write_oidcc_config_plan_config(),
            "oidf-oidcc-frontchannel-logout-plan-config.json": module.write_frontchannel_logout_plan_config(),
            "oidf-oidcc-session-management-plan-config.json": module.write_session_management_plan_config(),
        }
        configs.update(module.write_fapi_ciba_plan_config())
        configs.update(module.write_fapi_matrix_plan_configs())
        plan_set = module.plan_expressions_for_configs(configs)

        groups = module.bounded_parallel_plan_groups(plan_set)

        self.assertEqual(
            list(groups),
            [
                "01-oidc-core.json",
                "02-oidc-formpost-thirdparty-config.json",
                "03-fapi-ciba.json",
                "04-fapi-message-and-mtls-dpop.json",
                "05-fapi-mtls-mtls.json",
                "06-fapi-private-dpop.json",
                "07-fapi-private-mtls.json",
                "08-frontchannel.json",
                "09-session.json",
            ],
        )
        flattened = [plan for group in groups.values() for plan in group]
        self.assertEqual(len(flattened), 25)
        self.assertEqual(sorted(flattened), sorted(plan_set))
        self.assertEqual(len(groups["03-fapi-ciba.json"]), 4)
        self.assertEqual(len(groups["08-frontchannel.json"]), 1)
        self.assertEqual(len(groups["09-session.json"]), 1)

    def test_help_exits_before_generating_runtime_files(self):
        module = load_setup_module()

        with mock.patch.object(module, "ensure_cert") as ensure_cert:
            with self.assertRaises(SystemExit) as raised:
                module.main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        ensure_cert.assert_not_called()

    def test_unknown_argument_exits_before_generating_runtime_files(self):
        module = load_setup_module()

        with mock.patch.object(module, "ensure_cert") as ensure_cert:
            with self.assertRaises(SystemExit) as raised:
                module.main(["--not-a-real-option"])

        self.assertEqual(raised.exception.code, 2)
        ensure_cert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
