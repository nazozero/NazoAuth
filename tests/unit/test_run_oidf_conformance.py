import importlib.util
import unittest
from pathlib import Path


def load_runner_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "run_oidf_conformance.py"
    spec = importlib.util.spec_from_file_location("run_oidf_conformance", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RunOidfConformanceTests(unittest.TestCase):
    def test_successful_completion_log_allows_browser_script_noise(self):
        module = load_runner_module()

        logs = [
            {"src": "BROWSER", "msg": "Error during JavaScript execution"},
            {"result": "SUCCESS", "src": "ValidateFrontchannelLogoutIss"},
            {"result": "FINISHED", "msg": "Test has run to completion"},
        ]

        self.assertIsNone(module.oidf_log_failure("module-id", logs))
        self.assertTrue(module.oidf_log_has_successful_completion(logs))

    def test_successful_completion_log_does_not_hide_warning_or_failure(self):
        module = load_runner_module()

        logs = [
            {"result": "SUCCESS", "src": "ValidateFrontchannelLogoutIss"},
            {"result": "FAILURE", "src": "ValidatePostLogoutRedirect", "msg": "bad state"},
            {"result": "FINISHED", "msg": "Test has run to completion"},
        ]

        self.assertIn("FAILURE", module.oidf_log_failure("module-id", logs))
        self.assertTrue(module.oidf_log_has_successful_completion(logs))

    def test_early_monitor_can_defer_result_failure_without_log_failure(self):
        module = load_runner_module()

        info = {
            "_id": "module-id",
            "testName": "oidcc-frontchannel-rp-initiated-logout",
            "status": "FINISHED",
            "result": "FAILED",
        }

        self.assertTrue(module.oidf_info_failure_can_wait_for_final_result(info))

    def test_early_monitor_does_not_defer_status_or_structured_errors(self):
        module = load_runner_module()

        self.assertFalse(
            module.oidf_info_failure_can_wait_for_final_result(
                {"status": "FAILED", "result": "FAILED"}
            )
        )
        self.assertFalse(
            module.oidf_info_failure_can_wait_for_final_result(
                {"status": "FINISHED", "result": "FAILED", "error": "runner crashed"}
            )
        )


if __name__ == "__main__":
    unittest.main()
