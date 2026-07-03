import json
import unittest
from pathlib import Path


TEMPLATE = Path(__file__).resolve().parents[2] / "docs" / "conformance" / "oidf-plan-config-template.json"


def browser_commands(value):
    if isinstance(value, dict):
        browser = value.get("browser")
        if isinstance(browser, list):
            for entry in browser:
                if not isinstance(entry, dict):
                    continue
                for task in entry.get("tasks", []):
                    if not isinstance(task, dict):
                        continue
                    for command in task.get("commands", []):
                        yield command
        for child in value.values():
            yield from browser_commands(child)
    elif isinstance(value, list):
        for child in value:
            yield from browser_commands(child)


class OidfPlanConfigTemplateTests(unittest.TestCase):
    def test_fapi_ciba_clients_have_acr_value_when_discovery_advertises_acr(self):
        template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        config = template["configs"][
            "oidf-fapi-ciba-plain-private-key-jwt-poll-plan-config.json"
        ]

        self.assertEqual(config["client"]["acr_value"], "1")
        self.assertEqual(config["client2"]["acr_value"], "1")

    def test_logout_and_session_management_wait_for_result_pages(self):
        data = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        commands = list(browser_commands(data))

        self.assertNotIn(["wait", "contains", "/post_logout_redirect", 10], commands)
        self.assertNotIn(["wait", "contains", "/session_verify", 10], commands)
        self.assertIn(["wait", "contains", "/post_logout_redirect?state=", 10], commands)
        self.assertIn(["wait", "contains", "/session_result?state=unchanged", 30], commands)
        self.assertIn(["wait", "contains", "/second_session_result?state=changed", 30], commands)


if __name__ == "__main__":
    unittest.main()
