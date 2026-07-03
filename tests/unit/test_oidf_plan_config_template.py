import json
import unittest
from pathlib import Path


class OidfPlanConfigTemplateTests(unittest.TestCase):
    def test_fapi_ciba_clients_have_acr_value_when_discovery_advertises_acr(self):
        template = json.loads(
            Path("docs/conformance/oidf-plan-config-template.json").read_text(
                encoding="utf-8"
            )
        )
        config = template["configs"][
            "oidf-fapi-ciba-plain-private-key-jwt-poll-plan-config.json"
        ]

        self.assertEqual(config["client"]["acr_value"], "1")
        self.assertEqual(config["client2"]["acr_value"], "1")


if __name__ == "__main__":
    unittest.main()
