import importlib.util
import unittest
from pathlib import Path


def load_setup_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "setup_local_oidf_podman.py"
    spec = importlib.util.spec_from_file_location("setup_local_oidf_podman", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SetupLocalOidfPodmanTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
