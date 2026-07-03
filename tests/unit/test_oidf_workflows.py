import json
import unittest
from pathlib import Path


def workflow_heredoc_json(workflow: str, name: str):
    marker = f"cat > {name} <<'JSON'"
    payload = workflow.split(marker, 1)[1].split("JSON", 1)[0]
    return json.loads(payload)


class OidfWorkflowTests(unittest.TestCase):
    def test_full_matrix_workflow_defaults_to_no_parallel_runner(self):
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("NO_PARALLEL: ${{ vars.OIDF_NO_PARALLEL || 'true' }}", workflow)
        self.assertIn('if [ "$NO_PARALLEL" = "true" ]; then', workflow)
        self.assertIn("args+=(--no-parallel)", workflow)

    def test_full_matrix_workflow_has_parallel_isolated_mode(self):
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("runner_mode:", workflow)
        self.assertIn("parallel-isolated", workflow)
        self.assertIn("oidf-concurrent-plan-set.json", workflow)
        self.assertIn("oidf-frontchannel-plan-set.json", workflow)
        self.assertIn("oidf-session-management-plan-set.json", workflow)

        full_plan_set = workflow_heredoc_json(workflow, "oidf-full-plan-set.json")
        concurrent_plan_set = workflow_heredoc_json(
            workflow,
            "oidf-concurrent-plan-set.json",
        )
        frontchannel_plan_set = workflow_heredoc_json(
            workflow,
            "oidf-frontchannel-plan-set.json",
        )
        session_management_plan_set = workflow_heredoc_json(
            workflow,
            "oidf-session-management-plan-set.json",
        )

        self.assertFalse(
            any("frontchannel-rp-initiated-logout" in plan for plan in concurrent_plan_set)
        )
        self.assertFalse(
            any("session-management-certification-test-plan" in plan for plan in concurrent_plan_set)
        )
        self.assertEqual(
            sorted(full_plan_set),
            sorted(concurrent_plan_set + frontchannel_plan_set + session_management_plan_set),
        )

        self.assertIn("run_oidf_plan_set oidf-frontchannel-plan-set.json frontchannel", workflow)
        self.assertIn(
            "run_oidf_plan_set oidf-session-management-plan-set.json session-management",
            workflow,
        )
        self.assertIn('"$GITHUB_WORKSPACE/oidf-results/$export_subdir"', workflow)
        self.assertIn("isolated_args+=(--no-parallel)", workflow)


if __name__ == "__main__":
    unittest.main()
