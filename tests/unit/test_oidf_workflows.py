import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
