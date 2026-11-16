"""Keep one full suite per CI event without losing coverage exclusions."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class CiExecutionTests(unittest.TestCase):
    def test_large_backlog_regression_has_an_explicit_ci_owner(self):
        scale = (ROOT / ".github/workflows/audit-scale.yml").read_text()
        source = (ROOT / "crates/persistence-postgres/tests/audit_ledger.rs").read_text()
        self.assertIn("audit_claim_at_backlog_sizes(&[0, 10_000])", source)
        self.assertIn("audit_claim_at_backlog_sizes(&[1_000_000, 15_000_000])", source)
        self.assertRegex(source, r'#\[ignore = [^\n]+\]\s*async fn audit_claim_is_bounded_at_million_row_backlogs')
        self.assertIn("audit_claim_is_bounded_at_million_row_backlogs -- --ignored --exact --nocapture", scale)
        self.assertNotIn("  schedule:", scale)
        self.assertNotIn("  pull_request:", scale)
        self.assertNotIn("  push:", scale)
        self.assertIn("  workflow_dispatch:", scale)

    def test_coverage_is_called_by_quality_not_another_push(self):
        quality = (ROOT / ".github/workflows/code-quality.yml").read_text()
        coverage = (ROOT / ".github/workflows/codecov.yml").read_text()
        self.assertIn("  workflow_call:", coverage)
        self.assertNotIn("  push:", coverage)
        self.assertIn("uses: ./.github/workflows/codecov.yml", quality)
        self.assertIn("cargo nextest archive --workspace --all-features --locked", quality)
        self.assertIn("shard: [1, 2, 3, 4, 5, 6]", quality)
        self.assertIn("--partition slice:${{ matrix.shard }}/6 --test-threads 1 --no-fail-fast", quality)
        self.assertIn("test(=pending_migrations_create_all_runtime_module_state_tables)", quality)
        for result in ("BUILD_RESULT", "CLIPPY_RESULT", "FIXTURE_RESULT", "SHARDS_RESULT"):
            self.assertIn(f'test "${result}" = success', quality)
        self.assertIn("cargo test --workspace --all-features --locked --doc", quality)
        from scripts.ci_inputs import INPUTS
        for path in (".github/workflows/codecov.yml", "codecov.yml", "requirements/codecov.txt"):
            self.assertIn(path, INPUTS["rust"])
        self.assertIn("scripts/ci_build_jobs.py", INPUTS["rust"])
        self.assertIn("needs.inputs.outputs.run != 'false'", quality)
        self.assertIn("  schedule:", coverage)

    def test_every_coverage_exclusion_has_an_uninstrumented_owner(self):
        script = (ROOT / "scripts/generate_codecov_lcov.sh").read_text()
        quality = (ROOT / ".github/workflows/code-quality.yml").read_text()
        issuance = (ROOT / "crates/server/tests/token_issuance_simplification.rs").read_text()
        owned = set(re.findall(r"#\[(?:tokio::|actix_web::)?test(?:\([^\]]*\))?\]\s*(?:async\s+)?fn\s+(\w+)", issuance))
        self.assertTrue(owned)
        convergence = "two_processes_converge_on_lifecycle_mutations_and_survive_cache_failures"
        owned.add(convergence)
        self.assertEqual(set(re.findall(r"--skip (\w+)", script)), owned)
        timing = quality.split("- name: Test timing contracts excluded from coverage", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("if: github.event_name == 'workflow_dispatch'", timing)
        self.assertIn("--test tenant_directory_convergence", timing)
        self.assertIn(convergence, timing)
        self.assertIn("--test token_issuance_simplification", timing)


if __name__ == "__main__":
    unittest.main()
