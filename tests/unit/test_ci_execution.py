"""Keep one full suite per CI event without losing coverage exclusions."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class CiExecutionTests(unittest.TestCase):
    def test_coverage_is_called_by_quality_not_another_push(self):
        quality = (ROOT / ".github/workflows/code-quality.yml").read_text()
        coverage = (ROOT / ".github/workflows/codecov.yml").read_text()
        self.assertIn("  workflow_call:", coverage)
        self.assertNotIn("  push:", coverage)
        self.assertIn("uses: ./.github/workflows/codecov.yml", quality)
        full = quality.split("- name: Test workspace with PostgreSQL and Valkey", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("if: github.event_name == 'pull_request'", full)
        self.assertIn("cargo test --workspace --all-features --locked --no-fail-fast", full)
        self.assertIn("cargo test --workspace --all-features --locked --doc", quality)
        for path in (".github/workflows/codecov.yml", "codecov.yml", "requirements/codecov.txt"):
            self.assertIn(f'      - "{path}"', quality)

    def test_every_coverage_exclusion_has_an_uninstrumented_owner(self):
        script = (ROOT / "scripts/generate_codecov_lcov.sh").read_text()
        quality = (ROOT / ".github/workflows/code-quality.yml").read_text()
        issuance = (ROOT / "crates/nazoauth/tests/token_issuance_simplification.rs").read_text()
        owned = set(re.findall(r"#\[(?:tokio::|actix_web::)?test(?:\([^\]]*\))?\]\s*(?:async\s+)?fn\s+(\w+)", issuance))
        self.assertTrue(owned)
        convergence = "two_processes_converge_on_lifecycle_mutations_and_survive_cache_failures"
        owned.add(convergence)
        self.assertEqual(set(re.findall(r"--skip (\w+)", script)), owned)
        timing = quality.split("- name: Test timing contracts excluded from coverage", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("if: github.event_name != 'pull_request'", timing)
        self.assertIn("--test tenant_directory_convergence", timing)
        self.assertIn(convergence, timing)
        self.assertIn("--test token_issuance_simplification", timing)


if __name__ == "__main__":
    unittest.main()
