#!/usr/bin/env python3
"""Regression tests for the dependency-free real-HTTP source-policy gate."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("full_real_request_e2e.py")


class SourcePolicyTests(unittest.TestCase):
    def test_policy_self_tests_reject_dead_or_non_registry_evidence(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--source-policy-self-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_live_source_policy_accepts_executable_registry(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--source-policy-check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
