"""Database-clock expiry evidence and its single-instance acceptance gates."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import single_instance_scaling as sis  # noqa: E402
from perf.tests import test_single_instance_scaling as fixtures  # noqa: E402


class IssuanceMaintenanceEvidenceTest(unittest.TestCase):
    start = 1_800_000_000
    contract = {"issuance_retention_seconds": 300,
                "issuance_max_expired_age_seconds": 120}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "soak.jsonl"
        self.rows = []
        for offset in range(0, 601, 2):
            ts = self.start + offset
            sample = {"sampled_at_s": ts,
                      "oldest_due_at_s": ts - (offset % 60)}
            if offset % 60 == 0:
                sample.update(due_count=offset + 10, due_count_sampled_at_s=ts)
            self.rows.append({
                "ts": ts, "issuance_maintenance": sample,
                "rel_bytes": {"oauth_token_issuances": {
                    "ins": offset * 3000, "del": max(0, offset - 300) * 3000}}})

    def evidence(self, contract=None, end=600):
        self.path.write_text("\n".join(json.dumps(row) for row in self.rows))
        return sis.issuance_maintenance_evidence(
            self.path, self.start * 1000, (self.start + end) * 1000,
            self.contract if contract is None else contract)

    def test_periodic_nonzero_backlog_can_pass_declared_age_slo(self):
        evidence = self.evidence()
        self.assertEqual(evidence["status"], "PASS")
        self.assertGreater(evidence["due_count"]["slope_per_s"], 0)
        self.assertEqual(evidence["oldest_expired_age"]["max"], 58)
        self.assertEqual(evidence["counter_window"]["deleted_per_s"], 3000)

    def test_one_sample_above_slo_fails(self):
        sample = self.rows[250]["issuance_maintenance"]
        sample["oldest_due_at_s"] = sample["sampled_at_s"] - 121
        self.assertEqual(self.evidence()["status"], "FAIL")

    def test_missing_contract_is_invalid(self):
        self.assertEqual(self.evidence({})["status"], "INVALID")

    def test_short_mature_window_is_invalid(self):
        evidence = self.evidence(end=479)
        self.assertEqual(evidence["status"], "INVALID")
        self.assertEqual(evidence["reason"], "insufficient_mature_observation")

    def test_future_due_clock_is_invalid_not_clamped_to_zero(self):
        sample = self.rows[250]["issuance_maintenance"]
        sample["oldest_due_at_s"] = sample["sampled_at_s"] + 1
        self.assertEqual(self.evidence()["status"], "INVALID")

    def test_database_clock_offset_is_invalid(self):
        self.rows[250]["issuance_maintenance"]["sampled_at_s"] += 5
        self.assertEqual(self.evidence()["status"], "INVALID")

    def test_missing_middle_and_end_samples_are_invalid(self):
        self.rows = self.rows[:200] + self.rows[205:-4]
        self.assertEqual(self.evidence()["status"], "INVALID")

    def test_stat_reset_is_invalid(self):
        self.rows[250]["rel_bytes"]["oauth_token_issuances"]["del"] = 0
        self.assertEqual(self.evidence()["status"], "INVALID")

    def test_no_expired_rows_is_not_missing_data(self):
        for row in self.rows:
            row["issuance_maintenance"]["oldest_due_at_s"] = None
        self.assertEqual(self.evidence()["status"], "PASS")

    def test_missing_oldest_field_is_not_no_expired_rows(self):
        del self.rows[250]["issuance_maintenance"]["oldest_due_at_s"]
        self.assertEqual(self.evidence()["status"], "INVALID")

    def test_ledger_parses_actual_issuance_record_shapes(self):
        self.path.write_text(
            "META|sampled_at|2026-09-25 05:25:40.136724\n"
            "ROW_COUNTS|oauth_token_issuances|1961417\n"
            "EXPIRED_BACKLOG|issuances_due|1128769|2026-09-25 05:18:51\n")
        evidence = sis.issuance_ledger(self.path)
        self.assertEqual(evidence["rows"], 1961417)
        self.assertEqual(evidence["due_count"], 1128769)
        self.assertAlmostEqual(evidence["oldest_expired_age_s"], 409.136724, places=5)


class IssuanceAndPreparationGateTest(unittest.TestCase):
    def test_phase3_requires_real_issuance_evidence(self):
        a, b = fixtures.Phase3GateTest().make()
        b["issuance_maintenance"] = {"status": "INVALID", "pass": False}
        self.assertEqual(sis.evaluate_phase3_gates(a, b)["verdict"], "INVALID")
        b["issuance_maintenance"] = {"status": "FAIL", "pass": False}
        self.assertEqual(sis.evaluate_phase3_gates(a, b)["verdict"], "FAIL")

    def test_phase3_prepare_source_controls_invalid_versus_fail(self):
        for counter, verdict in (("outcome_prepare_failed", "INVALID"),
                                 ("outcome_prepare_local_failed", "INVALID"),
                                 ("outcome_prepare_sut_failed", "FAIL")):
            with self.subTest(counter=counter):
                a, b = fixtures.Phase3GateTest().make(b_over={counter: 1})
                self.assertEqual(sis.evaluate_phase3_gates(a, b)["verdict"], verdict)

    def test_phase2_prepare_source_controls_invalid_versus_fail(self):
        for counter, verdict in (("outcome_prepare_failed", "INVALID"),
                                 ("outcome_prepare_local_failed", "INVALID"),
                                 ("outcome_prepare_sut_failed", "FAIL")):
            with self.subTest(counter=counter):
                records = fixtures.Phase2GateTest().make_records()
                records["B1"][counter] = 1
                self.assertEqual(sis.evaluate_phase2_gates(records)["verdict"], verdict)


if __name__ == "__main__":
    unittest.main()
