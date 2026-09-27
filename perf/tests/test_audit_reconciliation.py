"""Audit-free PAR must retain a valid prefix; issuance must advance it."""
import base64
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from point_runner import reconcile_audit_state


class AuditPrefixTests(unittest.TestCase):
    def setUp(self):
        raw = bytes(range(32))
        wire = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        checkpoint = {"collected": True, "last_sequence": 0,
                      "last_hash": wire, "accepted_events": 0,
                      "deployment_id": "test-deployment"}
        self.pre = {"receiver_checkpoint": copy.deepcopy(checkpoint)}
        self.post = {"deployment_id": "test-deployment",
                     "db": {"collected": True, "pending": 0, "last_sequence": 0,
                            "anchor_sequence": 0, "last_hash": raw.hex(),
                            "anchor_hash": raw.hex(), "anchor_deployment_id": "test-deployment"},
                     "receiver_state": {"collected": True, "fault": "none"},
                     "receiver_checkpoint": checkpoint}
        self.journal = {"collected": True, "malformed_lines": 0,
                        "foreign_deployment_batches": 0, "duplicate_sequences": 0,
                        "sequence_gaps": 0, "range_contiguous": True,
                        "events_in_range": 0, "token_issued_in_range": 0}

    def verdict(self, allow=True, expected=None):
        return reconcile_audit_state(self.pre, self.post, "point", expected,
                                     self.journal, allow_empty_prefix=allow)["verdict"]

    def test_audit_free_par_preserves_empty_prefix(self):
        self.assertEqual(self.verdict(), "PASS")

    def test_issuance_still_requires_progress_and_issued_event(self):
        self.assertEqual(self.verdict(allow=False, expected=1), "FAIL")

    def test_ordinary_workload_cannot_assume_no_audit(self):
        self.assertEqual(self.verdict(allow=False), "FAIL")

    def test_unchanged_sequence_cannot_change_hash(self):
        raw = bytes(reversed(range(32)))
        self.post["receiver_checkpoint"]["last_hash"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.post["db"]["last_hash"] = raw.hex()
        self.post["db"]["anchor_hash"] = raw.hex()
        self.assertEqual(self.verdict(), "FAIL")

    def test_empty_prefix_still_requires_all_integrity_evidence(self):
        for field, value in (("collected", False), ("sequence_gaps", 1),
                             ("duplicate_sequences", 1), ("events_in_range", 1)):
            with self.subTest(field=field):
                original = self.journal[field]
                self.journal[field] = value
                self.assertEqual(self.verdict(), "FAIL")
                self.journal[field] = original

    def test_receiver_count_must_match_empty_delta(self):
        self.post["receiver_checkpoint"]["accepted_events"] = 1
        self.assertEqual(self.verdict(), "FAIL")

    def test_sequence_regression_never_passes(self):
        self.pre["receiver_checkpoint"]["last_sequence"] = 1
        self.assertEqual(self.verdict(), "FAIL")

    def test_positive_prefix_progress_remains_valid(self):
        self.post["receiver_checkpoint"].update(last_sequence=1, accepted_events=1)
        self.post["db"].update(last_sequence=1, anchor_sequence=1)
        self.journal.update(events_in_range=1, token_issued_in_range=1)
        self.assertEqual(self.verdict(allow=False, expected=1), "PASS")
