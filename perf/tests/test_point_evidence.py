"""Evidence must retain its workload, time-window and counter identity."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import ledger_check
import point_runner as pr
import single_instance_scaling as sis


class PointEvidenceTests(unittest.TestCase):
    def test_counter_window_rejects_reset_with_higher_counter_and_sampling_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            stream = Path(directory) / "sampler.jsonl"
            meta = {"kind": "meta", "interval_s": 5}
            for rows in [
                [{"ts": 100, "wal_bytes": 10, "wal_stats_reset": "a"},
                 {"ts": 105, "wal_bytes": 100, "wal_stats_reset": "b"}],
                [{"ts": 100, "wal_bytes": 10, "wal_stats_reset": "a"},
                 {"ts": 130, "wal_bytes": 100, "wal_stats_reset": "a"}],
            ]:
                stream.write_text("\n".join(json.dumps(row) for row in [meta, *rows]))
                result = sis.windowed_series_delta(stream, "wal_bytes", 100000, rows[-1]["ts"] * 1000)
                self.assertIsNone(result["delta"])

    def test_wal_io_compares_each_identity_epoch_with_baseline(self):
        pre = {"pg_stat_wal": {"stats_reset": "w"},
               "pg_stat_io_wal": [{"backend_type": "client backend", "object": "wal",
                                   "context": "normal", "stats_reset": "old", "fsyncs": 1}]}
        post = {"pg_stat_wal": {"stats_reset": "w"},
                "pg_stat_io_wal": [{"backend_type": "client backend", "object": "wal",
                                    "context": "normal", "stats_reset": "new", "fsyncs": 9}]}
        result = sis.wal_delta(pre, post)
        self.assertFalse(result["valid"])
        self.assertIsNone(result["fsyncs_total"])

    def test_sidecar_end_bounds_the_common_window(self):
        main = {"window_start_ms": 100000, "window_end_ms": 300000,
                "scenario_clock_ok": 1}
        ev = {"side": {"terminal_summary": True, "interrupted": False,
                       "started_ts": 100, "observed_end_ts": 180,
                       "duration_s": 60, "warmup_s": 15}}
        result = pr._common_window_seconds(main, ev, [{"name": "side"}])
        self.assertEqual(result["start_ms"], 135000)
        self.assertEqual(result["end_ms"], 160000)
        self.assertEqual(result["seconds"], 25)
        del ev["side"]["observed_end_ts"]
        self.assertIsNone(pr._common_window_seconds(main, ev, [{"name": "side"}])["seconds"])

    def test_missing_sidecar_evidence_cannot_disappear_from_intersection(self):
        main = {"window_start_ms": 100000, "window_end_ms": 300000,
                "scenario_clock_ok": 1}
        self.assertIsNone(pr._common_window_seconds(main, {}, [{"name": "side"}])["seconds"])

    def test_journal_completion_denominator_excludes_other_event_types(self):
        events = [{"sequence": n, "event_type": kind,
                   "occurred_at": "2026-10-21T00:00:01Z"}
                  for n, kind in enumerate(["token_issued", "login", "token_issued"], 1)]
        envelope = {"checkpoint_kind": "batch", "deployment_id": "test",
                    "first_sequence": 1, "last_sequence": 3,
                    "event_count": 3, "events": events}
        result = pr._journal_scan([json.dumps(envelope)], "test", 0, 3)
        self.assertEqual(result["events_in_range"], 3)
        self.assertEqual(sum(result["token_issued_per_second_counts"].values()), 2)

    def test_reset_is_checked_for_each_io_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            pre, post = [Path(directory) / name for name in ("pre", "post")]
            pre.write_text('IO|a|stats_reset|old\nIO|a|reads|1\nIO|b|stats_reset|old\nIO|b|reads|2\n')
            post.write_text('IO|a|stats_reset|old\nIO|a|reads|2\nIO|b|stats_reset|new\nIO|b|reads|10\n')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(ledger_check.diff(pre, post), 2)
            self.assertIn("b/reads: stats_reset changed", output.getvalue())


if __name__ == "__main__":
    unittest.main()
