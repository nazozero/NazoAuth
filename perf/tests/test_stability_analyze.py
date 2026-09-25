#!/usr/bin/env python3
"""stability_analyze: sustained-cliff rules, checkpoint windows,
anomaly bucketing, active-VU series, reauth herd detection."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import stability_analyze as sa  # noqa: E402


def _bucket(i, ops=180000, p95=30.0, p99=80.0, reauth=0, span_s=60.0):
    return {"bucket": i, "span_s": span_s, "scheduled": 180000,
            "began": ops, "ops": ops,
            "ops_per_s": round(ops / span_s, 1) if span_s else None,
            "errors": 0, "p50": 5.0, "p95": p95, "p99": p99,
            "subject_initial_mint": 0, "subject_refresh_update": 25000,
            "subject_expired_reauth": reauth}


def _buckets(n=30, **kw):
    return {i: _bucket(i, **kw) for i in range(1, n + 1)}


class SustainedCliffTest(unittest.TestCase):
    def test_clean_run_no_cliff(self):
        self.assertFalse(sa.sustained_cliff(_buckets(), {})[
            "sustained_cliff"])

    def test_single_spike_is_not_cliff(self):
        b = _buckets()
        b[7]["p95"], b[7]["p99"] = 109.0, 395.0
        self.assertFalse(sa.sustained_cliff(b, {})["sustained_cliff"])

    def test_four_of_five_latency_buckets_is_cliff(self):
        b = _buckets()
        for i in (10, 11, 12, 14):
            b[i]["p99"] = 300.0
        r = sa.sustained_cliff(b, {})
        self.assertTrue(r["sustained_cliff"])
        self.assertEqual("A_latency", r["triggers"][0]["rule"])

    def test_three_of_five_is_not_cliff(self):
        b = _buckets()
        for i in (10, 11, 12):
            b[i]["p99"] = 300.0
        self.assertFalse(sa.sustained_cliff(b, {})["sustained_cliff"])

    def test_pool_exhaustion_five_minutes(self):
        b = _buckets()
        pool = {i: {"waiting_mean": 600.0, "checked_out_mean": 31.5,
                    "waiting_max": 700, "checked_out_max": 32}
                for i in range(1, 31)}
        r = sa.sustained_cliff(b, pool)
        self.assertTrue(r["sustained_cliff"])
        self.assertTrue(any(t["rule"] == "B_pool_exhaustion"
                            for t in r["triggers"]))

    def test_pool_waiting_alone_not_cliff(self):
        # waiting high but pool not near-exhausted -> no rule B
        pool = {i: {"waiting_mean": 900.0, "checked_out_mean": 20.0,
                    "waiting_max": 1000, "checked_out_max": 25}
                for i in range(1, 31)}
        self.assertFalse(sa.sustained_cliff(_buckets(), pool)
                         ["sustained_cliff"])

    def test_rate_under_2850_five_minutes(self):
        b = _buckets()
        for i in (20, 21, 22, 23, 24):
            b[i]["ops"] = 170000  # 2833/s
            b[i]["ops_per_s"] = 2833.3
        r = sa.sustained_cliff(b, {})
        self.assertTrue(any(t["rule"] == "C_rate_under_2850"
                            for t in r["triggers"]))

    def test_partial_tail_bucket_not_counted_in_rate(self):
        # A 25s tail bucket naturally shows <2850*60 ops; ops_per_s is
        # computed on its real span so it must not trigger rule C.
        b = _buckets(29)
        b[30] = _bucket(30, ops=75000, span_s=25.0)
        b[30]["ops_per_s"] = 3000.0
        self.assertFalse(sa.sustained_cliff(b, {})["sustained_cliff"])


class CheckpointEventsTest(unittest.TestCase):
    def _rows(self):
        # cumulative counters: ckpt requested at t=100, completes t=200
        return [
            {"kind": "meta"},
            {"ts": 90.0, "checkpoints": {"timed": 0, "requested": 0,
             "done": 0, "write_time_ms": 0.0, "sync_time_ms": 0.0,
             "buffers_written": 0}},
            {"ts": 100.0, "checkpoints": {"timed": 1, "requested": 1,
             "done": 0, "write_time_ms": 0.0, "sync_time_ms": 0.0,
             "buffers_written": 0}},
            {"ts": 200.0, "checkpoints": {"timed": 1, "requested": 1,
             "done": 1, "write_time_ms": 95000.0, "sync_time_ms": 300.0,
             "buffers_written": 40000}},
        ]

    def test_event_bounds_and_deltas(self):
        ev = sa.checkpoint_events(self._rows())
        self.assertEqual(1, len(ev))
        self.assertEqual(90.0, ev[0]["start_ts"])  # interval lower bound
        self.assertEqual(100.0, ev[0]["start_observed_ts"])
        self.assertEqual(200.0, ev[0]["end_ts"])
        self.assertEqual(95000.0, ev[0]["write_time_ms_delta"])
        self.assertEqual(40000, ev[0]["buffers_written_delta"])
        self.assertEqual("timed", ev[0]["kind"])

    def test_incomplete_checkpoint_marked(self):
        rows = self._rows()[:2] + [
            {"ts": 150.0, "checkpoints": {"timed": 1, "requested": 1,
             "done": 0, "write_time_ms": 0.0, "sync_time_ms": 0.0,
             "buffers_written": 0}}]
        ev = sa.checkpoint_events(rows)
        self.assertTrue(ev[0].get("incomplete"))


class AnomalyAndHerdTest(unittest.TestCase):
    def test_anomaly_flagged_in_ckpt_window(self):
        b = _buckets()
        b[7]["p99"] = 395.0
        # checkpoint write window covering minute 7 ([360,480]s rel)
        out = sa.anomaly_buckets(b, [(360.0, 480.0)])
        self.assertEqual([7], [a["bucket"] for a in out])
        self.assertTrue(out[0]["in_checkpoint_write_window"])

    def test_anomaly_outside_ckpt(self):
        b = _buckets()
        b[3]["p95"] = 120.0
        out = sa.anomaly_buckets(b, [(360.0, 480.0)])
        self.assertFalse(out[0]["in_checkpoint_write_window"])

    def test_reauth_herd_threshold(self):
        b = _buckets()
        b[9]["subject_expired_reauth"] = 501
        self.assertTrue(sa.reauth_herd(b)["herd"])
        b[9]["subject_expired_reauth"] = 499
        self.assertFalse(sa.reauth_herd(b)["herd"])


class ActiveVuTest(unittest.TestCase):
    def test_series_parsed_and_windowed(self):
        log = ("\nrunning (00m01.0s), 2048/2048 VUs, 10 complete\n"
               "running (01m00.0s), 0030/2048 VUs, 100 complete\n"
               "running (02m00.0s), 0050/2048 VUs, 200 complete\n"
               "running (30m00.0s), 0000/2048 VUs, 300 complete\n")
        r = sa.active_vu_series(log, (15.0, 1795.0))
        # window [15,1795) excludes the t=1s init spike and t=1800 end
        self.assertEqual(2, r["samples"])
        self.assertEqual(40.0, r["mean"])
        self.assertEqual(50, r["max"])
        self.assertEqual(2048, r["first300s_max"])  # init wave recorded


if __name__ == "__main__":
    unittest.main()
