"""Unit tests for the business-pool residency analyzer."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

import residency_analyze as ra  # noqa: E402


def _backend(pid, state, qid=None, wet=None, we=None, sc=None):
    return {"pid": pid, "app": "", "caddr": "10.0.0.2", "state": state,
            "wet": wet, "we": we, "qid": qid, "xs": None, "qs": None,
            "sc": sc, "bs": 1000.0, "xid": None, "xmin_age": None}


def _sample(ts, con=24, idle=2, waiting=0, acq=1000, backends=()):
    return {"kind": "sample", "ts": ts, "t_pre": ts, "t_post": ts + 0.01,
            "span_ms": 10.0,
            "pool": {"con": con, "idle": idle, "waiting": waiting,
                     "acq": acq, "wait_ns": 0, "wait_max_ns": 0},
            "backends": [dict(b, pg_ts=b.get("pg_ts", ts)) for b in backends],
            "self": {"utime_s": 0.1, "stime_s": 0.05}}


def _write(tmp: Path, name: str, rows) -> Path:
    p = tmp / name
    if isinstance(rows, dict):
        p.write_text(json.dumps(rows))
        return p
    with open(p, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return p


class ResidencyAnalyzeTest(unittest.TestCase):
    def _fixture(self, tmp: Path):
        # 4 valid samples in [100, 104]; each: 22 checked out =
        # 10 active + 5 idle-in-tx + 7 pg-idle-estimate.
        backends = (
            [_backend(1000 + i, "active", qid=11,
                      wet=None if i % 2 else "IO",
                      we=None if i % 2 else "WALSync")
             for i in range(10)]
            + [_backend(2000 + i, "idle in transaction", qid=22,
                        sc=None) for i in range(5)]
            + [_backend(3000 + i, "idle") for i in range(7)])
        samples = []
        acq = 1000
        for i in range(4):
            ts = 100.0 + i
            be = [dict(b) for b in backends]
            for b in be:
                if b["state"] == "idle in transaction":
                    b["sc"] = ts - 0.45  # 450ms idle age each sample
            samples.append(_sample(ts, acq=acq, backends=be,
                                   waiting=3 if i % 2 else 0))
            acq += 240  # 240 acq/s -> rate known for Little's law
        rows = [
            {"kind": "meta", "run_id": "m1", "script_sha256": "ab" * 4,
             "interval_s": 0.25, "runtime_role": "nazoauth_perf_runtime"},
            {"kind": "role_check", "ts": 100.0,
             "roles": [["nazoauth_perf_runtime", 22],
                       ["postgres", 2]]},
            {"kind": "pgss", "ts": 101.0, "rows": [
                [5, "nazoauth_perf_runtime", True, 11, 100, 50.0,
                 "INSERT INTO oauth_token_issuances ..."],
                [5, "nazoauth_perf_runtime", True, 22, 100, 40.0,
                 "SELECT ... FROM oauth_clients ... FOR SHARE"]]},
        ] + samples
        res = _write(tmp, "residency.jsonl", rows)
        point = _write(tmp, "point.json", {
            "run_id": "m1",
            "point": {"scenario": "cap_mixed"},
            "metrics": {"window_start_ms": 100_000,
                        "window_end_ms": 104_000,
                        "successful_ops_per_s": 2800.0,
                        "outcome_success": 100, "op_p99_ms": 1081.0,
                        "outcome_unexpected": 0}})
        return ra.analyze_point(res, point)

    def test_validity_and_accounting(self):
        with tempfile.TemporaryDirectory() as td:
            out = self._fixture(Path(td))
        self.assertEqual(out["validity"]["samples"], 4)
        self.assertEqual(out["validity"]["valid"], 4)
        self.assertEqual(out["validity"]["valid_ratio"], 1.0)
        co = out["pool"]["checked_out"]
        self.assertEqual(co["mean"], 22)
        self.assertEqual(out["runtime_state"]["active"]["mean"], 10)
        self.assertEqual(
            out["runtime_state"]["idle_in_transaction"]["mean"], 5)
        self.assertEqual(
            out["runtime_state"]["checked_out_pg_idle_estimate"]["mean"],
            7)
        self.assertEqual(out["identity"]["runtime_role"],
                         "nazoauth_perf_runtime")

    def test_littles_law(self):
        with tempfile.TemporaryDirectory() as td:
            out = self._fixture(Path(td))
        ll = out["littles_law"]
        # 3 deltas of 240 acq over 3s -> 240/s; mean checked_out 22 ->
        # 91.67ms implied residency.
        self.assertEqual(ll["acquire_rate_per_s"], 240.0)
        self.assertAlmostEqual(ll["implied_residency_ms"], 91.666, places=2)

    def test_idle_in_tx_attribution(self):
        with tempfile.TemporaryDirectory() as td:
            out = self._fixture(Path(td))
        itx = out["idle_in_tx"]
        self.assertEqual(itx["samples"], 20)  # 5 backends x 4 samples
        self.assertEqual(itx["histogram_count"]["100-500ms"], 20)
        cls = itx["by_class"]["client"]  # oauth_clients -> client class
        self.assertEqual(cls["count"], 20)
        self.assertAlmostEqual(cls["p50"], 450.0, places=1)

    def test_active_wait_distribution(self):
        with tempfile.TemporaryDirectory() as td:
            out = self._fixture(Path(td))
        waits = out["active_wait"]["by_wait_event"]
        self.assertEqual(waits.get("IO:WALSync"), 20)
        self.assertEqual(waits.get("no_wait:-"), 20)
        self.assertEqual(
            out["active_wait"]["by_query_class"]["issuance_insert"], 40)

    def test_waiting_conditioned(self):
        with tempfile.TemporaryDirectory() as td:
            out = self._fixture(Path(td))
        cond = out["waiting_conditioned"]
        self.assertEqual(cond["p_waiting_gt0"], 0.5)
        # checked_out=22 < con-1=23 -> never "full"
        self.assertEqual(cond["p_checked_out_full_given_waiting"], 0.0)

    def test_extra_runtime_backends_invalid(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            be = [_backend(1000 + i, "idle") for i in range(25)]
            rows = [
                {"kind": "meta", "runtime_role": "r"},
                _sample(100.0, con=24, idle=0, backends=be),
            ]
            res = _write(tmp, "r.jsonl", rows)
            point = _write(tmp, "p.json", {
                "run_id": "x", "point": {}, "metrics": {
                    "window_start_ms": 99_000, "window_end_ms": 101_000}})
            out = ra.analyze_point(res, point)
        self.assertEqual(out["validity"]["valid"], 0)
        self.assertEqual(
            out["validity"]["invalid_reasons"]["extra_runtime_backends"], 1)

    def test_negative_idle_estimate_invalid(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # 23 active+itx but only 20 checked out -> negative estimate.
            be = ([_backend(1000 + i, "active") for i in range(20)]
                  + [_backend(2000 + i, "idle in transaction", sc=99.0)
                     for i in range(3)])
            rows = [{"kind": "meta", "runtime_role": "r"},
                    _sample(100.0, con=24, idle=4, backends=be)]
            res = _write(tmp, "r.jsonl", rows)
            point = _write(tmp, "p.json", {
                "run_id": "x", "point": {}, "metrics": {
                    "window_start_ms": 99_000, "window_end_ms": 101_000}})
            out = ra.analyze_point(res, point)
        self.assertEqual(out["validity"]["valid"], 0)
        self.assertEqual(
            out["validity"]["invalid_reasons"]["negative_idle_estimate"], 1)

    def test_idle_age_uses_postgres_clock_and_rejects_invalid_evidence(self):
        for pg_ts, sc, reason in ((100.25, 100.20, None),
                                 (None, 100.20, "missing_pg_idle_age_clock"),
                                 (100.25, None, "missing_pg_idle_age_clock"),
                                 (100.25, 100.30, "invalid_pg_idle_age"),
                                 (float("nan"), 100.2, "invalid_pg_idle_age")):
            with self.subTest(pg_ts=pg_ts, sc=sc), tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                b = dict(_backend(1, "idle in transaction", sc=sc), pg_ts=pg_ts)
                # Host timestamp precedes state_change: using host clock would
                # manufacture a zero age rather than the actual 50ms age.
                res = _write(tmp, "r.jsonl", [_sample(100.0, backends=[b])])
                point = _write(tmp, "p.json", {"metrics": {}})
                out = ra.analyze_point(res, point)
                if reason:
                    self.assertEqual(out["validity"]["valid"], 0)
                    self.assertEqual(out["validity"]["invalid_reasons"][reason], 1)
                else:
                    self.assertEqual(out["validity"]["valid"], 1)
                    self.assertEqual(out["idle_in_tx"]["histogram_count"]["20-100ms"], 1)


if __name__ == "__main__":
    unittest.main()
