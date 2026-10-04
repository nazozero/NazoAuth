"""Offline old/new audit-schema regressions; never starts Docker or load."""
import importlib.util
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import ledger_check
import point_runner
import single_instance_scaling as sis

# soak_sampler is mounted alone and its runtime drivers are not host deps.
spec = importlib.util.spec_from_file_location("audit_test_sampler", TOOLS / "soak_sampler.py")
sampler = importlib.util.module_from_spec(spec)
with mock.patch.dict(sys.modules, {
    "psycopg": types.SimpleNamespace(connect=mock.Mock()),
    "redis": types.SimpleNamespace(Redis=mock.Mock()),
    "redis.backoff": types.SimpleNamespace(NoBackoff=mock.Mock()),
    "redis.retry": types.SimpleNamespace(Retry=mock.Mock()),
}):
    spec.loader.exec_module(sampler)


class AuditSchemaTests(unittest.TestCase):
    def setUp(self):
        sis.reset_audit_schema_cache()
        self.addCleanup(sis.reset_audit_schema_cache)

    def test_old_and_new_predicates_probe_once_per_target_and_reset(self):
        for present, predicates in [("t", ("exported_at IS NULL", "exported_at IS NOT NULL")),
                                    ("f", ("TRUE", "FALSE"))]:
            with self.subTest(present=present), mock.patch.object(sis, "psql", return_value=present) as sql:
                sis.reset_audit_schema_cache()
                self.assertEqual(sis.audit_event_predicates(), predicates)
                self.assertEqual(sis.audit_event_predicates(), predicates)
                self.assertEqual(sql.call_count, 1)
                with mock.patch.object(sis, "PROJECT", "different-project"):
                    self.assertEqual(sis.audit_event_predicates(), predicates)
                with mock.patch.object(sis, "POSTGRES", "different-postgres"):
                    self.assertEqual(sis.audit_event_predicates(), predicates)
                self.assertEqual(sql.call_count, 3)
                sis.reset_audit_schema_cache()
                sis.audit_event_predicates()
                self.assertEqual(sql.call_count, 4)

    def test_probe_failure_or_invalid_response_is_not_cached_as_legacy(self):
        for failure in [RuntimeError("database unavailable"), "", "unexpected"]:
            with self.subTest(failure=failure), mock.patch.object(sis, "psql", side_effect=[failure, "t"]) as sql:
                sis.reset_audit_schema_cache()
                with self.assertRaises((RuntimeError, ValueError)):
                    sis.audit_event_predicates()
                self.assertEqual(sis.audit_event_predicates()[0], "exported_at IS NULL")
                self.assertEqual(sql.call_count, 2)

    def test_drain_counts_retained_rows_only_once_after_pending_reaches_zero(self):
        with mock.patch.object(sis, "psql", side_effect=["t", "2|10|8", "0|10|10", "7|7"]) as sql, \
                mock.patch.object(sis.time, "time", return_value=0), \
                mock.patch.object(sis.time, "sleep") as sleep:
            result = sis.audit_drain()
        self.assertEqual(result, {"pending": 0, "last_sequence": 10, "anchor_sequence": 10,
                                  "drained": True, "total": 7, "exported_retained": 7})
        queries = [call.args[0] for call in sql.call_args_list]
        self.assertEqual(sum("FROM pg_attribute" in query for query in queries), 1)
        self.assertEqual(sum("count(*) FILTER" in query for query in queries), 1)
        self.assertTrue(all("WHERE exported_at IS NULL" in query for query in queries[1:3]))
        sleep.assert_called_once_with(3)
        self.assertTrue(sis.audit_db_drained_of(result))

    def test_drain_legacy_schema_still_means_pending_equals_all_rows(self):
        with mock.patch.object(sis, "psql", side_effect=["f", "0|10|10", "0|0"]) as sql, \
                mock.patch.object(sis.time, "time", return_value=0):
            result = sis.audit_drain()
        self.assertTrue(result["drained"])
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["exported_retained"], 0)
        self.assertIn("WHERE TRUE", sql.call_args_list[1].args[0])
        self.assertIn("WHERE FALSE", sql.call_args_list[2].args[0])
        self.assertNotIn("exported_at", " ".join(call.args[0] for call in sql.call_args_list[1:]))

    def test_timeout_keeps_exact_pending_gate_and_captures_totals_once(self):
        with mock.patch.object(sis, "psql", side_effect=["t", "2|10|8", "7|5"]) as sql, \
                mock.patch.object(sis.time, "time", side_effect=[0, 0, 2]), \
                mock.patch.object(sis.time, "sleep"):
            result = sis.audit_drain(timeout_s=1)
        self.assertFalse(result["drained"])
        self.assertEqual(result["pending"], 2)
        self.assertEqual(result["total"], 7)
        self.assertEqual(result["exported_retained"], 5)
        self.assertEqual(sql.call_count, 3)
        self.assertFalse(sis.audit_db_drained_of(result))

    def test_point_snapshot_keeps_pending_and_total_independent_on_both_schemas(self):
        for present, pending, total, retained in [("t", 0, 7, 7), ("f", 7, 7, 0)]:
            with self.subTest(present=present), mock.patch.object(sis, "psql", side_effect=[
                present, f"{pending}|10|hash|deployment|10|hash", f"{total}|{retained}",
            ]) as sql:
                sis.reset_audit_schema_cache()
                result = point_runner.db_chain_state()
                self.assertTrue(result["collected"], result)
                self.assertEqual((result["pending"], result["total"], result["exported_retained"]),
                                 (pending, total, retained))
                expected = "exported_at IS NULL" if present == "t" else "TRUE"
                self.assertIn("WHERE " + expected, sql.call_args_list[1].args[0])

    def test_lifecycle_entry_points_invalidate_target_cache(self):
        # Stop before external work: each lifecycle boundary must reset first.
        for module, operation, args, first_external in [
            (sis, sis.stack_down, (), "compose"),
            (sis, sis.stack_up, ({"name": "point", "image": "image"},), "dc"),
            (sis, point_runner.stack_up_pinned, ({"name": "point", "image": "image"},), "dc"),
        ]:
            with self.subTest(operation=operation.__name__):
                sis._AUDIT_SCHEMA_CACHE[(sis.PROJECT, sis.POSTGRES, "oauth")] = True
                with mock.patch.object(module, first_external, side_effect=RuntimeError("stop before external action")):
                    with self.assertRaises(RuntimeError):
                        operation(*args)
                self.assertEqual(sis._AUDIT_SCHEMA_CACHE, {})


class FakeConnection:
    def __init__(self, has_exported_at):
        self.has_exported_at = has_exported_at
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params=None):
        self.queries.append(query)
        if "FROM pg_attribute" in query:
            row = (self.has_exported_at,)
        elif "FROM security_audit_chain_state" in query:
            expected = "exported_at IS NULL" if self.has_exported_at else "TRUE"
            assert "WHERE " + expected in query
            row = (2 if self.has_exported_at else 7, 10, 8)
        elif "FROM security_audit_events" in query:
            expected = "exported_at IS NOT NULL" if self.has_exported_at else "FALSE"
            assert "FILTER (WHERE " + expected + ")" in query
            row = (7, 5 if self.has_exported_at else 0)
        elif "count(*) FROM oauth_token_issuances" in query:
            row = (100, 0)
        elif "pg_database_size" in query or "wal_bytes::bigint" in query:
            row = (0,)
        else:
            row = ()
        return types.SimpleNamespace(fetchone=lambda: row, fetchall=lambda: [])


class SamplerTests(unittest.TestCase):
    def test_sampler_old_new_counts_are_independent_and_totals_are_optional(self):
        for present in (False, True):
            with self.subTest(present=present):
                connection = FakeConnection(present)
                predicates = sampler.audit_event_predicates(connection)
                result = sampler.audit_snapshot(connection, predicates)
                self.assertEqual(result["pending"], 2 if present else 7)
                self.assertNotIn("total", result)
                self.assertEqual(len(connection.queries), 2)
                result = sampler.audit_snapshot(connection, predicates, include_totals=True)
                self.assertEqual(result["total"], 7)
                self.assertEqual(result["exported_retained"], 5 if present else 0)
                self.assertFalse(any("to_json" in query for query in connection.queries))

    def test_sampler_probes_once_across_connections_and_totals_are_sparse(self):
        class StopSampler(Exception):
            pass

        for present in (False, True):
            with self.subTest(present=present):
                connections = [FakeConnection(present), FakeConnection(present)]
                output = io.StringIO()
                with mock.patch.object(sampler, "open", return_value=output, create=True), \
                        mock.patch.object(sampler, "self_sha256", return_value="test"), \
                        mock.patch.object(sampler.psycopg, "connect", side_effect=connections), \
                        mock.patch.object(sampler.time, "monotonic", return_value=100), \
                        mock.patch.object(sampler.time, "time", return_value=100), \
                        mock.patch.object(sampler.time, "sleep", side_effect=[None, StopSampler]), \
                        mock.patch.object(sampler.urllib.request, "urlopen", side_effect=RuntimeError("offline")):
                    sampler.redis.Redis.from_url.return_value.info.return_value = {}
                    with self.assertRaises(StopSampler):
                        sampler.main()
                rows = [json.loads(line) for line in output.getvalue().splitlines()]
                self.assertNotIn("pg_err", rows[1])
                self.assertNotIn("pg_err", rows[2])
                queries = [query for connection in connections for query in connection.queries]
                self.assertEqual(sum("FROM pg_attribute" in query for query in queries), 1)
                self.assertEqual(sum("FILTER (WHERE" in query and "FROM security_audit_events" in query
                                     for query in queries), 1)
                self.assertEqual(rows[1]["audit"]["total"], 7)
                self.assertNotIn("total", rows[2]["audit"])
                self.assertEqual(rows[2]["audit"]["pending"], 2 if present else 7)


class LedgerCompatibilityTests(unittest.TestCase):
    def test_ledger_pending_and_oldest_queries_use_one_schema_probe(self):
        source = (TOOLS / "ledger.sql").read_text()
        self.assertEqual(source.count("FROM pg_attribute"), 1)
        branches = source.split("\\if :audit_has_exported_at", 1)[1].split("\\endif", 1)[0]
        new, old = branches.split("\\else", 1)
        for branch, expected in [(new, ("exported_at IS NULL", "exported_at IS NOT NULL")),
                                 (old, ("TRUE", "FALSE"))]:
            variables = {}
            for line in branch.splitlines():
                if line.startswith("\\set "):
                    _, name, value = line.split(" ", 2)
                    variables[name] = value.strip("'")
            self.assertEqual((variables["audit_pending_predicate"], variables["audit_exported_predicate"]), expected)
            audit = source.split("-- ============================ AUDIT (KV)", 1)[1].split(
                "-- ============================ XACT_HORIZON", 1)[0]
            for name, value in variables.items():
                audit = audit.replace(":" + name, value)
            self.assertEqual(audit.count("WHERE " + expected[0]), 2)
            self.assertIn("WHERE " + expected[1], audit)
            self.assertIn("'events',\n       (SELECT count(*)::text FROM security_audit_events)", audit)
            if expected[0] == "TRUE":
                self.assertNotIn("exported_at", audit)
        self.assertIn("FROM security_audit_events WHERE :audit_pending_predicate\nUNION ALL SELECT 'EXPIRED_BACKLOG'", source)

    def test_historical_ledger_and_drain_shapes_still_parse_unchanged(self):
        historical = (
            "META|run_id|historic\nAUDIT|ledger|pending_export|9\n"
            "AUDIT|ledger|events|9\nAUDIT|ledger|oldest_pending_age_s|4\n"
            "EXPIRED_BACKLOG|pending_events|9|2026-09-01 00:00:00\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.txt"
            path.write_text(historical)
            errors = []
            before = ledger_check.parse_ledger(str(path), errors)
            self.assertEqual(errors, [])
            self.assertEqual(before["AUDIT"][0], {"kind": "ledger", "key": "pending_export", "value": "9"})
            path.write_text(historical + "AUDIT|ledger|exported_retained|0\n")
            after = ledger_check.parse_ledger(str(path), errors)
            self.assertEqual(after["AUDIT"][:-1], before["AUDIT"])
            self.assertEqual(after["EXPIRED_BACKLOG"], before["EXPIRED_BACKLOG"])
            self.assertEqual(errors, [])
        self.assertTrue(sis.audit_db_drained_of({"pending": 0, "drained": True,
                                               "last_sequence": 10, "anchor_sequence": 10}))


if __name__ == "__main__":
    unittest.main()
