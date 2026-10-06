import importlib.util,pathlib,sys,unittest
from unittest.mock import patch
TOOLS=pathlib.Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
import blackbox_contract as contract
import point_runner as points
import single_instance_scaling as sis
from perf.tests.test_pool_size_ab import _rec
class BlackboxContractTests(unittest.TestCase):
    def test_internal_gates_are_unknown_even_when_legacy_values_are_zero(self):
        rec=_rec();rec["collection_contract"]=contract.CONTRACT
        health=points._health_checks(rec,mixed=True)
        for key in contract.INTERNAL_GATES:
            self.assertNotIn(key,health)
            self.assertEqual(contract.unverified_gates()[key]["status"],"UNVERIFIED")
            self.assertIsNone(contract.unverified_gates()[key]["value"])
        queue=contract.audit_queue_unverified()
        self.assertFalse(queue["collected"])
        for key in ("pending_in_process","dropped","enqueued","persisted"):
            self.assertIsNone(queue[key])
    def test_database_or_receiver_failure_remains_a_failed_security_gate(self):
        rec=_rec();rec["collection_contract"]=contract.CONTRACT
        rec["metrics"]["audit_db_drained"]=False
        rec["audit_state_check"]["verdict"]="FAIL"
        rec["audit_state_check"]["journal"]["sequence_gaps"]=1
        health=points._health_checks(rec,mixed=True)
        self.assertFalse(health["db_outbox_drained"])
        self.assertFalse(health["audit_reconciled"])
        self.assertFalse(health["journal_contiguous"])
    def test_new_points_must_declare_contract_and_cannot_enable_retired_collector(self):
        with self.assertRaises(ValueError):contract.require_external_point({})
        with self.assertRaises(ValueError):contract.require_external_point({"collection_contract":contract.CONTRACT,"residency_observer":True})
        contract.require_external_point({"collection_contract":contract.CONTRACT})
    def test_retired_collection_does_not_issue_a_network_or_docker_request(self):
        with patch.object(sis,"dc",side_effect=AssertionError("network must not be attempted")):
            with self.assertRaises(RuntimeError):sis.app_perf_schema()
        self.assertEqual(points.audit_queue_final(pathlib.Path("missing"))["status"],"UNVERIFIED")
    def test_missing_wait_counters_are_not_zero_deltas(self):
        import checkpoint_analyze as ca
        data=[{"ts":1,"pool":{"acquire_count":3,"wait_nanos_total":None}},
              {"ts":2,"pool":{"acquire_count":4}}]
        self.assertEqual(ca.pool_deltas(data)[0],[])
        import stability_analyze as sa
        self.assertEqual(sa.per_bucket_pool([{"kind":"sample","ts":61,"pool":{"con":32,"idle":0}}],0,2),{})
    def test_legacy_health_contract_retains_its_internal_gates(self):
        rec=_rec();health=points._health_checks(rec,mixed=True)
        self.assertTrue(all(key in health for key in contract.INTERNAL_GATES))
if __name__=="__main__":unittest.main()
