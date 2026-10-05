"""Service affinity must cover mixed UIDs, child processes and threads."""
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import single_instance_scaling as sis


def snapshot(*rows):
    return subprocess.CompletedProcess([], 0, "inspector 90\n" + "\n".join(row + " 12345" for row in rows) + "\nsnapshot_complete 1", "")


class ServiceAffinityTests(unittest.TestCase):
    def test_pid1_matches_but_daemon_does_not(self):
        with patch.object(sis, "dcx", return_value=snapshot(
                "1 1 0 0 8-9 tini", "7 7 1 999 0-63 valkey-server")):
            self.assertFalse(sis.verify_pin("fixture", "8-9"))

    def test_matching_init_mask_without_actual_daemon_does_not_qualify(self):
        with patch.object(sis, "dcx", return_value=snapshot("1 1 0 0 8-9 tini")):
            self.assertFalse(sis.verify_pin("fixture", "8-9", "valkey-server"))

    def test_unread_still_present_worker_invalidates_otherwise_matching_rows(self):
        result = snapshot("1 1 0 10001 8-9 nazoauth")
        result.stdout = result.stdout.replace("snapshot_complete 1", "unread 1 17 13\nsnapshot_complete 0")
        result.returncode = 1
        with patch.object(sis, "dcx", return_value=result):
            report = sis.container_task_snapshot("fixture")
            self.assertFalse(report['complete'])
            self.assertEqual(report['read_errors'], [{'pid': 1, 'tid': 17, 'errno': 13}])
            self.assertFalse(sis.verify_pin("fixture", "8-9"))

    def test_confirmed_exited_worker_is_retained_without_invalidating_live_tasks(self):
        result = snapshot("1 1 0 10001 8-9 nazoauth")
        result.stdout = result.stdout.replace("snapshot_complete 1", "gone 1 17 2\nsnapshot_complete 1")
        with patch.object(sis, "dcx", return_value=result):
            report = sis.container_task_snapshot("fixture")
            self.assertTrue(report['complete'])
            self.assertEqual(report['confirmed_gone'], [{'pid': 1, 'tid': 17, 'errno': 2}])
            self.assertTrue(sis.verify_pin("fixture", "8-9"))

    def test_missing_collector_footer_cannot_qualify_matching_rows(self):
        result = snapshot("1 1 0 10001 8-9 nazoauth")
        result.stdout = result.stdout.replace("\nsnapshot_complete 1", "")
        with patch.object(sis, "dcx", return_value=result):
            self.assertFalse(sis.verify_pin("fixture", "8-9"))

    def test_one_worker_thread_outside_mask_rejects_process(self):
        with patch.object(sis, "dcx", return_value=snapshot(
                "1 1 0 10001 8-9 nazoauth", "1 17 0 10001 0-63 worker")):
            self.assertFalse(sis.verify_pin("fixture", "8-9"))

    def test_child_and_grandchild_threads_are_checked(self):
        with patch.object(sis, "dcx", return_value=snapshot(
                "1 1 0 0 8-9 python", "7 7 1 0 8-9 sh",
                "12 12 7 0 8-9 k6", "12 15 7 0 0-63 k6")):
            self.assertFalse(sis.verify_pin("fixture", "8-9"))

    def test_transient_exec_inspectors_are_excluded_even_when_reparented(self):
        with patch.object(sis, "dcx", return_value=snapshot(
                "1 1 0 0 8-9 tini", "7 7 1 999 8-9 valkey-server",
                "90 90 1 0 0-63 sh", "91 91 90 0 0-63 awk",
                "80 80 0 999 0-63 healthcheck")):
            self.assertTrue(sis.verify_pin("fixture", "8-9"))

    def test_missing_pid1_and_failed_or_malformed_snapshots_fail_closed(self):
        cases = [snapshot("7 7 1 999 8-9 valkey-server"),
                 subprocess.CompletedProcess([], 1, "", ""),
                 snapshot("1 1 0 0 bad tini"), snapshot("incomplete")]
        for result in cases:
            with self.subTest(result=result.stdout), patch.object(sis, "dcx", return_value=result):
                self.assertFalse(sis.verify_pin("fixture", "8-9"))

    def test_mixed_owners_pin_each_service_tree_as_its_owner(self):
        before = snapshot("1 1 0 0 0-63 tini", "7 7 1 999 0-63 valkey-server",
                          "7 8 1 999 0-63 valkey-server")
        after = snapshot("1 1 0 0 8-9 tini", "7 7 1 999 8-9 valkey-server",
                         "7 8 1 999 8-9 valkey-server")
        with patch.object(sis, "ensure_pinset"), patch.object(sis, "dcx", side_effect=[before, after]), \
                patch.object(sis, "dc", return_value=subprocess.CompletedProcess([], 0, "pinned", "")) as execute:
            result = sis.pin_container("fixture", "8-9")
        self.assertTrue(result['verified'])
        self.assertEqual([call.args[2] for call in execute.call_args_list], ['0', '999'])
        self.assertEqual([call.args[-1] for call in execute.call_args_list], ['1', '7'])
        self.assertEqual(len(result['task_masks']), 3)

    def test_owner_pin_failure_retains_invalid_actual_daemon_mask(self):
        unchanged = snapshot("1 1 0 0 8-9 tini", "7 7 1 999 0-63 valkey-server")
        with patch.object(sis, "ensure_pinset"), patch.object(sis, "dcx", return_value=unchanged), \
                patch.object(sis, "dc", return_value=subprocess.CompletedProcess([], 1, "", "")):
            result = sis.pin_container("fixture", "8-9")
        self.assertEqual(result['pin_rc'], 1)
        self.assertFalse(result['verified'])


if __name__ == "__main__":
    unittest.main()
