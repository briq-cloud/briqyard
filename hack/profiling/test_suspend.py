"""Pure log fixtures: no machine, API or system service."""
import json
import unittest

from suspend import summarize


def stage(machine, pid, name, finished, elapsed=0):
    return json.dumps({"fields": {
        "profile": "lifecycle",
        "operation": "suspend", "stage": name, "machine": machine, "pid": pid,
        "elapsed_us": elapsed, "finished_us": finished, "completed": True,
        "unexpected": "must not enter the report",
    }})


class SuspendProfile(unittest.TestCase):
    def test_separates_process_exit_and_transport_without_summing_nested_stages(self):
        lines = [stage("m_a", 42, "kill_begin", 100),
                 stage("m_other", 42, "exit_observed", 200),
                 stage("m_a", 43, "exit_observed", 300),
                 stage("m_a", 42, "exit_observed", 450),
                 stage("m_a", 42, "total", 1000, 900),
                 json.dumps({"fields": {"request_id": "r_a", "path": "/v1/machines/m_a/stop",
                                        "ms": 2, "status": 200, "extra": "discard"}}),
                 "not json", "null", "[]"]
        result = summarize(lines, "m_a", 42, "abcdef0", "abcdef1", "r_a", 4.5)
        self.assertEqual(result["kill_to_exit_observed_us"], 350)
        self.assertEqual(result["caller_minus_daemon_ms"], 2.5)
        self.assertEqual(len(result["stages"]), 3)
        self.assertNotIn("unexpected", json.dumps(result))
        self.assertNotIn("extra", json.dumps(result))

    def test_does_not_pair_ambiguous_or_out_of_order_exit_events(self):
        for lines in [[stage("m_a", 42, "kill_begin", 100),
                       stage("m_a", 42, "exit_observed", 90)],
                      [stage("m_a", 42, "kill_begin", 100),
                       stage("m_a", 42, "kill_begin", 200),
                       stage("m_a", 42, "exit_observed", 300)]]:
            self.assertIsNone(summarize(lines, "m_a", 42, "abcdef0")["kill_to_exit_observed_us"])


if __name__ == "__main__":
    unittest.main()
