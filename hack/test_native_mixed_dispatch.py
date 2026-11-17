"""Offline dispatch-binding regressions; native execution remains a separate gate."""
import unittest
from test_native_mixed_contract import FakeAPI, mixed


class MixedDispatchTests(unittest.TestCase):
    def test_resource_admissions_dispatch_exact_cpu_volume_and_nested_class(self):
        api = FakeAPI()
        api.nested = True
        runner = mixed.Mixed(api, "fixture", nested=True)
        runner.dispatch_resources()
        receipts = {r["case"]: r for r in runner.receipts}
        for label, cpu, volume, runtime_class in (("cpu", 250, None, "default"),
                                                 ("volume", 500, 2, "default"),
                                                 ("nested-volume", 1000, 2, "nested")):
            prefix = "resource-" + label
            requirement = receipts[prefix + "-reserve"]["request"]["json"]["requirements"]
            self.assertEqual(len(requirement), 1)
            request = receipts[prefix + "-matching"]["request"]
            self.assertEqual(request["json"]["size"], requirement[0]["size"])
            self.assertEqual(request["json"]["size"]["cpu_millis"], cpu)
            self.assertEqual(request["json"].get("volume", {}).get("size_gb"), volume)
            self.assertEqual(request["json"]["runtime_class"], runtime_class)
            self.assertEqual(request["headers"]["x-briqyard-placement-request-id"], runner.prefix + "-" + prefix)
            for axis in ("cpu", "memory", "volume", "class"):
                self.assertEqual(receipts[prefix + "-mismatch-" + axis]["observed"]["status"], 409)
        self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 15)
        self.assertTrue(all(a["dispatched"] for a in api.admissions.values()))
        self.assertTrue(all(dispatched for _, dispatched in runner.admissions))
        runner.cleanup()
        self.assertEqual(set(api.machines), {"m_seed", "m_other"})

    def test_resource_mismatch_acceptance_fails_before_matching_dispatch(self):
        for index, axis in enumerate(("cpu", "memory", "volume", "class"), 1):
            with self.subTest(axis=axis):
                class Wrong(FakeAPI):
                    def call(self, method, path, body=None, headers=None, *, timeout=None):
                        self.bad_dispatch = bool(body and body.get("name", "").endswith("-mismatch-" + axis))
                        return super().call(method, path, body, headers, timeout=timeout)
                api = Wrong()
                # Make class mismatch a valid create too, so accepting it reaches the assertion.
                api.nested = True
                runner = mixed.Mixed(api, "fixture")
                with self.assertRaises(mixed.clone.ContractFailure):
                    runner.dispatch_resources()
                self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), index)
                self.assertFalse(any(r["case"].endswith("-matching") for r in runner.receipts))
                # An unexpectedly committed mismatch cannot be called clean cancellation.
                with self.assertRaises(mixed.clone.ContractFailure):
                    runner.cleanup()
                self.assertEqual(set(api.machines), {"m_seed", "m_other"})

    def test_lost_resource_dispatch_is_not_replayed_and_keeps_cleanup_uncertain(self):
        class Lost(FakeAPI):
            def call(self, method, path, body=None, headers=None, *, timeout=None):
                result = super().call(method, path, body, headers, timeout=timeout)
                if method == "POST" and path == "/machines" and result[0] == 201:
                    raise TimeoutError()
                return result
        api = Lost()
        runner = mixed.Mixed(api, "fixture")
        with self.assertRaises(TimeoutError):
            runner.dispatch_resources()
        self.assertTrue(runner.admissions[-1][1])
        # Existing cleanup may discover/delete the exact owned create, never POST it again.
        with self.assertRaises(mixed.clone.ContractFailure):
            runner.cleanup()
        self.assertEqual(sum(m == "POST" and p == "/machines" for m, p, _ in api.calls), 5)
        self.assertEqual(set(api.machines), {"m_seed", "m_other"})

    def test_resource_dispatch_does_not_claim_nested_when_fixture_disables_it(self):
        api = FakeAPI()
        runner = mixed.Mixed(api, "fixture")
        runner.dispatch_resources()
        self.assertFalse(any("nested-volume" in r["case"] for r in runner.receipts))
        runner.cleanup()


if __name__ == "__main__":
    unittest.main()
