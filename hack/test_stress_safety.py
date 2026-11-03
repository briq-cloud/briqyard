import json
import os
import unittest
import threading
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, MagicMock
import stress

from stress_safety import BudgetExpired, Safety


class SafetyTest(unittest.TestCase):
    def setUp(self):
        self.policy = Safety()
        self.addCleanup(lambda: os.unlink(self.policy.receipt))
        self.calls = []
        self.machines = []
        self.answer = (201, json.dumps({'id': 'owned'}))

    def send(self, method, path, body=None, op=None, timeout=300):
        self.calls.append((method, path, timeout))
        if method == 'GET':
            if path == '/v1/machines':
                return 200, json.dumps(self.machines)
            return 200, json.dumps(self.machines[0])
        if self.answer[0] == 201 and method == 'POST':
            return 201, json.dumps(dict(body, id='owned'))
        return self.answer

    def create(self):
        return self.policy.request(self.send, 'POST', '/v1/machines',
                                   {'namespace': self.policy.identity + '-t0', 'name': 'm0'})

    def test_unique_identity_independent_of_seed(self):
        other = Safety()
        self.addCleanup(lambda: os.unlink(other.receipt))
        self.assertNotEqual(other.identity, self.policy.identity)
        self.assertEqual(os.stat(self.policy.receipt).st_mode & 0o777, 0o600)

    def test_collision_not_adopted(self):
        self.machines = [{'namespace': self.policy.identity + '-t0', 'name': 'm0'}]
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            self.create()
        self.assertTrue(all(c[0] == 'GET' for c in self.calls))
        self.assertEqual(self.policy.owned, {})

    def test_exact_cleanup_preserves_unknown_and_changed(self):
        self.create()
        good = {'id': 'owned', 'namespace': self.policy.identity + '-t0',
                'name': 'm0', 'metadata': {'stress': self.policy.identity}}
        for machine in [dict(good, id='unknown'), dict(good, namespace=self.policy.identity + '-t00'),
                        dict(good, metadata={})]:
            self.machines = [machine]
            with self.assertRaisesRegex(RuntimeError, 'preserving'):
                self.policy.request(self.send, 'DELETE', '/v1/machines/owned')
        self.assertFalse(any(c[0] == 'DELETE' for c in self.calls))
        self.machines = [good]
        self.policy.request(self.send, 'DELETE', '/v1/machines/owned')
        self.assertEqual(self.calls[-1][0], 'DELETE')

    def test_swapped_owned_response_cannot_authorize_requested_id(self):
        self.create()
        other = {'id': 'other', 'namespace': 'other-ns', 'name': 'other-name',
                 'metadata': {'stress': self.policy.identity}}
        self.policy.owned['other'] = ['other-ns', 'other-name']
        self.machines = [other]
        for method, path, body in [
                ('DELETE', '/v1/machines/owned', None),
                ('POST', '/v1/machines/owned/start', None),
                ('POST', '/v1/machines', {'namespace': 'ns', 'name': 'fork',
                                        'fork': {'machine_id': 'owned'}}),
                ('POST', '/v1/machines', {'namespace': 'ns', 'name': 'restore',
                                        'restore': {'machine_id': 'owned'}})]:
            before = len(self.calls)
            with self.assertRaisesRegex(RuntimeError, 'preserving'):
                self.policy.request(self.send, method, path, body)
            self.assertTrue(all(c[0] == 'GET' for c in self.calls[before:]))
        self.assertIn('owned', self.policy.owned)

    def test_deadline_transport_timeout_is_completion_except_create(self):
        api = stress.Api('http://unused.invalid', '', self.policy)
        self.policy.deadline = 12
        def timed_out(*args, **kwargs):
            self.assertEqual(kwargs['timeout'], 2)
            raise stress.urllib.error.URLError(TimeoutError('timed out'))
        with patch('stress.time.monotonic', side_effect=[10, 10, 10, 12]), \
                patch('stress.urllib.request.urlopen', side_effect=timed_out):
            with self.assertRaises(BudgetExpired):
                api.call('GET', '/v1/machines')
        self.assertEqual(api.failures, [])

        def create_transport(method, path, body=None, op=None, timeout=300):
            if method == 'GET':
                return 200, '[]'
            return api._request(method, path, body, op, timeout)
        with patch('stress.time.monotonic', side_effect=[10, 10, 10, 10, 12, 12]), \
                patch('stress.urllib.request.urlopen', side_effect=timed_out):
            with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
                self.policy.request(create_transport, 'POST', '/v1/machines',
                                    {'namespace': 'ns', 'name': 'm0'})
        self.assertTrue(self.policy.unresolved)
        self.assertEqual(self.policy.intents, [['ns', 'm0']])
        self.assertEqual(self.policy.owned, {})

    def test_ambiguous_create_no_replay_or_mutation(self):
        self.answer = (0, 'timeout')
        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            self.create()
        self.assertTrue(self.policy.unresolved)
        with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
            self.create()
        with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
            self.policy.request(self.send, 'POST', '/v1/machines/owned/start')
        self.assertEqual(sum(c[0] == 'POST' for c in self.calls), 1)
        with open(self.policy.receipt) as f:
            receipt = json.load(f)
        self.assertEqual(receipt['accepted'], {})
        self.assertEqual(len(receipt['intents']), 1)

    def test_deadline_caps_and_stops_new_operations(self):
        with patch('stress_safety.time.monotonic', return_value=10):
            self.policy.deadline = 12
            self.policy.request(self.send, 'GET', '/v1/machines', timeout=600)
            self.assertEqual(self.calls[-1][2], 2)
            with patch('stress_safety.time.sleep') as sleep:
                self.policy.sleep(20)
                sleep.assert_called_once_with(2)
        with patch('stress_safety.time.monotonic', return_value=13):
            with self.assertRaises(BudgetExpired):
                self.create()
            self.assertFalse(any(c[0] == 'POST' for c in self.calls))
            self.policy.begin_cleanup()
            self.assertEqual(self.policy.cap(600), 180)

    def test_four_creates_enter_transport_concurrently(self):
        barrier = threading.Barrier(4, timeout=3)
        def transport(method, path, body=None, op=None, timeout=300):
            if method == 'GET':
                return 200, '[]'
            barrier.wait()
            return 201, json.dumps(dict(body, id=body['name']))
        def create(i):
            return self.policy.request(transport, 'POST', '/v1/machines',
                                       {'namespace': self.policy.identity + '-t0', 'name': str(i)})
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(create, range(4)))
        self.assertEqual(len(self.policy.owned), 4)
        self.assertEqual(self.policy.intents, [])

    def test_create_response_mismatch_never_authorizes_mutation(self):
        for field, value in [('namespace', 'other'), ('name', 'other'), ('metadata', {})]:
            def transport(method, path, body=None, op=None, timeout=300):
                if method == 'GET':
                    return 200, '[]'
                return 201, json.dumps(dict(dict(body, id='wrong'), **{field: value}))
            self.policy.unresolved = False
            self.policy.intents.clear()
            with self.assertRaisesRegex(RuntimeError, 'inconsistent'):
                self.policy.request(transport, 'POST', '/v1/machines',
                                    {'namespace': 'ns', 'name': 'm0'})
            self.assertEqual(self.policy.owned, {})

    def test_changed_ownership_blocks_all_mutations_and_sources(self):
        self.create()
        self.machines = [{'id': 'owned', 'namespace': 'changed', 'name': 'm0'}]
        for method, path, body in [
                ('POST', '/v1/machines/owned/exec', {}),
                ('POST', '/v1/machines/owned/start', {}),
                ('POST', '/v1/machines/owned/stop', {}),
                ('POST', '/v1/machines/owned/snapshots', {}),
                ('PATCH', '/v1/machines/owned', {}),
                ('PUT', '/v1/machines/owned/files', {}),
                ('POST', '/v1/machines', {'namespace': 'ns', 'name': 'fork', 'fork': {'machine_id': 'owned'}}),
                ('POST', '/v1/machines', {'namespace': 'ns', 'name': 'restore', 'restore': {'machine_id': 'owned'}})]:
            before = len(self.calls)
            with self.assertRaisesRegex(RuntimeError, 'preserving'):
                self.policy.request(self.send, method, path, body)
            self.assertTrue(all(c[0] == 'GET' for c in self.calls[before:]))

    def test_inflight_acceptance_survives_another_ambiguous_create(self):
        barrier = threading.Barrier(2, timeout=3)
        ambiguous_done = threading.Event()
        def transport(method, path, body=None, op=None, timeout=300):
            if method == 'GET':
                return 200, '[]'
            barrier.wait()
            if body['name'] == 'bad':
                return 0, ''
            self.assertTrue(ambiguous_done.wait(3))
            return 201, json.dumps(dict(body, id='accepted'))
        def create(name):
            try:
                self.policy.request(transport, 'POST', '/v1/machines', {'namespace': 'ns', 'name': name})
            except RuntimeError:
                ambiguous_done.set()
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(create, ['bad', 'good']))
        self.assertTrue(self.policy.unresolved)
        self.assertEqual(self.policy.owned, {'accepted': ['ns', 'good']})
        self.assertEqual(self.policy.intents, [['ns', 'bad']])

    def test_duration_completion_and_cleanup_exit_status_and_report_order(self):
        for failures, unresolved, cleanup_error, expected in [
                ([], False, None, 0), ([('failed',)], False, None, 1),
                ([], True, None, 1), ([], False, RuntimeError('cleanup failed'), 1)]:
            run = MagicMock()
            run.namespaces = ['retained']
            run.api.failures = failures
            run.broken = []
            run.safety.unresolved = unresolved
            run.safety.owned = {}
            run.run.side_effect = BudgetExpired('duration complete')
            run.destroy_all.side_effect = cleanup_error
            with patch('stress.Run', return_value=run), patch('sys.argv', ['stress']), patch('stress.signal.signal'):
                with self.assertRaises(SystemExit) as exit_result:
                    stress.main()
            self.assertEqual(exit_result.exception.code, expected)
            calls = [call[0] for call in run.mock_calls]
            self.assertLess(calls.index('destroy_all'), calls.index('report'))



class CapacityObservationTest(unittest.TestCase):
    def fixture(self, *, sampler_failure=False, start_failure=False, missing_response=False, no_sample=False, cutoff=False):
        done = threading.Event()
        sampler = SimpleNamespace(joined=False, unhandled=[])
        def thread(target):
            def start():
                try:
                    if no_sample:
                        done.set()
                    target()
                except Exception as error:
                    sampler.unhandled.append(error)
            sampler.start = start
            sampler.join = lambda: setattr(sampler, 'joined', True)
            return sampler
        run = object.__new__(stress.Run)
        run.a = SimpleNamespace(image='fixed-test-image', boot_timeout=1)
        run.namespaces = ['fixed-test-namespace']
        run.broken = []
        run.phase = MagicMock()
        run.log = MagicMock()
        run.invariants = MagicMock()
        run.destroy_all = MagicMock()
        run.report = MagicMock()
        run.safety = SimpleNamespace(sleep=lambda _: done.set(), begin_cleanup=MagicMock(),
                                     unresolved=False, owned={})
        def call(method, path, body=None, **kwargs):
            if path == '/v1/status':
                if cutoff == 'status':
                    raise BudgetExpired('stress time budget exhausted')
                return {'capacity': {'memory_mb': 100}, 'used': {'memory_mb': 10}}
            if method == 'POST':
                if cutoff == 'create' and body['name'] == 'cap2':
                    raise BudgetExpired('stress time budget exhausted')
                return {'id': body['name']}
        def request(method, path, **kwargs):
            if start_failure and '/cap3/' in path:
                raise RuntimeError('UNSAFE_SYNTHETIC_START_ERROR')
            return (200, '{}') if '/cap0/' in path else (503, '{"code":"capacity"}')
        run.api = SimpleNamespace(call=call, request=request, failures=[])
        def wait(mid, want, **kwargs):
            if (cutoff is True and want == {'running'}) or (cutoff == 'created' and want == {'created'}):
                raise BudgetExpired('stress time budget exhausted')
        run.wait_state = wait
        if sampler_failure:
            run.mlist = MagicMock(side_effect=RuntimeError('UNSAFE_SYNTHETIC_SAMPLE_ERROR'))
        else:
            run.mlist = MagicMock(return_value=[{'state': 'running', 'size': {'memory_mb': 10}},
                                               {'state': 'running', 'size': {'memory_mb': 31}}])
        run.mget = MagicMock(return_value={'state': 'created'}, side_effect=BudgetExpired('stress time budget exhausted') if cutoff == 'refused_state' else None)
        parallel_calls = 0
        def parallel(items, fn, workers):
            nonlocal parallel_calls
            parallel_calls += 1
            results, errors = {}, {}
            for i, item in enumerate(items):
                if missing_response and parallel_calls == 2 and i == 3:
                    continue
                try:
                    results[i] = fn(item)
                except Exception as error:
                    errors[i] = error
            return results, errors
        return run, sampler, done, thread, parallel

    def exercise(self, **kwargs):
        run, sampler, done, thread, parallel = self.fixture(**kwargs)
        with patch('stress.threading.Event', return_value=done), \
                patch('stress.threading.Thread', side_effect=thread), \
                patch('stress.parallel', side_effect=parallel):
            run.starts_past_capacity()
        self.assertTrue(sampler.joined)
        return run, sampler

    def test_sampler_get_failure_cannot_pass_capacity_phase(self):
        run, sampler = self.exercise(sampler_failure=True)
        self.assertTrue(run.broken, 'sampler failure must fail capacity observation')
        self.assertFalse(sampler.unhandled)
        self.assertNotIn('UNSAFE_SYNTHETIC', str(run.log.call_args_list))

    def test_start_exception_cannot_hide_behind_acceptance_and_refusal(self):
        run, _ = self.exercise(start_failure=True)
        self.assertTrue(run.broken, 'one accepted and two refused do not cover a failed worker')
        self.assertNotIn('UNSAFE_SYNTHETIC', str(run.log.call_args_list))

    def test_begun_capacity_phase_cutoff_is_not_successful_duration_completion(self):
        for cutoff in (True, 'status', 'create', 'created', 'refused_state'):
            with self.subTest(cutoff=cutoff):
                run, sampler, done, thread, parallel = self.fixture(cutoff=cutoff)
                run.run = lambda: run.starts_past_capacity()
                with patch('stress.threading.Event', return_value=done), \
                        patch('stress.threading.Thread', side_effect=thread), \
                        patch('stress.parallel', side_effect=parallel), \
                        patch('stress.Run', return_value=run), patch('sys.argv', ['stress']), \
                        patch('stress.signal.signal'):
                    with self.assertRaises(SystemExit) as result:
                        stress.main()
                if hasattr(sampler, 'start'):
                    self.assertTrue(sampler.joined)
                self.assertEqual(result.exception.code, 1)
                self.assertTrue(run.broken)
                self.assertIn('capacity_phase_incomplete', str(run.log.call_args_list))

    def test_missing_start_response_cannot_pass_capacity_phase(self):
        run, _ = self.exercise(missing_response=True)
        self.assertTrue(run.broken)
        self.assertIn('start_response_missing', str(run.log.call_args_list))

    def test_no_sampler_observation_cannot_use_zero_as_a_valid_maximum(self):
        run, _ = self.exercise(no_sample=True)
        self.assertTrue(run.broken)
        self.assertIn('sample_missing', str(run.log.call_args_list))

    def test_complete_observations_keep_host_wide_guest_budget_sampling(self):
        run, sampler = self.exercise()
        self.assertEqual(run.broken, [])
        self.assertFalse(sampler.unhandled)
        self.assertIn('sampled guest quota max 41 MB of 100', str(run.log.call_args_list))


if __name__ == '__main__':
    unittest.main()
