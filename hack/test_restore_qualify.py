"""Safety and oracle checks; real workload qualification is native CI, not these fakes."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('restore', Path(__file__).with_name('restore-qualify.py'))
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


class QualificationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.s = restore.Suite(SimpleNamespace(output=self.tmp.name+'/out', cafile=None,
            url='http://localhost', token='', source_region='', destination_region='', store_transfer=None))
        self.addCleanup(self.s.ledger.close)
        self.addCleanup(self.s.results.close)
        self.s.record = Mock()

    def test_fork_does_not_send_null_image(self):
        self.s.api = Mock(side_effect=[{'id': 'm_1'}, {'state': 'running'}])
        self.s.create(fork={'machine_id': 'm_0', 'consistency': 'unsynced'})
        body = self.s.api.call_args_list[0].args[2]
        self.assertNotIn('image', body)
        self.assertIn('restore_qualification', body['metadata'])

    def test_fallback_fails_instead_of_claiming_filesystem(self):
        self.s.api = Mock(return_value={'id':'b1', 'consistency':'unsynced'})
        with self.assertRaises(restore.Failure):
            self.s.backup('m_1')
        self.assertEqual(self.s.sources, ['m_1'])

    def test_transport_or_timeout_is_never_a_missing_file(self):
        self.s.api = Mock(return_value={'exit_code':0, 'timed_out':True, 'stdout':'', 'stderr':''})
        with self.assertRaises(restore.Failure):
            self.s.py('m_1', 'print(1)')

    def test_foreign_machine_is_preserved_during_cleanup(self):
        ns = self.s.ns
        self.s.api = Mock(side_effect=lambda method, path, **kw:
            [{'id':'foreign', 'namespace':ns, 'name':'q1', 'metadata':{}}]
            if method == 'GET' and path.endswith(ns) else [])
        self.assertFalse(self.s.cleanup())
        self.assertFalse(any('/machines/foreign' in c.args[1] for c in self.s.api.call_args_list))

    def test_postgres_waits_through_temporary_server_and_init_restart(self):
        def answer(code, stdout='', timed_out=False):
            return dict(exit_code=code, stdout=stdout, stderr='', timed_out=timed_out)
        self.s.execute = Mock(side_effect=[answer(1), answer(0), answer(2), answer(0, '1\n')])
        with patch.object(restore.time, 'sleep'):
            self.s.postgres_ready('m_1')
        self.assertEqual(self.s.execute.call_count, 4)
        for call in self.s.execute.call_args_list:
            script = call.args[1][2]
            self.assertIn('pg_isready -h /var/run/postgresql', script)
            self.assertIn('listen_addresses', script)
            self.assertIn('pg_is_in_recovery()', script)
            self.assertFalse(call.kwargs['check'])
            self.assertLessEqual(call.kwargs['timeout_ms'], 5000)

    def test_postgres_ready_timeout_names_final_server_and_probe(self):
        with patch.object(restore.time, 'monotonic', side_effect=[0, 2]):
            with self.assertRaisesRegex(restore.Failure, 'Postgres final server not ready.*within 1s'):
                self.s.postgres_ready('m_1', seconds=1)

    def test_postgres_timed_out_query_cannot_pass_readiness(self):
        self.s.execute = Mock(return_value=dict(exit_code=0, stdout='1', stderr='', timed_out=True))
        with patch.object(restore.time, 'monotonic', side_effect=[0, 0, 0, 0, 2]), \
             patch.object(restore.time, 'sleep'):
            with self.assertRaisesRegex(restore.Failure, 'last probe:'):
                self.s.postgres_ready('m_1', seconds=1)

    def test_no_replay_after_create_timeout(self):
        self.s.api = Mock(side_effect=TimeoutError('unknown outcome'))
        with self.assertRaises(TimeoutError):
            self.s.create(restore.PYTHON)
        self.assertEqual(self.s.api.call_count, 1)
        self.assertEqual(self.s.planned, {(self.s.ns, 'q1')})


if __name__ == '__main__':
    unittest.main()
