"""Safety and oracle checks; real workload qualification is native CI, not these fakes."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

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

    def test_no_replay_after_create_timeout(self):
        self.s.api = Mock(side_effect=TimeoutError('unknown outcome'))
        with self.assertRaises(TimeoutError):
            self.s.create(restore.PYTHON)
        self.assertEqual(self.s.api.call_count, 1)
        self.assertEqual(self.s.planned, {(self.s.ns, 'q1')})


if __name__ == '__main__':
    unittest.main()
