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
            url='http://localhost', token='', source_region='', destination_region='',
            store_transfer=None, source_offline_hook=None))
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

    def fake_sender(self, pid, parent, machine):
        proc = Path(self.tmp.name)/'proc'/str(pid)
        proc.mkdir(parents=True)
        (proc/'stat').write_text(f'{pid} (zfs) '+' '.join(['S', str(parent)]+['0']*17+['123']))
        (proc/'cmdline').write_bytes(b'zfs\0send\0-w\0byard/m/'+machine.encode()+b'/data@bk-b2\0')
        (proc/'exe').symlink_to(Path(self.tmp.name)/'zfs')
        return proc

    def native_paths(self, value):
        return {'/proc': Path(self.tmp.name)/'proc',
                '/var/lib/briqyard/backups/backups': Path(self.tmp.name)/'store'}[value]

    def test_pause_signals_only_own_daemon_child_with_stream_bytes(self):
        self.fake_sender(201, 124, 'm_own')
        self.fake_sender(202, 123, 'm_other')
        self.fake_sender(203, 123, 'm_own')
        stream = Path(self.tmp.name)/'store/m_own/data/b2.zfs#1'
        stream.parent.mkdir(parents=True)
        stream.write_bytes(b'stream bytes')
        with patch.object(restore, 'Path', side_effect=self.native_paths), \
             patch.object(restore.os, 'pidfd_open', return_value=99, create=True) as opened, \
             patch.object(restore.signal, 'pidfd_send_signal', create=True) as sent:
            self.assertEqual(self.s.pause_backup_send('m_own', 123), (99, 'b2'))
        opened.assert_called_once_with(203)
        sent.assert_called_once_with(99, restore.signal.SIGSTOP)

    def test_pause_requires_bytes_and_rejects_reused_pid(self):
        proc = self.fake_sender(203, 123, 'm_own')
        stream = Path(self.tmp.name)/'store/m_own/data/b2.zfs#1'
        stream.parent.mkdir(parents=True)
        stream.touch()
        for has_bytes in (False, True):
            if has_bytes:
                stream.write_bytes(b'stream bytes')
            def reused(_pid):
                (proc/'stat').write_text((proc/'stat').read_text().replace('123', '124'))
                return 99
            with patch.object(restore, 'Path', side_effect=self.native_paths), \
                 patch.object(restore.time, 'monotonic', side_effect=[0, 0, 2]), \
                 patch.object(restore.time, 'sleep'), \
                 patch.object(restore.os, 'pidfd_open', side_effect=reused, create=True) as opened, \
                 patch.object(restore.os, 'close') as closed, \
                 patch.object(restore.signal, 'pidfd_send_signal', create=True) as sent:
                with self.assertRaisesRegex(restore.Failure, 'own data backup stream bytes'):
                    self.s.pause_backup_send('m_own', 123, seconds=1)
            sent.assert_not_called()
            self.assertEqual(opened.call_count, int(has_bytes))
            self.assertEqual(closed.call_count, int(has_bytes))

    def test_interrupted_client_must_fail_and_recovery_barrier_must_clear(self):
        calls = []
        statuses = iter([{'error': 'recovering'}, {'conditions': [
            {'type': 'memory_protection', 'status': True}]}, {'conditions': []}])
        def api(method, path, **kw):
            if path == '/v1/status':
                self.assertEqual(kw['expected'], (200, 503))
                calls.append('status')
                return next(statuses)
            if method == 'POST':
                raise ConnectionResetError('interrupted')
            return [{'id': 'b1'}]
        self.s.api = Mock(side_effect=api)
        self.s.execute = Mock()
        self.s.pause_backup_send = Mock(return_value=(99, 'b2'))
        self.s.verify_database = Mock()
        with patch.dict(restore.os.environ, RUNNER_ENVIRONMENT='github-hosted'), \
             patch.object(restore.os, 'geteuid', return_value=0), \
             patch.object(restore.subprocess, 'check_output', return_value=b'123'), \
             patch.object(restore.os, 'kill', side_effect=lambda *_: calls.append('daemon')), \
             patch.object(restore.signal, 'pidfd_send_signal', create=True,
                          side_effect=lambda *_: calls.append('sender')), \
             patch.object(restore.os, 'close'), patch.object(restore.time, 'sleep'):
            self.s.failure_restore('m_own', {'id':'b1'}, [], 0)
        self.assertEqual(calls, ['daemon', 'sender', 'status', 'status', 'status'])
        self.s.verify_database.assert_called_once_with('m_own', {'id':'b1'}, [], 0)

    def test_offhost_verification_never_queries_destroyed_source(self):
        self.s.restore = Mock(return_value=({'id':'m_new', 'host':'B'}, 0))
        self.s.postgres_ready = Mock()
        self.s.sql = Mock(return_value={'stdout':'1\n2\n'})
        self.s.execute = Mock()
        self.s.destroy = Mock()
        self.s.acks = [(1, 1), (2, 3), (3, 4)]
        self.s.a.source_offline_hook = 'fixture'
        def api(method, path):
            self.assertEqual((method, path), ('GET', '/v1/machines/m_new/logs?limit=1000'))
            return ['database system is ready to accept connections',
                    'database system was interrupted', 'redo done']
        self.s.api = Mock(side_effect=api)
        b = {'id':'b1', 'bytes':1024, 'disks':[], 'consistency':'filesystem'}
        self.s.verify_database('m_gone', b, [(1, 1)], 2,
                               offhost=True, source_host='A', chain=[b])
        result = self.s.record.call_args.kwargs
        self.assertTrue(result['source_destroyed'] and result['source_offline'])
        self.assertEqual(result['lost_ack_ids'], [3])
        self.s.destroy.assert_called_once_with('m_new')


if __name__ == '__main__':
    unittest.main()
