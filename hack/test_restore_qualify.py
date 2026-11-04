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
            store_transfer=None, source_offline_hook=None, require='', rounds=1,
            allow_daemon_kill=False))
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
        self.s.attempt_artifacts = Mock(side_effect=[dict(marker_present=True,
            published_streams=['root/b2.zfs'], partial_uploads=[dict(file='data/b2.zfs#1', bytes=123)],
            snapshots=['byard/m/m_own/root@bk-b2', 'byard/m/m_own/data@bk-b2']),
            dict(marker_present=False, published_streams=[],
                 partial_uploads=[dict(file='data/b2.zfs#1', bytes=123)],
                 snapshots=['byard/m/m_own/root@bk-b2', 'byard/m/m_own/data@bk-b2']),
            dict(marker_present=False, published_streams=[],
                 partial_uploads=[dict(file='data/b2.zfs#1', bytes=123)], snapshots=[])])
        self.s.attempt_marker = Mock(return_value=SimpleNamespace(exists=lambda: False))
        self.s.postgres_ready = Mock()
        self.s.database_settings = Mock()
        self.s.commit = Mock()
        fresh = {'id':'b3', 'disks':[{'disk':'root'}, {'disk':'data'}], 'incremental':False}
        self.s.backup = Mock(return_value=(fresh, [], 0))
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
        self.assertEqual(self.s.verify_database.call_count, 2)
        self.s.verify_database.assert_any_call('m_own', {'id':'b1'}, [], 0)
        self.s.verify_database.assert_any_call('m_own', fresh, [], 0)
        self.s.commit.assert_called_once_with('m_own', 1)
        self.assertFalse(self.s.record.call_args.kwargs['interrupted_offered'])
        self.assertEqual(self.s.record.call_args.kwargs['new_backup'], 'b3')

    def test_offhost_verification_never_queries_destroyed_source(self):
        self.s.restore = Mock(return_value=({'id':'m_new', 'host':'B'}, 0))
        self.s.postgres_ready = Mock()
        self.s.sql = Mock(return_value={'stdout':'1|t\n2|t\n'})
        self.s.database_settings = Mock()
        self.s.execute = Mock(return_value=dict(exit_code=0, timed_out=False, stdout='checked', stderr=''))
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

    def completed_baseline(self, rounds=1):
        self.s.a.rounds = rounds
        self.s.outcomes = [(c, 0, 'passed') for c in
            ('files', 'synced', 'multidisk', 'multidisk', 'multidisk', 'unsynced', 'python_startup')]
        for r in range(1, rounds+1):
            self.s.outcomes.extend([(c, r, 'passed') for c in ('postgres', 'postgres', 'chain')])

    def test_required_check_cannot_be_missing_or_skipped(self):
        self.completed_baseline()
        self.s.a.require = 'offhost,failure'
        for status in (None, 'skipped', 'failed'):
            with self.subTest(status=status):
                self.s.outcomes = [o for o in self.s.outcomes if o[0] not in ('offhost', 'failure')]
                if status:
                    self.s.outcomes.extend([('offhost', 1, status), ('failure', 1, status)])
                with self.assertRaisesRegex(restore.Failure, 'required checks did not pass'):
                    self.s.assert_required()
        self.s.outcomes.extend([('offhost', 1, 'passed'), ('failure', 1, 'passed')])
        with self.assertRaises(restore.Failure):  # A later pass cannot hide a skip/fail.
            self.s.assert_required()

    def test_required_mode_must_pass_every_round(self):
        self.completed_baseline(rounds=3)
        self.s.a.destination_region = 'B'
        self.s.outcomes.extend([('offhost', 1, 'passed'), ('offhost', 2, 'passed')])
        with self.assertRaisesRegex(restore.Failure, r'offhost\[round=3\]'):
            self.s.assert_required()
        self.s.outcomes.append(('offhost', 3, 'passed'))
        self.s.assert_required()
        self.s.a.destination_region = ''
        self.s.a.allow_daemon_kill = True
        with self.assertRaisesRegex(restore.Failure, 'failure'):
            self.s.assert_required()

    def test_record_retains_skipped_evidence_for_gate(self):
        with patch('builtins.print'):
            restore.Suite.record(self.s, 'offhost', status='skipped')
        self.assertEqual(self.s.outcomes, [('offhost', 0, 'skipped')])

    def test_cli_returns_failure_when_required_offhost_was_skipped(self):
        real_record = self.s.__class__.record.__get__(self.s)
        self.s.record = Mock(wraps=real_record)
        def files():
            for check in ('files', 'synced', 'multidisk', 'multidisk', 'multidisk',
                          'unsynced', 'python_startup'):
                self.s.record(check, status='passed')
        def database():
            for check in ('postgres', 'postgres', 'chain'):
                self.s.record(check, status='passed')
            self.s.record('offhost', status='skipped')
        def suite(args):
            self.s.a = args
            return self.s
        self.s.files = files
        self.s.database = database
        self.s.cleanup = Mock(return_value=True)
        with patch.object(restore, 'Suite', side_effect=suite), \
             patch('sys.argv', ['restore-qualify.py', '--require', 'offhost']), \
             patch('builtins.print'):
            self.assertEqual(restore.main(), 1)
        errors = [c.kwargs.get('error', '') for c in self.s.record.call_args_list]
        self.assertTrue(any('offhost[round=1]' in e and 'skipped' in e for e in errors))

    def test_multidisk_atomic_pair_bound_rejects_torn_skew_and_rollback(self):
        def pair(root, data):
            return [dict(epoch=i, complement=~i) for i in (root, data)]
        for root, data in ((100, 100), (101, 100)):
            restore.verify_disk_pair(pair(root, data), 100)
        for root, data in ((102, 100), (99, 100), (99, 99)):
            with self.subTest(root=root, data=data), self.assertRaises(restore.Failure):
                restore.verify_disk_pair(pair(root, data), 100)
        torn = pair(100, 100)
        torn[0]['complement'] = 0
        with self.assertRaisesRegex(restore.Failure, 'torn disk epoch'):
            restore.verify_disk_pair(torn, 100)

    def test_postgres_requires_both_durability_settings(self):
        for settings in ('off\non\n', 'on\noff\n', 'remote_write\non\n'):
            self.s.sql = Mock(return_value={'stdout':settings})
            with self.assertRaisesRegex(restore.Failure, 'durability settings must be on'):
                self.s.database_settings('m_1')
        self.s.sql = Mock(return_value={'stdout':'on\non\n'})
        self.s.database_settings('m_1')

    def test_payload_mismatch_fails_before_amcheck(self):
        self.s.restore = Mock(return_value=({'id':'m_new'}, 0))
        self.s.postgres_ready = Mock()
        self.s.database_settings = Mock()
        self.s.sql = Mock(return_value={'stdout':'1|f\n'})
        self.s.execute = Mock()
        b = {'id':'b1', 'bytes':1024, 'disks':[]}
        with self.assertRaisesRegex(restore.Failure, 'DATA INTEGRITY: payload mismatch at id 1'):
            self.s.verify_database('m_own', b, [], 0, chain=[b])
        self.s.execute.assert_not_called()

    def test_amcheck_failure_keeps_diagnostic_output(self):
        self.s.restore = Mock(return_value=({'id':'m_new'}, 0))
        self.s.postgres_ready = Mock()
        self.s.database_settings = Mock()
        self.s.sql = Mock(return_value={'stdout':'1|t\n'})
        self.s.execute = Mock(return_value=dict(exit_code=1, timed_out=False, stdout='checked', stderr='bad page'))
        b = {'id':'b1', 'bytes':1024, 'disks':[]}
        with self.assertRaisesRegex(restore.Failure, 'DATA INTEGRITY: pg_amcheck failed'):
            self.s.verify_database('m_own', b, [], 0, chain=[b])
        self.assertIn('bad page', (self.s.output/'m_new-amcheck.json').read_text())

    def test_attempt_inspection_distinguishes_partial_stream_snapshot_and_marker(self):
        root = Path(self.tmp.name)/'store/m_own'
        (root/'root').mkdir(parents=True)
        (root/'data').mkdir()
        (root/'root/b2.zfs').write_bytes(b'published')
        (root/'data/b2.zfs#1').write_bytes(b'partial')
        (root/'data/foreign.zfs#1').write_bytes(b'preserve')
        marker = Path(self.tmp.name)/'marker'
        marker.touch()
        self.s.attempt_marker = Mock(return_value=marker)
        with patch.object(restore, 'Path', side_effect=lambda _: root.parent), \
             patch.object(restore.subprocess, 'check_output', return_value=
                'byard/m/m_own/root@bk-b2\nbyard/m/m_own/data@bk-b2\nbyard/m/m_other/data@bk-b2\n'):
            evidence = self.s.attempt_artifacts('m_own', 'b2')
        self.assertTrue(evidence['marker_present'])
        self.assertEqual(evidence['published_streams'], ['root/b2.zfs'])
        self.assertEqual(evidence['partial_uploads'], [dict(file='data/b2.zfs#1', bytes=7)])
        self.assertEqual(len(evidence['snapshots']), 2)
        self.assertEqual(self.s.partial_uploads, {root/'data/b2.zfs#1'})


if __name__ == '__main__':
    unittest.main()
