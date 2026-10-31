#!/usr/bin/env python3
"""Native protocol/cleanup fixtures for sibling-overlap.sh; no daemon or network needed."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

FAKE = r'''
import os,sys
from pathlib import Path
state=Path(os.environ['OVERLAP_FIXTURE'])
with (state/'pids').open('a') as f:f.write(str(os.getpid())+'\n')
if 'psql' in sys.argv:
    for line in sys.stdin:
        line=line.strip()
        if line=='BEGIN;':(state/'sql').touch()
        elif line=='SELECT 43;':
            assert (state/'http').exists(), 'SQL was not concurrent with the gateway response'
            (state/'overlap').touch();print(43,flush=True)
        elif line.startswith('\\echo '):print(line[6:],flush=True)
        elif line=='\\q':
            (state/'sql').unlink();break
elif sys.argv[-1].endswith('/overlap'):
    assert '-i' in sys.argv[1:sys.argv.index('--')], 'HTTP output requires streaming exec'
    assert sys.stdin.read() == '', 'HTTP exec must receive EOF without input'
    (state/'http-streaming').touch()
    assert (state/'sql').exists(), 'gateway started without an active database transaction'
    (state/'http').touch();print('gateway-ready',flush=True)
    with (state/'release').open() as f:assert f.readline()=='release\n'
    print('injected=True',flush=True);(state/'http').unlink()
elif sys.argv[-1].endswith('/release'):
    assert (state/'overlap').exists(), 'gateway released before the SQL query completed'
    if os.environ.get('FAIL_RELEASE'):sys.exit(7)
    with (state/'release').open('w') as f:f.write('release\n')
    print('released',flush=True)
else:raise AssertionError(sys.argv)
'''


class Overlap(unittest.TestCase):
    def run_fixture(self, fail_release=False):
        with tempfile.TemporaryDirectory(prefix='sibling-overlap-') as directory:
            state = Path(directory)
            executable = state / 'briqyard'
            executable.write_text('#!' + sys.executable + '\n' + FAKE)
            executable.chmod(0o700)
            os.mkfifo(state / 'release')
            environment = dict(os.environ, PATH=str(state) + os.pathsep + os.environ['PATH'],
                               OVERLAP_FIXTURE=str(state))
            if fail_release:
                environment['FAIL_RELEASE'] = '1'
            process = subprocess.Popen(['bash', str(Path(__file__).with_name('sibling-overlap.sh')), 'm_fixture'],
                                       env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.communicate(timeout=4)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate(timeout=2)
                raise
            result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            self.assertEqual(result.returncode == 0, not fail_release, result.stdout + result.stderr)
            self.assertTrue((state / 'http-streaming').exists(), 'HTTP exec did not stream after stdin EOF')
            self.assertTrue((state / 'overlap').exists(), 'no query completed during the gateway response')
            if fail_release:
                self.assertEqual(result.stderr.strip(), 'sibling overlap failed: gateway-release')
            for pid in (state / 'pids').read_text().splitlines():
                with self.assertRaises(ProcessLookupError, msg='fixture child survived cleanup: ' + pid):
                    os.kill(int(pid), 0)

    def test_query_completes_before_gateway_response_is_released(self):
        self.run_fixture()

    def test_failed_release_reaps_the_blocked_gateway_and_sql_children(self):
        self.run_fixture(fail_release=True)


if __name__ == '__main__':
    if not shutil.which('timeout'):
        raise SystemExit('GNU timeout is required, as for e2e.sh')
    unittest.main()
