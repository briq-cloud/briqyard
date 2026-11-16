import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('authority', Path(__file__).with_name('native-mixed-authority.py'))
a = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a)


class AuthorityTests(unittest.TestCase):
    def test_failure_receipt_contains_only_fixed_bounded_diagnostics(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-output'
            path.write_text('private secret\nscoped native: failed phase=scoped_dispatch\n'
                            'scoped installation refusal: host_verification Time\n'
                            'scoped installation refusal: host_verification Time secret\n'
                            'Error: authority exec returned 503 Service Unavailable\n'
                            'scoped native: failed phase=private\n')
            result = a.failure(path)
            self.assertEqual(len(result['events']), 3)
            self.assertNotIn('private', json.dumps(result))
            self.assertNotIn('secret', json.dumps(result))
            self.assertFalse(result['truncated'])
            path.write_bytes(b'x' * (64 * 1024) + b'\nscoped native: failed phase=gateway\n')
            self.assertEqual(a.failure(path)['events'], {})
            self.assertTrue(a.failure(path)['truncated'])

    def test_running_authority_must_match_candidate_digest(self):
        before = {'candidateFleetSha256': 'candidate'}
        a.validate_authority(before, {'sha256': 'candidate'})
        for digest in ('source', '', None):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                a.validate_authority(before, {'sha256': digest})

    def test_source_binary_and_configuration_must_be_restored(self):
        before = {'daemon': {'sha256': 'source'}, 'configurationSha256': 'original'}
        a.validate_restored(before, before)
        for after in ({'daemon': {'sha256': 'candidate'}, 'configurationSha256': 'original'},
                      {'daemon': {'sha256': 'source'}, 'configurationSha256': 'temporary'}):
            with self.subTest(after=after), self.assertRaises(ValueError):
                a.validate_restored(before, after)

    def test_sum_parser_rejects_duplicate_and_malformed_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'sums'
            for content in ('not-a-digest  binary\n', ('a' * 64 + '  binary\n') * 2):
                file.write_text(content)
                with self.assertRaises(ValueError):
                    a.sums(file)

    def test_standalone_stops_before_callback_and_propagates_driver_failure(self):
        text = Path(__file__).with_name('scoped-execution-native.sh').read_text()
        block = text.split('PHASE=scoped_dispatch\n', 1)[1].split('# The fixture uses', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            driver = root / 'driver'
            for code in (0, 1):
                with self.subTest(code=code):
                    marker = root / 'cleanup'
                    marker.unlink(missing_ok=True)
                    driver.write_text('#!/bin/sh\nexit ' + str(code) + '\n')
                    driver.chmod(0o755)
                    output = root / 'receipt'
                    output.unlink(missing_ok=True)
                    prefix = 'MODE=standalone; PHASE=test; D=x; T=x; M=x; S=x\nsudo() { if [ "$1" = python3 ]; then echo "{}"; else "$@"; fi; }\n'
                    prefix += 'DRIVER="$5"; CLEANUP_MARKER="$6"\ntrap \'echo ended > "$CLEANUP_MARKER"\' EXIT\n'
                    result = subprocess.run(['bash', '-e', '-c', prefix + block, 'sh', 'standalone', 'authority',
                                             'input', str(output), str(driver), str(marker)], capture_output=True)
                    self.assertEqual(result.returncode, code)
                    self.assertTrue(marker.exists())
                    self.assertEqual(output.exists(), code == 0)

    def test_authority_receipt_requires_same_driver_and_current_daemon(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / 'before'
            before.write_text(json.dumps({'candidateFleetSha256': 'candidate', 'driverSha256': 'driver',
                                          'daemon': {'sha256': 'source'}}))
            (root / 'authority.pid').write_text('42')
            for daemon_digest, driver_digest in (('source', 'changed'), ('changed', 'driver')):
                with self.subTest(daemon=daemon_digest, driver=driver_digest), \
                     patch.object(a, 'process', return_value={'sha256': 'candidate'}), \
                     patch.object(a, 'daemon', return_value={'sha256': daemon_digest}), \
                     patch.object(a, 'sha', return_value=driver_digest), self.assertRaises(ValueError):
                    a.main(['authority', str(before), str(root), 'driver'])


if __name__ == '__main__':
    unittest.main()
