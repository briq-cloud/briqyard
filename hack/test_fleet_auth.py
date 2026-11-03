#!/usr/bin/env python3
"""Exercise fleet suite auth and composed cleanup without invoking any host or API."""

import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest

from test_monitoring_auth import _run_bounded

ROOT = Path(__file__).resolve().parent
FLEET_TOKEN = 'fleet-"quote\\tail'
HOST_TOKEN = 'host-distinct-token'


class FleetAuthTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        bindir = root / 'bin'
        bindir.mkdir()
        audit = root / 'audit'
        # Fake curl inspects the actual private config, argv and environment, and
        # never opens a socket. The host wrapper executes only transported source.
        wrapper = f'''#!{sys.executable}
import json, os, pathlib, shlex, sys
args = sys.argv[1:]
name = pathlib.Path(sys.argv[0]).name
needles = {FLEET_TOKEN!r}, {HOST_TOKEN!r}
clean = not any(n in a for n in needles for a in args)
clean = clean and not any(n in v for n in needles for k, v in os.environ.items() if not (name == 'briqyard' and k == 'BRIQYARD_TOKEN'))
cli_auth = name == 'briqyard' and os.environ.get('BRIQYARD_TOKEN') == needles[0]
header = None
if name == 'curl':
    clean = clean and args[0] == '--disable'
    config = args[args.index('--config') + 1] if '--config' in args else None
    text = (sys.stdin.read() if config == '-' else pathlib.Path(config).read_text()) if config else ''
    header = shlex.split(text)[2] if text.strip() else None
with open(os.environ['AUDIT'], 'a') as out:
    out.write(json.dumps(dict(name=name, clean=clean, header=header, cli_auth=cli_auth)) + '\\n')
if not clean: raise SystemExit(90)
if name == 'remote': os.execvp(args[0], args)
print('{{"key":"fixture"}}')
'''
        for name in ('curl', 'remote', 'briqyard'):
            path = bindir / name
            path.write_text(wrapper)
            path.chmod(0o700)
        env = dict(os.environ)
        for key in ('BRIQYARD_METRICS_TOKEN', 'GRAFANA_PASSWORD_FILE'):
            env.pop(key, None)
        env.update(PATH=str(bindir) + os.pathsep + env['PATH'], TMPDIR=directory,
                   AUDIT=str(audit), BRIQYARD_TOKEN=FLEET_TOKEN)
        return root, audit, env

    def prefix(self, name):
        source = (ROOT / name).read_text()
        marker = '\necho "== two hosts"' if name == 'fleet-two-hosts.sh' else '\nSTATE=$(on_fleet'
        prefix = source.split(marker, 1)[0]
        return prefix.replace('script_dir=${BASH_SOURCE[0]%/*}', 'script_dir=' + shlex.quote(str(ROOT)))

    def run_script(self, script, env):
        return _run_bounded(['bash', '-x', '-c', script], env=env, timeout=15)

    def assert_safe(self, result, root, audit):
        for token in (FLEET_TOKEN, HOST_TOKEN):
            self.assertNotIn(token, result.stdout + result.stderr)
        rows = [json.loads(line) for line in audit.read_text().splitlines()]
        self.assertTrue(rows)
        self.assertTrue(all(row['clean'] for row in rows))
        self.assertFalse(list(root.glob('briqyard-monitoring-auth.*')))
        return rows

    def test_composed_cleanup_keeps_auth_until_resources_end_and_preserves_status(self):
        for name in ('fleet-two-hosts.sh', 'fleet-restore.sh'):
            for ending, status in (('SUITE_DONE=1; exit 0', 0), ('exit 7', 7),
                                   ('kill -TERM $$', 143), ('kill -HUP $$', 129),
                                   ('kill -INT $$', 130), ('exit 0', 1)):
                with self.subTest(name=name, ending=ending), tempfile.TemporaryDirectory() as tmp:
                    root, audit, env = self.fixture(tmp)
                    script = self.prefix(name) + '''
# Each cleanup resource action verifies fleet auth is still available.
briqyard() { hosts >/dev/null; }
on_fleet() { hosts >/dev/null; }
on_second() { hosts >/dev/null; }
RESTORE_STARTED=1
hosts >/dev/null
''' + ending
                    result = self.run_script(script, env)
                    self.assertEqual(result.returncode, status, result.stderr)
                    rows = self.assert_safe(result, root, audit)
                    self.assertGreater(len(rows), 1)
                    self.assertTrue(all(row['header'] == 'Authorization: Bearer ' + FLEET_TOKEN for row in rows))

    def test_initialization_failure_uses_only_helper_cleanup(self):
        for name in ('fleet-two-hosts.sh', 'fleet-restore.sh'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root, audit, env = self.fixture(tmp)
                env['BRIQYARD_TOKEN'] = 'reject\rheader'
                result = self.run_script(self.prefix(name), env)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('ENDED EARLY', result.stdout)
                self.assertNotIn('cleanup', result.stdout)
                self.assertFalse(audit.exists())
                self.assertFalse(list(root.glob('briqyard-monitoring-auth.*')))

    def test_two_host_cli_alone_receives_its_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, audit, env = self.fixture(tmp)
            script = self.prefix('fleet-two-hosts.sh').split('# Run on any exit,', 1)[0]
            result = self.run_script(script + '\nbriqyard machine ls >/dev/null; hosts >/dev/null', env)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = self.assert_safe(result, root, audit)
            self.assertTrue(rows[0]['cli_auth'])
            self.assertFalse(rows[1]['cli_auth'])

    def test_restore_host_context_is_distinct_and_does_not_replace_outer_traps(self):
        source = (ROOT / 'fleet-restore.sh').read_text()
        function = 'host_key() (' + source.split('host_key() (', 1)[1].split('\nHOST=', 1)[0]
        for token in (HOST_TOKEN, 'reject\rheader'):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as tmp:
                root, audit, env = self.fixture(tmp)
                script = self.prefix('fleet-restore.sh') + '\n' + function + f'''
token={shlex.quote(token)}
advertise=http://fixture.invalid
RESTORE_STARTED=1
on_fleet() {{ hosts >/dev/null; }}
on_second() {{ :; }}
key=$(host_key)
SUITE_DONE=1
'''
                result = self.run_script(script, env)
                self.assertEqual(result.returncode, 0 if token == HOST_TOKEN else 1, result.stderr)
                rows = self.assert_safe(result, root, audit)
                expected = ['Authorization: Bearer ' + FLEET_TOKEN]
                if token == HOST_TOKEN:
                    expected.insert(0, 'Authorization: Bearer ' + HOST_TOKEN)
                self.assertEqual([row['header'] for row in rows], expected)

    def test_remote_wrapper_transports_source_and_preserves_stdin_and_arguments(self):
        source = self.prefix('fleet-two-hosts.sh').split('# Run on any exit,', 1)[0]
        for token in (HOST_TOKEN, 'reject\rheader'):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as tmp:
                root, audit, env = self.fixture(tmp)
                conf = root / 'host.yaml'
                conf.write_text(f'token: "{token}"\n  advertise: http://fixture.invalid\nfleet:\n  url: http://fleet.invalid\n')
                script = source + f'''
CONF2={shlex.quote(str(conf))}
SECOND_HOST_SH=remote
printf 'stdin-preserved' | as_second 'test "$(cat)" = stdin-preserved && test "$1" = argument && ask_key "{{}}"' argument
'''
                result = self.run_script(script, env)
                rows = self.assert_safe(result, root, audit)
                if token == HOST_TOKEN:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(rows[-1]['header'], 'Authorization: Bearer ' + HOST_TOKEN)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(any(row['name'] == 'curl' for row in rows))


if __name__ == '__main__':
    unittest.main()
