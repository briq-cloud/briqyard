#!/usr/bin/env python3
"""Bind the standalone scoped fixture to published mixed-version binaries."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def require(value):
    if not value:
        raise ValueError('mixed authority binding refused')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sums(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        digest, name = line.split()
        require(len(digest) == 64 and all(c in '0123456789abcdef' for c in digest))
        require(name not in result)
        result[name] = digest
    return result


def process(pid):
    require(str(pid).isdigit() and int(pid) > 1)
    root = Path('/proc') / str(pid)
    fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    require(fields[0] != 'Z')
    return {'sha256': sha(root / 'exe'), 'pid': int(pid), 'start': fields[19]}


def daemon():
    pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', 'briqyardd'], text=True).strip()
    return process(pid)


def validate_authority(before, running):
    require(running['sha256'] == before['candidateFleetSha256'])


def validate_restored(before, after):
    require(after['daemon']['sha256'] == before['daemon']['sha256'])
    require(after['configurationSha256'] == before['configurationSha256'])


def main(args):
    mode = args[0]
    if mode == 'before':
        previous, candidate, driver, source = map(Path, args[1:])
        old = sums(previous)
        new = sums(candidate / 'SHA256SUMS-x86_64')
        running = daemon()
        require(running['sha256'] == old['briqyardd-linux-x86_64'])
        require(sha(candidate / 'briqyard-fleet-linux-x86_64') == new['briqyard-fleet-linux-x86_64'])
        record = {'schema': 1, 'kind': 'mixed-authority-input', 'daemon': running,
                  'configurationSha256': sha('/etc/briqyard/config.yaml'),
                  'candidateFleetSha256': new['briqyard-fleet-linux-x86_64'],
                  'driverSha256': sha(driver),
                  'driverSourceCommit': subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip(),
                  'driverCratesTree': subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD:crates'], text=True).strip()}
    elif mode == 'authority':
        before = json.loads(Path(args[1]).read_text())
        directory = Path(args[2])
        running = process((directory / 'authority.pid').read_text().strip())
        validate_authority(before, running)
        require(sha(args[3]) == before['driverSha256'])
        require(daemon()['sha256'] == before['daemon']['sha256'])
        record = {'schema': 1, 'kind': 'mixed-authority-exercised', 'authority': running,
                  'hostConfigurationSha256': sha('/etc/briqyard/config.yaml'),
                  'authorityConfigurationSha256': sha(directory / 'authority.yaml'),
                  'standaloneContractPassed': True, 'inputSha256': sha(args[1])}
    elif mode == 'after':
        before, exercised = [json.loads(Path(p).read_text()) for p in args[1:]]
        require(exercised['kind'] == 'mixed-authority-exercised' and exercised['standaloneContractPassed'] is True)
        require(exercised['inputSha256'] == sha(args[1]))
        validate_authority(before, exercised['authority'])
        restored = {'daemon': daemon(), 'configurationSha256': sha('/etc/briqyard/config.yaml')}
        validate_restored(before, restored)
        record = {'schema': 1, 'kind': 'mixed-authority-contract', 'passed': True,
                  'source': before, 'exercised': exercised, 'restored': restored,
                  'scope': 'standalone-authority; no renewable callback or private gateway qualification',
                  'preservationBasis': 'fixture runs before upgrade preservation baseline'}
    else:
        raise ValueError('invalid mode')
    print(json.dumps(record, sort_keys=True))


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception:
        print('mixed authority binding unavailable', file=sys.stderr)
        raise SystemExit(1)
