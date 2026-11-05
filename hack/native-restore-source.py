#!/usr/bin/env python3
"""Disposable CI only: provision the existing source pool with a fleet-held key.

Runs after the existing suites, so their file-key and key-absence assertions stay
unchanged. The key is read in memory and passed only to ZFS stdin.
"""
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import yaml

assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
assert os.geteuid() == 0
config = Path('/etc/briqyard/config.yaml')
fleet_config = Path('/etc/briqyard/fleet.yaml')
c = yaml.safe_load(config.read_text())
f = yaml.safe_load(fleet_config.read_text())
token = 'restore-source-token'  # Disposable fixture credential, never a real host token.
local = next(h for h in f['hosts'] if h['id'] == 'local')
local['token'] = token
if f.get('tls') is False:
    f['tls'] = 'off'
fleet_config.write_text(yaml.safe_dump(f, sort_keys=False))
subprocess.run(['systemctl', 'stop', 'briqyardd'], check=True, timeout=60)
subprocess.run(['systemctl', 'restart', 'briqyard-fleet'], check=True, timeout=60)
# The service retains its socket across restart; wait for the replacement to
# answer a read before the one-shot key request. Never retry a key mutation.
deadline = time.monotonic()+60
while True:
    try:
        with urllib.request.urlopen('http://127.0.0.1:7430/v1/hosts', timeout=3) as response:
            json.load(response)
        break
    except (urllib.error.URLError, TimeoutError):
        if time.monotonic() >= deadline:
            raise RuntimeError('fleet did not answer after source fixture restart') from None
        time.sleep(0.2)
req = urllib.request.Request('http://127.0.0.1:7430/v1/hosts/key',
    data=json.dumps({'url': local['url']}).encode(),
    headers={'Content-Type': 'application/json', 'Authorization': 'Bearer '+token})
with urllib.request.urlopen(req, timeout=30) as response:
    key = json.load(response)['key']
assert len(key) == 64 and all(x in '0123456789abcdefABCDEF' for x in key)
subprocess.run(['zfs', 'change-key', '-o', 'keylocation=prompt', c['storage']['pool']],
               input=(key+'\n').encode(), check=True, timeout=60,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
c['storage']['key'] = 'fleet'
c['token'] = token
c['fleet'] = {'url': 'http://127.0.0.1:7430', 'advertise': local['url']}
config.write_text(yaml.safe_dump(c, sort_keys=False))
subprocess.run(['systemctl', 'start', 'briqyardd'], check=True, timeout=60)
deadline = time.monotonic()+120
while True:
    try:
        req = urllib.request.Request(local['url']+'/v1/status',
            headers={'Authorization': 'Bearer '+token})
        with urllib.request.urlopen(req, timeout=3) as response:
            status = json.load(response)
        if not any(c['type'] == 'memory_protection' and c['status'] for c in status['conditions']):
            break
    except (urllib.error.URLError, TimeoutError):
        pass
    if time.monotonic() >= deadline:
        raise RuntimeError('fleet-keyed source daemon did not become ready')
    time.sleep(0.2)
print('Restore source: storage.key=fleet; pool key held in fleet registry')
