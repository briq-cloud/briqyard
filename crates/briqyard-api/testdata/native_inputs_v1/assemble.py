#!/usr/bin/env python3
"""Synthetic, public, non-authorizing assembler for the native.inputs/v1 test fixture.

Every digest, byte string, version, commit and release ID below is invented for tests: no
real release, host, process, key or secret is represented. This is a simple canonical
reference (sorted keys, compact separators, ASCII) written without the Rust types, so the
Rust reader can be checked against bytes it did not produce. It is not the briq operation
preparer and approves nothing.

Usage: python3 -I assemble.py [output-dir]
"""
import base64, hashlib, json, pathlib, sys

out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent
D = lambda b: hashlib.sha256(b).hexdigest()
T = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip('=')
B = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
C = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
BOOT = '00000000-0000-4000-8000-000000000004'
OTHER_BOOT = '00000000-0000-4000-8000-000000000005'


def proc(pid, exe, build, boot=BOOT):
    return {'boot': boot, 'pid': pid, 'start': 100 + pid, 'exe': exe, 'build': build}


names = ['briqyardd-linux-x86_64', 'briqyard-fleet-linux-x86_64', 'briqyard-linux-x86_64']
releases = []
for index, (label, version, digit) in enumerate([('source', '0.1.9', 'a'), ('target', '0.2.0', 'b')]):
    assets = [('synthetic-daemon-v%d' % index).encode(), ('synthetic-fleet-v%d' % index).encode(), ('synthetic-cli-v%d' % index).encode()]
    digests = {name: D(asset) for name, asset in zip(names, assets)}
    other = D(b'synthetic-public-other-asset')
    sums = ''.join('%s  %s\n' % (digest, name) for name, digest in [
        (names[0], digests[names[0]]), ('other-public-asset', other), (names[1], digests[names[1]]), (names[2], digests[names[2]])
    ]).encode()
    pin = {
        'release': version, 'commit': digit * 40, 'releaseId': 1009 + index,
        'sha256': dict({'SHA256SUMS-x86_64': D(sums)}, **digests),
        'source': 'https://github.com/briq-cloud/briqyard/releases/tag/v' + version,
    }
    raw_pin = json.dumps(pin, indent=2, sort_keys=True).encode() + b'\n'
    (out / (label + '_pin.json')).write_bytes(raw_pin)
    (out / (label + '_sums.txt')).write_bytes(sums)
    releases.append({
        'version': version, 'commit': digit * 40, 'release_id': pin['releaseId'], 'pin_file': D(raw_pin),
        'sums': D(sums), 'daemon': digests[names[0]], 'fleet': digests[names[1]], 'cli': digests[names[2]],
    })
source, target = releases

pre_d = proc(10, source['daemon'], 'daemon-v1-build')
pre_a = proc(20, source['fleet'], 'fleet-v1-build')
cust_d = proc(30, source['daemon'], 'daemon-v1-build')
cust_a = proc(40, source['daemon'], 'daemon-v1-build')


def resource(pre, custodian, role):
    daemon = role == 'daemon'
    executable = ('synthetic-daemon-v1' if daemon else 'synthetic-fleet-v1').encode()
    guard = ('synthetic %s guard' % role).encode()
    config = ('synthetic %s config\n' % role).encode()
    cert = ('synthetic %s ordinary TLS certificate bytes\n' % role).encode()
    key = ('synthetic %s ordinary TLS key placeholder, not a key\n' % role).encode()
    names = ['api', 'metrics'] if daemon else ['api']
    return {
        'pre': pre, 'custodian': custodian,
        'guard': {'file': {'path': T('/usr/local/bin/briqyardd' if daemon else '/usr/local/bin/briqyard-fleet'), 'bytes': len(guard), 'sha256': D(guard)}, 'build': 'guard-v1'},
        'candidate': {'file': {'path': T('/var/lib/briq-sealed/candidates/' + role), 'bytes': len(executable), 'sha256': D(executable)}, 'build': 'candidate-d' if daemon else 'candidate-a'},
        'config': {'path': T('/etc/briqyard/config.yaml' if daemon else '/etc/briq-execution/authority/config.json'), 'bytes': len(config), 'sha256': D(config)},
        'tls_cert': {'bytes': len(cert), 'sha256': D(cert)},
        'tls_key': {'bytes': len(key), 'sha256': D(key)},
        'fragment': T('/etc/systemd/system/briqyard.service' if daemon else '/etc/systemd/system/briqyard-fleet.service'),
        'legacy_fragment': D(('synthetic %s legacy fragment\n' % role).encode()),
        'guarded_fragment': D(('synthetic %s guarded fragment\n' % role).encode()),
        'control': {'path': T('/run/briqyard-sealed/%s/control' % role), 'uid': 0, 'gid': 0 if daemon else 1000, 'mode': 384 if daemon else 432},
        'journal': {'path': T('/var/lib/briqyard/journal' if daemon else '/var/lib/briq-execution-authority/journal'), 'uid': 0 if daemon else 1000, 'gid': 0 if daemon else 1000, 'mode': 448},
        'listeners': {'count': len(names), 'names': D(':'.join(names).encode()), 'store_max': 2770 if daemon else 1},
        'writer_profile': D(('synthetic %s writer profile\n' % role).encode()),
    }


actors = [
    {'actor': 'A', 'id': 'authority-1', 'proc': None},
    {'actor': 'B', 'id': 'api-1', 'proc': None},
    {'actor': 'H', 'id': 'h15', 'proc': None},
    {'actor': 'R', 'id': 'receiver-1', 'proc': None},
    {'actor': 'gateway', 'id': 'gateway-1', 'proc': proc(50, D(b'synthetic gateway image'), 'gateway-v1', OTHER_BOOT)},
    {'actor': 'installer', 'id': 'installer-1', 'proc': proc(60, D(b'synthetic installer image'), 'installer-v1', OTHER_BOOT)},
]
ports = {'H': 7541, 'A': 7542, 'B': 9000, 'R': 9001, 'gateway': 9002, 'installer': 9003}
peers = []
for actor in actors:
    role = actor['actor']
    pair = lambda purpose: {'leaf': D(('synthetic leaf %s %s' % (role, purpose)).encode()), 'spki': D(('synthetic spki %s %s' % (role, purpose)).encode())}
    peers.append({
        'actor': role, 'id': actor['id'], 'endpoint': T('https://%s.example.test:%d' % (role.lower(), ports[role])),
        'server_name': T('%s.example.test' % role.lower()), 'server': pair('server'), 'client': pair('client'),
    })
roots = sorted([b'synthetic trust anchor one', b'synthetic trust anchor two'], key=D)
x = {'aud': 'staging', 'host': 'host.test', 'op': '0' * 64, 'serial': 1}
closure = {
    'format': 'native.closure/v1', 'x': x,
    'registry': D(b'synthetic public registry\n'), 'admin_host': D(b'synthetic host administrator commitment'),
    'admin_fleet': D(b'synthetic fleet administrator commitment'),
    'continuation': {
        'url': T('https://api.example.test/internal/execution/v1/continue'), 'bearer': D(b'synthetic continuation commitment'),
        'roots': [B(root) for root in roots], 'server_name': T('api.example.test'),
    },
    'peers': peers, 'admin_tls': None, 'backup_s3': None, 'file_key': None,
    'support': {
        'image_root': D(b'synthetic dm-verity root input'), 'boot_id': BOOT,
        'release_policy': D(b'synthetic release policy\n'), 'profile': D(b'synthetic deployment profile\n'),
    },
}
host = lambda registered, intrinsic: {'registered': registered, 'intrinsic': intrinsic, 'reader_floor': D(('synthetic reader floor %s\n' % registered).encode())}
inputs = {
    'format': 'native.inputs/v1', 'assets_abi': 3, 'x': x, 'registered': 'h15',
    'source_release': source, 'target_release': target,
    'topology': {
        'regions': [
            {'id': 'eu', 'hosts': [host('h17-eu', 'host-eu.test')], 'minimum_accepting': 1},
            {'id': 'na', 'hosts': [host('h15', 'host.test'), host('h16', 'host-na-2.test')], 'minimum_accepting': 1},
        ],
        'order': ['h17-eu', 'h16', 'h15'], 'policy_inventory': D(b'synthetic topology inventory\n'),
    },
    'actors': actors, 'daemon': resource(pre_d, cust_d, 'daemon'), 'authority': resource(pre_a, cust_a, 'authority'),
    'closure': closure,
}
manifest = C(inputs)
assert len(manifest) <= 65536 and not manifest.endswith(b'\n')
(out / 'inputs.json').write_bytes(manifest)
print('inputs bytes', len(manifest), 'sha256', D(manifest))
