#!/usr/bin/env python3
"""Running-service memory template checks and timings (ADR 0127).

  service_template.py e2e     isolation checks on a small service fixture
  service_template.py bench   cold start against clone, interleaved, then simultaneous clones

Run through hack/service-template.sh, which enables the profile and puts the configuration back.
The fixture is plain busybox: no language runtime. Timings on a nested host are relative only."""
import base64, json, math, os, statistics, subprocess, sys, threading, time, urllib.error, urllib.request

BASE = os.getenv('BRIQYARD_URL', 'http://127.0.0.1:7420')
HEAD = {'Content-Type': 'application/json'}
if os.getenv('BRIQYARD_TOKEN'):
    HEAD['Authorization'] = 'Bearer ' + os.environ['BRIQYARD_TOKEN']
IMAGE = os.getenv('FIXTURE_IMAGE', 'docker.io/library/busybox:1.36')
NS = 'svc-tpl-%d' % os.getpid()


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__('%s %s' % (status, body))
        self.status, self.body = status, body


def api(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + '/v1' + path, data, HEAD, method=method)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            b = r.read()
            return json.loads(b) if b else None
    except urllib.error.HTTPError as e:
        raise ApiError(e.code, e.read().decode(errors='replace'))


def cli(*args):
    return subprocess.run(['briqyard', 'machine', *args], capture_output=True, text=True, timeout=120)


SVC = r'''#!/bin/sh
head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > /tmp/cached
if [ "${LOAD_MB:-0}" -gt 0 ]; then
  mkdir -p /mnt/load && mount -t tmpfs -o size=$((LOAD_MB+16))m tmpfs /mnt/load
  head -c 1048576 /dev/urandom > /tmp/pattern
  i=0; while [ $i -lt "$LOAD_MB" ]; do cat /tmp/pattern; i=$((i+1)); done > /mnt/load/blob
fi
if [ "${LOAD_S:-0}" -gt 0 ]; then
  end=$(( $(date +%s) + LOAD_S )); while [ "$(date +%s)" -lt "$end" ]; do :; done
fi
exec busybox httpd -f -p 8080 -h /www
'''
INFO = r'''#!/bin/sh
echo "Content-Type: text/plain"; echo
echo "hostname=$(hostname)"
echo "machine_id=$(cat /etc/machine-id 2>/dev/null)"
echo "mac=$(cat /sys/class/net/eth0/address)"
echo "ip=$(ip -4 -o addr show eth0 | awk '{print $4}')"
echo "cached=$(cat /tmp/cached)"
echo "fresh=$(cat /tmp/fresh 2>/dev/null)"
echo "clone=$(tr -d ' \n' < /run/briqyard/clone.json 2>/dev/null)"
'''
PARK = '#!/bin/sh\nsync\n'
RESUME = r'''#!/bin/sh
head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > /tmp/fresh
if grep -q bad /run/briqyard/clone.json; then echo "refusing: $(cat /run/briqyard/clone.json)" >&2; exit 1; fi
'''


def files():
    def f(path, text):
        return {'path': path, 'base64': base64.b64encode(text.encode()).decode(), 'mode': '0755'}
    return [f('/app/svc.sh', SVC), f('/www/cgi-bin/info', INFO), f('/app/park', PARK), f('/app/resume', RESUME)]


def builder_body(name, load_mb=0, load_s=0, mem=512, hooks=True):
    b = {'namespace': NS, 'name': name, 'image': IMAGE, 'size': {'vcpus': 1, 'memory_mb': mem},
         'cmd': ['/app/svc.sh'], 'files': files(), 'sleep': 'never',
         'env': {'LOAD_MB': str(load_mb), 'LOAD_S': str(load_s)}, 'ports': [8080]}
    if hooks:
        b['template_build'] = 'service-ready-v1'
        b['clone_hooks'] = {'park': ['/app/park'], 'resume': ['/app/resume'], 'park_timeout_s': 30, 'resume_timeout_s': 30}
    return b


def get(mid, state='running', timeout=180):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        m = api('GET', '/machines/' + mid)
        if m['state'] == state:
            return m
        if m['state'] == 'error' or (state == 'running' and m['state'] == 'stopped'):
            raise RuntimeError('%s is %s (%s)' % (mid, m['state'], m.get('error_reason')))
        time.sleep(0.02)
    raise TimeoutError('%s never %s' % (mid, state))


def http(ip, path='/cgi-bin/info', timeout=1.0):
    with urllib.request.urlopen('http://%s:8080%s' % (ip, path), timeout=timeout) as r:
        return r.read().decode()


def serves(ip, timeout=300):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            return http(ip)
        except Exception:
            time.sleep(0.02)
    raise TimeoutError('no answer from ' + ip)


def info(text):
    return dict(l.split('=', 1) for l in text.splitlines() if '=' in l)


ids = []


def make(body):
    m = api('POST', '/machines', body)
    ids.append(m['id'])
    return m


def clone_body(name, snap):
    return {'namespace': NS, 'name': name, 'fork': {'machine_id': SRC, 'snapshot': snap}}


SRC = ''


def cleanup():
    for i in reversed(ids):
        try:
            api('DELETE', '/machines/' + i)
        except Exception:
            pass
    try:
        for m in api('GET', '/machines?namespace=' + NS) or []:
            try:
                api('DELETE', '/machines/' + m['id'])
            except Exception:
                pass
    except Exception:
        pass


passed = failed = 0


def check(name, cond, detail=''):
    global passed, failed
    if cond:
        passed += 1
        print('  ok   ' + name)
    else:
        failed += 1
        print('  FAIL %s %s' % (name, detail))


def e2e():
    global SRC
    b = make(builder_body('svc-src'))
    SRC = b['id']
    b = get(SRC)
    serves(b['ip'])
    # 3: an established external socket refuses the seal and the source serves again.
    cli('exec', SRC, '--', 'sh', '-c',
        'ip=$(ip -4 -o addr show eth0 | awk \'{print $4}\' | cut -d/ -f1); '
        '(setsid sh -c \"sleep 3600 | nc -l -p 9999 >/dev/null 2>&1\" </dev/null >/dev/null 2>&1 &); sleep 1; '
        '(setsid sh -c "sleep 3600 | nc $ip 9999 >/dev/null 2>&1" </dev/null >/dev/null 2>&1 &); sleep 1')
    try:
        api('POST', '/machines/%s/snapshots' % SRC, {'name': 'loaded', 'memory': True, 'template': True})
        check('seal refused with an open external socket', False, 'sealed')
    except ApiError as e:
        check('seal refused with an open external socket', e.status == 409 and 'established' in e.body, str(e))
    check('source still running after the refusal', api('GET', '/machines/' + SRC)['state'] == 'running')
    try:
        check('source serves again after the refusal', 'hostname=' in http(b['ip'], timeout=3))
    except Exception as e:
        check('source serves again after the refusal', False, str(e))
    cli('exec', SRC, '--', 'sh', '-c', 'pkill nc; true')
    # 1: seal, then three clones.
    snap = api('POST', '/machines/%s/snapshots' % SRC, {'name': 'loaded', 'memory': True, 'template': True})
    check('sealed', bool(snap.get('clone_generation')), str(snap))
    check('source stopped after the seal', get(SRC, 'stopped', 30)['state'] == 'stopped')
    t0 = time.monotonic()
    cl = []
    for n in range(3):
        m = make(clone_body('ok%d' % n, 'loaded'))
        cl.append(get(m['id']))
    print('  three clones running in %.2fs' % (time.monotonic() - t0))
    out = [info(serves(m['ip'])) for m in cl]
    for key in ('mac', 'ip', 'machine_id', 'hostname', 'fresh'):
        vals = [o.get(key) for o in out]
        check('clones differ in ' + key, len(set(vals)) == 3 and all(vals), str(vals))
    # 2: the draw taken before the seal is shared: the documented application duty.
    check('cached draw is shared across clones', len({o['cached'] for o in out}) == 1 and bool(out[0]['cached']))
    for o, m in zip(out, cl):
        c = json.loads(o['clone']) if o.get('clone') else {}
        check('clone.json matches the clone ' + m['name'],
              c.get('ip') == m['ip'] and c.get('hostname') == o['hostname'] and c.get('machine_id') == o['machine_id'], str(c))
    # 6: the template cannot be deleted while clones exist.
    try:
        api('DELETE', '/machines/%s/snapshots/%s' % (SRC, snap['id']))
        check('template deletion refused while clones exist', False, 'deleted')
    except ApiError as e:
        check('template deletion refused while clones exist', e.status in (409, 412), str(e))
    # 4: a resume hook that exits 1 quarantines that clone alone.
    res = {}
    try:
        res['bad'] = make(clone_body('bad', 'loaded'))
    except ApiError as e:
        res['bad_err'] = e
    ok3 = make(clone_body('ok3', 'loaded'))
    get(ok3['id'])
    bad = next((m for m in api('GET', '/machines?namespace=' + NS) if m['name'] == 'bad'), None)
    if bad:
        ids.append(bad['id']) if bad['id'] not in ids else None
        bad = get(bad['id'], 'error', 60)
    check('failed resume leaves that clone in error with clone_hook_failed', bool(bad) and bad.get('error_reason') == 'clone_hook_failed', str(bad and bad.get('error_reason')))
    check('the failed clone has no running VMM', bool(bad) and not bad.get('pid'), str(bad and bad.get('pid')))
    check('other clones keep serving', all('hostname=' in http(m['ip'], timeout=3) for m in cl))
    check('the clone after the failure starts', api('GET', '/machines/' + ok3['id'])['state'] == 'running')
    cleanup()
    left = [m for m in api('GET', '/machines?namespace=' + NS) or []]
    check('everything destroyed', not left, str(left))
    print('service e2e: %d passed, %d failed' % (passed, failed))
    return failed == 0


def stats(xs):
    xs = sorted(xs)
    return {'n': len(xs), 'p50_s': round(statistics.median(xs), 2), 'max_s': round(max(xs), 2), 'samples_s': [round(x, 2) for x in xs]}


def rss_mb():
    out = subprocess.run("ps -eo rss,comm | awk '/firecracker/{s+=$1} END{print s/1024}'", shell=True, capture_output=True, text=True).stdout
    return float(out.strip() or 0)


def bench():
    global SRC
    n = int(os.getenv('BENCH_N', '5'))
    mb, secs = int(os.getenv('LOAD_MB', '1024')), int(os.getenv('LOAD_S', '20'))
    mem = 2048
    b = make(builder_body('bench-src', mb, secs, mem))
    SRC = b['id']
    t = time.monotonic()
    b = get(SRC)
    serves(b['ip'])
    print('builder loaded in %.1fs' % (time.monotonic() - t))
    t = time.monotonic()
    snap = api('POST', '/machines/%s/snapshots' % SRC, {'name': 'loaded', 'memory': True, 'template': True})
    print('seal (park, snapshot) in %.1fs' % (time.monotonic() - t))
    cold, clone = [], []
    for i in range(n):
        t = time.monotonic()
        m = make(builder_body('cold%d' % i, mb, secs, mem, hooks=False))
        m = get(m['id'])
        serves(m['ip'])
        cold.append(time.monotonic() - t)
        api('DELETE', '/machines/' + m['id'])
        t = time.monotonic()
        m = make(clone_body('clone%d' % i, 'loaded'))
        m = get(m['id'])
        serves(m['ip'])
        clone.append(time.monotonic() - t)
        api('DELETE', '/machines/' + m['id'])
    res = {'fixture': {'load_mb': mb, 'load_s': secs, 'vcpus': 1, 'memory_mb': mem}, 'cold': stats(cold), 'clone': stats(clone)}
    res['clone_p50_over_cold_p50'] = round(res['clone']['p50_s'] / res['cold']['p50_s'], 3)
    base = rss_mb()
    conc = []
    out = {}

    def one(k):
        t = time.monotonic()
        m = make(clone_body('par%d' % k, 'loaded'))
        m = get(m['id'])
        serves(m['ip'])
        out[k] = (m, time.monotonic() - t)
    th = [threading.Thread(target=one, args=(k,)) for k in range(8)]
    t0 = time.monotonic()
    [x.start() for x in th]
    [x.join() for x in th]
    conc = [v[1] for v in out.values()]
    for m, _ in out.values():
        http(m['ip'])
    res['eight_simultaneous'] = {'ready': len(out), 'wall_s': round(time.monotonic() - t0, 2), **{k: v for k, v in stats(conc).items() if k != 'samples_s'},
                                 'firecracker_rss_mb_before': round(base), 'firecracker_rss_mb_after': round(rss_mb())}
    print(json.dumps(res, indent=1))
    cleanup()
    return res['clone_p50_over_cold_p50'] <= 0.25


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'e2e'
    ok = False
    try:
        ok = {'e2e': e2e, 'bench': bench}[mode]()
    finally:
        cleanup()
        try:
            api('DELETE', '/namespaces/' + NS)
        except Exception:
            pass
    sys.exit(0 if ok else 1)
