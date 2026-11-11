#!/usr/bin/env python3
"""Running-service memory template checks and timings (ADR 0127).

  service_template.py e2e     isolation checks on a small service fixture
  service_template.py bench   cold start against clone, interleaved, then simultaneous clones
  service_template.py qualify [--clones N] [--age-seconds S] [--sequential] [--memory-mb M]
                              seal one template, start N clones and check VMGenID, the effective MAC,
                              the wall clock and the kernel RNG in each; the last line is a JSON summary

Run through hack/service-template.sh, which enables the profile and puts the configuration back.
The fixture is plain busybox: no language runtime. Timings on a nested host are relative only."""
import argparse, base64, json, math, os, re, statistics, subprocess, sys, threading, time, urllib.error, urllib.request

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
PARK = '#!/bin/sh\nsync\nif [ -f /tmp/bgpark ]; then sleep 60417 & echo $! > /tmp/bgpark.pid; fi\n'
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


def clone_body(name, snap, mem=512):
    return {'namespace': NS, 'name': name, 'size': {'vcpus': 1, 'memory_mb': mem},
            'fork': {'machine_id': SRC, 'snapshot': snap}}


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
    cli('exec', SRC, '--', 'sh', '-c', 'pkill nc; pkill -f "sleep 360[0]"; sleep 1; true')
    # 3b: a process outside the workload cgroup (an exec session's) refuses the seal.
    cli('exec', SRC, '--', 'sh', '-c', '(setsid sleep 601 </dev/null >/dev/null 2>&1 &); sleep 1')
    try:
        api('POST', '/machines/%s/snapshots' % SRC, {'name': 'loaded', 'memory': True, 'template': True})
        check('seal refused with a process outside the workload', False, 'sealed')
    except ApiError as e:
        check('seal refused with a process outside the workload', e.status == 409 and 'outside the workload' in e.body, str(e))
    check('source still running after the process refusal', api('GET', '/machines/' + SRC)['state'] == 'running')
    cli('exec', SRC, '--', 'sh', '-c', 'pkill -f "sleep 60[1]"; touch /tmp/bgpark; true')
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
    # 3c: the park hook's background child was killed when the hook ended: no clone has it.
    # The child wrote its pid before the seal (it ran), and neither it nor its zombie is left
    # (a pid reused by another process counts as gone).
    gone = cli('exec', cl[0]['id'], '--', 'sh', '-c',
               'p=$(cat /tmp/bgpark.pid 2>/dev/null); '
               'if [ -z "$p" ]; then echo never-ran; '
               'elif [ ! -e /proc/$p ]; then echo gone; '
               'elif tr "\\0" " " < /proc/$p/cmdline 2>/dev/null | grep -q "^sleep 60417"; then echo alive; '
               'elif grep -q "^State:.*Z" /proc/$p/status 2>/dev/null; then echo zombie; else echo gone-pid-reused; fi').stdout
    check('park hook background child ran, and is absent from the clone', gone.strip() in ('gone', 'gone-pid-reused'), gone.strip())
    # 2: the draw taken before the seal is shared: the documented application duty.
    check('cached draw is shared across clones', len({o['cached'] for o in out}) == 1 and bool(out[0]['cached']))
    for o, m in zip(out, cl):
        c = json.loads(o['clone']) if o.get('clone') else {}
        check('clone.json matches the clone ' + m['name'],
              str(c.get('ip', '')).split('/')[0] == m['ip'] and c.get('hostname') == o['hostname'] and c.get('machine_id') == o['machine_id'], str(c))
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
        m = make(clone_body('clone%d' % i, 'loaded', mem))
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
        m = make(clone_body('par%d' % k, 'loaded', mem))
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


# ---- qualify: VMGenID, MAC, clock and RNG of loaded-service clones (ADR 0127) -------------------
# Each check is "pass", "fail" or "unsupported" (the pinned kernel has no such device). A fail makes
# the exit status non-zero; "unsupported" does not, and is listed in the summary. A nested host's
# timings are relative only: the numbers say nothing about a native host.

KERNEL_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kernel', 'base-x86_64.config')
FORK_MSG = 'crng reseeded due to virtual machine fork'

# One exec per clone, run right after it answers: the clock first, then the rest. Plain busybox.
GUEST_PROBE = r"""
echo "now=$(date +%s.%N 2>/dev/null)"
echo "mac=$(cat /sys/class/net/eth0/address)"
echo "uname=$(uname -r)"
echo "cmdline=$(cat /proc/cmdline)"
echo "draw=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
echo "dmesg_ok=$(dmesg >/dev/null 2>&1 && echo 1 || echo 0)"
echo "fork_msgs=$(dmesg 2>/dev/null | grep -c 'crng reseeded due to virtual machine fork')"
echo "fork_line=$(dmesg 2>/dev/null | grep 'crng reseeded due to virtual machine fork' | tail -n 1)"
echo "vmgenid_dev=$(ls /sys/bus/acpi/devices 2>/dev/null | grep -E '^(VMGENCTR|VMGENCNT|VM_GEN_COUNTER|FCVMGID)' | tr '\n' ' ')"
echo "vmgenid_drv=$(for d in /sys/bus/acpi/devices/VMGENCTR* /sys/bus/acpi/devices/VMGENCNT* /sys/bus/acpi/devices/VM_GEN_COUNTER* /sys/bus/acpi/devices/FCVMGID*; do [ -e "$d" ] && for l in "$d/driver" "$d"/physical_node/driver; do [ -e "$l" ] && echo "$(basename $d)->$(basename $(readlink -f $l))"; done; done 2>/dev/null | tr '\n' ' ')"
echo "acpi_devices=$(ls /sys/bus/acpi/devices 2>/dev/null | tr '\n' ' ')"
echo "vmgenid_log=$(dmesg 2>/dev/null | grep -i vmgenid | tail -n 2 | tr '\n' '|')"
echo "vmclock_dev=$(ls /sys/bus/acpi/devices 2>/dev/null | grep -E '^AMZNC10C' | tr '\n' ' ')"
echo "vmclock_node=$(ls /dev 2>/dev/null | grep -i vmclock | tr '\n' ' ')"
echo "ptp=$(for f in /sys/class/ptp/*/clock_name; do [ -e "$f" ] && echo "$(basename $(dirname $f))=$(cat $f)"; done 2>/dev/null | tr '\n' ' ')"
echo "vmclock_log=$(dmesg 2>/dev/null | grep -i vmclock | tail -n 2 | tr '\n' '|')"
echo "config=$(zcat /proc/config.gz 2>/dev/null | grep -E '^(# )?CONFIG_(VMGENID|PTP_1588_CLOCK_VMCLOCK)[ =]' | tr '\n' ';')"
"""


def config_line(text, option):
    """The kernel config's own line for an option: "CONFIG_X=y", "# CONFIG_X is not set", or ''."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(option + '=') or line == '# %s is not set' % option:
            return line
    return ''


def repo_config(option):
    try:
        with open(KERNEL_CONFIG) as f:
            return config_line(f.read(), option), 'hack/kernel/base-x86_64.config'
    except OSError:
        return '', ''


def pick_config(guest_config, option):
    """Config evidence for an option: the running guest's /proc/config.gz first, else the repo's
    copy of the pinned kernel's config. Returns (line, where)."""
    line = config_line(guest_config.replace(';', '\n'), option)
    if line:
        return line, 'guest /proc/config.gz'
    return repo_config(option)


def parse_probe(text):
    out = {}
    for l in text.splitlines():
        if '=' in l:
            k, v = l.split('=', 1)
            out[k] = v.strip()
    return out


def expected_mac(ip):
    """The MAC the daemon assigns a clone: locally administered 06:b1 followed by its IPv4 address
    (the API does not return it, so this follows the daemon's rule)."""
    return '06:b1:' + ':'.join('%02x' % int(o) for o in ip.split('/')[0].split('.'))


def clock_skew(guest_now, t0, t1):
    """Seconds between the guest's wall clock and the host's, as a lower bound. The guest read its
    clock once, somewhere in [t0, t1] on the host; without sub-second digits it is a second wide.
    Returns (skew_s, guest_minus_host_estimate_s, precise)."""
    # busybox date prints a literal %N where it has no sub-second digits: whole seconds then.
    m = re.match(r'^(\d+)(?:\.(\d{1,9}|%N))?$', guest_now or '')
    if not m:
        return None, None, False
    precise = m.group(2) is not None and m.group(2) != '%N'
    g0 = float(guest_now) if precise else float(m.group(1))  # %N: whole seconds
    g1 = g0 if precise else g0 + 1.0
    skew = max(0.0, g0 - t1, t0 - g1)
    return skew, (g0 + g1) / 2 - (t0 + t1) / 2, precise


def verdict(statuses):
    if 'fail' in statuses:
        return 'fail'
    if statuses and all(s == 'unsupported' for s in statuses):
        return 'unsupported'
    return 'pass' if statuses else 'fail'


def vmgenid_status(p):
    opt, where = pick_config(p.get('config', ''), 'CONFIG_VMGENID')
    ev = {'config': opt or 'no config evidence', 'config_from': where or 'none', 'device': p.get('vmgenid_dev') or 'none', 'driver': p.get('vmgenid_drv') or 'none',
          'acpi_devices': p.get('acpi_devices', ''), 'fork_messages': p.get('fork_msgs'), 'fork_line': p.get('fork_line', ''),
          'cmdline': p.get('cmdline', '')}
    if opt.startswith('#'):
        return 'unsupported', '%s (%s)' % (opt, where), ev
    if not opt and not p.get('vmgenid_dev'):
        return 'unsupported', 'no VM generation ID device and no kernel config evidence', ev
    if p.get('dmesg_ok') != '1':
        return 'fail', 'the kernel log is unreadable in the guest, so the reseed cannot be observed', ev
    if not p.get('vmgenid_dev'):
        return 'fail', '%s, but the guest has no VM generation ID ACPI device (is ACPI on?)' % (opt or 'config unknown'), ev
    if not p.get('fork_msgs', '0').isdigit() or int(p['fork_msgs']) < 1:
        return 'fail', 'device present, but the kernel never logged "%s": the generation ID did not change on restore' % FORK_MSG, ev
    return 'pass', 'device %s, and "%s" logged %s time(s): the ID changed across the restore' % (p['vmgenid_dev'].strip(), FORK_MSG, p['fork_msgs']), ev


def vmclock_info(p):
    opt, where = pick_config(p.get('config', ''), 'CONFIG_PTP_1588_CLOCK_VMCLOCK')
    present = bool(p.get('vmclock_dev') or p.get('vmclock_node') or re.search(r'vmclock|virtual machine ptp', p.get('ptp', ''), re.I))
    status = 'present' if present else ('unsupported' if opt.startswith('#') else 'absent')
    return {'status': status, 'config': opt or 'no config evidence', 'config_from': where or 'none', 'acpi_device': p.get('vmclock_dev') or 'none',
            'dev_node': p.get('vmclock_node') or 'none', 'ptp': p.get('ptp') or 'none', 'log': p.get('vmclock_log', '')}


def free_mb():
    mem = {}
    with open('/proc/meminfo') as f:
        for l in f:
            k, v = l.split(':', 1)
            mem[k] = int(v.split()[0]) // 1024
    return {'free_mb': mem['MemFree'], 'available_mb': mem['MemAvailable']}


def tool_version(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip().splitlines()[0]
    except Exception:
        return 'unknown'


def qualify(args):
    global SRC
    mem = args.memory_mb
    b = make(builder_body('qual-src', 0, 0, mem))
    SRC = b['id']
    b = get(SRC)
    serves(b['ip'])
    t = time.monotonic()
    snap = api('POST', '/machines/%s/snapshots' % SRC, {'name': 'loaded', 'memory': True, 'template': True})
    print('sealed in %.1fs (generation %s)' % (time.monotonic() - t, snap.get('clone_generation')))
    get(SRC, 'stopped', 60)
    if args.age_seconds:
        print('template ages %ds before the first clone' % args.age_seconds)
        time.sleep(args.age_seconds)
    before = {**free_mb(), 'firecracker_rss_mb': round(rss_mb())}
    res = {}

    def one(k):
        r = res[k] = {}
        t = time.monotonic()
        try:
            m = make(clone_body('q%d' % k, 'loaded', mem))
            m = get(m['id'])
            serves(m['ip'])
            r['ready_s'] = time.monotonic() - t
            r['id'], r['ip'] = m['id'], m['ip']
            t0 = time.time()
            p = cli('exec', m['id'], '--', 'sh', '-c', GUEST_PROBE)
            t1 = time.time()
            r['probe'] = parse_probe(p.stdout)
            r['exec_s'] = t1 - t0
            if p.returncode != 0 or 'mac' not in r['probe']:
                r['error'] = 'probe exec failed: rc %s %s' % (p.returncode, p.stderr.strip()[:200])
            r['t0'], r['t1'] = t0, t1
            r['fresh'] = info(http(m['ip'], timeout=3)).get('fresh', '')
        except Exception as e:
            r['error'] = '%s: %s' % (type(e).__name__, str(e)[:300])
    th = [threading.Thread(target=one, args=(k,)) for k in range(args.clones)]
    t0 = time.monotonic()
    for x in th:
        x.start()
        if args.sequential:
            x.join()
    for x in th:
        x.join()
    wall = time.monotonic() - t0
    after = {**free_mb(), 'firecracker_rss_mb': round(rss_mb())}
    rs = [res[k] for k in range(args.clones)]
    ready = [r['ready_s'] for r in rs if 'ready_s' in r]

    checks = {n: {'per_clone': [], 'evidence': []} for n in ('vmgenid', 'mac', 'clock', 'rng')}
    for k, r in enumerate(rs):
        p = r.get('probe') or {}
        if r.get('error') and not p:
            for n in checks:
                checks[n]['per_clone'].append(('fail', 'clone %d: %s' % (k, r['error'])))
            continue
        st, why, ev = vmgenid_status(p)
        checks['vmgenid']['per_clone'].append((st, 'clone %d: %s' % (k, why)))
        checks['vmgenid']['evidence'].append(ev)
        want, got = expected_mac(r['ip']), p.get('mac', '')
        checks['mac']['per_clone'].append(('pass' if want == got else 'fail', 'clone %d: eth0 %s, assigned %s' % (k, got, want)))
        skew, est, precise = clock_skew(p.get('now'), r['t0'], r['t1'])
        if skew is None:
            checks['clock']['per_clone'].append(('fail', 'clone %d: unreadable guest clock %r' % (k, p.get('now'))))
        else:
            checks['clock']['per_clone'].append(('pass' if skew <= 1.0 else 'fail',
                                                 'clone %d: skew >= %.2fs (guest - host about %+.2fs, %s, exec %.2fs)' % (k, skew, est, 'sub-second' if precise else 'whole seconds', r['exec_s'])))
    macs = [(r.get('probe') or {}).get('mac') for r in rs]
    draws = [(r.get('probe') or {}).get('draw') for r in rs] + [r.get('fresh') for r in rs]
    fresh = [r.get('fresh') for r in rs]
    if args.clones > 1:
        checks['mac']['per_clone'].append(('pass' if len(set(macs)) == len(macs) and all(macs) else 'fail', 'MACs differ across clones: %s' % macs))
        distinct = all(fresh) and len(set(fresh)) == len(fresh) and all(draws[:args.clones]) and len(set(draws[:args.clones])) == args.clones
        checks['rng']['per_clone'].append(('pass' if distinct else 'fail', 'resume-hook draws %s, probe draws %s' % (fresh, draws[:args.clones])))
    else:
        checks['rng']['per_clone'].append(('unsupported', 'one clone: nothing to compare against'))
    for k, r in enumerate(rs):
        if not r.get('probe'):
            checks['rng']['per_clone'].append(('fail', 'clone %d: %s' % (k, r.get('error', 'no probe'))))
    out = {}
    for n, c in checks.items():
        v = verdict([s for s, _ in c['per_clone']])
        out[n] = {'status': v, 'details': [d for _, d in c['per_clone']]}
        if c['evidence']:
            out[n]['evidence'] = c['evidence'][0]
        print('  %-12s %s' % (n, v))
        for s, d in c['per_clone']:
            print('       %-11s %s' % (s, d))
    vc = vmclock_info((rs[0].get('probe') or {}) if rs else {})
    print('  vmclock      %s (config: %s)' % (vc['status'], vc['config']))
    failed = [n for n, c in out.items() if c['status'] == 'fail']
    if any('error' in r for r in rs):
        failed.append('clones')
    summary = {
        'qualify': 'service-ready-v1', 'ok': not failed, 'failed': failed,
        'unsupported': [n for n, c in out.items() if c['status'] == 'unsupported'],
        'clones': args.clones, 'sequential': args.sequential, 'age_seconds': args.age_seconds, 'memory_mb': mem,
        'create_to_ready_s': {'n': len(ready), 'p50': round(statistics.median(ready), 2) if ready else None, 'max': round(max(ready), 2) if ready else None,
                              'wall': round(wall, 2)},
        'host_memory_mb': {'before': before, 'after': after},
        'checks': out, 'vmclock': vc,
        'guest_kernel': next(((r.get('probe') or {}).get('uname') for r in rs if r.get('probe')), None),
        'firecracker': tool_version('firecracker', '--version'),
        'nested_or_relative_only': True,
    }
    cleanup()
    print(json.dumps(summary, separators=(',', ':')))
    return not failed


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('mode', nargs='?', default='e2e', choices=['e2e', 'bench', 'qualify'])
    ap.add_argument('--clones', type=int, default=3, help='qualify: clones to start (8 for the simultaneous run)')
    ap.add_argument('--age-seconds', type=int, default=30, help='qualify: wait between the seal and the first clone')
    ap.add_argument('--sequential', action='store_true', help='qualify: start the clones one after another instead of together')
    ap.add_argument('--memory-mb', type=int, default=512, help='qualify: memory of the builder and its clones')
    args = ap.parse_args()
    mode = args.mode
    ok = False
    try:
        ok = {'e2e': e2e, 'bench': bench, 'qualify': lambda: qualify(args)}[mode]()
    finally:
        cleanup()
        try:
            api('DELETE', '/namespaces/' + NS)
        except Exception:
            pass
    sys.exit(0 if ok else 1)
