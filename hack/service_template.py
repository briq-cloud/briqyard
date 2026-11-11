#!/usr/bin/env python3
"""Running-service memory template checks and timings (ADR 0127).

  service_template.py e2e     isolation checks on a small service fixture
  service_template.py bench   cold start against clone, interleaved, then simultaneous clones
  service_template.py qualify [--clones N] [--age-seconds S] [--sequential] [--memory-mb M] [--allow-unsupported]
                              seal one template, start N clones and check VMGenID, the effective MAC (in the
                              guest and on the host), the wall clock and the kernel RNG; the last line is
                              always a JSON summary (ok false on any fail, unsupported check or error)

Run through hack/service-template.sh, which enables the profile and puts the configuration back.
The fixture is plain busybox: no language runtime. Timings on a nested host are relative only."""
import argparse, base64, ipaddress, json, math, os, re, socket, statistics, subprocess, sys, threading, time, traceback, urllib.error, urllib.parse, urllib.request

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
PARK = '#!/bin/sh\ndmesg 2>/dev/null | grep -c "crng reseeded due to virtual machine fork" > /tmp/pre_seal_fork_msgs\nsync\nif [ -f /tmp/bgpark ]; then sleep 60417 & echo $! > /tmp/bgpark.pid; fi\n'
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
# Each check is "pass", "fail" or "unsupported" (the pinned kernel has no such device, or the check
# could not be read). The summary is `ok` only when every check passes: a fail, an unsupported check
# (unless --allow-unsupported) or a clone error makes `ok` false and the exit status 1.
#
# What each check proves (the same text is in the JSON):
#  - vmgenid   the hypervisor and the kernel: the VM generation ID changed on restore and the guest
#              kernel reseeded its CRNG for it. Nothing in the daemon or the init does that for it.
#  - mac_host  an outside observation of the activation path: the guest init sets the MAC and the host learns
#              it from the guest's ARP reply, so the host's neighbour entry (flushed first) shows what the init set.
#              It is not a hypervisor check; VMGenID is the only one.
#  - mac, clock, rng
#              the activation path only. clone_configure_v1 writes the daemon's per-clone MAC, wall
#              clock and entropy into the guest before the clone is ready, so these pass whenever the
#              activation works, whatever the hypervisor restores. They catch a regression of that path.
# A nested host's timings are relative only: the numbers say nothing about a native host.

KERNEL_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kernel', 'base-x86_64.config')
FORK_MSG = 'crng reseeded due to virtual machine fork'
CHECKS = ('vmgenid', 'mac', 'mac_host', 'clock', 'rng')
PROVES = {
    'vmgenid': 'hypervisor and kernel: the VM generation ID changed on restore and the guest kernel reseeded its CRNG for it',
    'mac': 'activation path: clone_configure_v1 writes the daemon\'s per-clone MAC; the guest applied it and the MACs differ',
    'mac_host': 'outside observation of the activation path (not a hypervisor check): the host\'s freshly learned neighbour entry for the clone shows the assigned MAC, distinct per clone',
    'clock': 'activation path: clone_configure_v1 sets the wall clock from the host; it is not proof of what the hypervisor restores',
    'rng': 'activation path: the init reseeds from per-clone host entropy; it is not proof of what the hypervisor restores',
}

# One exec per clone, run right after it answers: the clock first, then the rest. Plain busybox.
GUEST_PROBE = r"""
echo "now=$(date +%s.%N 2>/dev/null)"
echo "mac=$(cat /sys/class/net/eth0/address)"
echo "uname=$(uname -r)"
echo "cmdline=$(cat /proc/cmdline)"
echo "draw=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
echo "dmesg_ok=$(dmesg >/dev/null 2>&1 && echo 1 || echo 0)"
echo "fork_msgs=$(dmesg 2>/dev/null | grep -c 'crng reseeded due to virtual machine fork')"
echo "pre_fork=$(cat /tmp/pre_seal_fork_msgs 2>/dev/null)"
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
    """key=value lines; the value is everything after the first '=' (a kernel command line has more)."""
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


def parse_neigh(text):
    """The link-layer address in `ip neigh show <ip>` output, lower case, or None (no entry, FAILED)."""
    for l in text.splitlines():
        m = re.search(r'\blladdr\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b', l, re.I)
        if m and 'FAILED' not in l:
            return m.group(1).lower()
    return None


def host_neigh(ip, request=None):
    """(mac or None, raw text): the daemon host's neighbour entry for a clone, learned fresh. The entry is
    flushed first and one request (`request`) makes the host resolve it again, so a stale entry cannot match.
    A failed flush gives None (the check is then unsupported)."""
    ip = ip.split('/')[0]
    sudo = [] if os.geteuid() == 0 else ['sudo', '-n']
    try:
        f = subprocess.run([*sudo, 'ip', 'neigh', 'flush', 'to', ip], capture_output=True, text=True, timeout=10)
        if f.returncode != 0:
            return None, 'ip neigh flush failed: %s' % ((f.stderr or f.stdout).strip()[:150] or 'rc %d' % f.returncode)
        req_err = None
        if request:
            try:
                request()
            except Exception as e:  # the ARP reply may still have arrived: read the entry anyway
                req_err = type(e).__name__
        r = subprocess.run(['ip', 'neigh', 'show', ip], capture_output=True, text=True, timeout=10)
    except Exception as e:
        return None, 'ip neigh unavailable: %s' % type(e).__name__
    raw = (r.stdout.strip() or r.stderr.strip() or 'no entry')[:200]
    if req_err:
        raw = ('request failed: %s; ' % req_err + raw)[:200]
    return parse_neigh(r.stdout), raw


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
    """pass only when every status is pass; any fail wins over unsupported; nothing to judge is a fail."""
    if not statuses or 'fail' in statuses:
        return 'fail'
    if 'unsupported' in statuses:
        return 'unsupported'
    return 'pass'


def evaluate(statuses, clone_errors, allow_unsupported):
    """`ok` is true only when every required check passed. An unsupported check is not a pass:
    it makes `ok` false unless --allow-unsupported was given (recorded in the summary)."""
    failed = [n for n in CHECKS if statuses.get(n, 'fail') == 'fail']
    if clone_errors:
        failed.append('clones')
    unsupported = [n for n in CHECKS if statuses.get(n) == 'unsupported']
    return {'ok': not failed and (allow_unsupported or not unsupported), 'failed': failed, 'unsupported': unsupported}


def exit_status(summary):
    return 0 if summary.get('ok') is True else 1


def vmgenid_status(p):
    opt, where = pick_config(p.get('config', ''), 'CONFIG_VMGENID')
    pre = int(p['pre_fork']) if p.get('pre_fork', '').isdigit() else None
    ev = {'config': opt or 'no config evidence', 'config_from': where or 'none', 'device': p.get('vmgenid_dev') or 'none', 'driver': p.get('vmgenid_drv') or 'none',
          'acpi_devices': p.get('acpi_devices', ''), 'fork_messages': p.get('fork_msgs'), 'fork_messages_before_seal': pre if pre is not None else 'unknown',
          'fork_line': p.get('fork_line', ''), 'cmdline': p.get('cmdline', '')}
    if opt.startswith('#'):
        return 'unsupported', '%s (%s)' % (opt, where), ev
    if not opt and not p.get('vmgenid_dev'):
        return 'unsupported', 'no VM generation ID device and no kernel config evidence', ev
    if p.get('dmesg_ok') != '1':
        return 'fail', 'the kernel log is unreadable in the guest, so the reseed cannot be observed', ev
    if not p.get('pre_fork', '').isdigit():
        return 'fail', 'the park hook left no fork message count (/tmp/pre_seal_fork_msgs is missing), so the reseed cannot be told from an earlier one', ev
    if not p.get('vmgenid_dev'):
        return 'fail', '%s, but the guest has no VM generation ID ACPI device (is ACPI on?)' % (opt or 'config unknown'), ev
    n = int(p['fork_msgs']) if p.get('fork_msgs', '').isdigit() else 0
    if n <= (pre or 0):
        return ('fail', 'no vmfork reseed logged (%d "%s" message(s), %d before the seal); possible causes: the generation ID did not change on restore, '
                'the CRNG was not ready when the notification came, or the log buffer lost the line' % (n, FORK_MSG, pre or 0), ev)
    return 'pass', 'device %s, and "%s" logged %d time(s) (%d before the seal): the ID changed across the restore' % (p['vmgenid_dev'].strip(), FORK_MSG, n, pre or 0), ev


def vmclock_info(p):
    opt, where = pick_config(p.get('config', ''), 'CONFIG_PTP_1588_CLOCK_VMCLOCK')
    present = bool(p.get('vmclock_dev') or p.get('vmclock_node') or re.search(r'vmclock|virtual machine ptp', p.get('ptp', ''), re.I))
    status = 'present' if present else ('unsupported' if opt.startswith('#') else 'absent')
    return {'status': status, 'config': opt or 'no config evidence', 'config_from': where or 'none', 'acpi_device': p.get('vmclock_dev') or 'none',
            'dev_node': p.get('vmclock_node') or 'none', 'ptp': p.get('ptp') or 'none', 'log': p.get('vmclock_log', '')}


def vmclock_summary(probes):
    """VMClock across all clones that answered: the status when they agree, else "mixed"."""
    infos = [vmclock_info(p) for p in probes]
    if not infos:
        return {'status': 'unknown', 'per_clone': []}
    per = [i['status'] for i in infos]
    return {**infos[0], 'status': per[0] if len(set(per)) == 1 else 'mixed', 'per_clone': per}


def detect_nested(cpuinfo, hypervisor_type):
    """True when the host is itself a guest: the `hypervisor` CPU flag or /sys/hypervisor/type.
    None when neither source could be read. x86 only (the `hypervisor` CPU flag); an arm64 host is reported by
    /sys/hypervisor/type or not at all."""
    if cpuinfo is None and hypervisor_type is None:
        return None
    flag = any(l.startswith('flags') and 'hypervisor' in l.split() for l in (cpuinfo or '').splitlines())
    return flag or bool((hypervisor_type or '').strip())


def _can_bind(addr):
    try:
        with socket.socket(socket.AF_INET6 if ':' in addr else socket.AF_INET) as s:
            s.bind((addr, 0))
        return True
    except OSError:
        return False


def is_local_host(host, can_bind=_can_bind):
    """True when the host name or address is this machine: loopback, or an address it can bind.
    An empty host and wildcard addresses (0.0.0.0, ::) name no machine, so they are not local."""
    if not host or not host.strip():
        return False
    try:
        addrs = {i[4][0].split('%')[0] for i in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    try:
        ips = [ipaddress.ip_address(a) for a in addrs]
    except ValueError:
        return False
    return any(not a.is_unspecified and (a.is_loopback or can_bind(str(a))) for a in ips)


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def host_facts(url=None):
    url = url or BASE
    host = urllib.parse.urlparse(url).hostname or ''
    hv = _read('/sys/hypervisor/type')
    return {'hostname': socket.gethostname(), 'nested': detect_nested(_read('/proc/cpuinfo'), hv), 'hypervisor_type': (hv or '').strip() or None,
            'daemon_host': host, 'daemon_local': is_local_host(host)}


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


class Refused(RuntimeError):
    """The run was refused before any call to the daemon: nothing to tear down."""


def clone_unusable(r):
    """Why a clone's result cannot be judged (a reason), or None. A clone that failed early lacks the keys."""
    p = r.get('probe')
    if any(k not in r for k in ('ip', 't0', 't1', 'exec_s', 'neigh')) or p is None or ('error' in r and 'mac' not in p):
        return r.get('error') or 'the clone did not reach the probe'
    return None


def qualify(args, facts):
    """Runs the checks and returns the summary's fields. Raises on anything that stops the run."""
    global SRC
    if not facts['daemon_local']:
        raise Refused('BRIQYARD_URL points at %r, not this host: memory, RSS, firecracker and clock readings would describe the wrong machine. '
                           'Run qualify on the daemon host.' % facts['daemon_host'])
    mem = args.memory_mb
    b = make(builder_body('qual-src', 0, 0, mem))
    SRC = b['id']
    b = get(SRC)
    serves(b['ip'])
    t = time.monotonic()
    snap = api('POST', '/machines/%s/snapshots' % SRC, {'name': 'loaded', 'memory': True, 'template': True})
    print('sealed in %.1fs (generation %s)' % (time.monotonic() - t, snap.get('clone_generation')))
    get(SRC, 'stopped', 60)
    print('template ages %ds before the first clone' % args.age_seconds)
    time.sleep(args.age_seconds)
    before = {**free_mb(), 'host_firecracker_rss_mb': round(rss_mb())}
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
            r['neigh'] = host_neigh(m['ip'], lambda: http(m['ip'], timeout=3))
            t0 = time.time()
            p = cli('exec', m['id'], '--', 'sh', '-c', GUEST_PROBE)
            t1 = time.time()
            r['probe'] = parse_probe(p.stdout)
            r['exec_s'] = t1 - t0
            if p.returncode != 0 or 'mac' not in r['probe']:
                r['error'] = 'probe exec failed: rc %s %s' % (p.returncode, p.stderr.strip()[:200])
            r['t0'], r['t1'] = t0, t1
            r['fresh'] = info(http(m['ip'], timeout=3)).get('fresh', '')
        except KeyboardInterrupt:
            raise
        except BaseException as e:
            r['error'] = '%s: %s' % (type(e).__name__, str(e)[:300])
    th = [threading.Thread(target=one, args=(k,), daemon=True) for k in range(args.clones)]
    t0 = time.monotonic()
    for x in th:
        x.start()
        if args.sequential:
            x.join()
    for x in th:
        x.join()
    wall = time.monotonic() - t0
    after = {**free_mb(), 'host_firecracker_rss_mb': round(rss_mb())}
    rs = [res[k] for k in range(args.clones)]
    ready = [r['ready_s'] for r in rs if 'ready_s' in r]

    checks = {n: {'per_clone': [], 'evidence': []} for n in CHECKS}
    for k, r in enumerate(rs):
        p = r.get('probe') or {}
        why_not = clone_unusable(r)
        if why_not:
            for n in checks:
                checks[n]['per_clone'].append(('fail', 'clone %d: %s' % (k, why_not)))
            continue
        st, why, ev = vmgenid_status(p)
        checks['vmgenid']['per_clone'].append((st, 'clone %d: %s' % (k, why)))
        checks['vmgenid']['evidence'].append(ev)
        want, got = expected_mac(r['ip']), p.get('mac', '')
        checks['mac']['per_clone'].append(('pass' if want == got else 'fail', 'clone %d: eth0 %s, assigned %s' % (k, got, want)))
        seen, raw = r['neigh']
        if seen is None:
            checks['mac_host']['per_clone'].append(('unsupported', 'clone %d: host neighbour entry unreadable (%s)' % (k, raw)))
        else:
            checks['mac_host']['per_clone'].append(('pass' if seen == want else 'fail', 'clone %d: host sees %s, assigned %s' % (k, seen, want)))
        skew, est, precise = clock_skew(p.get('now'), r['t0'], r['t1'])
        if skew is None:
            checks['clock']['per_clone'].append(('fail', 'clone %d: unreadable guest clock %r' % (k, p.get('now'))))
        else:
            checks['clock']['per_clone'].append(('pass' if skew <= 1.0 else 'fail',
                                                 'clone %d: skew >= %.2fs (guest - host about %+.2fs, %s, exec %.2fs)' % (k, skew, est, 'sub-second' if precise else 'whole seconds', r['exec_s'])))
    good = [r for r in rs if not clone_unusable(r) and r.get('fresh') is not None]
    if len(good) >= 2:
        macs = [r['probe'].get('mac') for r in good]
        checks['mac']['per_clone'].append(('pass' if len(set(macs)) == len(macs) and all(macs) else 'fail', 'MACs differ across clones: %s' % macs))
        seen = [r['neigh'][0] for r in good if r['neigh'][0]]
        if len(seen) == len(good):
            checks['mac_host']['per_clone'].append(('pass' if len(set(seen)) == len(seen) else 'fail', 'host-side MACs differ across clones: %s' % seen))
        fresh = [r['fresh'] for r in good]
        draws = [r['probe'].get('draw') for r in good]
        distinct = all(fresh) and len(set(fresh)) == len(fresh) and all(draws) and len(set(draws)) == len(draws)
        checks['rng']['per_clone'].append(('pass' if distinct else 'fail', 'resume-hook draws %s, probe draws %s' % (fresh, draws)))
    out = {}
    for n, c in checks.items():
        v = verdict([s for s, _ in c['per_clone']])
        out[n] = {'status': v, 'proves': PROVES[n], 'details': [d for _, d in c['per_clone']]}
        if c['evidence']:
            out[n]['evidence'] = c['evidence'][0]
        print('  %-12s %s' % (n, v))
        for s, d in c['per_clone']:
            print('       %-11s %s' % (s, d))
    vc = vmclock_summary([r['probe'] for r in rs if r.get('probe')])
    print('  vmclock      %s (config: %s)' % (vc['status'], vc.get('config', 'n/a')))
    clone_errors = {str(k): r['error'] for k, r in enumerate(rs) if 'error' in r}
    ev = evaluate({n: c['status'] for n, c in out.items()}, clone_errors, args.allow_unsupported)
    return {
        **ev, 'clones': args.clones, 'sequential': args.sequential, 'age_seconds': args.age_seconds, 'memory_mb': mem,
        'clone_errors': clone_errors,
        'create_to_ready_s': {'n': len(ready), 'p50': round(statistics.median(ready), 2) if ready else None, 'max': round(max(ready), 2) if ready else None,
                              'wall': round(wall, 2)},
        'host_memory_mb': {'before': before, 'after': after},
        'checks': out, 'vmclock': vc,
        'guest_kernel': next((r['probe'].get('uname') for r in rs if r.get('probe')), None),
        'firecracker': tool_version('firecracker', '--version'),
    }


def teardown():
    """Destroys the namespace's machines and the namespace, then checks nothing is left (as the e2e does)."""
    left, err = [], ''
    for attempt in range(3):
        cleanup()
        try:
            left = [m['id'] for m in api('GET', '/machines?namespace=' + NS) or []]
        except Exception as e:
            left, err = [], 'listing failed: %s' % str(e)[:200]
        if not left:
            break
        time.sleep(1)
    try:
        api('DELETE', '/namespaces/' + NS)
    except ApiError as e:
        if e.status != 404:
            err = err or 'namespace delete failed: %s' % str(e)[:200]
    except Exception as e:
        err = err or 'namespace delete failed: %s' % str(e)[:200]
    return {'machines_left': left, 'error': err}


def run_qualify(args):
    """Always prints one JSON summary line last, whatever happened. Returns the exit status."""
    summary = {'qualify': 'service-ready-v1', 'ok': False, 'allow_unsupported': args.allow_unsupported}
    touched = True
    try:
        try:
            facts = host_facts()
            summary['host'] = facts
            summary.update(qualify(args, facts))
        except Refused as e:
            touched = False
            summary['ok'] = False
            summary['error'] = 'Refused: %s' % str(e)[:500]
        except BaseException as e:
            traceback.print_exc()
            summary['ok'] = False
            summary['error'] = '%s: %s' % (type(e).__name__, str(e)[:500])
    finally:
        if touched:
            try:
                td = teardown()
            except BaseException as e:
                td = {'machines_left': [], 'error': 'teardown failed: %s: %s' % (type(e).__name__, str(e)[:200])}
            summary['cleanup'] = td
            if td['machines_left'] or td['error']:
                summary['ok'] = False
                summary['failed'] = [*summary.get('failed', []), 'cleanup']
        else:
            summary['cleanup'] = {'skipped': 'refused before any call to the daemon'}
        print(json.dumps(summary, separators=(',', ':')))
    return exit_status(summary)


MAX_CLONES = 64
MIN_AGE_SECONDS = 5


def qualify_usage_error(args):
    """A reason to refuse the qualify arguments (exit 2, no JSON), or None."""
    if args.clones < 2:
        return '--clones must be at least 2: one clone has nothing to compare its randomness against'
    if args.clones > MAX_CLONES:
        return '--clones must be at most %d' % MAX_CLONES
    if args.age_seconds < MIN_AGE_SECONDS:
        return '--age-seconds must be at least %d: the clock check allows about 1 s and the exec round trip, so a younger template proves nothing' % MIN_AGE_SECONDS
    if args.memory_mb < 1:
        return '--memory-mb must be a positive number of megabytes'
    return None


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('mode', nargs='?', default='e2e', choices=['e2e', 'bench', 'qualify'])
    ap.add_argument('--clones', type=int, default=3, help='qualify: clones to start, 2 to 64 (8 for the simultaneous run)')
    ap.add_argument('--age-seconds', type=int, default=30, help='qualify: wait between the seal and the first clone (at least 5)')
    ap.add_argument('--sequential', action='store_true', help='qualify: start the clones one after another instead of together')
    ap.add_argument('--memory-mb', type=int, default=512, help='qualify: memory of the builder and its clones')
    ap.add_argument('--allow-unsupported', action='store_true', help='qualify: an unsupported check (no VMGenID in the kernel, no host neighbour entry) does not make the run fail')
    args = ap.parse_args()
    if args.mode == 'qualify':
        err = qualify_usage_error(args)
        if err:
            ap.error(err)
        sys.exit(run_qualify(args))
    mode = args.mode
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
