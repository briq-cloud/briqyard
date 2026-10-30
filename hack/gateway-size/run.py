"""Run as root on the locked Linux development host; all artifacts are synthetic."""
import base64, json, os, re, signal, socket, subprocess, sys, threading, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGE = sys.argv[1]
FIXTURE_IMAGE = os.environ.get('BENCH_FIXTURE_IMAGE', 'python:3.12-alpine')
FIXTURE_VCPUS = int(os.environ.get('BENCH_FIXTURE_VCPUS', '2'))
FIXTURE_MEMORY = int(os.environ.get('BENCH_FIXTURE_MEMORY_MB', '1024'))
STREAM_CLIENT = os.environ.get('BENCH_STREAM_CLIENT', 'python')
TLS_SERVER = os.environ.get('BENCH_TLS_SERVER', 'python')
if FIXTURE_VCPUS <= 0 or FIXTURE_MEMORY <= 0 or STREAM_CLIENT not in ('python', 'rust') or TLS_SERVER not in ('python', 'rust'):
    raise ValueError('invalid fixture configuration')
MEMORY = int(os.environ.get('BENCH_MEMORY_MB', '128'))
VCPUS = int(os.environ.get('BENCH_VCPUS', '1'))
NATIVE_CPU = int(os.environ.get('BENCH_NATIVE_CPU_MILLIS', '0'))
NAMESPACE_GATEWAY = os.environ.get('BENCH_NAMESPACE_GATEWAY', '0') == '1'
HELD = os.environ.get('BENCH_HELD_BODIES', '8')
BODY_MB = os.environ.get('BENCH_MAX_BODY_MB', '8')
UPLOAD_MB = os.environ.get('BENCH_UPLOAD_MB', BODY_MB)
MAX_CONNECTIONS = os.environ.get('BENCH_MAX_CONNECTIONS', '1024')
BODY_CONCURRENCY = int(os.environ.get('BENCH_BODY_CONCURRENCY', '8'))
STREAM_COUNTS = [int(n) for n in os.environ.get('BENCH_STREAM_COUNTS', '100,1000').split(',')]
CONNECT_LIMIT = int(os.environ.get('BENCH_CONNECT_LIMIT', '0'))
RAMP_PER_SECOND = float(os.environ.get('BENCH_RAMP_PER_SECOND', '0'))
DIRECT_CONTROL = os.environ.get('BENCH_DIRECT_CONTROL', '0') == '1'
MODES = set(os.environ.get('BENCH_MODES', 'bodies,throughput,streams').split(','))
if not MODES or not MODES <= {'bodies', 'throughput', 'streams', 'idle', 'overload'}:
    raise ValueError('invalid workload modes')
REPEATS = int(os.environ.get('BENCH_REPEATS', '1'))
if REPEATS <= 0:
    raise ValueError('repeats must be positive')
CPU_MILLIS = [int(n) for n in os.environ.get('BENCH_CPU_MILLIS', '1000,100,250,500').split(',')]
if RAMP_PER_SECOND < 0 or CONNECT_LIMIT < 0 or any(n <= 0 for n in STREAM_COUNTS):
    raise ValueError('invalid concurrency settings')
if BODY_CONCURRENCY <= 0 or MEMORY <= 0 or int(HELD) < 0 or int(BODY_MB) <= 0 or not CPU_MILLIS or any(n <= 0 for n in CPU_MILLIS):
    raise ValueError('invalid benchmark limits')
if VCPUS <= 0 or NATIVE_CPU < 0 or NATIVE_CPU > VCPUS * 1000 or (NATIVE_CPU and CPU_MILLIS != [NATIVE_CPU]):
    raise ValueError('native CPU must match the single measured quota and fit guest topology')
TENANT = 'gateway-size-' + str(os.getpid())
OUT = Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
BASE = 'http://127.0.0.1:7420/v1'
made = []
diagnostic_ids = []

def interrupted(signum, frame):
    raise KeyboardInterrupt(f'signal {signum}')

for signum in (signal.SIGTERM, signal.SIGHUP):
    signal.signal(signum, interrupted)

def api(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=360) as r:
        b = r.read()
        return json.loads(b) if b else None

def emit(kind, **data):
    row = dict(kind=kind, time=time.time(), **data)
    with (OUT / 'measurements.jsonl').open('a') as f:
        f.write(json.dumps(row) + '\n')
    print(json.dumps(row), flush=True)

def file(name, target=None):
    return {'path': target or '/tmp/' + name, 'base64': base64.b64encode((HERE/name).read_bytes()).decode()}

def create(**kw):
    spec = dict(tenant=TENANT, size=kw.pop('size', {'vcpus': 1, 'memory_mb': 128}), sleep='never', **kw)
    m = api('POST', '/machines', spec)
    made.append(m['id'])
    diagnostic_ids.append(m['id'])
    deadline = time.monotonic() + 300
    target = 'created' if kw.get('start') is False else 'running'
    while m.get('state') != target:
        if m.get('state') in ('error', 'destroying') or time.monotonic() > deadline:
            raise RuntimeError('machine did not reach ' + target + ': ' + json.dumps(m))
        time.sleep(.05)
        m = api('GET', '/machines/' + m['id'])
    return m

def exec_cmd(mid, *cmd, timeout='120s'):
    return ['briqyard', 'machine', 'exec', '--timeout', timeout, mid, '--', *cmd]

def guest(mid, *cmd):
    return subprocess.check_output(exec_cmd(mid, *cmd, timeout='10s'), text=True, timeout=15)

def ready(ip, port):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((ip, port), timeout=.2):
                return
        except OSError:
            time.sleep(.02)
    raise TimeoutError((ip, port))

def process(mid):
    return json.loads(Path('/var/lib/briqyard/state/machines', mid + '.json').read_text())['pid']

def cgroup(mid):
    cg = Path('/proc', str(process(mid)), 'cgroup').read_text().strip().split('::')[-1]
    return Path('/sys/fs/cgroup' + cg)

def sample(mid, phase, expected_guest_pid=None):
    try:
        pid = process(mid)
        host = Path('/proc', str(pid), 'smaps_rollup').read_text()
        mem = guest(mid, '/busybox', 'sh', '-c',
            'found=0; for p in /proc/[0-9]*/comm; do read n < "$p"; case "$n" in credential-gate*) found=$((found+1)); /busybox cat "${p%comm}status" || exit 1;; esac; done; test "$found" = 1 || exit 1; /busybox cat /proc/meminfo')
        guest_pids = re.findall(r'^Pid:\s+(\d+)$', mem, re.M)
        if len(guest_pids) != 1 or not re.search(r'^VmHWM:\s+\d+ kB$', mem, re.M):
            raise RuntimeError('missing gateway PID or memory high-water mark')
        if expected_guest_pid is not None and guest_pids[0] != expected_guest_pid:
            raise RuntimeError('gateway restarted during workload')
        emit('memory', phase=phase, pid=pid, host_smaps=host, guest=mem,
             cgroup_memory=cgroup(mid).joinpath('memory.current').read_text().strip())
        return guest_pids[0]
    except Exception as e:
        emit('sample_error', phase=phase, error=repr(e))
        raise


def counters(mid):
    cg = cgroup(mid)
    return {name: cg.joinpath(name).read_text().strip()
            for name in ('cpu.stat', 'memory.events', 'memory.current', 'memory.peak')}

def values(text):
    return {key: int(value) for key, value in (line.split() for line in text.splitlines())}

class HighWater:
    """Poll without guest exec overhead; kernel and guest lifetime peaks are also recorded."""
    def __init__(self, ids):
        self.paths = {label: cgroup(mid) / 'memory.current' for label, mid in ids.items()}
        self.stop = threading.Event()
        self.peaks = {label: 0 for label in ids}
        self.samples = 0
        self.errors = []
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            while not self.stop.is_set():
                for label, path in self.paths.items():
                    self.peaks[label] = max(self.peaks[label], int(path.read_text()))
                self.samples += 1
                self.stop.wait(.05)
        except Exception as e:
            self.errors.append(repr(e))

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=2)
        if self.thread.is_alive() or self.errors or self.samples == 0:
            raise RuntimeError('invalid host sampling: ' + repr(self.errors))

try:
    emit('environment', uname=os.uname(), image=IMAGE, fixture_image=FIXTURE_IMAGE, fixture_vcpus=FIXTURE_VCPUS, fixture_memory_mb=FIXTURE_MEMORY, stream_client=STREAM_CLIENT, tls_server=TLS_SERVER, status=api('GET', '/status'), memory_mb=MEMORY, vcpus=VCPUS, native_cpu_millis=NATIVE_CPU, namespace_gateway=NAMESPACE_GATEWAY, repeats=REPEATS, held_bodies=HELD, max_body_mb=BODY_MB, upload_mb=UPLOAD_MB, max_connections=MAX_CONNECTIONS, body_concurrency=BODY_CONCURRENCY, cpu_millis=CPU_MILLIS, stream_counts=STREAM_COUNTS, connect_limit=CONNECT_LIMIT, direct_control=DIRECT_CONTROL, ramp_per_second=RAMP_PER_SECOND)
    bench = create(name='bench', image=FIXTURE_IMAGE, size={'vcpus': FIXTURE_VCPUS, 'memory_mb': FIXTURE_MEMORY},
        files=[file(n) for n in ['server.py', 'client.py', 'overload.py', 'cert.pem', 'key.pem']] + [file('ca.pem', '/tmp/bench-ca.pem')],
        env={'BENCH_TLS_SERVER': TLS_SERVER}, cmd=['python', '/tmp/server.py'])
    ready(bench['ip'], 8399)
    ready(bench['ip'], 443)
    gateway_size = {'vcpus': VCPUS, 'memory_mb': MEMORY}
    if NATIVE_CPU:
        gateway_size['cpu_millis'] = NATIVE_CPU
    gateway_spec = dict(image=IMAGE, size=gateway_size,
        env={'BRIQ_API_URL': 'http://bench.internal:8399', 'BRIQ_GATEWAY_TOKEN': 'benchmark',
             'BENCH_UPSTREAM_CA': '/bench-ca.pem', 'GATEWAY_MAX_CONNECTIONS': MAX_CONNECTIONS,
             'GATEWAY_HELD_BODIES': HELD, 'GATEWAY_MAX_BODY_MB': BODY_MB, 'GATEWAY_LOG_LEVEL': 'error'},
        files=[file('ca.pem', '/bench-ca.pem')])
    if NAMESPACE_GATEWAY:
        ns = api('PUT', '/namespaces/' + TENANT + '/gateway', dict(gateway_spec, port=3128))
        mid = ns['gateway']['machine_id']
        diagnostic_ids.append(mid)
        gw = api('GET', '/machines/' + mid)
        consumer = create(name='consumer', image=FIXTURE_IMAGE, start=False,
            size={'vcpus': 1, 'memory_mb': 128, 'cpu_millis': 1000},
            egress={'mode': 'via', 'via': 'gateway'}, cmd=['python', '-c', 'import time; time.sleep(3600)'])
    else:
        gw = create(name='proxy', start=False, **gateway_spec)
        mid = gw['id']
    for action in (['first', 'cold'] if NAMESPACE_GATEWAY else ['first', 'cold', 'resume']):
        if action != 'first':
            stop_use = api('GET', '/status')['used']
            stop_id = consumer['id'] if NAMESPACE_GATEWAY else mid
            api('POST', '/machines/' + stop_id + '/stop', {'suspend': action == 'resume'})
            if NAMESPACE_GATEWAY:
                deadline = time.monotonic() + 75
                while api('GET', '/machines/' + mid)['state'] != 'stopped':
                    if time.monotonic() > deadline:
                        raise TimeoutError('namespace gateway did not stop after its consumer')
                    time.sleep(.2)
                stopped_use = api('GET', '/status')['used']
                expected_delta = (NATIVE_CPU or VCPUS * 1000) + 1000
                if stop_use['cpu_millis'] - stopped_use['cpu_millis'] != expected_delta:
                    raise RuntimeError('host did not release gateway and consumer CPU reservations')
                emit('reservation_release', before=stop_use, after=stopped_use, expected_delta=expected_delta)
        gateway_before_start = api('GET', '/machines/' + mid)
        before_use = api('GET', '/status')['used']
        start = time.monotonic()
        start_id = consumer['id'] if NAMESPACE_GATEWAY else mid
        api('POST', '/machines/' + start_id + '/start', {})
        gw = api('GET', '/machines/' + mid)
        ready(gw['ip'], 3128)
        emit('boot', action=('consumer_restart' if action == 'cold' else action) if NAMESPACE_GATEWAY else action,
             scope='consumer start API through gateway TCP readiness' if NAMESPACE_GATEWAY else 'gateway start API through gateway TCP readiness',
             gateway_was_suspended=gateway_before_start.get('suspended', False), seconds=time.monotonic()-start)
        if NAMESPACE_GATEWAY:
            binding = api('GET', '/namespaces/' + TENANT)['gateway']
            if binding['machine_id'] != mid or binding['ip'] != gw['ip'] or gw['size'] != gateway_size:
                raise RuntimeError('namespace gateway binding or size mismatch')
            used = api('GET', '/status')['used']
            expected_delta = (NATIVE_CPU or VCPUS * 1000) + 1000
            if used['cpu_millis'] - before_use['cpu_millis'] != expected_delta:
                raise RuntimeError('host did not account for gateway and consumer CPU reservations')
            emit('reservation', before=before_use, after=used, expected_delta=expected_delta)
        sample(mid, 'idle-' + action)
    for millis in CPU_MILLIS:
        period = 100000 if millis >= 10 else 1000000
        expected_cpu_max = f'{millis * period // 1000} {period}'
        if NATIVE_CPU:
            if cgroup(mid).joinpath('cpu.max').read_text().strip() != expected_cpu_max:
                raise RuntimeError('native CPU quota does not match the requested size')
        else:
            cgroup(mid).joinpath('cpu.max').write_text(expected_cpu_max)
        emit('cpu', millis=millis, cpu_max=cgroup(mid).joinpath('cpu.max').read_text().strip())
        # Body pressure is measured before an optional connection-burst failure.
        cases = [('proxy', 'bodies', BODY_CONCURRENCY), ('proxy', 'throughput', 16)]
        for count in STREAM_COUNTS:
            if DIRECT_CONTROL:
                cases.append(('direct', 'streams', count))
            cases.append(('proxy', 'streams', count))
        if 'overload' in MODES:
            cases.append(('proxy', 'overload', int(MAX_CONNECTIONS)))
        for iteration, (route, mode, count) in enumerate(cases * REPEATS):
            if mode not in MODES:
                continue
            phase = f'{millis}m-{route}-{mode}-{count}'
            if REPEATS > 1:
                phase += f'-repeat{iteration // len(cases) + 1}'
            guest_pid = sample(mid, phase + '-before')
            before = {'gateway': counters(mid), 'fixture': counters(bench['id'])}
            scheduler_before = {'host': Path('/proc/stat').read_text(),
                'gateway': guest(mid, '/busybox', 'cat', '/proc/stat'),
                'fixture': guest(bench['id'], '/bin/cat', '/proc/stat')}
            high_water = HighWater({'gateway': mid, 'fixture': bench['id']})
            high_water.thread.start()
            p = None
            health_under_overload = False
            try:
                with (OUT / (phase + '.json')).open('w') as log:
                    client_command = (['python', '/tmp/overload.py'] if mode == 'overload' else
                        ['/bench-client'] if mode == 'streams' and STREAM_CLIENT == 'rust' else ['python', '/tmp/client.py'])
                    p = subprocess.Popen(exec_cmd(bench['id'], *client_command, mode, str(count), gw['ip'], UPLOAD_MB, route, str(CONNECT_LIMIT), str(RAMP_PER_SECOND)),
                                         stdout=log, stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 140
                    while p.poll() is None:
                        if time.monotonic() > deadline:
                            raise TimeoutError('load command exceeded its deadline')
                        if mode == 'overload' and not health_under_overload:
                            marker = guest(bench['id'], 'python', '-c', "from pathlib import Path; print(Path('/tmp/overload-ready').exists())").strip()
                            if marker == 'True':
                                guest(mid, '/credential-gateway', 'health')
                                guest(bench['id'], 'python', '-c', "from pathlib import Path; Path('/tmp/overload-release').write_text('health checked')")
                                health_under_overload = True
                        sample(mid, phase, guest_pid)
                        time.sleep(2)
            except BaseException as error:
                observed = {}
                for label, machine_id in [('gateway', mid), ('fixture', bench['id'])]:
                    try:
                        observed[label] = counters(machine_id)
                    except Exception as diagnostic:
                        observed[label] = {'unavailable': repr(diagnostic)}
                result_path = OUT / (phase + '.json')
                emit('load_exception', phase=phase, error=repr(error),
                     result=result_path.read_text() if result_path.exists() else '',
                     counters_before=before, counters_after=observed,
                     sampled_memory_peak=high_water.peaks, host_sample_count=high_water.samples)
                raise
            finally:
                if p is not None and p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=5)
                high_water.finish()
            after = {'gateway': counters(mid), 'fixture': counters(bench['id'])}
            scheduler_after = {'host': Path('/proc/stat').read_text(),
                'gateway': guest(mid, '/busybox', 'cat', '/proc/stat'),
                'fixture': guest(bench['id'], '/bin/cat', '/proc/stat')}
            result_text = (OUT / (phase + '.json')).read_text()
            emit('load', phase=phase, exit_code=p.returncode, result=result_text,
                 counters_before=before, counters_after=after,
                 scheduler_before=scheduler_before, scheduler_after=scheduler_after,
                 sampled_memory_peak=high_water.peaks, host_sample_count=high_water.samples,
                 peak_scope='sampled peaks are per phase; memory.peak and guest VmHWM are lifetime peaks')
            if mode == 'overload' and not health_under_overload:
                raise RuntimeError('health was not checked while admission was full')
            if p.returncode:
                raise RuntimeError('load failed: ' + phase)
            result = json.loads(result_text)
            if result['error_count'] or result['completed'] != count:
                raise RuntimeError('incomplete workload: ' + phase)
            for label in before:
                initial = values(before[label]['memory.events'])
                final = values(after[label]['memory.events'])
                if any(final.get(k, 0) > initial.get(k, 0) for k in ('oom', 'oom_kill', 'max')):
                    raise RuntimeError(label + ' hit its memory limit: ' + phase)
            guest(mid, '/credential-gateway', 'health')
            sample(mid, phase + '-after', guest_pid)

except Exception as err:
    emit('failure', error=repr(err))
    for failed_id in diagnostic_ids:
        try:
            emit('failure_machine', machine=api('GET', '/machines/' + failed_id),
                 logs=api('GET', '/machines/' + failed_id + '/logs?limit=20000'))
        except Exception as diagnostic:
            emit('diagnostic_error', machine=failed_id, error=repr(diagnostic))
    raise
finally:
    for mid in reversed(made):
        try:
            api('DELETE', '/machines/' + mid)
        except Exception as e:
            emit('cleanup_error', machine=mid, error=repr(e))
    try:
        api('DELETE', '/tenants/' + TENANT)
    except Exception as e:
        emit('cleanup_error', tenant=TENANT, error=repr(e))
