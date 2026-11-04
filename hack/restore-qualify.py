#!/usr/bin/env python3
"""Real workload backup qualification. Standard library only; JSONL ledger/results.

Filesystem copies promise closed pre-request files and durable pre-request database
commits, not application transactions spanning disks or commits after the request.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid

POSTGRES = 'postgres:17-bookworm@sha256:839fbb5a4942a7758dd93e18b42ea5649807491a0545b5eeeb8f0b8bb11857a5'
PYTHON = 'python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30'


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


class Suite:
    def __init__(self, args):
        self.a = args
        self.ns = 'restore-q-' + uuid.uuid4().hex[:16]
        self.namespaces = [self.ns, self.ns + '-offhost']
        self.machines = []
        self.started = time.monotonic()
        self.sources = []
        self.ctx = ssl.create_default_context(cafile=args.cafile)
        self.output = Path(args.output)
        self.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.ledger = (self.output / 'ledger.jsonl').open('x', buffering=1)
        self.results = (self.output / 'results.jsonl').open('x', buffering=1)
        self.stop = threading.Event()
        self.writer = None
        self.lock = threading.Lock()
        self.acks = []
        self.writer_error = None
        self.seq = 0
        self.planned = set()

    def record(self, event, **fields):
        row = dict(event=event, monotonic=time.monotonic(), **fields)
        line = json.dumps(row)
        self.results.write(line + '\n')
        print(line, flush=True)

    def api(self, method, path, body=None, expected=(200, 201, 204), timeout=180):
        req = urllib.request.Request(self.a.url.rstrip('/') + path,
                                     data=None if body is None else json.dumps(body).encode(),
                                     method=method, headers={'Content-Type': 'application/json',
                                     'Authorization': 'Bearer ' + self.a.token})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as res:
                status, data = res.status, res.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as err:
            status, data = err.code, err.read(65536)
        try:
            value = json.loads(data) if data else None
        except ValueError:
            raise Failure(f'{method} {path}: non-JSON response ({status})')
        require(status in expected, f'{method} {path}: HTTP {status}: {value}')
        return value

    def execute(self, mid, cmd, check=True, timeout_ms=30000):
        value = self.api('POST', f'/v1/machines/{mid}/exec',
                         {'cmd': cmd, 'timeout_ms': timeout_ms, 'wake': False}, timeout=timeout_ms/1000+10)
        if check:
            require(value['exit_code'] == 0 and not value['timed_out'],
                    f'exec {mid}: {value}')
        return value

    def py(self, mid, code):
        return self.execute(mid, ['python3', '-c', code])['stdout']

    def wait(self, probe, label, seconds=120):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            value = probe()
            if value:
                return value
            time.sleep(0.2)
        raise Failure(f'timed out: {label}')

    def create(self, image=None, restore=None, offhost=False, **extra):
        self.seq += 1
        ns = self.namespaces[1] if offhost else self.ns
        body = dict(namespace=ns, name=f'q{self.seq}', size={'vcpus': 1, 'memory_mb': 512},
                    sleep='never', backup=None,
                    region=self.a.destination_region if offhost else self.a.source_region)
        if restore:
            body['restore'] = restore
        elif image is not None:
            body['image'] = image
        body.update(extra)
        body['metadata'] = {'restore_qualification': self.ns}
        self.planned.add((ns, body['name']))
        value = self.api('POST', '/v1/machines', body)
        mid = value['id']
        self.machines.append(mid)
        self.record('created', machine=mid, namespace=ns)

        def ready():
            m = self.api('GET', f'/v1/machines/{mid}')
            require(m['state'] not in ('error', 'stopped'), f'boot failed {mid}: {m}')
            return m if m['state'] == 'running' else None
        return self.wait(ready, f'boot {mid}', 240)

    def backup(self, mid, consistency=None, expected_consistency=None):
        with self.lock:
            start = time.monotonic()
            before = list(self.acks)
        self.ledger.write(json.dumps(dict(event='backup_begin', machine=mid,
                                         monotonic=start, acked=[x[0] for x in before])) + '\n')
        if mid not in self.sources:
            self.sources.append(mid)
        b = self.api('POST', f'/v1/machines/{mid}/backups',
                     {} if consistency is None else {'consistency': consistency}, timeout=300)
        if mid not in self.sources:
            self.sources.append(mid)
        require(b['consistency'] in ('filesystem', 'synced', 'unsynced'), 'unknown consistency')
        require(b['consistency'] == (expected_consistency or consistency or 'filesystem'), f'copy fell back: {b}')
        self.record('backup', machine=mid, backup=b['id'], consistency=b['consistency'],
                    consistency_reason=b.get('consistency_reason'), seconds=time.monotonic()-start,
                    incremental=b['incremental'], bytes=b['bytes'])
        return b, before, start

    def restore(self, mid, b, offhost=False):
        start = time.monotonic()
        m = self.create(restore={'machine_id': mid, 'backup': b['id']}, offhost=offhost)
        return m, start

    def sql(self, mid, sql, check=True):
        return self.execute(mid, ['psql', '-h', '/var/run/postgresql', '-U', 'postgres', '-d', 'postgres', '-At',
                                  '-v', 'ON_ERROR_STOP=1', '-c', sql], check)

    def postgres_ready(self, mid, seconds=120):
        # The official image's temporary init server accepts socket queries too,
        # but starts with listen_addresses=''. Only its final server enables TCP.
        # Probe the same socket used by the workload, with no mutation to replay.
        sql = "SELECT 1 WHERE current_setting('listen_addresses') <> '' AND NOT pg_is_in_recovery()"
        cmd = ['sh', '-c',
               'export PGCONNECT_TIMEOUT=2 PGOPTIONS="-c statement_timeout=2000"; '
               'pg_isready -h /var/run/postgresql -U postgres -d postgres -t 2 >/dev/null && '
               'exec psql -h /var/run/postgresql -U postgres -d postgres -At '
               '-v ON_ERROR_STOP=1 -c ' + shlex.quote(sql)]
        start = time.monotonic()
        deadline = start + seconds
        last = None
        while time.monotonic() < deadline:
            remaining = deadline-time.monotonic()
            last = self.execute(mid, cmd, check=False,
                                timeout_ms=max(1, min(5000, int(remaining*1000))))
            if last['exit_code'] == 0 and not last['timed_out'] and last['stdout'].strip() == '1':
                self.record('postgres_ready', machine=mid, seconds=time.monotonic()-start,
                            probe='socket pg_isready and query on final server outside recovery')
                return
            time.sleep(min(0.2, max(0, deadline-time.monotonic())))
        raise Failure(f'Postgres final server not ready on /var/run/postgresql within {seconds}s '
                      f'(temporary init server excluded); last probe: {last}')

    def database(self):
        m = self.create(POSTGRES, env={'POSTGRES_HOST_AUTH_METHOD': 'trust',
                        'PGDATA': '/data/pg'}, volume={'size_gb': 1, 'mount': '/data'})
        mid = m['id']
        self.postgres_ready(mid)
        self.sql(mid, 'CREATE TABLE ledger (id bigint PRIMARY KEY, payload text NOT NULL)')

        def write():
            try:
                for i in range(1, 100001):
                    if self.stop.is_set():
                        break
                    v = self.sql(mid, f"INSERT INTO ledger VALUES ({i}, repeat(md5('{i}'),128)); SELECT {i}")
                    require(v['stdout'].strip().splitlines()[-1] == str(i), 'unacknowledged commit')
                    with self.lock:
                        ack = (i, time.monotonic())
                        self.ledger.write(json.dumps(dict(event='ack', id=i, monotonic=ack[1])) + '\n')
                        self.acks.append(ack)
            except Exception as err:
                self.writer_error = str(err)
        self.writer = threading.Thread(target=write)
        self.writer.start()
        self.wait(lambda: len(self.acks) >= 20 or self.writer_error, '20 commits')
        points = []
        for _ in range(3):
            require(not self.writer_error, self.writer_error)
            b, before, start = self.backup(mid)
            points.append((b, before, start))
            count = len(self.acks)
            self.wait(lambda: len(self.acks) >= count + 10 or self.writer_error, 'writer advances')
        self.stop.set()
        self.writer.join(45)
        require(not self.writer.is_alive() and not self.writer_error, f'writer: {self.writer_error}')
        require(not points[0][0]['incremental'], 'first backup must be full')
        for index in (1, 2):
            b = points[index][0]
            require(b['incremental'] and all(d.get('from') == points[index-1][0]['id'] for d in b['disks']),
                    'expected two linked incrementals')
        for index in (2, 0):
            self.verify_database(mid, *points[index])
        status = self.api('DELETE', f"/v1/machines/{mid}/backups/{points[1][0]['id']}", expected=(409,))
        require(status.get('code') == 'conflict', f'middle delete wrong reason: {status}')
        self.record('chain', status='passed', middle_delete='409 conflict; descendants retained')
        if self.a.destination_region:
            chain = self.api('GET', f'/v1/machines/{mid}/backups')
            if self.a.store_transfer:
                subprocess.run([self.a.store_transfer, 'copy', mid], check=True, timeout=180)
            self.destroy(mid)
            self.record('source_destroyed', machine=mid, host=m.get('host'))
            if self.a.source_offline_hook:
                try:
                    subprocess.run([self.a.source_offline_hook, 'offline', mid], check=True, timeout=90)
                    self.wait(lambda: any(h['id'] == m['host'] and h['state'] == 'down'
                                          for h in self.api('GET', '/v1/hosts')),
                              'fleet observes source host down', 120)
                    self.record('source_offline', status='passed', host=m['host'])
                    self.verify_database(mid, *points[2], offhost=True, source_host=m['host'], chain=chain)
                finally:
                    subprocess.run([self.a.source_offline_hook, 'recover', mid], check=True, timeout=90)
                    self.wait(lambda: any(h['id'] == m['host'] and h['state'] == 'ready'
                                          for h in self.api('GET', '/v1/hosts')),
                              'source host recovered for cleanup', 120)
            else:
                self.verify_database(mid, *points[2], offhost=True, source_host=m.get('host'), chain=chain)
        else:
            self.record('offhost', status='skipped', reason='no destination region supplied')
        if self.a.allow_daemon_kill and not self.a.destination_region:
            self.failure_restore(mid, *points[2])
        else:
            self.record('failure', status='skipped', reason='interrupted backup runs in the single-host job' if self.a.destination_region else '--allow-daemon-kill absent')
        if mid in self.machines:
            self.destroy(mid)

    def verify_database(self, source, b, before, backup_start, offhost=False, source_host=None, chain=None):
        m, start = self.restore(source, b, offhost)
        mid = m['id']
        self.postgres_ready(mid)
        first_query = time.monotonic() - start
        if chain is None:
            chain = self.api('GET', f'/v1/machines/{source}/backups')
        by_id = {x['id']: x for x in chain}
        pending = [b['id']]
        seen = set()
        while pending:
            bid = pending.pop()
            if bid in seen:
                continue
            seen.add(bid)
            pending.extend(d['from'] for d in by_id[bid]['disks'] if d.get('from'))
        stream_bytes = sum(by_id[bid]['bytes'] for bid in seen)
        values = self.sql(mid, 'SELECT id FROM ledger ORDER BY id')['stdout'].splitlines()
        ids = [int(x) for x in values]
        require(ids == list(range(1, len(ids)+1)), f'DATA INTEGRITY: holes in restored ledger {mid}')
        require(len(ids) >= len(before), f'DATA INTEGRITY: missing pre-backup ack {mid}')
        self.execute(mid, ['pg_amcheck', '-U', 'postgres', '--database=postgres', '--install-missing'])
        logs = self.api('GET', f'/v1/machines/{mid}/logs?limit=1000')
        (self.output / f'{mid}-logs.json').write_text(json.dumps(logs))
        text = json.dumps(logs)
        require('database system is ready to accept connections' in text, 'no automatic postgres startup evidence')
        require('database system was interrupted' in text and ('redo done' in text or 'redo is not required' in text),
                f'no crash recovery completion evidence: {text}')
        require('ERROR:' not in text and 'PANIC:' not in text and 'invalid checkpoint' not in text and 'could not locate a valid checkpoint' not in text,
                f'DATA INTEGRITY: recovery errors: {text}')
        after = [i for i, t in self.acks if t >= backup_start]
        lost = [i for i, _ in self.acks if i > len(ids)]
        lost_times = [t for i, t in self.acks if i in lost]
        if offhost:
            require(source_host and m.get('host') and source_host != m['host'], 'offhost restore landed on source')
        self.record('offhost' if offhost else 'postgres', status='passed', backup=b['id'],
                    consistency=b['consistency'], pre_request_acks=len(before), restored_rows=len(ids),
                    acked_after_backup_start=len(after), lost_ack_ids=lost,
                    loss_window_seconds=(max(lost_times)-min(lost_times)) if lost_times else 0,
                    backup_start_to_last_ack_seconds=max(0, self.acks[-1][1]-backup_start),
                    restore_to_first_query_seconds=first_query,
                    restored_chain_bytes=stream_bytes,
                    seconds_per_stream_gib=first_query/(stream_bytes/2**30),
                    source_host=source_host, destination_host=m.get('host'),
                    source_destroyed=offhost, source_offline=bool(offhost and self.a.source_offline_hook))
        self.destroy(mid)

    def destroy(self, mid):
        self.api('DELETE', f'/v1/machines/{mid}', expected=(200, 204, 404))
        if mid in self.machines:
            self.machines.remove(mid)

    def files(self):
        self.stop.clear()
        # No fsync: every close acknowledged by the guest is checked against a host manifest.
        m = self.create(PYTHON, entrypoint=['python3'], cmd=['-c', 'import time; time.sleep(86400)'],
                        volume={'size_gb': 1, 'mount': '/data'})
        mid = m['id']
        code = """import hashlib,json,os
out={}
for root in ['/root/files','/data/files']:
 os.makedirs(root,exist_ok=True)
 for i in range(128):
  p=root+'/'+str(i); b=hashlib.sha256(str(i).encode()).digest()*2048
  with open(p,'wb') as f: f.write(b)
  out[p]=hashlib.sha256(b).hexdigest()
print(json.dumps(out))
"""
        manifest = json.loads(self.py(mid, code))
        (self.output / 'manifest.json').write_text(json.dumps(manifest))
        b, _, _ = self.backup(mid)
        require({d['disk'] for d in b['disks']} == {'root', 'data'}, 'two disks not captured')
        r, _ = self.restore(mid, b)
        verify = """import hashlib,json,os
out={}
for root in ['/root/files','/data/files']:
 for n in os.listdir(root):
  p=root+'/'+n
  with open(p,'rb') as f: out[p]=hashlib.sha256(f.read()).hexdigest()
print(json.dumps(out))
"""
        require(json.loads(self.py(r['id'], verify)) == manifest, 'DATA INTEGRITY: frozen file bytes differ')
        self.record('files', status='passed', files=len(manifest), consistency=b['consistency'])
        self.destroy(r['id'])
        self.api('POST', f'/v1/machines/{mid}/stop', {'timeout_sec': 10, 'suspend': True})
        self.wait(lambda: self.api('GET', f'/v1/machines/{mid}').get('suspended'), 'synced suspend')
        b, _, _ = self.backup(mid, expected_consistency='synced')
        r, _ = self.restore(mid, b)
        require(json.loads(self.py(r['id'], verify)) == manifest, 'DATA INTEGRITY: synced files differ')
        self.record('synced', status='passed', consistency=b['consistency'], files=len(manifest))
        self.destroy(r['id'])
        self.api('POST', f'/v1/machines/{mid}/start', {})
        self.wait(lambda: self.api('GET', f'/v1/machines/{mid}')['state'] == 'running', 'restart files')
        # A continuously replaced root/data pair has only these legal interleavings:
        # root==data or root==data+1. Freeze may happen between the two writes.
        self.py(mid, "from pathlib import Path; Path('/root/epoch').write_text('0'); Path('/data/epoch').write_text('0')")
        writer = "from pathlib import Path; import os;\nfor i in range(1,100000):\n for root in ['/root','/data']:\n  p=Path(root+'/epoch.next'); p.write_text(str(i)); os.replace(p,root+'/epoch')"
        self.execute(mid, ['sh', '-c', 'python3 -c ' + shlex.quote(writer) + ' >/tmp/epoch.log 2>&1 &'])
        b, _, _ = self.backup(mid)
        r, _ = self.restore(mid, b)
        pair = json.loads(self.py(r['id'], "from pathlib import Path; import json; print(json.dumps([int(Path(p+'/epoch').read_text()) for p in ['/root','/data']]))"))
        require(pair[0] in (pair[1], pair[1]+1), f'DATA INTEGRITY: impossible two-disk state {pair}')
        self.record('multidisk', status='passed', root=pair[0], data=pair[1], consistency=b['consistency'])
        self.destroy(r['id'])
        self.destroy(mid)
        self.unsynced_control()
        self.python_startup()

    def unsynced_control(self):
        # Copy immediately after a closed write. Fork avoids stream upload latency in
        # measuring the dirty-cache interval; disk copy semantics are the same (ADR 0092).
        for attempt in range(4):
            m = self.create(PYTHON, entrypoint=['python3'], cmd=['-c', 'import time; time.sleep(86400)'])
            mid = m['id']
            marker = uuid.uuid4().hex
            start = time.monotonic()
            self.py(mid, f"open('/root/dirty','w').write({marker!r})")
            fork = self.create(fork={'machine_id': mid, 'consistency': 'unsynced'})
            origin = fork.get('fork', {})
            require(origin.get('consistency') == 'unsynced', f'opt-out misreported: {origin}')
            value = self.py(fork['id'], "import json; from pathlib import Path; p=Path('/root/dirty'); print(json.dumps(p.read_text() if p.exists() else None))")
            missing = json.loads(value) != marker
            self.record('unsynced_trial', attempt=attempt, data_lost=missing, seconds=time.monotonic()-start,
                        consistency='unsynced')
            self.destroy(fork['id'])
            self.destroy(mid)
            if missing:
                self.record('unsynced', status='passed', control='successful read demonstrated lost closed write')
                return
        raise Failure('unsynced positive control inconclusive: no loss in four trials')

    def python_startup(self):
        # Import real bytecode on both boots. Copy as soon as startup has produced
        # at least one .pyc; restored readiness must come from this boot's console.
        app = """from pathlib import Path
import importlib,time
p=Path('/root/modules'); p.mkdir(exist_ok=True)
import sys; sys.path.insert(0,str(p))
for i in range(150):
 f=p/('m'+str(i)+'.py')
 if not f.exists(): f.write_text('value='+repr('x'*32768))
for i in range(150): importlib.import_module('m'+str(i))
print('RESTORE_QUALIFY_PYTHON_READY', flush=True)
while True: time.sleep(1)
"""
        m = self.create(PYTHON, entrypoint=['python3'], cmd=['-c', app])
        self.wait(lambda: self.py(m['id'], "from pathlib import Path; print(int(any(Path('/root/modules').glob('__pycache__/*.pyc'))))").strip() == '1', 'Python imports begin')
        b, _, _ = self.backup(m['id'])
        r, _ = self.restore(m['id'], b)
        self.wait(lambda: 'RESTORE_QUALIFY_PYTHON_READY' in json.dumps(self.api('GET', f"/v1/machines/{r['id']}/logs?limit=1000")), 'restored Python imports complete')
        # Inspect the actual process as well as its file (the file could be inherited).
        v = self.py(r['id'], "from pathlib import Path; import json; print(json.dumps([p.name for p in Path('/root/modules/__pycache__').iterdir()]))")
        require(len(json.loads(v)) == 150, 'DATA INTEGRITY: incomplete Python bytecode cache')
        logs = self.api('GET', f"/v1/machines/{r['id']}/logs?limit=1000")
        require('Traceback' not in json.dumps(logs), f'DATA INTEGRITY: Python startup: {logs}')
        self.record('python_startup', status='passed', consistency=b['consistency'])
        self.destroy(r['id'])
        self.destroy(m['id'])

    def pause_backup_send(self, mid, daemon, seconds=30):
        # Native CI directory store only. Observe this machine's data stream bytes
        # before stopping its exact daemon-owned sender. pidfd binds both signals
        # to the observed process even if its numeric pid is later reused.
        end = time.monotonic()+seconds
        directory = Path('/var/lib/briqyard/backups/backups')/mid/'data'
        while time.monotonic() < end:
            for proc in Path('/proc').iterdir():
                if not proc.name.isdecimal():
                    continue
                fd = None
                keep = False
                try:
                    stat = (proc/'stat').read_text().rsplit(')', 1)[1].split()
                    args = (proc/'cmdline').read_bytes().split(b'\0')
                    if (int(stat[1]) != daemon or args[1:2] != [b'send'] or
                            (proc/'exe').resolve().name != 'zfs'):
                        continue
                    snapshot = next((arg for arg in args if b'/m/'+mid.encode()+b'/data@bk-' in arg), None)
                    if snapshot is None:
                        continue
                    bid = snapshot.split(b'@bk-', 1)[1].decode('ascii')
                    if not any(p.stat().st_size > 0 for p in directory.glob(bid+'.zfs*')):
                        continue
                    fd = os.pidfd_open(int(proc.name))
                    current = (proc/'stat').read_text().rsplit(')', 1)[1].split()
                    if current[19] != stat[19]:
                        continue
                    signal.pidfd_send_signal(fd, signal.SIGSTOP)
                    keep = True
                    self.record('backup_paused', machine=mid, backup=bid,
                                evidence='data stream bytes present; exact daemon child paused')
                    return fd, bid
                except (FileNotFoundError, ProcessLookupError):
                    pass
                finally:
                    if fd is not None and not keep:
                        os.close(fd)
            time.sleep(0.01)
        raise Failure('timed out: own data backup stream bytes and sender in flight')

    def failure_restore(self, mid, b, before, start):
        require(os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and os.geteuid() == 0,
                'daemon kill requires root on the disposable native runner')
        self.execute(mid, ['sh', '-c', 'head -c 300000000 /dev/urandom > /data/cut; sync'], timeout_ms=120000)
        complete_ids = {v['id'] for v in self.api('GET', f'/v1/machines/{mid}/backups')}
        daemon = int(subprocess.check_output(
            ['systemctl', 'show', '-p', 'MainPID', '--value', 'briqyardd'], timeout=10))
        require(daemon > 1, 'daemon MainPID absent')
        outcome = []
        def backup():
            try:
                outcome.append(self.api('POST', f'/v1/machines/{mid}/backups', {}, timeout=180))
            except Exception:
                outcome.append(None)
        thread = threading.Thread(target=backup)
        thread.start()
        held = None
        killed = False
        try:
            held, interrupted = self.pause_backup_send(mid, daemon)
            # #145 closes admission while any old service helper survives. Kill the
            # paused sender immediately after the daemon, then require recovery;
            # do not reset the service, remove markers or bypass the barrier.
            os.kill(daemon, signal.SIGKILL)
            killed = True
        finally:
            if held is not None:
                try:
                    signal.pidfd_send_signal(held, signal.SIGKILL if killed else signal.SIGCONT)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(held)
            thread.join(190)
        require(not thread.is_alive() and outcome == [None], 'backup was not interrupted: client must fail')
        def recovered():
            try:
                status = self.api('GET', '/v1/status', expected=(200, 503), timeout=3)
                return 'conditions' in status and not any(
                    c['type'] == 'memory_protection' and c['status'] for c in status['conditions'])
            except (urllib.error.URLError, TimeoutError):
                return False
        self.wait(recovered, 'automatic daemon recovery after exact sender exit', 120)
        listed = self.api('GET', f'/v1/machines/{mid}/backups')
        require({v['id'] for v in listed} == complete_ids and interrupted not in complete_ids,
                'interrupted backup offered or complete backup missing')
        self.verify_database(mid, b, before, start)
        self.record('failure', status='passed', last_complete=b['id'], interrupted_offered=False,
                    recovery='automatic after paused sender killed; no barrier bypass')

    def cleanup(self):
        self.stop.set()
        if self.writer:
            self.writer.join(45)
        errors = []
        # Discover only exact namespaces uniquely generated by this run, including a
        # create whose HTTP response was lost. Never delete a shared namespace.
        for ns in self.namespaces:
            try:
                ms = self.api('GET', '/v1/machines?namespace=' + ns)
                for m in ms:
                    require(m['namespace'] == ns and
                            (ns, m['name']) in self.planned and
                            m.get('metadata', {}).get('restore_qualification') == self.ns,
                            'cleanup ownership mismatch; preserving machine')
                    self.destroy(m['id'])
            except Exception as err:
                errors.append(str(err))
        for mid in self.sources:
            try:
                for b in self.api('GET', f'/v1/machines/{mid}/backups?namespace={self.ns}'):
                    self.api('DELETE', f"/v1/machines/{mid}/backups/{b['id']}?chain=true&namespace={self.ns}", expected=(200,204,404))
            except Exception as err:
                errors.append(str(err))
        if self.a.store_transfer:
            for mid in self.sources:
                try:
                    subprocess.run([self.a.store_transfer, 'cleanup', mid], check=True, timeout=180)
                except Exception as err:
                    errors.append(str(err))
        for ns in self.namespaces:
            try:
                self.api('DELETE', '/v1/namespaces/' + ns, expected=(200,204,404))
            except Exception as err:
                errors.append(str(err))
        self.record('cleanup', status='failed' if errors else 'passed', errors=errors)
        self.ledger.close()
        self.results.close()
        return not errors


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--url', default=os.environ.get('BRIQYARD_URL', 'http://127.0.0.1:7420'))
    p.add_argument('--token', default=os.environ.get('BRIQYARD_TOKEN', ''))
    p.add_argument('--cafile')
    p.add_argument('--output', default='restore-qualification-' + uuid.uuid4().hex[:8])
    p.add_argument('--source-region', default='')
    p.add_argument('--destination-region', default='', help='different fleet region for off-host restore')
    p.add_argument('--store-transfer', help='CI-only executable: receives copy|cleanup and a machine id; operates on store objects only')
    p.add_argument('--source-offline-hook', help='disposable CI hook receiving offline|recover and source machine id')
    p.add_argument('--allow-daemon-kill', action='store_true')
    a = p.parse_args()
    if a.allow_daemon_kill and os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        p.error('--allow-daemon-kill requires disposable native CI')
    if a.source_offline_hook and not (a.allow_daemon_kill and a.destination_region):
        p.error('--source-offline-hook needs --allow-daemon-kill and --destination-region')
    s = Suite(a)
    def interrupted(signum, _frame):
        raise Failure(f'signal {signum}')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    success = False
    try:
        s.record('begin', namespace=s.ns, promise='filesystem, not application transaction consistency')
        s.files()
        s.database()
        success = True
    except Exception as err:
        for mid in s.machines:
            try:
                logs = s.api('GET', f'/v1/machines/{mid}/logs?limit=1000')
                (s.output / f'{mid}-failure-logs.json').write_text(json.dumps(logs))
            except Exception:
                pass
        s.record('failure', status='failed', error=str(err))
    finally:
        s.record('end', status='passed' if success else 'failed', seconds=time.monotonic()-s.started)
        success = s.cleanup() and success
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
